# Design Document: NMAP Port Scanner

## 1. Resource & API Design

`scans` is the one resource. There are two endpoints:

| Endpoint | Method | Side effects | Purpose |
|---|---|---|---|
| `POST /v1/scans` | Writes | Runs `nmap`, writes to DB | Scan one or more hosts, then return each host's full history |
| `GET /v1/scans?target=` | Read only | None | Read a host's stored scan history, without scanning |

They're split into two endpoints so a `GET` can never accidentally trigger a scan.

**`POST /v1/scans`** always takes a list of targets, even if it's just one
host. It scans them all concurrently. For each target, the response includes
the new scan, a diff against the previous one, and the full history, so you
never need to make a second request just to see it:

```json
{
  "results": [
    {
      "target": "scanme.nmap.org",
      "ok": true,
      "result": {
        "current_scan": { "id": 3, "scanned_at": "2026-08-14T00:38:05Z", "open_ports": [22, 80] },
        "diff": { "added": [], "removed": [] },
        "history": [ { "id": 3, "scanned_at": "2026-08-14T00:38:05Z", "open_ports": [22, 80] } ]
      },
      "error": null
    }
  ]
}
```

Each target gets one entry in `results`, either `ok: true` with a `result`,
or `ok: false` with an `error`. Never both.

**`GET /v1/scans?target=`** requires `target`; there's no "give me every
host" mode. A host that's never been scanned just returns an empty list, not
a 404. Not having any history is a perfectly normal answer.

**Status codes:** both endpoints return `200`, even when a multi target
`POST` only partially succeeds. `400` is reserved for a malformed request.
`503` shows up if the database can't be reached. `POST` doesn't return `201`
because there's no per resource `GET /scans/{id}` endpoint. Scans are only
retrievable in aggregate via `GET /scans`, so there's no single URI to put
in `Location`.

## 2. Database Schema

There are two tables. A scan has one target but many ports, and cramming a
list of ports into a single column would make a query like "every scan where
port 8080 was open" painful: you'd be stuck doing string matching (`LIKE '%,8080,%'`) instead of an indexed lookup. So instead:
```
scans                          open_ports
  id            PK               id           PK
  target        VARCHAR(255)     scan_id      FK -> scans.id
  scanned_at    DATETIME         port         INT
```

- The composite index `(target, scanned_at)` on `scans` covers the only read
  query we actually run: scans for target X, newest first. One index handles
  both the filter and the sort.
- `open_ports.scan_id` is indexed too, for the join back to `scans`.
- `storage.get_history()` uses `joinedload(Scan.ports)` so it doesn't end up
  running an extra query per scan.
- `scans.target` is intentionally not unique. Having many rows per target is
  the point of keeping history.

## 3. Objects in the Design

Storage and the API are two separate sets of classes, so a change to how
something's stored doesn't quietly change what a client sees.

**`models.py`** (SQLAlchemy, how a scan is stored)
- `Scan`: one row per scan, `id`, `target`, `scanned_at`, plus a relationship
  to its ports
- `OpenPort`: one row per open port on a scan

**`schemas.py`** (Pydantic, what the API sends and receives)
- `ScanRequest`: the incoming `{"targets": [...]}`
- `ScanResult`: one scan, reused for both `current_scan` and each entry in
  `history`
- `PortDiff`: `{"added": [...], "removed": [...]}`
- `ScanResponse`: `target` plus `current_scan`, `diff`, and `history`
- `BatchScanItem` / `BatchScanResponse`: the wrapper that carries an
  `ok`/`result`/`error` per target

## 4. Error Handling

There are three tiers:

| Failure | Scope | Response |
|---|---|---|
| Malformed request (missing/empty `targets`) | The request itself | `400` + `{"detail": "..."}` |
| Invalid host syntax, unresolvable host, `nmap` failure | One target | `200` overall; that target's entry is `{"ok": false, "error": "..."}` |
| Database unreachable | Any DB read/write | `503` + `{"detail": "Database is unavailable. Please try again shortly."}` |

Every target gets validated before `nmap` even runs and before anything gets
written, so a bad target is never scanned or stored in the first place. And
if one target in a batch is bad, it only fails its own entry, not the whole
request. The `503` handler only catches connection level failures
(`OperationalError`), so an actual data bug still shows up as a real error
instead of getting hidden behind a generic "try again" message. There's also
an access log middleware that records the method, path, status, and duration
of every response.

## 5. Testing

There are 89 tests in `tests/unit_tests/`, with 97% coverage. None of it
touches a live system: the database is SQLite running in memory instead of
MySQL, and every `nmap` call is mocked. You don't need a real database,
`nmap`, or network access to run the suite.

Coverage covers both the smaller components (port diffing, host validation, parsing
nmap's output) and the full request cycle through FastAPI's `TestClient`:
routing, DB writes, how the diff and history get assembled, per target
errors, and the `503` path.

## 6. Future Considerations

A few ideas came up during design that this project doesn't need yet.
Noted here instead of built.

### 6.1 A hosts table

A separate `hosts` table with `scans.host_id` as a foreign key would let
the database enforce host identity instead of code. But `storage.save_scan()`
is already the only place a scan gets written, so normalizing `target` there
gives the same guarantee without a third table. The real case for a `hosts`
table is future features like nicknames or alert thresholds, none of which exist today. Worth adding once one of those becomes a requirement.

### 6.2 Pagination

`GET /v1/scans` returns a host's full history in one response, with no
`limit`/`offset`. Every call is scoped to a single host through the required
`target` param, and at this project's scale that history isn't going to get
large enough to matter. It could become worth adding if a host is ever
scanned frequently enough, over a long enough period, for that response to
get slow.

### 6.3 Treating a hostname and its IP as the same host

`localhost` and `127.0.0.1` are stored as two separate targets today, even
though they often resolve to the same machine. It is also a shaky basis
for defining "same host," since a hostname's IP can change over time. A
machine that gets replaced behind the same hostname would look unchanged,
and a hostname that legitimately moves to a new machine would look like a
brand new host. This is a reasonable feature to build once there is a
concrete need for it, and it is fine to leave out for now.
