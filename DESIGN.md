# Design Document: NMAP Port Scanner

## 1. Resource & API Design

`scans` is the one resource in this system. Two endpoints operate on it:

| Endpoint | Method | Side effects | Purpose |
|---|---|---|---|
| `POST /v1/scans` | Writes | Runs `nmap`, writes to DB | Scan one or more hosts concurrently |
| `GET /v1/scans?target=` | Read-only | None | Read a host's stored scan history |

Two endpoints, not one, because `POST` changes state and `GET` doesn't — merging
them risks a monitoring script silently triggering scans while polling history.

**`POST /v1/scans`** — request:
```json
{ "targets": ["scanme.nmap.org"] }
```
`targets` is always a list, even for a single host — there's no separate
"single scan" endpoint; a one-item list runs through the same concurrent
scanning path as a ten-item one. Response:
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
One `results` entry per target, in order, each `ok: true` + `result` or
`ok: false` + `error` — never both. `current_scan` is the same object as
`history[0]`; `diff` is the ports opened/closed vs. the scan immediately before it.

**`GET /v1/scans?target=`** — read-only, never triggers a scan. `target` is
required (no "all hosts" use case). A never-scanned host returns an empty
list, not a `404` — "never scanned" is a legitimate answer.

**Status codes:** `200` for both endpoints, including partial success in a
multi-target `POST`. `400` only for a malformed request itself (missing/empty
`targets`, missing `target` param). `503` if the database is unreachable.
`200`, not `201 + Location`, on `POST`: a scan is immutable, nothing ever
fetches one in isolation, and one request can create several scans at once —
there's no single URI to redirect to.

## 2. Database Schema

Two tables, not one — a scan has one target but many ports, and packing a
variable-length port list into one column would make a query like "every
scan where port 8080 was open" awkward:

```
scans                          open_ports
  id            PK               id           PK
  target        VARCHAR(255)     scan_id      FK -> scans.id
  scanned_at    DATETIME         port         INT
```

- **Composite index `(target, scanned_at)`** on `scans` — the only read query is
  "all scans for target X, newest first," so one index serves both the filter
  and the sort. No separate standalone index on `target` alone: a composite
  index's leftmost column already covers that filter, so a second index
  would only add write overhead with nothing that needs it.
- **Index on `open_ports.scan_id`** for the join back to `scans`.
- `storage.get_history()` uses `joinedload(Scan.ports)` to fetch a target's
  scans plus every port on each in one query, avoiding N+1.
- `scans.target` is deliberately **not** unique — many rows per target is the
  point of a history feature.

## 3. Objects in the Design

Two parallel sets of classes, split by responsibility — a DB row and an API
response are different boundaries, and a storage-only change shouldn't
silently change what a client receives:

**`models.py`** (SQLAlchemy — how a scan is stored)
- `Scan` — one row per scan: `id`, `target`, `scanned_at`, plus an `open_ports`
  relationship to its ports
- `OpenPort` — one row per open port on a scan

**`schemas.py`** (Pydantic — what the API sends/receives)
- `ScanRequest` — incoming `{"targets": [...]}`
- `ScanResult` — one scan (`id`, `target`, `scanned_at`, `open_ports`), used
  for both `current_scan` and every `history` entry
- `PortDiff` — `{"added": [...], "removed": [...]}`
- `ScanResponse` — `target` + `current_scan` + `diff` + `history`, assembled
  from several `Scan` rows plus a computed diff — no single DB row looks like it
- `BatchScanItem` / `BatchScanResponse` — the per-target `ok`/`result`/`error`
  wrapper; a pure API-layer concept with no database equivalent at all

## 4. Error Handling

Three tiers, each mapped to what actually failed:

| Failure | Scope | Response |
|---|---|---|
| Malformed request (missing/empty `targets`) | The request itself | `400` + `{"detail": "..."}` |
| Invalid host syntax, unresolvable host, `nmap` failure | One target in an otherwise-valid request | `200` overall; that target's entry is `{"ok": false, "error": "..."}` |
| Database unreachable | Any DB read/write | `503` + `{"detail": "Database is unavailable. Please try again shortly."}` |

Every target is validated and normalized *before* `nmap` runs and *before*
anything is written, so a bad target is never scanned or stored. A single bad
target never fails the whole multi-target request — it's reported per-target
instead of as a top-level error, so nine good targets aren't sunk by one typo.

The `503` handler specifically catches `OperationalError` (connection-level
failures — server down, lost connection, timeout via SQLAlchemy's
`pool_pre_ping`), not query bugs like a constraint violation, so a real data
bug still surfaces as an unhandled error instead of being masked as "try
again shortly." An access-log middleware records every response's method,
path, status code, and duration for observability regardless of which tier
handled it.

## 5. Testing

All 89 tests live in one `tests/unit_tests/` suite at **97% coverage**.
Nothing in it touches a live external system — the database is in-memory
SQLite (not production MySQL) and every `nmap` subprocess call is mocked —
so the whole suite is hermetic, deterministic, and needs no real MySQL,
`nmap`, or network access to run.

Coverage spans pure-function tests (port diffing, host validation, `nmap`
output parsing, timestamp serialization) through tests that exercise the
full request cycle via FastAPI's `TestClient` — routing, DB writes, the
diff/history assembly, per-target error handling, and the `503` path — which
are what actually catch cross-module wiring bugs and verify the acceptance
criteria at the HTTP behavior level.
