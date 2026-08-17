# Design Document: NMAP Port Scanner

## 1. Resource & API Design

`scans` is the one resource. Two endpoints:

| Endpoint | Method | Side effects | Purpose |
|---|---|---|---|
| `POST /v1/scans` | Writes | Runs `nmap`, writes to DB | Scan one or more hosts, then return each host's full history |
| `GET /v1/scans?target=` | Read-only | None | Read a host's stored scan history, without scanning |

Split into two endpoints so `GET` can never accidentally trigger a scan.

**`POST /v1/scans`** — always takes a list of targets (even for one host) and
scans them concurrently. Per target, the response includes the new scan, a
diff against the previous one, and the full history — no follow-up `GET`
needed:
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
One `results` entry per target: `ok: true` + `result`, or `ok: false` + `error` — never both.

**`GET /v1/scans?target=`** — `target` is required (no "all hosts" use case).
A never-scanned host returns an empty list, not a `404`.

**Status codes:** `200` for both endpoints, even partial success in a
multi-target `POST`. `400` for a malformed request. `503` if the database is
unreachable. No `201` on `POST` — a scan is immutable and one request can
create several, so there's no single URI to redirect to.

## 2. Database Schema

Two tables — a scan has one target but many ports, so a variable-length port
list gets its own table instead of one packed column:

```
scans                          open_ports
  id            PK               id           PK
  target        VARCHAR(255)     scan_id      FK -> scans.id
  scanned_at    DATETIME         port         INT
```

- Composite index `(target, scanned_at)` on `scans` covers the one read
  query ("scans for target X, newest first") — filter and sort in one index.
- Index on `open_ports.scan_id` for the join back to `scans`.
- `storage.get_history()` uses `joinedload(Scan.ports)` to avoid N+1.
- `scans.target` is not unique — many rows per target is the point.

## 3. Objects in the Design

Storage and API are separate class hierarchies, so a DB-only change can't
silently change what a client receives.

**`models.py`** (SQLAlchemy — how a scan is stored)
- `Scan` — one row per scan: `id`, `target`, `scanned_at`, ports relationship
- `OpenPort` — one row per open port on a scan

**`schemas.py`** (Pydantic — what the API sends/receives)
- `ScanRequest` — incoming `{"targets": [...]}`
- `ScanResult` — one scan, used for both `current_scan` and each `history` entry
- `PortDiff` — `{"added": [...], "removed": [...]}`
- `ScanResponse` — `target` + `current_scan` + `diff` + `history`
- `BatchScanItem` / `BatchScanResponse` — per-target `ok`/`result`/`error` wrapper

## 4. Error Handling

Three tiers:

| Failure | Scope | Response |
|---|---|---|
| Malformed request (missing/empty `targets`) | The request itself | `400` + `{"detail": "..."}` |
| Invalid host syntax, unresolvable host, `nmap` failure | One target | `200` overall; that target's entry is `{"ok": false, "error": "..."}` |
| Database unreachable | Any DB read/write | `503` + `{"detail": "Database is unavailable. Please try again shortly."}` |

Targets are validated before `nmap` runs and before anything is written, so a
bad target is never scanned or stored — and it only fails its own entry, not
the whole request. The `503` handler catches connection-level failures only
(`OperationalError`), so real data bugs still surface as errors instead of
being masked. An access-log middleware records every response's method, path,
status, and duration.

## 5. Testing

89 tests in `tests/unit_tests/`, 97% coverage. Fully hermetic — SQLite
in-memory instead of MySQL, every `nmap` call mocked — so no real database,
`nmap`, or network access is needed to run it.

Coverage spans pure-function tests (diffing, host validation, output
parsing) and full-request tests via FastAPI's `TestClient` (routing, DB
writes, diff/history assembly, per-target errors, the `503` path).
