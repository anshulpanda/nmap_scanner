"""HTTP layer — thin handlers that wire the layers below together.

No subprocess calls and no SQL live here; those belong to scanner.py and
storage.py respectively.
"""

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.database import get_db
from app.diff import compute_diff
from app.models import Scan
from app.schemas import (
    BatchScanItem,
    BatchScanResponse,
    HistoryResponse,
    PortDiff,
    ScanRequest,
    ScanResponse,
    ScanResult,
)
from app.scanner import ScanError, scan_ports
from app.storage import get_history, save_scan
from app.validation import InvalidHostError, normalize_target

BASE_DIR = Path(__file__).resolve().parent.parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

# Cap on concurrent nmap processes fired from one request.
MAX_PARALLEL_SCANS = 8

router = APIRouter()


def _validate(target: str) -> str:
    """Normalize a target or fail with 400 — before nmap runs, before any write."""
    try:
        return normalize_target(target)
    except InvalidHostError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


def _to_scan_results(scans: list[Scan]) -> list[ScanResult]:
    return [
        ScanResult(
            id=scan.id,
            target=scan.target,
            scanned_at=scan.scanned_at,
            open_ports=scan.open_ports,
        )
        for scan in scans
    ]


def _record_scan(db: Session, target: str, open_ports: list[int]) -> ScanResponse:
    """Persist a new scan, then return it (with its diff) alongside full history.

    Fetching history *after* the write means the newest entry (history[0]) is
    the scan just saved, and history[1] — if it exists — is the baseline its
    diff is computed against.
    """
    save_scan(db, target, open_ports)
    scans = get_history(db, target)
    history = _to_scan_results(scans)
    previous_ports = scans[1].open_ports if len(scans) > 1 else None
    diff = compute_diff(previous_ports, scans[0].open_ports)
    return ScanResponse(
        target=target, current_scan=history[0], diff=PortDiff(**diff), history=history
    )


@router.get("/", response_class=HTMLResponse, include_in_schema=False)
def index(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(request, "index.html")


def _safe_scan(target: str) -> tuple[list[int], str | None]:
    """Scan without raising, so one failed target can't abort the rest."""
    try:
        return scan_ports(target), None
    except ScanError as exc:
        return [], str(exc)


@router.post("/v1/scans", response_model=BatchScanResponse)
def create_scan(payload: ScanRequest, db: Session = Depends(get_db)) -> BatchScanResponse:
    """Scan one or more hosts concurrently; one bad target doesn't sink the rest.

    Always takes a list, even for a single target. A one-item list runs
    through the same thread pool as a ten-item one — spinning up an idle
    ThreadPoolExecutor costs microseconds next to an actual nmap invocation,
    so there's no meaningful overhead to special-case away. One endpoint, one
    code path, no "single scan" vs "batch scan" distinction for callers to
    learn.

    Only the nmap calls run in parallel. The database writes are serialized
    through this request's single session, which is not thread-safe.
    """
    # (target, validation error) in request order, duplicates collapsed so a
    # repeated host isn't scanned and stored twice.
    entries: list[tuple[str, str | None]] = []
    for raw in dict.fromkeys(payload.targets):
        try:
            entries.append((_validate(raw), None))
        except HTTPException as exc:
            entries.append((raw, str(exc.detail)))

    scannable = [target for target, error in entries if error is None]
    with ThreadPoolExecutor(max_workers=MAX_PARALLEL_SCANS) as pool:
        scanned = dict(zip(scannable, pool.map(_safe_scan, scannable)))

    results = []
    for target, error in entries:
        if error is None:
            ports, error = scanned[target]
        if error is not None:
            results.append(BatchScanItem(target=target, ok=False, error=error))
        else:
            results.append(
                BatchScanItem(
                    target=target, ok=True, result=_record_scan(db, target, ports)
                )
            )

    return BatchScanResponse(results=results)


@router.get("/v1/scans", response_model=HistoryResponse)
def list_scans(
    target: str = Query(..., min_length=1, description="IP address or hostname"),
    db: Session = Depends(get_db),
) -> HistoryResponse:
    """Return stored scan history for a target. Read-only — never triggers a scan.

    `target` is required: this project has no use case for "all scans across
    all hosts," and making it required avoids needing pagination as a
    first-class concern. A target with no history returns an empty list, not
    a 404 — "never scanned" is a legitimate answer, not an error.
    """
    normalized = _validate(target)
    return HistoryResponse(
        target=normalized,
        scans=_to_scan_results(get_history(db, normalized)),
    )
