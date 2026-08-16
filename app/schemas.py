"""Pydantic schemas — the public JSON contract.

Kept separate from models.py on purpose: the shape of a MySQL table and the
shape of an API response are different boundaries, and a change to one should
not silently change the other.
"""

from datetime import datetime, timezone

from pydantic import BaseModel, ConfigDict, Field, field_serializer


class ScanRequest(BaseModel):
    """One endpoint, one shape: a single scan is just a list of one target."""

    targets: list[str] = Field(..., min_length=1, description="IPs or hostnames")


class PortDiff(BaseModel):
    added: list[int]
    removed: list[int]


class ScanResult(BaseModel):
    """One scan, in the same shape everywhere it appears (current_scan, history,
    or a bare list entry) — so a client can always find `id` on it.
    """

    model_config = ConfigDict(from_attributes=True)

    id: int
    target: str
    scanned_at: datetime
    open_ports: list[int]

    @field_serializer("scanned_at")
    def _as_utc(self, value: datetime) -> str:
        """Timestamps are stored naive-UTC; label them so clients don't guess."""
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


class ScanResponse(BaseModel):
    target: str
    # Same object as history[0] — intentional duplication for a client that
    # only wants the latest scan without indexing into the history array.
    current_scan: ScanResult
    # Ports opened/closed since the scan immediately before current_scan —
    # the one diff this system ever needs to show a caller. Not carried on
    # older history entries: nothing reads a diff for anything but the scan
    # that was just triggered.
    diff: PortDiff
    history: list[ScanResult]


class HistoryResponse(BaseModel):
    target: str
    scans: list[ScanResult]


class BatchScanItem(BaseModel):
    """One target's outcome in a batch scan — success or failure, never both."""

    target: str
    ok: bool
    result: ScanResponse | None = None
    error: str | None = None


class BatchScanResponse(BaseModel):
    results: list[BatchScanItem]
