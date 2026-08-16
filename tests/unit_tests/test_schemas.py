"""ScanResult's timestamp serialization — pure logic, no DB, no HTTP."""

from datetime import datetime, timedelta, timezone

from app.schemas import ScanResult


def _serialized_scanned_at(value: datetime) -> str:
    result = ScanResult(id=1, target="localhost", scanned_at=value, open_ports=[22])
    return result.model_dump()["scanned_at"]


def test_naive_datetime_is_labelled_utc():
    """Naive timestamps are how they're stored (MySQL DATETIME has no offset)."""
    naive = datetime(2026, 8, 14, 12, 30, 45)
    assert _serialized_scanned_at(naive) == "2026-08-14T12:30:45Z"


def test_aware_utc_datetime_gets_z_suffix_not_plus_zero():
    aware_utc = datetime(2026, 8, 14, 12, 30, 45, tzinfo=timezone.utc)
    assert _serialized_scanned_at(aware_utc) == "2026-08-14T12:30:45Z"


def test_aware_non_utc_datetime_is_converted_to_utc():
    eastern = timezone(timedelta(hours=-5))
    aware = datetime(2026, 8, 14, 7, 30, 45, tzinfo=eastern)
    assert _serialized_scanned_at(aware) == "2026-08-14T12:30:45Z"
