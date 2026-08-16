"""Scan/OpenPort's pure helpers — plain object construction, no DB session."""

from datetime import datetime, timedelta, timezone

from app.models import OpenPort, Scan, _utcnow


def test_utcnow_is_naive():
    """MySQL DATETIME columns don't store an offset, so this must not have one."""
    assert _utcnow().tzinfo is None


def test_utcnow_is_close_to_the_real_time():
    before = datetime.now(timezone.utc).replace(tzinfo=None)
    result = _utcnow()
    after = datetime.now(timezone.utc).replace(tzinfo=None)
    assert before <= result <= after + timedelta(seconds=1)


def test_open_ports_maps_the_ports_relationship_to_plain_ints():
    scan = Scan(target="localhost")
    scan.ports = [OpenPort(port=443), OpenPort(port=22)]
    assert scan.open_ports == [443, 22]


def test_open_ports_is_empty_with_no_ports():
    scan = Scan(target="localhost")
    scan.ports = []
    assert scan.open_ports == []
