"""storage.py against a real (in-memory) database.

Behavior that test_routes.py already verifies end-to-end (newest-first
ordering, scoping by target) isn't repeated here — this covers the one thing
no HTTP-level test exercises: save_scan's own port dedup/sort contract,
since nmap output already arrives deduplicated and sorted by the time it
reaches storage in the normal request path.
"""

from app.storage import save_scan


def test_save_scan_deduplicates_and_sorts_ports(db_session):
    scan = save_scan(db_session, "localhost", [443, 22, 443, 22, 80])
    assert scan.open_ports == [22, 80, 443]
