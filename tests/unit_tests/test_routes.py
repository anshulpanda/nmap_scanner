"""Endpoint behaviour with the nmap subprocess mocked.

No real scanning happens here, so the suite needs neither nmap nor network.
"""

from app.models import Scan
from app.scanner import HostResolutionError, ScanError


def _scan(client, target):
    """POST a single-target request and return that target's result item."""
    body = client.post("/v1/scans", json={"targets": [target]}).json()
    return body["results"][0]


def test_scan_returns_current_ports_diff_and_history(client, fake_nmap):
    fake_nmap([22, 443])

    response = client.post("/v1/scans", json={"targets": ["localhost"]})

    assert response.status_code == 200
    item = response.json()["results"][0]
    assert item["ok"] is True
    assert item["target"] == "localhost"
    assert item["result"]["current_scan"]["open_ports"] == [22, 443]
    assert item["result"]["diff"] == {"added": [], "removed": []}
    assert len(item["result"]["history"]) == 1


def test_scan_result_includes_an_id(client, fake_nmap):
    fake_nmap([22])
    item = _scan(client, "localhost")

    assert isinstance(item["result"]["current_scan"]["id"], int)
    assert item["result"]["history"][0]["id"] == item["result"]["current_scan"]["id"]


def test_first_scan_of_a_host_has_an_empty_diff(client, fake_nmap):
    fake_nmap([22])
    item = _scan(client, "brand-new-host.test")
    assert item["result"]["diff"] == {"added": [], "removed": []}


def test_second_scan_reports_added_ports(client, fake_nmap):
    fake_nmap([22])
    _scan(client, "localhost")

    fake_nmap([22, 8000])
    item = _scan(client, "localhost")

    assert item["result"]["diff"] == {"added": [8000], "removed": []}
    assert len(item["result"]["history"]) == 2


def test_scan_reports_removed_ports(client, fake_nmap):
    fake_nmap([22, 8000])
    _scan(client, "localhost")

    fake_nmap([22])
    item = _scan(client, "localhost")

    assert item["result"]["diff"] == {"added": [], "removed": [8000]}


def test_unchanged_ports_produce_an_empty_diff(client, fake_nmap):
    fake_nmap([22, 443])
    _scan(client, "localhost")
    item = _scan(client, "localhost")

    assert item["result"]["diff"] == {"added": [], "removed": []}


def test_history_is_newest_first(client, fake_nmap):
    for ports in ([22], [22, 80], [22, 80, 443]):
        fake_nmap(ports)
        _scan(client, "localhost")

    history = client.get("/v1/scans", params={"target": "localhost"}).json()["scans"]
    assert [scan["open_ports"] for scan in history] == [[22, 80, 443], [22, 80], [22]]


def test_history_is_scoped_to_one_target(client, fake_nmap):
    fake_nmap([22])
    _scan(client, "host-a.test")
    _scan(client, "host-b.test")

    body = client.get("/v1/scans", params={"target": "host-a.test"}).json()
    assert len(body["scans"]) == 1


def test_scan_with_no_open_ports_is_still_recorded(client, fake_nmap):
    fake_nmap([])
    item = _scan(client, "localhost")

    assert item["result"]["current_scan"]["open_ports"] == []
    assert len(item["result"]["history"]) == 1


def test_timestamps_are_utc_labelled(client, fake_nmap):
    fake_nmap([22])
    item = _scan(client, "localhost")
    assert item["result"]["current_scan"]["scanned_at"].endswith("Z")


# --- Invalid input -------------------------------------------------------


def test_invalid_host_is_rejected_before_nmap_runs(client, fake_nmap, db_session):
    calls = fake_nmap([22])

    item = _scan(client, "not a real host!")

    assert item["ok"] is False
    assert "not a real host!" in item["error"]
    assert calls == []  # nmap was never invoked
    assert db_session.query(Scan).count() == 0  # and nothing was stored


def test_unresolvable_host_reports_a_per_target_error_and_stores_nothing(
    client, fake_nmap, db_session
):
    fake_nmap(raises=HostResolutionError("'nope.invalid' could not be resolved."))

    item = _scan(client, "nope.invalid")

    assert item["ok"] is False
    assert "could not be resolved" in item["error"]
    assert db_session.query(Scan).count() == 0


def test_scanner_failure_reports_a_per_target_error(client, fake_nmap, db_session):
    fake_nmap(raises=ScanError("nmap is not installed or not on PATH."))

    item = _scan(client, "localhost")

    assert item["ok"] is False
    assert "not installed" in item["error"]
    assert db_session.query(Scan).count() == 0


def test_missing_targets_field_returns_400(client):
    """Deliberate: malformed body and invalid host share one status and shape."""
    response = client.post("/v1/scans", json={})
    assert response.status_code == 400
    assert "detail" in response.json()


def test_empty_target_reports_a_per_target_error(client):
    item = _scan(client, "")
    assert item["ok"] is False


def test_history_without_target_returns_400(client):
    assert client.get("/v1/scans").status_code == 400


# --- Read-only history ---------------------------------------------------


def test_history_for_unknown_target_is_empty_not_an_error(client):
    response = client.get("/v1/scans", params={"target": "never-scanned.test"})

    assert response.status_code == 200
    assert response.json() == {"target": "never-scanned.test", "scans": []}


def test_history_never_triggers_a_scan(client, fake_nmap, db_session):
    calls = fake_nmap([22])

    client.get("/v1/scans", params={"target": "localhost"})

    assert calls == []
    assert db_session.query(Scan).count() == 0


# --- Normalization -------------------------------------------------------


def test_history_lookup_matches_regardless_of_case(client, fake_nmap):
    fake_nmap([22])
    _scan(client, "Example.COM")

    body = client.get("/v1/scans", params={"target": "example.com"}).json()
    assert len(body["scans"]) == 1


def test_localhost_and_loopback_ip_have_separate_history(client, fake_nmap):
    fake_nmap([22])
    _scan(client, "localhost")
    _scan(client, "127.0.0.1")

    assert len(client.get("/v1/scans", params={"target": "localhost"}).json()["scans"]) == 1


# --- Parallel scanning of multiple targets --------------------------------


def test_scan_handles_several_targets(client, fake_nmap):
    calls = fake_nmap([22])

    body = client.post(
        "/v1/scans", json={"targets": ["host-a.test", "host-b.test"]}
    ).json()

    assert sorted(calls) == ["host-a.test", "host-b.test"]
    assert [item["target"] for item in body["results"]] == ["host-a.test", "host-b.test"]
    assert all(item["ok"] for item in body["results"])
    assert body["results"][0]["result"]["current_scan"]["open_ports"] == [22]


def test_scan_reports_per_target_failures(client, fake_nmap, db_session):
    fake_nmap([22])

    body = client.post(
        "/v1/scans", json={"targets": ["good-host.test", "bad host!"]}
    ).json()

    results = {item["target"]: item for item in body["results"]}
    assert results["good-host.test"]["ok"] is True
    assert results["bad host!"]["ok"] is False
    assert results["bad host!"]["error"]
    # The valid target was still scanned and stored.
    assert db_session.query(Scan).count() == 1


def test_scan_collapses_duplicate_targets(client, fake_nmap, db_session):
    calls = fake_nmap([22])

    body = client.post(
        "/v1/scans", json={"targets": ["host-a.test", "host-a.test"]}
    ).json()

    assert calls == ["host-a.test"]
    assert len(body["results"]) == 1
    assert db_session.query(Scan).count() == 1
