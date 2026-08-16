"""The access-log middleware, via TestClient — real request/response cycle."""

import logging

import pytest


@pytest.fixture(autouse=True)
def _capture_access_log(caplog):
    caplog.set_level(logging.INFO, logger="app.access")


def test_logs_method_path_status_and_duration(client, fake_nmap, caplog):
    fake_nmap([22])

    caplog.clear()
    client.post("/v1/scans", json={"targets": ["localhost"]})

    assert len(caplog.records) == 1
    message = caplog.records[0].getMessage()
    assert message.startswith("POST /v1/scans -> 200 (")
    assert message.endswith("ms)")


def test_logs_the_actual_status_code_on_a_malformed_request(client, caplog):
    caplog.clear()
    client.post("/v1/scans", json={})

    assert len(caplog.records) == 1
    assert "POST /v1/scans -> 400" in caplog.records[0].getMessage()


def test_logs_get_requests_too(client, caplog):
    caplog.clear()
    client.get("/v1/scans", params={"target": "localhost"})

    assert len(caplog.records) == 1
    assert caplog.records[0].getMessage().startswith("GET /v1/scans -> 200 (")
