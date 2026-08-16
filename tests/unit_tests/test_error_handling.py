"""App-level exception handlers in main.py — DB outages and malformed requests."""

from sqlalchemy.exc import OperationalError


def _raise_operational_error(*args, **kwargs):
    raise OperationalError("SELECT 1", {}, Exception("Can't connect to MySQL server"))


def test_database_outage_on_read_returns_clean_503(client, monkeypatch):
    monkeypatch.setattr("app.routes.get_history", _raise_operational_error)

    response = client.get("/v1/scans", params={"target": "localhost"})

    assert response.status_code == 503
    assert response.json() == {"detail": "Database is unavailable. Please try again shortly."}


def test_database_outage_on_write_returns_clean_503(client, fake_nmap, monkeypatch):
    fake_nmap([22])
    monkeypatch.setattr("app.routes.save_scan", _raise_operational_error)

    response = client.post("/v1/scans", json={"targets": ["localhost"]})

    assert response.status_code == 503
    assert response.json() == {"detail": "Database is unavailable. Please try again shortly."}
