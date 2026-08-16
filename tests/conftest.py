"""Shared fixtures.

Tests run against an in-memory SQLite database and a mocked nmap, so the suite
needs neither MySQL, nor nmap, nor network access.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import get_db
from app.main import app
from app.models import Base


@pytest.fixture
def db_session():
    """A fresh in-memory database per test.

    StaticPool keeps every connection pointed at the same in-memory database,
    which would otherwise vanish when a connection is returned to the pool.
    """
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


@pytest.fixture
def client(db_session):
    """TestClient wired to the test database.

    The app is not entered as a context manager on purpose: that would run the
    startup hook and try to create tables in the real MySQL database.
    """
    app.dependency_overrides[get_db] = lambda: db_session
    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides.clear()


@pytest.fixture
def fake_nmap(monkeypatch):
    """Replace the nmap subprocess call with a scripted result.

    Usage:
        fake_nmap([22, 443])                  # every scan returns these ports
        fake_nmap(raises=ScanError("boom"))   # every scan fails
    """

    def configure(ports=None, raises=None):
        calls = []

        def fake_scan(target):
            calls.append(target)
            if raises is not None:
                raise raises
            return list(ports or [])

        monkeypatch.setattr("app.routes.scan_ports", fake_scan)
        return calls

    return configure
