"""All database reads and writes. Nothing above this layer writes SQL."""

from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload

from app.models import OpenPort, Scan


def save_scan(db: Session, target: str, open_ports: list[int]) -> Scan:
    """Persist a scan and its open ports as one transaction."""
    scan = Scan(
        target=target,
        ports=[OpenPort(port=port) for port in sorted(set(open_ports))],
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


def get_history(db: Session, target: str) -> list[Scan]:
    """Every scan for a target, most recent first, ports pre-loaded in one join.

    Shared by POST /v1/scans and GET /v1/scans — POST calls it directly rather
    than making an internal HTTP request for what is just a query.

    joinedload collapses this into a single `SELECT ... JOIN open_ports ...`
    regardless of history length. Without it, each scan's `.ports` access
    would run a separate query — 1 + N queries for a host with N past scans.
    """
    stmt = (
        select(Scan)
        .options(joinedload(Scan.ports))
        .where(Scan.target == target)
        .order_by(Scan.scanned_at.desc(), Scan.id.desc())
    )
    return list(db.execute(stmt).unique().scalars().all())
