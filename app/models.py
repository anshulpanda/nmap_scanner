"""SQLAlchemy models — how a scan lives in MySQL.

One scan has many open ports, so the data is split across two tables rather
than stuffing a variable-length port list into a single column.
"""

from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, ForeignKey, Index, Integer, String
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


def _utcnow() -> datetime:
    """Naive UTC timestamp — MySQL DATETIME columns don't store an offset."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True)
    # No standalone index here: ix_scans_target_scanned_at below covers any
    # target-only filter via its leftmost prefix, so a second index on just
    # `target` would only add write overhead with no query it's needed for.
    target = Column(String(255), nullable=False)
    scanned_at = Column(DateTime, nullable=False, default=_utcnow)

    ports = relationship(
        "OpenPort",
        back_populates="scan",
        cascade="all, delete-orphan",
        order_by="OpenPort.port",
        lazy="selectin",
    )

    __table_args__ = (
        # The dominant query is "scans for target X, newest first" — a composite
        # index satisfies both the filter and the sort without a filesort step.
        Index("ix_scans_target_scanned_at", "target", "scanned_at"),
    )

    @property
    def open_ports(self) -> list[int]:
        return [p.port for p in self.ports]


class OpenPort(Base):
    __tablename__ = "open_ports"

    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False, index=True)
    port = Column(Integer, nullable=False)

    scan = relationship("Scan", back_populates="ports")
