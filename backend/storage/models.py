"""SQLAlchemy declarative models for QVis database tables.

These models serve two purposes:

1. **Alembic autogenerate** — Alembic inspects ``Base.metadata`` to detect
   schema differences and generate migration scripts automatically.
2. **Future PostgreSQL abstraction** — The same models can be used with
   ``async_sessionmaker`` against PostgreSQL via SQLAlchemy's async API.

The *runtime* persistence layer (``backend/storage/database.py``) continues
to use ``aiosqlite`` directly for the default SQLite backend, so there is
zero performance or behavioral change for existing deployments.
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Base class for all QVis ORM models."""
    pass


class ThreatEventModel(Base):
    """ORM mapping for the ``threat_events`` table.

    Matches the DDL defined in ``database.py`` exactly so that Alembic
    autogenerate sees no diff against a freshly-created SQLite database.
    """

    __tablename__ = "threat_events"

    id = sa.Column(sa.Text, primary_key=True)
    technique_id = sa.Column(sa.Text, nullable=False)
    severity = sa.Column(sa.Text, nullable=False)
    platform = sa.Column(sa.Text, nullable=False)
    backend_id = sa.Column(sa.Text, nullable=True)
    title = sa.Column(sa.Text, nullable=False)
    description = sa.Column(sa.Text, nullable=False)
    evidence = sa.Column(sa.Text, nullable=False, server_default="{}")
    detected_at = sa.Column(sa.Text, nullable=False)
    visual_effect = sa.Column(sa.Text, nullable=False, server_default="")
    visual_intensity = sa.Column(sa.Float, nullable=False, server_default="0.0")
    remediation = sa.Column(sa.Text, nullable=False, server_default="[]")
    resolved_at = sa.Column(sa.Text, nullable=True)


class CorrelationEventModel(Base):
    """ORM mapping for the ``correlation_events`` table."""

    __tablename__ = "correlation_events"

    id = sa.Column(sa.Text, primary_key=True)
    pattern_name = sa.Column(sa.Text, nullable=False)
    techniques = sa.Column(sa.Text, nullable=False, server_default="[]")
    backends = sa.Column(sa.Text, nullable=False, server_default="[]")
    detected_at = sa.Column(sa.Text, nullable=False)
    severity = sa.Column(sa.Text, nullable=False)


# ── Convenience: list all models for autogenerate discovery ─────────────
__all__ = ["Base", "ThreatEventModel", "CorrelationEventModel"]
