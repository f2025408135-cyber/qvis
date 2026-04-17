"""Alembic migration runner for QVis.

Provides ``run_migrations()`` which is called during application startup
(after ``init_db()``) to ensure the database schema is up-to-date.

The runner delegates to the ``alembic`` CLI via Alembic's Python API so
that it works identically to running ``alembic upgrade head`` from the
command line, but without requiring a subprocess.

Supports both SQLite and PostgreSQL backends transparently.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

# The Alembic config file lives at the project root (one level above backend/)
_ALEMBIC_CONFIG_PATH = str(Path(__file__).resolve().parent.parent.parent / "alembic.ini")


def run_migrations(database_url: Optional[str] = None) -> None:
    """Run all pending Alembic migrations to bring the schema up-to-date.

    Parameters
    ----------
    database_url:
        Optional SQLAlchemy URL override.  When ``None``, Alembic reads
        the URL from ``alembic.ini`` or the ``DATABASE_URL`` environment
        variable (as configured in ``alembic/env.py``).

    Raises
    ------
    Exception
        If any migration fails.  The caller should decide whether to abort
        startup or continue with a degraded database.
    """
    from alembic.config import Config
    from alembic import command

    alembic_cfg = Config(_ALEMBIC_CONFIG_PATH)

    # If a specific URL is provided (e.g. from Settings), set it before
    # running so that env.py picks it up.
    if database_url is not None:
        # Translate async URLs to sync for Alembic's DDL transaction management
        sync_url = database_url
        for async_drv, sync_drv in [
            ("sqlite+aiosqlite://", "sqlite://"),
            ("postgresql+asyncpg://", "postgresql://"),
            ("postgresql+psycopg://", "postgresql://"),
        ]:
            sync_url = sync_url.replace(async_drv, sync_drv)
        alembic_cfg.set_main_option("sqlalchemy.url", sync_url)

    command.upgrade(alembic_cfg, "head")


def get_current_revision(database_url: Optional[str] = None) -> Optional[str]:
    """Return the current Alembic revision in the database, or None.

    Reads the ``alembic_version`` table directly to avoid the complexity
    of Alembic's environment API in test scenarios.
    """
    if database_url is None:
        return None

    # Translate async URL to sync for direct DB access
    sync_url = database_url
    for async_drv, sync_drv in [
        ("sqlite+aiosqlite://", "sqlite://"),
        ("postgresql+asyncpg://", "postgresql://"),
        ("postgresql+psycopg://", "postgresql://"),
    ]:
        sync_url = sync_url.replace(async_drv, sync_drv)

    try:
        from sqlalchemy import create_engine, text
        engine = create_engine(sync_url)
        with engine.connect() as conn:
            result = conn.execute(text("SELECT version_num FROM alembic_version"))
            row = result.fetchone()
            if row:
                return row[0]
            return None
    except Exception:
        return None
