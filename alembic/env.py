"""Alembic migration environment for QVis.

Supports both SQLite (default / demo) and PostgreSQL (production) backends
via the ``DATABASE_URL`` environment variable.  Falls back to the SQLite
default defined in ``alembic.ini`` when the variable is not set.

Online migrations use a synchronous connection so that Alembic's
transaction management works correctly.  For production PostgreSQL
deployments the URL should use the ``postgresql+psycopg2`` (sync) driver
so that DDL statements run inside a single transaction.
"""

from __future__ import annotations

import os
import sys
from logging.config import fileConfig
from typing import Any

from sqlalchemy import engine_from_config, pool

from alembic import context

# ── Ensure project root is on sys.path ──────────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ── Import QVis config (lazy to avoid circular imports) ─────────────────
from backend.config import settings

# ── Alembic Config object ──────────────────────────────────────────────
config = context.config

# Override the sqlalchemy.url from the environment variable if set.
# This takes precedence over alembic.ini so operators can switch databases
# without editing config files.
#
# IMPORTANT: The URL may have already been set programmatically by
# backend.storage.migrations.run_migrations().  We only override if
# DATABASE_URL is a recognizable SQLAlchemy URL (contains "://").
# Non-SQLAlchemy URLs (e.g. "file:/..." from test environments) are
# silently ignored to prevent parse errors.
database_url = os.environ.get("DATABASE_URL", "")
if database_url and "://" in database_url:
    # For online (sync) migrations, translate async driver URLs to sync
    # equivalents so Alembic can manage transactions properly.
    sync_url = database_url
    for async_drv, sync_drv in [
        ("sqlite+aiosqlite://", "sqlite://"),
        ("postgresql+asyncpg://", "postgresql://"),
        ("postgresql+psycopg://", "postgresql://"),
    ]:
        sync_url = sync_url.replace(async_drv, sync_drv)
    config.set_main_option("sqlalchemy.url", sync_url)

# ── Logging ─────────────────────────────────────────────────────────────
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# ── Target metadata for autogenerate support ────────────────────────────
# Import the SQLAlchemy Base and models so Alembic can detect schema
# changes and generate migrations automatically.
try:
    from backend.storage.models import Base

    target_metadata: Any = Base.metadata
except ImportError:
    target_metadata = None


# ── Offline mode ────────────────────────────────────────────────────────
def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    Configures the context with just a URL and not an Engine.  No DBAPI
    driver is needed — only SQL DDL strings are emitted to stdout.
    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


# ── Online mode ─────────────────────────────────────────────────────────
def run_migrations_online() -> None:
    """Run migrations in 'online' mode.

    Creates a synchronous Engine and associates a connection with the
    Alembic context.  Uses NullPool to avoid connection leaks during
    short-lived migration runs.
    """
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
