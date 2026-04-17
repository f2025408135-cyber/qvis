"""Async SQLite persistence layer for QVis threat events.

Provides a single shared aiosqlite connection with WAL mode for
concurrent read performance.  All threat and correlation events are
persisted so that /api/threats/history and /api/threats/stats can
report on all-time data rather than only the current in-memory window.

Schema management is handled by Alembic (see ``backend/storage/migrations.py``).
On startup, ``init_db()`` runs pending Alembic migrations after ensuring the
base tables exist via the embedded DDL.  This dual-path approach guarantees
backward compatibility: existing databases work without migration, while new
schema changes are applied incrementally through Alembic revision scripts.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import aiosqlite

# ─── Module-level shared state ──────────────────────────────────────────
_db_path: str = str(Path(__file__).resolve().parent.parent.parent / "data" / "qvis.db")
_connection: Optional[aiosqlite.Connection] = None
_init_lock = None  # asyncio.Lock, created lazily on first use


def _get_init_lock():
    """Lazily create the asyncio.Lock (no event loop at import time)."""
    global _init_lock
    if _init_lock is None:
        import asyncio
        _init_lock = asyncio.Lock()
    return _init_lock


async def init_db(db_path: Optional[str] = None) -> None:
    """Create the data directory (if needed), open a WAL-mode connection,
    and create tables if they do not yet exist.

    After the base tables are ensured, Alembic migrations are run to
    apply any incremental schema changes.  The base DDL serves as a
    safety net so that the application starts even if Alembic has not
    been configured.

    This must be called once during application startup *before* any
    other function in this module is used.
    """
    global _db_path, _connection

    if db_path is not None:
        _db_path = db_path

    # Ensure the parent directory exists
    db_dir = os.path.dirname(_db_path)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)

    _connection = await aiosqlite.connect(_db_path)
    _connection.row_factory = aiosqlite.Row

    # WAL mode: readers never block writers and vice-versa
    await _connection.execute("PRAGMA journal_mode=WAL;")
    await _connection.execute("PRAGMA synchronous=NORMAL;")

    # Base DDL — ensures tables exist even without Alembic
    await _connection.executescript(_DDL)
    await _connection.commit()

    # Run Alembic migrations for any incremental schema changes
    try:
        from backend.storage.migrations import run_migrations
        # Build the SQLAlchemy URL from the db_path
        url = f"sqlite+aiosqlite:///{_db_path}"
        run_migrations(database_url=url)
    except Exception:
        # Alembic is optional — the base DDL above already ensures
        # tables exist.  Log the error but do not abort startup.
        import structlog
        structlog.get_logger(__name__).warning(
            "alembic_migration_skipped",
            reason="Migration runner raised an exception; "
                   "base DDL already applied so tables are usable.",
        )


async def _get_connection() -> aiosqlite.Connection:
    """Return the shared connection, initialising lazily if needed.

    Uses an asyncio.Lock to prevent concurrent coroutines from racing
    to call init_db() simultaneously.
    """
    global _connection
    if _connection is None:
        async with _get_init_lock():
            # Double-check after acquiring lock
            if _connection is None:
                await init_db()
    return _connection


async def close_db() -> None:
    """Close the shared connection. Safe to call multiple times."""
    global _connection
    if _connection is not None:
        await _connection.close()
        _connection = None


# ─── Table definitions ──────────────────────────────────────────────────
_DDL = """\
CREATE TABLE IF NOT EXISTS threat_events (
    id               TEXT PRIMARY KEY,
    technique_id     TEXT    NOT NULL,
    severity         TEXT    NOT NULL,
    platform         TEXT    NOT NULL,
    backend_id       TEXT,
    title            TEXT    NOT NULL,
    description      TEXT    NOT NULL,
    evidence         TEXT    NOT NULL DEFAULT '{}',  -- JSON
    detected_at      TEXT    NOT NULL,               -- ISO-8601
    visual_effect    TEXT    NOT NULL DEFAULT '',
    visual_intensity REAL    NOT NULL DEFAULT 0.0,
    remediation      TEXT    NOT NULL DEFAULT '[]',  -- JSON
    resolved_at      TEXT                             -- ISO-8601, NULL while active
);

CREATE INDEX IF NOT EXISTS idx_threats_detected_at   ON threat_events(detected_at);
CREATE INDEX IF NOT EXISTS idx_threats_severity      ON threat_events(severity);
CREATE INDEX IF NOT EXISTS idx_threats_technique_id  ON threat_events(technique_id);
CREATE INDEX IF NOT EXISTS idx_threats_backend_id    ON threat_events(backend_id);
CREATE INDEX IF NOT EXISTS idx_threats_resolved_at   ON threat_events(resolved_at);

CREATE TABLE IF NOT EXISTS correlation_events (
    id              TEXT PRIMARY KEY,
    pattern_name    TEXT    NOT NULL,
    techniques      TEXT    NOT NULL DEFAULT '[]',  -- JSON array
    backends        TEXT    NOT NULL DEFAULT '[]',  -- JSON array
    detected_at     TEXT    NOT NULL,               -- ISO-8601
    severity        TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_corr_detected_at ON correlation_events(detected_at);
"""


# ─── Threat CRUD helpers ────────────────────────────────────────────────

async def save_threat(
    id: str,
    technique_id: str,
    severity: str,
    platform: str,
    backend_id: Optional[str],
    title: str,
    description: str,
    evidence: Dict[str, Any],
    detected_at: str,
    visual_effect: str,
    visual_intensity: float,
    remediation: List[str],
) -> None:
    """INSERT or REPLACE a single threat event.

    Using INSERT OR REPLACE keeps the schema simple: if a threat with the
    same id is re-saved we update every column (which is the desired
    behaviour when an active threat's metadata changes between cycles).
    """
    db = await _get_connection()
    await db.execute(
        """
        INSERT OR REPLACE INTO threat_events
            (id, technique_id, severity, platform, backend_id, title,
             description, evidence, detected_at, visual_effect,
             visual_intensity, remediation, resolved_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
        """,
        (
            id,
            technique_id,
            severity,
            platform,
            backend_id,
            title,
            description,
            json.dumps(evidence, default=str),
            detected_at,
            visual_effect,
            visual_intensity,
            json.dumps(remediation, default=str),
        ),
    )
    await db.commit()


async def get_threats(
    limit: int = 100,
    offset: int = 0,
    severity_filter: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Return paginated threat events, newest first.

    Parameters
    ----------
    limit: Maximum rows to return (1–1000).
    offset: Rows to skip.
    severity_filter: Optional severity string to filter on.
    """
    db = await _get_connection()
    limit = max(1, min(limit, 1000))
    offset = max(0, offset)

    if severity_filter:
        cursor = await db.execute(
            """
            SELECT * FROM threat_events
            WHERE severity = ?
            ORDER BY detected_at DESC
            LIMIT ? OFFSET ?
            """,
            (severity_filter, limit, offset),
        )
    else:
        cursor = await db.execute(
            """
            SELECT * FROM threat_events
            ORDER BY detected_at DESC
            LIMIT ? OFFSET ?
            """,
            (limit, offset),
        )

    rows = await cursor.fetchall()
    return [_row_to_threat_dict(r) for r in rows]


async def get_threat_by_id(threat_id: str) -> Optional[Dict[str, Any]]:
    """Look up a single threat by its primary key."""
    db = await _get_connection()
    cursor = await db.execute(
        "SELECT * FROM threat_events WHERE id = ?",
        (threat_id,),
    )
    row = await cursor.fetchone()
    if row is None:
        return None
    return _row_to_threat_dict(row)


async def resolve_threat(threat_id: str) -> bool:
    """Mark a threat as resolved by setting resolved_at to now.

    Returns True if a row was actually updated, False otherwise.
    """
    db = await _get_connection()
    now_iso = datetime.now(timezone.utc).isoformat()
    cursor = await db.execute(
        """
        UPDATE threat_events
        SET resolved_at = ?
        WHERE id = ? AND resolved_at IS NULL
        """,
        (now_iso, threat_id),
    )
    await db.commit()
    return cursor.rowcount > 0


async def get_threat_count() -> int:
    """Return the total number of threat events ever recorded."""
    db = await _get_connection()
    cursor = await db.execute("SELECT COUNT(*) AS cnt FROM threat_events")
    row = await cursor.fetchone()
    return row["cnt"] if row else 0


# ─── Correlation helpers ────────────────────────────────────────────────

async def save_correlation(
    id: str,
    pattern_name: str,
    techniques: List[str],
    backends: List[str],
    detected_at: str,
    severity: str,
) -> None:
    """INSERT OR REPLACE a correlation (campaign) event."""
    db = await _get_connection()
    await db.execute(
        """
        INSERT OR REPLACE INTO correlation_events
            (id, pattern_name, techniques, backends, detected_at, severity)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            id,
            pattern_name,
            json.dumps(techniques),
            json.dumps(backends),
            detected_at,
            severity,
        ),
    )
    await db.commit()


async def get_correlations(
    limit: int = 100,
    offset: int = 0,
) -> List[Dict[str, Any]]:
    """Return paginated correlation events, newest first."""
    db = await _get_connection()
    limit = max(1, min(limit, 1000))
    offset = max(0, offset)
    cursor = await db.execute(
        """
        SELECT * FROM correlation_events
        ORDER BY detected_at DESC
        LIMIT ? OFFSET ?
        """,
        (limit, offset),
    )
    rows = await cursor.fetchall()
    return [_row_to_corr_dict(r) for r in rows]


# ─── Statistics ─────────────────────────────────────────────────────────

async def get_threat_stats() -> Dict[str, Any]:
    """Return aggregated statistics over all persisted threat events.

    Returns a dict with:
      total_all_time:  int
      by_severity:     dict  {severity: count}
      by_platform:     dict  {platform: count}
      by_technique:    dict  {technique_id: count}
      first_detected:  str | None  (ISO-8601)
      last_detected:   str | None  (ISO-8601)
    """
    db = await _get_connection()

    # Total
    cursor = await db.execute("SELECT COUNT(*) AS cnt FROM threat_events")
    total = (await cursor.fetchone())["cnt"]

    # By severity
    cursor = await db.execute(
        "SELECT severity, COUNT(*) AS cnt FROM threat_events GROUP BY severity"
    )
    by_severity = {row["severity"]: row["cnt"] for row in await cursor.fetchall()}

    # By platform
    cursor = await db.execute(
        "SELECT platform, COUNT(*) AS cnt FROM threat_events GROUP BY platform"
    )
    by_platform = {row["platform"]: row["cnt"] for row in await cursor.fetchall()}

    # By technique
    cursor = await db.execute(
        "SELECT technique_id, COUNT(*) AS cnt FROM threat_events GROUP BY technique_id"
    )
    by_technique = {row["technique_id"]: row["cnt"] for row in await cursor.fetchall()}

    # First / last detected
    cursor = await db.execute(
        "SELECT MIN(detected_at) AS first, MAX(detected_at) AS last FROM threat_events"
    )
    row = await cursor.fetchone()
    first_detected = row["first"] if row and row["first"] else None
    last_detected = row["last"] if row and row["last"] else None

    return {
        "total_all_time": total,
        "by_severity": by_severity,
        "by_platform": by_platform,
        "by_technique": by_technique,
        "first_detected": first_detected,
        "last_detected": last_detected,
    }


# ─── Internal row-to-dict converters ────────────────────────────────────

def _row_to_threat_dict(row: aiosqlite.Row) -> Dict[str, Any]:
    """Convert a sqlite3 Row back into a threat-event dict."""
    evidence = json.loads(row["evidence"]) if row["evidence"] else {}
    remediation = json.loads(row["remediation"]) if row["remediation"] else []
    return {
        "id": row["id"],
        "technique_id": row["technique_id"],
        "severity": row["severity"],
        "platform": row["platform"],
        "backend_id": row["backend_id"],
        "title": row["title"],
        "description": row["description"],
        "evidence": evidence,
        "detected_at": row["detected_at"],
        "visual_effect": row["visual_effect"],
        "visual_intensity": row["visual_intensity"],
        "remediation": remediation,
        "resolved_at": row["resolved_at"],
    }


def _row_to_corr_dict(row: aiosqlite.Row) -> Dict[str, Any]:
    """Convert a sqlite3 Row back into a correlation-event dict."""
    return {
        "id": row["id"],
        "pattern_name": row["pattern_name"],
        "techniques": json.loads(row["techniques"]) if row["techniques"] else [],
        "backends": json.loads(row["backends"]) if row["backends"] else [],
        "detected_at": row["detected_at"],
        "severity": row["severity"],
    }
