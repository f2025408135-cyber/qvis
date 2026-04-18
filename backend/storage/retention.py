"""Data retention policy engine for QVis.

Automatically purges resolved threat events and correlation events that
exceed their configured TTL, and optionally runs SQLite VACUUM to reclaim
disk space.  Designed to be called from a background timer in the
simulation loop or a standalone cron/scheduler.

All operations are idempotent and safe to run concurrently (the caller
should use an asyncio.Lock if multiple coroutines could trigger cleanup
simultaneously).
"""

from __future__ import annotations

import time
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Optional

import structlog

from backend.config import settings

logger = structlog.get_logger(__name__)


def _cutoff_iso(days: int) -> str:
    """Return an ISO-8601 timestamp for ``now - days``."""
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()


async def purge_expired_threats(days: Optional[int] = None) -> int:
    """Delete resolved threat events older than *days*.

    Only rows where ``resolved_at IS NOT NULL`` are candidates — active
    (unresolved) threats are never purged, regardless of ``detected_at``.

    Parameters
    ----------
    days: Override for ``settings.retention_days_threats``.

    Returns
    -------
    int
        Number of rows deleted.
    """
    from backend.storage.database import _get_connection
    from backend.metrics import retention_rows_deleted_total

    days = days if days is not None else settings.retention_days_threats
    cutoff = _cutoff_iso(days)
    db = await _get_connection()

    cursor = await db.execute(
        """
        DELETE FROM threat_events
        WHERE resolved_at IS NOT NULL
          AND resolved_at < ?
        """,
        (cutoff,),
    )
    deleted = cursor.rowcount
    await db.commit()

    if deleted > 0:
        retention_rows_deleted_total.labels(table="threat_events").inc(deleted)
        logger.info(
            "retention_threats_purged",
            deleted=deleted,
            cutoff=cutoff,
            retention_days=days,
        )

    return deleted


async def purge_expired_correlations(days: Optional[int] = None) -> int:
    """Delete correlation events older than *days*.

    Unlike threat events, correlations have no ``resolved_at`` column,
    so the cutoff is based on ``detected_at``.

    Parameters
    ----------
    days: Override for ``settings.retention_days_correlations``.

    Returns
    -------
    int
        Number of rows deleted.
    """
    from backend.storage.database import _get_connection
    from backend.metrics import retention_rows_deleted_total

    days = days if days is not None else settings.retention_days_correlations
    cutoff = _cutoff_iso(days)
    db = await _get_connection()

    cursor = await db.execute(
        """
        DELETE FROM correlation_events
        WHERE detected_at < ?
        """,
        (cutoff,),
    )
    deleted = cursor.rowcount
    await db.commit()

    if deleted > 0:
        retention_rows_deleted_total.labels(table="correlation_events").inc(deleted)
        logger.info(
            "retention_correlations_purged",
            deleted=deleted,
            cutoff=cutoff,
            retention_days=days,
        )

    return deleted


async def vacuum_database() -> bool:
    """Run SQLite VACUUM to reclaim disk space after deletion.

    VACUUM rebuilds the entire database file, which requires an
    exclusive lock and may take significant time on large databases.
    It is a no-op for PostgreSQL (which handles this via autovacuum).

    Returns
    -------
    bool
        True if VACUUM was actually executed, False if skipped.
    """
    from backend.metrics import retention_vacuum_duration_seconds

    if not settings.retention_vacuum_enabled:
        logger.debug("retention_vacuum_skipped", reason="disabled")
        return False

    # Detect if we are on SQLite
    db_url = settings.database_url
    if not db_url.startswith("sqlite"):
        logger.debug("retention_vacuum_skipped", reason="not_sqlite", backend=db_url.split("+")[0])
        return False

    from backend.storage.database import _get_connection

    start = time.monotonic()
    db = await _get_connection()

    try:
        await db.execute("VACUUM;")
        elapsed = round(time.monotonic() - start, 3)
        retention_vacuum_duration_seconds.observe(elapsed)
        logger.info("retention_vacuum_complete", duration_seconds=elapsed)
        return True
    except Exception as exc:
        logger.warning("retention_vacuum_error", error=str(exc))
        return False


async def run_retention_cleanup(
    threat_days: Optional[int] = None,
    correlation_days: Optional[int] = None,
    do_vacuum: Optional[bool] = None,
) -> Dict[str, Any]:
    """Execute a full retention cleanup cycle.

    This is the primary entry point called from the simulation loop's
    background timer.  It purges expired threats and correlations, then
    optionally runs VACUUM.  All results are logged and recorded as
    Prometheus metrics.

    Parameters
    ----------
    threat_days: Override retention days for threats.
    correlation_days: Override retention days for correlations.
    do_vacuum: Override whether to run VACUUM (default: from settings).

    Returns
    -------
    dict
        Summary of the cleanup cycle with ``threats_deleted``,
        ``correlations_deleted``, ``vacuumed``, and ``duration_seconds``.
    """
    from backend.metrics import (
        retention_cleanup_duration_seconds,
        retention_cleanup_errors_total,
        retention_last_cleanup_timestamp,
    )

    start = time.monotonic()
    threats_deleted = 0
    correlations_deleted = 0
    vacuumed = False
    errors: list[str] = []

    try:
        threats_deleted = await purge_expired_threats(days=threat_days)
    except Exception as exc:
        errors.append(f"threats: {exc}")
        retention_cleanup_errors_total.inc()
        logger.error("retention_threats_error", error=str(exc))

    try:
        correlations_deleted = await purge_expired_correlations(days=correlation_days)
    except Exception as exc:
        errors.append(f"correlations: {exc}")
        retention_cleanup_errors_total.inc()
        logger.error("retention_correlations_error", error=str(exc))

    # Run VACUUM only if rows were actually deleted
    should_vacuum = do_vacuum if do_vacuum is not None else settings.retention_vacuum_enabled
    if should_vacuum and (threats_deleted > 0 or correlations_deleted > 0):
        try:
            vacuumed = await vacuum_database()
        except Exception as exc:
            errors.append(f"vacuum: {exc}")
            retention_cleanup_errors_total.inc()
            logger.error("retention_vacuum_error", error=str(exc))

    elapsed = round(time.monotonic() - start, 3)
    retention_cleanup_duration_seconds.observe(elapsed)
    retention_last_cleanup_timestamp.set_to_current_time()

    result = {
        "threats_deleted": threats_deleted,
        "correlations_deleted": correlations_deleted,
        "vacuumed": vacuumed,
        "errors": errors,
        "duration_seconds": elapsed,
    }

    if threats_deleted > 0 or correlations_deleted > 0:
        logger.info("retention_cleanup_complete", **result)
    else:
        logger.debug("retention_cleanup_noop", duration_seconds=elapsed)

    return result


async def get_retention_stats() -> Dict[str, Any]:
    """Return statistics about data eligible for retention cleanup.

    Useful for monitoring dashboards and the admin API.  Counts rows
    that *would* be deleted if ``run_retention_cleanup()`` were called
    right now, without actually deleting them.

    Returns
    -------
    dict
        ``threats_eligible``, ``correlations_eligible``,
        ``total_threats``, ``total_correlations``,
        ``threat_cutoff``, ``correlation_cutoff``.
    """
    from backend.storage.database import _get_connection

    threat_cutoff = _cutoff_iso(settings.retention_days_threats)
    correlation_cutoff = _cutoff_iso(settings.retention_days_correlations)
    db = await _get_connection()

    # Threats eligible for cleanup
    cursor = await db.execute(
        """
        SELECT COUNT(*) AS cnt FROM threat_events
        WHERE resolved_at IS NOT NULL AND resolved_at < ?
        """,
        (threat_cutoff,),
    )
    threats_eligible = (await cursor.fetchone())["cnt"]

    # Correlations eligible for cleanup
    cursor = await db.execute(
        """
        SELECT COUNT(*) AS cnt FROM correlation_events
        WHERE detected_at < ?
        """,
        (correlation_cutoff,),
    )
    correlations_eligible = (await cursor.fetchone())["cnt"]

    # Total counts
    cursor = await db.execute("SELECT COUNT(*) AS cnt FROM threat_events")
    total_threats = (await cursor.fetchone())["cnt"]

    cursor = await db.execute("SELECT COUNT(*) AS cnt FROM correlation_events")
    total_correlations = (await cursor.fetchone())["cnt"]

    return {
        "threats_eligible": threats_eligible,
        "correlations_eligible": correlations_eligible,
        "total_threats": total_threats,
        "total_correlations": total_correlations,
        "threat_cutoff": threat_cutoff,
        "correlation_cutoff": correlation_cutoff,
        "retention_days_threats": settings.retention_days_threats,
        "retention_days_correlations": settings.retention_days_correlations,
    }
