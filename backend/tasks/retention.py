"""
Data retention background task.
Deletes resolved threats older than THREAT_RETENTION_DAYS.
Runs every RETENTION_CHECK_INTERVAL_HOURS.
"""
import asyncio
import structlog
from datetime import datetime
from backend.storage.base import AbstractDatabase

logger = structlog.get_logger(__name__)


async def retention_loop(
    db: AbstractDatabase,
    retention_days: int,
    check_interval_hours: int,
) -> None:
    """
    Continuously run data retention cleanup.

    Designed to run as a background asyncio task alongside the
    simulation loop. Never raises — errors are logged and retried
    next cycle.

    Args:
        db: Database implementation to clean up.
        retention_days: Delete resolved threats older than this.
        check_interval_hours: How often to run the cleanup.
    """
    interval_seconds = check_interval_hours * 3600
    logger.info(
        "retention_loop_started",
        retention_days=retention_days,
        check_interval_hours=check_interval_hours,
    )

    while True:
        await asyncio.sleep(interval_seconds)
        try:
            deleted = await db.delete_threats_older_than(retention_days)
            logger.info(
                "retention_cleanup_complete",
                deleted_count=deleted,
                retention_days=retention_days,
            )
        except asyncio.CancelledError:
            # If the task is explicitly cancelled (e.g. during test teardown), exit loop
            break
        except Exception as e:
            logger.error(
                "retention_cleanup_failed",
                error=str(e),
                exc_info=True,
            )
