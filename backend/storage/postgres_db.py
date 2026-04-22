"""
PostgreSQL database backend using asyncpg.
Used when DATABASE_URL starts with postgresql:// or postgres://
"""
import asyncpg
import json
from typing import Optional, List, Any
from backend.storage.base import AbstractDatabase
from backend.threat_engine.models import ThreatEvent
import structlog
from datetime import datetime, timezone

logger = structlog.get_logger(__name__)


class PostgreSQLDatabase(AbstractDatabase):
    """
    PostgreSQL implementation of the database interface.

    Uses asyncpg connection pool for high-throughput async operations.
    Schema is identical to SQLite to allow data migration between backends.
    """

    def __init__(self, database_url: str, pool_size: int = 10):
        self._url = database_url
        self._pool_size = pool_size
        self._pool: asyncpg.Pool | None = None

    async def initialize(self) -> None:
        """Create connection pool and ensure schema exists."""
        self._pool = await asyncpg.create_pool(
            dsn=self._url,
            min_size=2,
            max_size=self._pool_size,
        )
        async with self._pool.acquire() as conn:
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS threats (
                    id TEXT PRIMARY KEY,
                    technique_id TEXT NOT NULL,
                    technique_name TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    platform TEXT NOT NULL,
                    backend_id TEXT,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    evidence JSONB NOT NULL DEFAULT '{}',
                    detected_at TIMESTAMPTZ NOT NULL,
                    resolved_at TIMESTAMPTZ,
                    visual_effect TEXT,
                    visual_intensity REAL,
                    remediation JSONB NOT NULL DEFAULT '[]'
                );
                CREATE INDEX IF NOT EXISTS idx_threats_detected_at
                    ON threats(detected_at DESC);
                CREATE INDEX IF NOT EXISTS idx_threats_severity
                    ON threats(severity);
                CREATE INDEX IF NOT EXISTS idx_threats_resolved
                    ON threats(resolved_at)
                    WHERE resolved_at IS NULL;

                CREATE TABLE IF NOT EXISTS audit_logs (
                    id SERIAL PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    action TEXT NOT NULL,
                    "user" TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    resource_type TEXT NOT NULL,
                    resource_id TEXT NOT NULL,
                    status INTEGER NOT NULL,
                    before JSONB NOT NULL,
                    after JSONB NOT NULL,
                    prev_hash TEXT NOT NULL,
                    hash TEXT NOT NULL UNIQUE
                );

            """)
        logger.info("postgres_initialized", pool_size=self._pool_size)

    async def save_threat(self, threat: ThreatEvent) -> None:
        async with self._pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO threats
                    (id, technique_id, technique_name, severity, platform, backend_id, title,
                     description, evidence, detected_at, visual_effect,
                     visual_intensity, remediation, resolved_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, NULL)
                ON CONFLICT (id) DO UPDATE SET
                    technique_id = EXCLUDED.technique_id,
                    technique_name = EXCLUDED.technique_name,
                    severity = EXCLUDED.severity,
                    platform = EXCLUDED.platform,
                    backend_id = EXCLUDED.backend_id,
                    title = EXCLUDED.title,
                    description = EXCLUDED.description,
                    evidence = EXCLUDED.evidence,
                    detected_at = EXCLUDED.detected_at,
                    visual_effect = EXCLUDED.visual_effect,
                    visual_intensity = EXCLUDED.visual_intensity,
                    remediation = EXCLUDED.remediation
                """,
                threat.id,
                threat.technique_id,
                threat.technique_name,
                str(threat.severity.value if hasattr(threat.severity, "value") else threat.severity),
                str(threat.platform.value if hasattr(threat.platform, "value") else threat.platform),
                threat.backend_id,
                threat.title,
                threat.description,
                json.dumps(threat.evidence, default=str),
                threat.detected_at if isinstance(threat.detected_at, datetime) else datetime.fromisoformat(threat.detected_at.replace("Z", "+00:00")),
                threat.visual_effect,
                threat.visual_intensity,
                json.dumps(threat.remediation, default=str),
            )

    async def resolve_threat(self, threat_id: str) -> None:
        async with self._pool.acquire() as conn:
            await conn.execute(
                """
                UPDATE threats
                SET resolved_at = $1
                WHERE id = $2 AND resolved_at IS NULL
                """,
                datetime.now(timezone.utc),
                threat_id,
            )

    async def get_recent_threats(
        self,
        limit: int = 100,
        severity: Optional[str] = None,
    ) -> List[dict]:
        limit = max(1, min(limit, 1000))
        async with self._pool.acquire() as conn:
            if severity:
                rows = await conn.fetch(
                    """
                    SELECT * FROM threats
                    WHERE severity = $1
                    ORDER BY detected_at DESC
                    LIMIT $2
                    """,
                    severity,
                    limit,
                )
            else:
                rows = await conn.fetch(
                    """
                    SELECT * FROM threats
                    ORDER BY detected_at DESC
                    LIMIT $1
                    """,
                    limit,
                )
            return [self._row_to_threat_dict(r) for r in rows]

    async def get_threat_stats(self) -> dict:
        async with self._pool.acquire() as conn:
            total = await conn.fetchval("SELECT COUNT(*) FROM threats")
            
            by_severity_rows = await conn.fetch("SELECT severity, COUNT(*) FROM threats GROUP BY severity")
            by_severity = {row["severity"]: row["count"] for row in by_severity_rows}
            
            by_platform_rows = await conn.fetch("SELECT platform, COUNT(*) FROM threats GROUP BY platform")
            by_platform = {row["platform"]: row["count"] for row in by_platform_rows}
            
            by_technique_rows = await conn.fetch("SELECT technique_id, COUNT(*) FROM threats GROUP BY technique_id")
            by_technique = {row["technique_id"]: row["count"] for row in by_technique_rows}
            
            first_last = await conn.fetchrow("SELECT MIN(detected_at) AS first, MAX(detected_at) AS last FROM threats")
            
            first_detected = first_last["first"].isoformat() if first_last and first_last["first"] else None
            last_detected = first_last["last"].isoformat() if first_last and first_last["last"] else None
            
            return {
                "total_all_time": total,
                "by_severity": by_severity,
                "by_platform": by_platform,
                "by_technique": by_technique,
                "first_detected": first_detected,
                "last_detected": last_detected,
            }

    async def delete_threats_older_than(self, days: int) -> int:
        async with self._pool.acquire() as conn:
            res = await conn.execute(
                """
                DELETE FROM threats
                WHERE resolved_at IS NOT NULL
                AND resolved_at < NOW() - INTERVAL '1 day' * $1
                """,
                days
            )
            # res is typically a string like "DELETE 5"
            return int(res.split()[-1])

    async def health_check(self) -> bool:
        if not self._pool:
            return False
        try:
            async with self._pool.acquire() as conn:
                await conn.execute("SELECT 1")
            return True
        except Exception:
            return False

    async def close(self) -> None:
        if self._pool:
            await self._pool.close()

    def _row_to_threat_dict(self, row: asyncpg.Record) -> dict:
        evidence = json.loads(row["evidence"]) if isinstance(row["evidence"], str) else row["evidence"]
        remediation = json.loads(row["remediation"]) if isinstance(row["remediation"], str) else row["remediation"]
        return {
            "id": row["id"],
            "technique_id": row["technique_id"],
            "technique_name": row["technique_name"],
            "severity": row["severity"],
            "platform": row["platform"],
            "backend_id": row["backend_id"],
            "title": row["title"],
            "description": row["description"],
            "evidence": evidence,
            "detected_at": row["detected_at"].isoformat() if row["detected_at"] else None,
            "visual_effect": row["visual_effect"],
            "visual_intensity": row["visual_intensity"],
            "remediation": remediation,
            "resolved_at": row["resolved_at"].isoformat() if row["resolved_at"] else None,
        }

    async def save_audit_log(self, payload: dict) -> None:
        async with self._pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO audit_logs
                (timestamp, action, "user", ip, resource_type, resource_id, status, before, after, prev_hash, hash)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
                """,
                payload["timestamp"],
                payload["action"],
                payload["user"],
                payload["ip"],
                payload["resource_type"],
                payload["resource_id"],
                payload["status"],
                json.dumps(payload["before"]),
                json.dumps(payload["after"]),
                payload["prev_hash"],
                payload["hash"]
            )

    async def get_all_audit_logs(self) -> List[dict]:
        async with self._pool.acquire() as conn:
            rows = await conn.fetch("SELECT * FROM audit_logs ORDER BY id ASC")
            return [dict(r) for r in rows]
