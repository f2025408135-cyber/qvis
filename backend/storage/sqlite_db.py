"""
SQLite database backend using aiosqlite.
Used when DATABASE_URL starts with sqlite:///
"""
import os
import json
import aiosqlite
from datetime import datetime, timezone
from typing import Optional, List, Any, Dict
from backend.storage.base import AbstractDatabase
from backend.threat_engine.models import ThreatEvent

class SQLiteDatabase(AbstractDatabase):
    """
    SQLite implementation of the database interface.
    """

    def __init__(self, db_path: str):
        self._db_path = db_path
        self._connection: Optional[aiosqlite.Connection] = None

    async def initialize(self) -> None:
        db_dir = os.path.dirname(self._db_path)
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)
            
        self._connection = await aiosqlite.connect(self._db_path)
        self._connection.row_factory = aiosqlite.Row

        await self._ensure_connection()
        cursor = await self._connection.execute("PRAGMA journal_mode=WAL;")
        await self._ensure_connection()
        cursor = await self._connection.execute("PRAGMA synchronous=NORMAL;")

        await self._ensure_connection()
        cursor = await self._connection.execute("""
            CREATE TABLE IF NOT EXISTS threats (
                id TEXT PRIMARY KEY,
                technique_id TEXT NOT NULL,
                technique_name TEXT NOT NULL,
                severity TEXT NOT NULL,
                platform TEXT NOT NULL,
                backend_id TEXT,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                evidence JSON NOT NULL DEFAULT '{}',
                detected_at TEXT NOT NULL,
                resolved_at TEXT,
                visual_effect TEXT,
                visual_intensity REAL,
                remediation JSON NOT NULL DEFAULT '[]'
            )
        """)
        await self._ensure_connection()
        cursor = await self._connection.execute("CREATE INDEX IF NOT EXISTS idx_threats_detected_at ON threats(detected_at DESC)")
        await self._ensure_connection()
        cursor = await self._connection.execute("CREATE INDEX IF NOT EXISTS idx_threats_severity ON threats(severity)")
        await self._ensure_connection()
        cursor = await self._connection.execute("CREATE INDEX IF NOT EXISTS idx_threats_resolved ON threats(resolved_at) WHERE resolved_at IS NULL")
        await self._ensure_connection()
        cursor = await self._connection.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                action TEXT NOT NULL,
                user TEXT NOT NULL,
                ip TEXT NOT NULL,
                resource_type TEXT NOT NULL,
                resource_id TEXT NOT NULL,
                status INTEGER NOT NULL,
                before JSON NOT NULL,
                after JSON NOT NULL,
                prev_hash TEXT NOT NULL,
                hash TEXT NOT NULL UNIQUE
            )
        """)
        await self._connection.commit()


    async def _ensure_connection(self):
        if self._connection is None:
            await self.initialize()

    async def save_threat(self, threat: ThreatEvent) -> None:
        await self._ensure_connection()
        cursor = await self._connection.execute(
            """
            INSERT OR REPLACE INTO threats
                (id, technique_id, technique_name, severity, platform, backend_id, title,
                 description, evidence, detected_at, visual_effect,
                 visual_intensity, remediation, resolved_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
            """,
            (
                threat.id,
                threat.technique_id,
                threat.technique_name,
                str(threat.severity.value if hasattr(threat.severity, "value") else threat.severity),
                str(threat.platform.value if hasattr(threat.platform, "value") else threat.platform),
                threat.backend_id,
                threat.title,
                threat.description,
                json.dumps(threat.evidence, default=str),
                threat.detected_at.isoformat() if isinstance(threat.detected_at, datetime) else threat.detected_at,
                threat.visual_effect,
                threat.visual_intensity,
                json.dumps(threat.remediation, default=str),
            ),
        )
        await self._connection.commit()

    async def resolve_threat(self, threat_id: str) -> None:
        now_iso = datetime.now(timezone.utc).isoformat()
        await self._ensure_connection()
        cursor = await self._connection.execute(
            """
            UPDATE threats
            SET resolved_at = ?
            WHERE id = ? AND resolved_at IS NULL
            """,
            (now_iso, threat_id),
        )
        await self._connection.commit()

    
    async def get_recent_threats(
        self,
        limit: int = 100,
        severity: Optional[str] = None,
    ) -> List[dict]:
        await self._ensure_connection()
        limit = max(1, min(limit, 1000))
        
        if severity:
            cursor = await self._connection.execute(
                "SELECT * FROM threats WHERE severity = ? ORDER BY detected_at DESC LIMIT ?",
                (severity, limit),
            )
        else:
            cursor = await self._connection.execute(
                "SELECT * FROM threats ORDER BY detected_at DESC LIMIT ?",
                (limit,),
            )

        rows = await cursor.fetchall()
        return [self._row_to_threat_dict(r) for r in rows]

    async def get_threat_stats(self) -> dict:
        await self._ensure_connection()
        cursor = await self._connection.execute("SELECT COUNT(*) AS cnt FROM threats")
        total = (await cursor.fetchone())["cnt"]

        cursor = await self._connection.execute(
            "SELECT severity, COUNT(*) AS cnt FROM threats GROUP BY severity"
        )
        by_severity = {row["severity"]: row["cnt"] for row in await cursor.fetchall()}

        cursor = await self._connection.execute(
            "SELECT platform, COUNT(*) AS cnt FROM threats GROUP BY platform"
        )
        by_platform = {row["platform"]: row["cnt"] for row in await cursor.fetchall()}

        cursor = await self._connection.execute(
            "SELECT technique_id, COUNT(*) AS cnt FROM threats GROUP BY technique_id"
        )
        by_technique = {row["technique_id"]: row["cnt"] for row in await cursor.fetchall()}

        cursor = await self._connection.execute(
            "SELECT MIN(detected_at) AS first, MAX(detected_at) AS last FROM threats"
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

    async def delete_threats_older_than(self, days: int) -> int:
        await self._ensure_connection()
        cursor = await self._connection.execute(
            f"DELETE FROM threats WHERE resolved_at IS NOT NULL AND resolved_at < datetime('now', '-{days} days')"
        )
        await self._connection.commit()
        return cursor.rowcount

    async def health_check(self) -> bool:
        if not self._connection:
            return False
        try:
            await self._ensure_connection()
            await self._connection.execute("SELECT 1")
            return True
        except Exception:
            return False
    async def close(self) -> None:
        if self._connection:
            await self._connection.close()
            self._connection = None

    def _row_to_threat_dict(self, row: aiosqlite.Row) -> Dict[str, Any]:
        evidence = json.loads(row["evidence"]) if row["evidence"] else {}
        remediation = json.loads(row["remediation"]) if row["remediation"] else []
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
            "detected_at": row["detected_at"],
            "visual_effect": row["visual_effect"],
            "visual_intensity": row["visual_intensity"],
            "remediation": remediation,
            "resolved_at": row["resolved_at"],
        }

    async def save_audit_log(self, payload: dict) -> None:
        await self._ensure_connection()
        await self._connection.execute(
            """
            INSERT INTO audit_logs
            (timestamp, action, user, ip, resource_type, resource_id, status, before, after, prev_hash, hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
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
        )
        await self._connection.commit()

    async def get_all_audit_logs(self) -> List[dict]:
        await self._ensure_connection()
        cursor = await self._connection.execute("SELECT * FROM audit_logs ORDER BY id ASC")
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]
