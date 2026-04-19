"""
Abstract database interface.
All database operations go through this interface.
Never call aiosqlite or asyncpg directly outside this module.
"""
from abc import ABC, abstractmethod
from typing import Optional, List
from backend.threat_engine.models import ThreatEvent


class AbstractDatabase(ABC):
    """Abstract base for all database backends."""

    @abstractmethod
    async def initialize(self) -> None:
        """Create tables / run migrations. Called once at startup."""

    @abstractmethod
    async def save_threat(self, threat: ThreatEvent) -> None:
        """Insert or replace a threat event."""

    @abstractmethod
    async def resolve_threat(self, threat_id: str) -> None:
        """Mark a threat as resolved by setting resolved_at."""

    @abstractmethod
    async def get_recent_threats(
        self,
        limit: int = 100,
        severity: Optional[str] = None,
    ) -> List[dict]:
        """Return recent threats ordered by detected_at desc."""

    @abstractmethod
    async def get_threat_stats(self) -> dict:
        """Return aggregate statistics for the /api/stats endpoint."""

    @abstractmethod
    async def delete_threats_older_than(self, days: int) -> int:
        """Delete resolved threats older than N days. Returns count deleted."""

    @abstractmethod
    async def health_check(self) -> bool:
        """Return True if database is reachable. Used by /health endpoint."""

    @abstractmethod
    async def close(self) -> None:
        """Release all connections. Called at application shutdown."""
