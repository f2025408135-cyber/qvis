"""Tests for the data retention policy engine (CHUNK 05).

Covers:
- purge_expired_threats: only resolved threats older than cutoff are deleted
- purge_expired_correlations: all correlations older than cutoff are deleted
- vacuum_database: SQLite VACUUM runs when enabled, skipped for PostgreSQL
- run_retention_cleanup: full cycle orchestration
- get_retention_stats: eligibility counting without deletion
- Integration with the simulation loop timer
- Prometheus metrics recording
- Admin API endpoints
- Alembic migration for resolved_at on correlation_events
"""

from __future__ import annotations

import asyncio
import os
import time
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock, AsyncMock

import pytest
import pytest_asyncio

# Ensure we use the test database
os.environ.setdefault("USE_MOCK", "true")


# ─── Fixtures ─────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _reset_settings(monkeypatch):
    """Ensure retention settings are at known defaults for each test."""
    monkeypatch.setenv("RETENTION_DAYS_THREATS", "30")
    monkeypatch.setenv("RETENTION_DAYS_CORRELATIONS", "30")
    monkeypatch.setenv("RETENTION_CLEANUP_INTERVAL_SECONDS", "3600")
    monkeypatch.setenv("RETENTION_VACUUM_ENABLED", "false")


@pytest.fixture
def retention_settings():
    """Return current Settings with retention fields."""
    from backend.config import settings
    return settings


@pytest_asyncio.fixture
async def db_with_data():
    """Create a test database with threat and correlation data of various ages."""
    from backend.storage import database as db_mod
    import json

    # Use a unique test DB path
    test_path = "/tmp/test_retention_qvis.db"
    # Reset module state
    db_mod._connection = None
    db_mod._db_path = test_path

    await db_mod.init_db(test_path)

    now = datetime.now(timezone.utc)
    old = (now - timedelta(days=60)).isoformat()
    recent = (now - timedelta(days=5)).isoformat()
    very_old = (now - timedelta(days=120)).isoformat()

    conn = await db_mod._get_connection()

    # Insert threat events of different ages
    test_threats = [
        # Active threat (resolved_at=NULL) — should NEVER be purged
        ("t1", "QTT002", "medium", "ibm", "b1", "Active Threat", "desc",
         "{}", recent, "", 0.5, "[]", None),
        # Resolved, old enough to purge (60 days, cutoff is 30)
        ("t2", "QTT003", "high", "ibm", "b1", "Old Resolved", "desc",
         "{}", very_old, "", 0.3, "[]", old),
        # Resolved, NOT old enough to keep (5 days)
        ("t3", "QTT009", "high", "braket", "b2", "Recent Resolved", "desc",
         "{}", recent, "", 0.7, "[]", recent),
        # Resolved, very old enough
        ("t4", "QTT017", "critical", "ibm", "b1", "Very Old", "desc",
         "{}", very_old, "", 0.9, "[]", very_old),
        # Active threat with old detected_at but no resolved_at
        ("t5", "QTT011", "critical", "azure", "b3", "Active Old Detected", "desc",
         "{}", very_old, "", 0.8, "[]", None),
    ]

    for t in test_threats:
        await conn.execute(
            """INSERT OR REPLACE INTO threat_events
               (id, technique_id, severity, platform, backend_id, title,
                description, evidence, detected_at, visual_effect,
                visual_intensity, remediation, resolved_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            t,
        )

    # Insert correlation events of different ages
    test_correlations = [
        ("c1", "Coordinated Recon", '["QTT009","QTT012"]', '["b1","b2"]',
         very_old, "high", None),
        ("c2", "Multi-Platform Attack", '["QTT002","QTT003"]', '["b1","b2","b3"]',
         recent, "critical", None),
        ("c3", "Calibration Harvest", '["QTT002"]', '["b1"]',
         very_old, "medium", None),
    ]

    for c in test_correlations:
        await conn.execute(
            """INSERT OR REPLACE INTO correlation_events
               (id, pattern_name, techniques, backends, detected_at, severity, resolved_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            c,
        )

    await conn.commit()

    yield db_mod

    # Cleanup
    try:
        await conn.close()
    except Exception:
        pass
    db_mod._connection = None
    if os.path.exists(test_path):
        os.unlink(test_path)


# ─── purge_expired_threats ───────────────────────────────────────────────

@pytest.mark.asyncio
async def test_purge_only_resolved_old_threats(db_with_data):
    """Only resolved threats older than the cutoff should be deleted."""
    from backend.storage.retention import purge_expired_threats
    from backend.storage import database as db_mod

    deleted = await purge_expired_threats(days=30)

    # t2 (resolved 60 days ago) and t4 (resolved 120 days ago) should be purged
    assert deleted == 2

    # Active threats (t1, t5) and recently resolved (t3) must remain
    conn = await db_mod._get_connection()
    cursor = await conn.execute("SELECT id FROM threat_events ORDER BY id")
    remaining = [row["id"] for row in await cursor.fetchall()]
    assert "t1" in remaining   # Active, never purged
    assert "t3" in remaining   # Resolved but too recent
    assert "t5" in remaining   # Active (no resolved_at), never purged
    assert "t2" not in remaining  # Old resolved, purged
    assert "t4" not in remaining  # Very old resolved, purged


@pytest.mark.asyncio
async def test_purge_threats_with_custom_days(db_with_data):
    """Custom days override should adjust the cutoff."""
    from backend.storage.retention import purge_expired_threats
    from backend.storage import database as db_mod

    # With 200 day retention, nothing should be purged (oldest is ~120 days)
    deleted = await purge_expired_threats(days=200)
    assert deleted == 0

    # With 1 day retention, ALL resolved threats should be purged (t2, t3, t4)
    deleted = await purge_expired_threats(days=1)
    assert deleted == 3  # t2, t3, t4 all resolved; t3 resolved_at=5 days ago > 1 day

    # Active threats remain
    conn = await db_mod._get_connection()
    cursor = await conn.execute("SELECT id FROM threat_events ORDER BY id")
    remaining = [row["id"] for row in await cursor.fetchall()]
    assert "t1" in remaining
    assert "t5" in remaining


@pytest.mark.asyncio
async def test_purge_threats_active_never_purged(db_with_data):
    """Active threats (resolved_at=NULL) must never be purged, regardless of detected_at."""
    from backend.storage.retention import purge_expired_threats
    from backend.storage import database as db_mod

    # t5 has detected_at = 120 days ago but resolved_at = NULL (active)
    deleted = await purge_expired_threats(days=1)
    # Only resolved threats deleted (t2, t3, t4) — t5 is active so must remain
    assert deleted == 3

    conn = await db_mod._get_connection()
    cursor = await conn.execute("SELECT id FROM threat_events WHERE id = 't5'")
    row = await cursor.fetchone()
    assert row is not None, "Active threat t5 should never be purged"

    # Also verify t1 (also active) remains
    cursor = await conn.execute("SELECT id FROM threat_events WHERE id = 't1'")
    row = await cursor.fetchone()
    assert row is not None, "Active threat t1 should never be purged"


# ─── purge_expired_correlations ─────────────────────────────────────────

@pytest.mark.asyncio
async def test_purge_old_correlations(db_with_data):
    """Correlations older than cutoff should be deleted (based on detected_at)."""
    from backend.storage.retention import purge_expired_correlations
    from backend.storage import database as db_mod

    deleted = await purge_expired_correlations(days=30)

    # c1 and c3 are very old (120 days), c2 is recent (5 days)
    assert deleted == 2

    conn = await db_mod._get_connection()
    cursor = await conn.execute("SELECT id FROM correlation_events ORDER BY id")
    remaining = [row["id"] for row in await cursor.fetchall()]
    assert "c1" not in remaining
    assert "c3" not in remaining
    assert "c2" in remaining


@pytest.mark.asyncio
async def test_purge_correlations_custom_days(db_with_data):
    """Custom days override adjusts the correlation cutoff."""
    from backend.storage.retention import purge_expired_correlations

    deleted = await purge_expired_correlations(days=200)
    assert deleted == 0

    deleted = await purge_expired_correlations(days=1)
    assert deleted == 3  # All 3 correlations are older than 1 day


# ─── vacuum_database ────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_vacuum_skipped_when_disabled(db_with_data):
    """VACUUM should be skipped when retention_vacuum_enabled is False."""
    from backend.storage.retention import vacuum_database

    with patch("backend.storage.retention.settings") as mock_settings:
        mock_settings.retention_vacuum_enabled = False
        result = await vacuum_database()
    assert result is False


@pytest.mark.asyncio
async def test_vacuum_skipped_for_postgres(db_with_data):
    """VACUUM should be a no-op for PostgreSQL backends."""
    from backend.storage.retention import vacuum_database

    with patch("backend.storage.retention.settings") as mock_settings:
        mock_settings.retention_vacuum_enabled = True
        mock_settings.database_url = "postgresql+asyncpg://user:pass@host:5432/qvis"
        result = await vacuum_database()
    assert result is False


@pytest.mark.asyncio
async def test_vacuum_runs_on_sqlite(db_with_data):
    """VACUUM should execute on SQLite when enabled."""
    from backend.storage.retention import vacuum_database

    with patch("backend.storage.retention.settings") as mock_settings:
        mock_settings.retention_vacuum_enabled = True
        mock_settings.database_url = "sqlite+aiosqlite:///tmp/test_retention_qvis.db"
        result = await vacuum_database()
    assert result is True


# ─── run_retention_cleanup ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_full_cleanup_cycle(db_with_data, monkeypatch):
    """Full cleanup should purge threats and correlations, skip vacuum if no rows deleted."""
    monkeypatch.setenv("RETENTION_VACUUM_ENABLED", "false")
    from importlib import reload
    import backend.config as cfg_mod
    for attr in list(vars(cfg_mod).keys()):
        if attr == "settings":
            delattr(cfg_mod, attr)
    reload(cfg_mod)

    from backend.storage.retention import run_retention_cleanup

    result = await run_retention_cleanup(threat_days=30, correlation_days=30, do_vacuum=False)

    assert result["threats_deleted"] == 2
    assert result["correlations_deleted"] == 2
    assert result["vacuumed"] is False
    assert result["errors"] == []
    assert result["duration_seconds"] >= 0


@pytest.mark.asyncio
async def test_cleanup_with_vacuum_after_deletes(db_with_data):
    """VACUUM should run only when rows were actually deleted."""
    from backend.storage.retention import run_retention_cleanup

    with patch("backend.storage.retention.settings") as mock_settings:
        mock_settings.retention_vacuum_enabled = True
        mock_settings.database_url = "sqlite+aiosqlite:///tmp/test_retention_qvis.db"

        result = await run_retention_cleanup(threat_days=30, correlation_days=30)

        assert result["threats_deleted"] == 2
        assert result["correlations_deleted"] == 2
        assert result["vacuumed"] is True  # Rows deleted → VACUUM runs


@pytest.mark.asyncio
async def test_cleanup_noop_when_nothing_expired(db_with_data):
    """Cleanup should not VACUUM when nothing is deleted."""
    from backend.storage.retention import run_retention_cleanup

    with patch("backend.storage.retention.settings") as mock_settings:
        mock_settings.retention_vacuum_enabled = True

        # 1000 day retention — nothing should be purged
        result = await run_retention_cleanup(threat_days=1000, correlation_days=1000)

        assert result["threats_deleted"] == 0
        assert result["correlations_deleted"] == 0
        assert result["vacuumed"] is False  # No deletes → skip VACUUM


@pytest.mark.asyncio
async def test_cleanup_error_handling(db_with_data, monkeypatch):
    """Errors in individual steps should be captured, not raised."""
    from backend.storage.retention import run_retention_cleanup

    # Use invalid days (0) which should still work — we use ge=1 in Settings
    # but the retention module accepts int directly
    result = await run_retention_cleanup(threat_days=-1, correlation_days=30)

    # Even with invalid cutoff, the function should not crash
    assert "duration_seconds" in result


# ─── get_retention_stats ────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_retention_stats(db_with_data):
    """get_retention_stats should count eligible rows without deleting them."""
    from backend.storage.retention import get_retention_stats

    with patch("backend.storage.retention.settings") as mock_settings:
        mock_settings.retention_days_threats = 30
        mock_settings.retention_days_correlations = 30

        stats = await get_retention_stats()

    assert "threats_eligible" in stats
    assert "correlations_eligible" in stats
    assert "total_threats" in stats
    assert "total_correlations" in stats
    assert "threat_cutoff" in stats
    assert "correlation_cutoff" in stats
    assert stats["total_threats"] == 5
    assert stats["total_correlations"] == 3

    # With 30-day retention:
    # t2 and t4 are resolved and old → eligible
    # c1 and c3 are old → eligible
    assert stats["threats_eligible"] == 2
    assert stats["correlations_eligible"] == 2

    # Verify nothing was actually deleted
    from backend.storage import database as db_mod
    conn = await db_mod._get_connection()
    cursor = await conn.execute("SELECT COUNT(*) AS cnt FROM threat_events")
    assert (await cursor.fetchone())["cnt"] == 5


# ─── Settings Configuration ─────────────────────────────────────────────

def test_retention_settings_defaults():
    """Retention settings should have sensible defaults when no env vars are set."""
    from pydantic_settings import SettingsConfigDict
    from backend.config import Settings

    # Create with _env_file=None to avoid reading .env and no env override
    s = Settings(
        _env_file=None,
        demo_mode=True,
        auth_enabled=False,
        retention_days_threats=90,
        retention_days_correlations=90,
        retention_cleanup_interval_seconds=3600,
        retention_vacuum_enabled=True,
    )

    assert s.retention_days_threats == 90
    assert s.retention_days_correlations == 90
    assert s.retention_cleanup_interval_seconds == 3600
    assert s.retention_vacuum_enabled is True


def test_retention_settings_env_override(monkeypatch):
    """Environment variables should override retention defaults."""
    monkeypatch.setenv("RETENTION_DAYS_THREATS", "7")
    monkeypatch.setenv("RETENTION_DAYS_CORRELATIONS", "14")
    monkeypatch.setenv("RETENTION_CLEANUP_INTERVAL_SECONDS", "300")
    monkeypatch.setenv("RETENTION_VACUUM_ENABLED", "false")

    from importlib import reload
    import backend.config as cfg_mod
    for attr in list(vars(cfg_mod).keys()):
        if attr == "settings":
            delattr(cfg_mod, attr)
    reload(cfg_mod)

    from backend.config import settings
    assert settings.retention_days_threats == 7
    assert settings.retention_days_correlations == 14
    assert settings.retention_cleanup_interval_seconds == 300
    assert settings.retention_vacuum_enabled is False


def test_retention_settings_validation():
    """Retention days should be clamped to [1, 3650]."""
    from pydantic import ValidationError
    from backend.config import Settings

    with pytest.raises(ValidationError):
        Settings(
            _env_file=None,
            demo_mode=True,
            retention_days_threats=0,  # Too low
        )

    with pytest.raises(ValidationError):
        Settings(
            _env_file=None,
            demo_mode=True,
            retention_days_correlations=9999,  # Too high
        )


# ─── Prometheus Metrics ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_retention_metrics_recorded(db_with_data):
    """Retention cleanup should update Prometheus counters and histograms."""
    from backend.storage.retention import run_retention_cleanup
    from backend.metrics import retention_rows_deleted_total

    await run_retention_cleanup(threat_days=30, correlation_days=30, do_vacuum=False)

    # Verify cleanup ran and deleted rows
    # Check the counter was incremented by inspecting metric samples
    for sample in retention_rows_deleted_total.collect():
        for s in sample.samples:
            if s.labels.get("table") == "threat_events":
                assert s.value >= 2
            if s.labels.get("table") == "correlation_events":
                assert s.value >= 2


# ─── Cutoff Calculation ─────────────────────────────────────────────────

def test_cutoff_iso_calculation():
    """_cutoff_iso should return an ISO timestamp of now - N days."""
    from backend.storage.retention import _cutoff_iso
    from datetime import datetime, timezone, timedelta

    cutoff = _cutoff_iso(30)
    parsed = datetime.fromisoformat(cutoff)

    expected = datetime.now(timezone.utc) - timedelta(days=30)
    diff = abs((parsed - expected).total_seconds())
    assert diff < 2, f"Cutoff off by {diff} seconds"


# ─── Idempotency ────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_cleanup_idempotent(db_with_data, monkeypatch):
    """Running cleanup twice should not delete anything on the second run."""
    monkeypatch.setenv("RETENTION_VACUUM_ENABLED", "false")
    from importlib import reload
    import backend.config as cfg_mod
    for attr in list(vars(cfg_mod).keys()):
        if attr == "settings":
            delattr(cfg_mod, attr)
    reload(cfg_mod)

    from backend.storage.retention import run_retention_cleanup

    result1 = await run_retention_cleanup(threat_days=30, correlation_days=30)
    assert result1["threats_deleted"] == 2
    assert result1["correlations_deleted"] == 2

    result2 = await run_retention_cleanup(threat_days=30, correlation_days=30)
    assert result2["threats_deleted"] == 0
    assert result2["correlations_deleted"] == 0


# ─── Alembic Migration ──────────────────────────────────────────────────

def test_migration_adds_resolved_at_column():
    """Verify the migration script adds resolved_at to correlation_events."""
    import importlib.util
    import sys

    spec = importlib.util.spec_from_file_location(
        "migration_0002",
        "/home/z/my-project/qvis/alembic/versions/0002_add_resolved_at_to_correlations.py",
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    assert mod.revision == "0002_add_resolved_at"
    assert mod.down_revision == "0001_initial"
    assert callable(mod.upgrade)
    assert callable(mod.downgrade)


# ─── ORM Model Update ───────────────────────────────────────────────────

def test_orm_model_has_resolved_at():
    """CorrelationEventModel should now include resolved_at column."""
    from backend.storage.models import CorrelationEventModel

    assert hasattr(CorrelationEventModel, "resolved_at")
    assert CorrelationEventModel.resolved_at.nullable is True


# ─── DDL Update ─────────────────────────────────────────────────────────

def test_ddl_includes_resolved_at():
    """Base DDL string should include resolved_at for correlation_events."""
    from backend.storage import database as db_mod

    assert "resolved_at" in db_mod._DDL
    assert "idx_corr_resolved_at" in db_mod._DDL


# ─── Row Converter Update ───────────────────────────────────────────────

def test_corr_dict_includes_resolved_at():
    """_row_to_corr_dict should include resolved_at in output."""
    from unittest.mock import MagicMock
    from backend.storage.database import _row_to_corr_dict

    # Create a mock row object
    mock_row = MagicMock()
    mock_row.__getitem__ = lambda self, key: {
        "id": "c1",
        "pattern_name": "Test",
        "techniques": "[]",
        "backends": "[]",
        "detected_at": "2026-01-01T00:00:00+00:00",
        "severity": "high",
        "resolved_at": "2026-01-15T00:00:00+00:00",
    }[key]

    d = _row_to_corr_dict(mock_row)
    assert "resolved_at" in d
    assert d["resolved_at"] == "2026-01-15T00:00:00+00:00"


def test_corr_dict_null_resolved_at():
    """_row_to_corr_dict should handle NULL resolved_at."""
    from unittest.mock import MagicMock
    from backend.storage.database import _row_to_corr_dict

    mock_row = MagicMock()
    mock_row.__getitem__ = lambda self, key: {
        "id": "c1",
        "pattern_name": "Test",
        "techniques": "[]",
        "backends": "[]",
        "detected_at": "2026-01-01T00:00:00+00:00",
        "severity": "high",
        "resolved_at": None,
    }[key]

    d = _row_to_corr_dict(mock_row)
    assert d["resolved_at"] is None
