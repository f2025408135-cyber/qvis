import pytest_asyncio
"""Tests for the data retention policy engine."""

import pytest
import asyncio
from datetime import datetime, timezone, timedelta
from backend.storage import create_database
from backend.threat_engine.models import ThreatEvent, Severity, Platform
from backend.config import Settings
from backend.tasks.retention import retention_loop

@pytest_asyncio.fixture
async def db():
    settings = Settings()
    settings.database_url = "sqlite:///:memory:"
    database = create_database(settings)
    await database.initialize()
    yield database
    await database.close()

@pytest.mark.asyncio
async def test_retention_deletes_old_resolved_threats(db):
    now = datetime.now(timezone.utc)
    for i in range(5):
        threat = ThreatEvent(
            id=f"old_resolved_{i}",
            technique_id="T0001",
            technique_name="Test Technique",
            severity=Severity.low,
            platform=Platform.ibm_quantum,
            backend_id="ibm_test",
            title="Test Title",
            description="Test Desc",
            evidence={},
            detected_at=now,
            visual_effect="none",
            visual_intensity=0.0,
            remediation=[],
        )
        await db.save_threat(threat)
        await db.resolve_threat(f"old_resolved_{i}")
        await db._connection.execute(f"UPDATE threats SET resolved_at = datetime('now', '-31 days') WHERE id = 'old_resolved_{i}'")
    await db._connection.commit()
    
    deleted = await db.delete_threats_older_than(30)
    assert deleted == 5
    
    remaining = await db.get_recent_threats()
    assert len(remaining) == 0

@pytest.mark.asyncio
async def test_retention_keeps_recent_resolved_threats(db):
    now = datetime.now(timezone.utc)
    for i in range(3):
        threat = ThreatEvent(
            id=f"recent_resolved_{i}",
            technique_id="T0001",
            technique_name="Test Technique",
            severity=Severity.low,
            platform=Platform.ibm_quantum,
            backend_id="ibm_test",
            title="Test Title",
            description="Test Desc",
            evidence={},
            detected_at=now,
            visual_effect="none",
            visual_intensity=0.0,
            remediation=[],
        )
        await db.save_threat(threat)
        await db.resolve_threat(f"recent_resolved_{i}")
        await db._connection.execute(f"UPDATE threats SET resolved_at = datetime('now', '-10 days') WHERE id = 'recent_resolved_{i}'")
    await db._connection.commit()
    
    deleted = await db.delete_threats_older_than(30)
    assert deleted == 0
    
    remaining = await db.get_recent_threats()
    assert len(remaining) == 3

@pytest.mark.asyncio
async def test_retention_keeps_unresolved_threats(db):
    now = datetime.now(timezone.utc)
    threat = ThreatEvent(
        id="old_unresolved",
        technique_id="T0001",
        technique_name="Test Technique",
        severity=Severity.low,
        platform=Platform.ibm_quantum,
        backend_id="ibm_test",
        title="Test Title",
        description="Test Desc",
        evidence={},
        detected_at=now,
        visual_effect="none",
        visual_intensity=0.0,
        remediation=[],
    )
    await db.save_threat(threat)
    await db._connection.execute("UPDATE threats SET detected_at = datetime('now', '-100 days') WHERE id = 'old_unresolved'")
    await db._connection.commit()
    
    deleted = await db.delete_threats_older_than(1)
    assert deleted == 0
    
    remaining = await db.get_recent_threats()
    assert len(remaining) == 1
    assert remaining[0]["id"] == "old_unresolved"

@pytest.mark.asyncio
async def test_retention_loop_survives_db_error(db, monkeypatch, capfd):
    async def mock_delete(days):
        raise Exception("DB error")
    
    monkeypatch.setattr(db, "delete_threats_older_than", mock_delete)
    
    task = asyncio.create_task(retention_loop(db, 30, 0.000001))
    await asyncio.sleep(0.05)
    task.cancel()
    
    out, err = capfd.readouterr()
    assert "retention_cleanup_failed" in out
    assert "DB error" in out

@pytest.mark.asyncio
async def test_run_retention_now_api(monkeypatch):
    import os
    os.environ["PYTEST_CURRENT_TEST"] = "true"
    from fastapi.testclient import TestClient
    from backend.main import app
    
    async def mock_delete(days):
        return 42

    with TestClient(app) as client:
        import backend.main
        monkeypatch.setattr(backend.main.db, "delete_threats_older_than", mock_delete)
        
        response = client.post("/api/admin/retention/run")
        assert response.status_code == 200
        assert response.json()["deleted"] == 42
