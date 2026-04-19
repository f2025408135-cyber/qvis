"""Tests for the database abstraction layer."""

import pytest
import os
import asyncio
from backend.storage import create_database
from backend.storage.sqlite_db import SQLiteDatabase
from backend.storage.postgres_db import PostgreSQLDatabase
from backend.config import Settings
from backend.threat_engine.models import ThreatEvent, Severity, Platform
from datetime import datetime, timezone

@pytest.mark.asyncio
async def test_sqlite_satisfies_interface():
    settings = Settings()
    settings.database_url = "sqlite:///./data/test.db"
    db = create_database(settings)
    assert isinstance(db, SQLiteDatabase)
    
    await db.initialize()
    assert await db.health_check() is True

    threat = ThreatEvent(
        id="test_threat",
        technique_id="T0001",
        technique_name="Test Technique",
        severity=Severity.low,
        platform=Platform.ibm_quantum,
        backend_id="ibm_test",
        title="Test Title",
        description="Test Desc",
        evidence={},
        detected_at=datetime.now(timezone.utc),
        visual_effect="none",
        visual_intensity=0.0,
        remediation=[],
    )
    
    await db.save_threat(threat)
    recent = await db.get_recent_threats()
    assert len(recent) == 1
    assert recent[0]["id"] == "test_threat"
    
    await db.resolve_threat("test_threat")
    
    # Backdate resolved_at to 10 days ago
    await db._connection.execute("UPDATE threats SET resolved_at = datetime('now', '-10 days') WHERE id = 'test_threat'")
    await db._connection.commit()
    
    deleted = await db.delete_threats_older_than(5)
    assert deleted == 1

    await db.close()

@pytest.mark.asyncio
async def test_postgres_satisfies_interface():
    settings = Settings()
    settings.database_url = "postgresql://user:pass@localhost/db"
    db = create_database(settings)
    assert isinstance(db, PostgreSQLDatabase)
    # Don't try to initialize or it will try to connect to localhost
