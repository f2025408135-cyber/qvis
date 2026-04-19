
import os
import time
import pytest

os.environ["PYTEST_CURRENT_TEST"] = "true"

from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)

def test_health_returns_200_when_all_healthy():
    response = client.get("/health")
    assert response.status_code == 200

def test_health_returns_503_when_db_unreachable(monkeypatch):
    import backend.main
    async def mock_execute(*args, **kwargs):
        raise Exception("DB unreachable")
    
    class MockDb:
        async def execute(self, *args):
            raise Exception("DB unreachable")
            
    async def mock_get_conn():
        return MockDb()
        
    monkeypatch.setattr("backend.storage.database._get_connection", mock_get_conn)
    response = client.get("/health")
    assert response.status_code == 503
    assert response.json()["status"] == "unhealthy"

def test_health_returns_degraded_when_collection_stale(monkeypatch):
    import backend.main
    from datetime import datetime, timezone, timedelta
    from backend.config import settings
    
    past_time = datetime.now(timezone.utc) - timedelta(seconds=settings.update_interval_seconds * 3)
    monkeypatch.setitem(backend.main._health_state, "last_collection_at", past_time)
    monkeypatch.setitem(backend.main._health_state, "last_collection_error", None)
    
    response = client.get("/health")
    data = response.json()
    assert response.status_code == 503
    assert data["status"] == "unhealthy"
    assert data["components"]["collector"]["status"] == "unhealthy"

def test_health_components_include_all_four():
    data = client.get("/health").json()
    assert "database" in data["components"]
    assert "collector" in data["components"]
    assert "threat_engine" in data["components"]
    assert "websocket" in data["components"]

def test_readiness_probe_returns_200():
    assert client.get("/ready").status_code == 200

def test_liveness_probe_always_returns_200():
    assert client.get("/live").status_code == 200
