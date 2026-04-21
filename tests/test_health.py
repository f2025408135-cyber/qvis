
import pytest
import os

@pytest.fixture(autouse=True)
def bypass_auth_for_legacy_tests(monkeypatch):
    from backend.config import settings
    monkeypatch.setattr(settings, "auth_enabled", False)

import os
import pytest
os.environ["PYTEST_CURRENT_TEST"] = "true"

from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)

def test_health_returns_200_when_all_healthy(monkeypatch):
    import backend.main
    from datetime import datetime, timezone
    
    async def mock_health_check():
        return True
        
    monkeypatch.setattr(backend.main.db, "health_check", mock_health_check)
    
    backend.main._health_state["last_collection_at"] = datetime.now(timezone.utc)
    backend.main._health_state["last_collection_error"] = None
    backend.main._health_state["last_engine_cycle_at"] = datetime.now(timezone.utc)
    backend.main._health_state["last_broadcast_at"] = datetime.now(timezone.utc)
    
    response = client.get("/health")
    assert response.status_code == 200, response.json()

def test_health_returns_503_when_db_unreachable(monkeypatch):
    import backend.main
    
    async def mock_health_check():
        return False
        
    monkeypatch.setattr(backend.main.db, "health_check", mock_health_check)
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

def test_readiness_probe_returns_200(monkeypatch):
    import backend.main
    from datetime import datetime, timezone
    
    async def mock_health_check():
        return True
        
    monkeypatch.setattr(backend.main.db, "health_check", mock_health_check)
    
    backend.main._health_state["last_collection_at"] = datetime.now(timezone.utc)
    backend.main._health_state["last_collection_error"] = None
    backend.main._health_state["last_engine_cycle_at"] = datetime.now(timezone.utc)
    backend.main._health_state["last_broadcast_at"] = datetime.now(timezone.utc)
    
    assert client.get("/ready").status_code == 200

def test_liveness_probe_always_returns_200():
    assert client.get("/live").status_code == 200
