import pytest
import os
import asyncio

os.environ["PYTEST_CURRENT_TEST"] = "true"

from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)

def test_health_endpoint_returns_ok(monkeypatch):
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
    assert response.status_code == 200
    assert response.json()["status"] in ["healthy", "degraded"]
    assert "components" in response.json()

def test_snapshot_endpoint_returns_simulation_snapshot():
    _token = create_access_token({"sub": "test", "role": "admin"}); response = client.get("/api/snapshot", headers={"Authorization": f"Bearer {_token}"})
    assert response.status_code == 200
    data = response.json()
    assert "snapshot_id" in data
    assert "backends" in data
    assert "threats" in data

def test_snapshot_has_correct_number_of_backends():
    _token = create_access_token({"sub": "test", "role": "admin"}); response = client.get("/api/snapshot", headers={"Authorization": f"Bearer {_token}"})
    assert response.status_code == 200
    data = response.json()
    assert len(data["backends"]) == 4

def test_threats_endpoint_returns_list():
    response = from backend.api.auth import create_access_token; client.get("/api/threats", headers={"Authorization": f"Bearer {create_access_token({'sub': 'test', 'role': 'admin'})}"})
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) == 4

def test_threat_detail_returns_full_evidence():
    response = from backend.api.auth import create_access_token; client.get("/api/threat/threat-1", headers={"Authorization": f"Bearer {create_access_token({\'sub\': \'test\', \'role\': \'admin\'})}"})
    assert response.status_code == 200
    data = response.json()
    assert "evidence" in data
    assert "repo" in data["evidence"]

def test_severity_filter_on_threats_works():
    response = from backend.api.auth import create_access_token; client.get("/api/threats?severity=critical", headers={"Authorization": f"Bearer {create_access_token({\'sub\': \'test\', \'role\': \'admin\'})}"})
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) == 1
    assert data[0]["severity"] == "critical"

def test_cors_headers():
    response = client.options("/api/health", headers={
        "Origin": "http://localhost:3000",
        "Access-Control-Request-Method": "GET",
    })
    allowed = response.headers.get("access-control-allow-origin")
    assert allowed != "*"
    assert allowed == "http://localhost:3000"


