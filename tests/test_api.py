import pytest
import os
from fastapi.testclient import TestClient
from backend.main import app, collector

collector.is_test = True

client = TestClient(app)

def test_health_endpoint_returns_ok():
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert "connected_platforms" in response.json()

def test_snapshot_endpoint_returns_simulation_snapshot():
    with TestClient(app) as client:
        response = client.get("/api/snapshot")
        assert response.status_code == 200
        data = response.json()
        assert "snapshot_id" in data
        assert "backends" in data
        assert "threats" in data

def test_snapshot_has_correct_number_of_backends():
    with TestClient(app) as client:
        response = client.get("/api/snapshot")
        assert response.status_code == 200
        data = response.json()
        assert len(data["backends"]) == 4

def test_threats_endpoint_returns_list():
    with TestClient(app) as client:
        response = client.get("/api/threats")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) == 4

def test_threat_detail_returns_full_evidence():
    with TestClient(app) as client:
        response = client.get("/api/threat/threat-1")
        assert response.status_code == 200
        data = response.json()
        assert "evidence" in data
        assert "repo" in data["evidence"]

def test_severity_filter_on_threats_works():
    with TestClient(app) as client:
        response = client.get("/api/threats?severity=critical")
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
    # Testing that it explicitly allows the origin from env, not *
    allowed = response.headers.get("access-control-allow-origin")
    assert allowed != "*"
    assert allowed == "http://localhost:3000"

def test_websocket_connection():
    with client.websocket_connect("/ws/simulation") as websocket:
        data = websocket.receive_json()
        assert "snapshot_id" in data
        assert "backends" in data
        
        # Test client request for new snapshot
        websocket.send_json({"type": "get_snapshot"})
        data2 = websocket.receive_json()
        assert "snapshot_id" in data2
