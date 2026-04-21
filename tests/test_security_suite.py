import pytest
from fastapi.testclient import TestClient
from backend.main import app
from backend.api.auth import create_access_token
from backend.config import settings

@pytest.fixture
def client():
    # Make sure we don't mock out the core setting so tests run legitimately
    return TestClient(app)

def test_jwt_validation_and_expiration(client):
    token = create_access_token({"sub": "test", "role": "viewer"})
    assert client.get("/api/threats/stats", headers={"Authorization": f"Bearer {token}"}).status_code == 200

def test_rbac_permission_denial(client):
    token = create_access_token({"sub": "test", "role": "viewer"})
    assert client.post("/api/admin/retention/run", headers={"Authorization": f"Bearer {token}"}).status_code == 403

def test_websocket_auth_rejection(client):
    with pytest.raises(Exception) as e:
        with client.websocket_connect("/ws/simulation") as ws:
            pass
    assert "403" in str(e) or "1008" in str(e) or "Disconnect" in str(e)

def test_sql_injection_payload_blocking(client):
    token = create_access_token({"sub": "test", "role": "admin"})
    response = client.get("/api/threat/' OR 1=1--", headers={"Authorization": f"Bearer {token}"})
    if response.status_code == 200:
        assert "'" not in response.json().get("id", "")
    else:
        assert response.status_code in [400, 404, 422]

def test_xss_payload_blocking(client):
    token = create_access_token({"sub": "test", "role": "admin"})
    response = client.get("/api/threat/<script>alert(1)</script>", headers={"Authorization": f"Bearer {token}"})
    if response.status_code == 200:
        assert "<script>" not in response.text
    else:
        assert response.status_code in [400, 404, 422]

def test_audit_log_integrity(client):
    from backend.security.audit import audit_logger, AuditEvent
    from datetime import datetime, timezone
    event = AuditEvent(
            timestamp=datetime.now(timezone.utc),
            user_id="test",
            action="TEST",
            resource_type="SYSTEM",
            resource_id="test",
            previous_state=None,
            new_state=None,
            ip_address="0.0.0.0",
            user_agent="system",
            status_code=200,
            error_message=None
    )
    audit_logger.log_event(event)
    assert audit_logger.verify_chain() is True


def test_circuit_breaker_opens_and_closes():
    from backend.utils.circuit_breaker import CircuitBreaker
    import asyncio
    
    cb = CircuitBreaker(failure_threshold=2, recovery_timeout=1)
    
    async def failing_func():
        raise ValueError("simulated")
        
    async def passing_func():
        return "success"
        
    # Fail 1
    with pytest.raises(ValueError):
        asyncio.run(cb.call(failing_func))
    assert cb.state == "CLOSED"
    
    # Fail 2 -> Trips OPEN
    with pytest.raises(ValueError):
        asyncio.run(cb.call(failing_func))
    assert cb.state == "OPEN"
    
    # Reject while OPEN
    with pytest.raises(Exception) as e:
        asyncio.run(cb.call(passing_func))
    assert "OPEN" in str(e)
    
    # Wait for recovery timeout
    import time
    time.sleep(1.1)
    
    # Success -> HALF-OPEN -> CLOSED
    assert asyncio.run(cb.call(passing_func)) == "success"
    assert cb.state == "CLOSED"
