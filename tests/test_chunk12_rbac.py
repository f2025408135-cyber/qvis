import pytest
from fastapi.testclient import TestClient
from backend.main import app
from backend.api.auth import create_access_token

@pytest.fixture
def client():
    return TestClient(app)

def test_rbac_jwt_viewer(client):
    import os
    os.environ['QVIS_AUTH_ENABLED'] = 'true'
    from backend.config import settings
    settings.auth_enabled = True
    token = create_access_token(data={"sub": "testuser", "role": "viewer"})
    headers = {"Authorization": f"Bearer {token}"}
    
    # Viewer can read stats
    resp = client.get("/api/threats/stats", headers=headers)
    assert resp.status_code == 200
    
    # Viewer cannot run retention
    resp = client.post("/api/admin/retention/run", headers=headers)
    assert resp.status_code == 403

def test_rbac_jwt_admin(client):
    import os
    os.environ['QVIS_AUTH_ENABLED'] = 'true'
    from backend.config import settings
    settings.auth_enabled = True
    token = create_access_token(data={"sub": "adminuser", "role": "admin"})
    headers = {"Authorization": f"Bearer {token}"}
    
    # Admin can run retention
    resp = client.post("/api/admin/retention/run", headers=headers)
    assert resp.status_code == 200
    assert "deleted" in resp.json()
