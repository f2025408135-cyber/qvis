import re
with open("tests/test_health.py", "r") as f:
    content = f.read()

# Add a mock for `db.health_check()` returning `True` for the good path!
# The `_get_connection` isn't returning a valid connected sqlite instance since we didn't run `initialize()` (due to test scope).

setup_healthy = """
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
"""
content = re.sub(
    r'def test_health_returns_200_when_all_healthy\(\):.*?assert response\.status_code == 200, response\.json\(\)',
    setup_healthy.strip(),
    content,
    flags=re.DOTALL
)

setup_ready = """
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
"""

content = re.sub(
    r'def test_readiness_probe_returns_200\(\):.*?assert client\.get\("/ready"\)\.status_code == 200',
    setup_ready.strip(),
    content,
    flags=re.DOTALL
)

with open("tests/test_health.py", "w") as f:
    f.write(content)

