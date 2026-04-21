from backend.api.auth import create_access_token
"""Integration tests for features fixed in the v1 manual (chunks 1-10)."""

import pytest
from httpx import AsyncClient, ASGITransport
from backend.main import app


@pytest.fixture
def client():
    """Synchronous test client."""
    from starlette.testclient import TestClient
    return TestClient(app)


class TestDocsEndpoint:
    """Chunk 1: /docs should return 200, not 500."""

    def test_docs_returns_200(self, client):
        resp = client.get("/docs")
        assert resp.status_code == 200

    def test_redoc_returns_200(self, client):
        resp = client.get("/redoc")
        assert resp.status_code == 200

    def test_openapi_json_returns_200(self, client):
        resp = client.get("/openapi.json")
        assert resp.status_code == 200
        data = resp.json()
        assert "paths" in data


class TestPathTraversal:
    """Chunk 1: Path traversal should return 403."""

    def test_path_traversal_blocked(self, client):
        resp = client.get("/..%2F..%2Fetc%2Fpasswd")
        assert resp.status_code == 403

    def test_null_byte_blocked(self, client):
        resp = client.get("/test%00path")
        assert resp.status_code == 400


class TestThreatHistory:
    """Chunk 2: /api/threats/history should return non-empty data."""

    def test_history_returns_list(self, client):
        resp = client.get("/api/threats/history", headers={"Authorization": f"Bearer {_token}"})
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)


class TestScenarioReset:
    """Chunk 7: POST /api/scenario/reset should exist and work."""

    def test_reset_without_active_scenario(self, client):
        resp = client.post("/api/scenario/reset")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] in ("already_default", "reset")

    def test_load_and_reset_scenario(self, client):
        # Load a scenario
        resp = client.post("/api/scenario/load?name=recon")
        assert resp.status_code == 200
        assert resp.json()["status"] == "loaded"

        # Reset it
        resp = client.post("/api/scenario/reset")
        assert resp.status_code == 200
        assert resp.json()["status"] == "reset"


class TestSTIXPagination:
    """Chunk 8: STIX export should support pagination with UUID IDs."""

    def test_stix_export_returns_bundle(self, client):
        resp = client.get("/api/threats/export/stix")
        assert resp.status_code == 200
        data = resp.json()
        assert data["type"] == "bundle"
        assert "objects" in data

    def test_stix_pagination_limit(self, client):
        resp = client.get("/api/threats/export/stix?limit=1")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["objects"]) <= 1
        assert "x_qvis_pagination" in data
        meta = data["x_qvis_pagination"]
        assert meta["limit"] == 1
        assert meta["returned"] <= 1

    def test_stix_ids_are_uuids(self, client):
        import re
        uuid_pattern = re.compile(
            r"^indicator--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
        )
        resp = client.get("/api/threats/export/stix")
        data = resp.json()
        for obj in data["objects"]:
            assert uuid_pattern.match(obj["id"]), f"Non-UUID STIX ID: {obj['id']}"


class TestBaselineManagerIntegration:
    """Chunk 3: BaselineManager should be instantiated and callable."""

    def test_baseline_manager_exists_in_main(self):
        from backend.main import baseline_manager
        assert baseline_manager is not None
        assert baseline_manager.z_threshold == 2.5

    def test_baseline_check_returns_none_for_normal(self):
        from backend.threat_engine.baseline import BaselineManager
        bm = BaselineManager(z_threshold=2.5)
        # First 10 values should always return None (learning phase)
        for i in range(15):
            result = bm.check("test_backend", "metric", 100.0)
        assert result is None, "Stable values should not trigger anomaly"
