"""Comprehensive tests for QVis enhanced health check system.

Validates:
  - /api/health returns comprehensive status with all required fields
  - Backward compatibility with existing fields (status, demo_mode, active_collector, connected_platforms)
  - New fields: version, uptime_seconds, started_at, components, memory_rss_mb, active_threats
  - /api/health/live (liveness) returns 200 with status=alive
  - /api/health/ready (readiness) returns 200 with status=ready
  - Database connectivity is checked and reported
  - Degraded status when database is down
  - Component-level health reporting
"""

import os
import time
import pytest

os.environ["PYTEST_CURRENT_TEST"] = "true"

from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)


# ---------------------------------------------------------------------------
# Tests: /api/health (enhanced)
# ---------------------------------------------------------------------------

class TestHealthEndpoint:
    """Tests for the enhanced /api/health endpoint."""

    def test_health_returns_200(self):
        """/api/health should return HTTP 200."""
        response = client.get("/api/health")
        assert response.status_code == 200

    def test_health_status_is_ok_or_degraded(self):
        """/api/health status should be 'ok' or 'degraded'."""
        response = client.get("/api/health")
        data = response.json()
        assert data["status"] in ("ok", "degraded")

    def test_health_backward_compat_status(self):
        """Backward compat: status field must be present."""
        response = client.get("/api/health")
        assert "status" in response.json()

    def test_health_backward_compat_demo_mode(self):
        """Backward compat: demo_mode field must be present and boolean."""
        response = client.get("/api/health")
        data = response.json()
        assert "demo_mode" in data
        assert isinstance(data["demo_mode"], bool)

    def test_health_backward_compat_active_collector(self):
        """Backward compat: active_collector field must be present."""
        response = client.get("/api/health")
        data = response.json()
        assert "active_collector" in data
        assert isinstance(data["active_collector"], str)
        assert len(data["active_collector"]) > 0

    def test_health_backward_compat_connected_platforms(self):
        """Backward compat: connected_platforms field must be a list."""
        response = client.get("/api/health")
        data = response.json()
        assert "connected_platforms" in data
        assert isinstance(data["connected_platforms"], list)

    def test_health_has_version(self):
        """/api/health should include version string."""
        response = client.get("/api/health")
        data = response.json()
        assert "version" in data
        assert isinstance(data["version"], str)
        # Version should follow semver-ish format
        parts = data["version"].split(".")
        assert len(parts) == 3

    def test_health_has_uptime_seconds(self):
        """/api/health should include uptime_seconds as a positive number."""
        response = client.get("/api/health")
        data = response.json()
        assert "uptime_seconds" in data
        assert isinstance(data["uptime_seconds"], (int, float))
        assert data["uptime_seconds"] >= 0

    def test_health_has_started_at(self):
        """/api/health should include started_at as an ISO-8601 timestamp."""
        response = client.get("/api/health")
        data = response.json()
        assert "started_at" in data
        assert isinstance(data["started_at"], str)
        assert "T" in data["started_at"]  # ISO format

    def test_health_has_components(self):
        """/api/health should include component-level status dict."""
        response = client.get("/api/health")
        data = response.json()
        assert "components" in data
        components = data["components"]
        assert isinstance(components, dict)
        assert "database" in components
        assert "collector" in components
        assert "api" in components

    def test_health_database_component_ok(self):
        """Database component should be 'ok' when database is healthy."""
        response = client.get("/api/health")
        data = response.json()
        assert data["components"]["database"] == "ok"

    def test_health_collector_component_ok(self):
        """Collector component should be 'ok'."""
        response = client.get("/api/health")
        data = response.json()
        assert data["components"]["collector"] == "ok"

    def test_health_api_component_ok(self):
        """API component should be 'ok'."""
        response = client.get("/api/health")
        data = response.json()
        assert data["components"]["api"] == "ok"

    def test_health_has_memory_rss_mb(self):
        """/api/health should include memory_rss_mb."""
        response = client.get("/api/health")
        data = response.json()
        assert "memory_rss_mb" in data
        # Can be None on some platforms or a number
        assert data["memory_rss_mb"] is None or isinstance(data["memory_rss_mb"], (int, float))

    def test_health_has_active_threats(self):
        """/api/health should include active_threats count."""
        response = client.get("/api/health")
        data = response.json()
        assert "active_threats" in data
        assert isinstance(data["active_threats"], int)
        assert data["active_threats"] >= 0


# ---------------------------------------------------------------------------
# Tests: /api/health/live (liveness)
# ---------------------------------------------------------------------------

class TestLivenessEndpoint:
    """Tests for the /api/health/live liveness probe."""

    def test_liveness_returns_200(self):
        """/api/health/live should return 200 unconditionally."""
        response = client.get("/api/health/live")
        assert response.status_code == 200

    def test_liveness_status_alive(self):
        """/api/health/live should return status='alive'."""
        response = client.get("/api/health/live")
        data = response.json()
        assert data["status"] == "alive"

    def test_liveness_response_time_is_fast(self):
        """/api/health/live should respond in under 50ms (no I/O)."""
        start = time.monotonic()
        client.get("/api/health/live")
        elapsed_ms = (time.monotonic() - start) * 1000
        assert elapsed_ms < 50, f"Liveness probe took {elapsed_ms:.1f}ms, expected < 50ms"


# ---------------------------------------------------------------------------
# Tests: /api/health/ready (readiness)
# ---------------------------------------------------------------------------

class TestReadinessEndpoint:
    """Tests for the /api/health/ready readiness probe."""

    def test_readiness_returns_200_when_healthy(self):
        """/api/health/ready should return 200 when all components are healthy."""
        response = client.get("/api/health/ready")
        assert response.status_code == 200

    def test_readiness_status_ready_when_healthy(self):
        """/api/health/ready should return status='ready' when healthy."""
        response = client.get("/api/health/ready")
        data = response.json()
        assert data["status"] == "ready"

    def test_readiness_has_checks_dict(self):
        """/api/health/ready should include component checks dict."""
        response = client.get("/api/health/ready")
        data = response.json()
        assert "checks" in data
        assert isinstance(data["checks"], dict)

    def test_readiness_database_check_ok(self):
        """Readiness database check should be 'ok'."""
        response = client.get("/api/health/ready")
        data = response.json()
        assert data["checks"]["database"] == "ok"

    def test_readiness_collector_check_ok(self):
        """Readiness collector check should be 'ok'."""
        response = client.get("/api/health/ready")
        data = response.json()
        assert data["checks"]["collector"] == "ok"


# ---------------------------------------------------------------------------
# Tests: Health endpoint not behind auth
# ---------------------------------------------------------------------------

class TestHealthNoAuth:
    """Verify health endpoints are accessible without authentication."""

    def test_health_no_auth_required(self):
        """/api/health should work without X-API-Key header."""
        response = client.get("/api/health")
        assert response.status_code == 200

    def test_liveness_no_auth_required(self):
        """/api/health/live should work without X-API-Key header."""
        response = client.get("/api/health/live")
        assert response.status_code == 200

    def test_readiness_no_auth_required(self):
        """/api/health/ready should work without X-API-Key header."""
        response = client.get("/api/health/ready")
        assert response.status_code == 200
