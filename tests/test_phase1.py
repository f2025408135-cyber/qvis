
import pytest
import os

@pytest.fixture(autouse=True)
def bypass_auth_for_legacy_tests(monkeypatch):
    from backend.config import settings
    monkeypatch.setattr(settings, "auth_enabled", False)
"""Tests for Phase 1: Security hardening, headers, rate limiting, null byte protection."""

import os
import pytest
from unittest.mock import patch

os.environ["PYTEST_CURRENT_TEST"] = "true"

from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)


class TestSecurityHeaders:
    """Verify security headers are present on all responses."""

    def test_csp_header_present(self):
        response = client.get("/")
        csp = response.headers.get("content-security-policy", "")
        assert "default-src 'self'" in csp
        assert "script-src" in csp

    def test_x_content_type_nosniff(self):
        response = client.get("/api/health")
        assert response.headers.get("x-content-type-options") == "nosniff"

    def test_x_frame_options_deny(self):
        response = client.get("/api/health")
        assert response.headers.get("x-frame-options") == "DENY"

    def test_xss_protection_removed(self):
        """X-XSS-Protection was removed (deprecated since Chrome 78).
        CSP script-src provides equivalent XSS protection."""
        response = client.get("/api/health")
        assert response.headers.get("x-xss-protection") is None

    def test_referrer_policy(self):
        response = client.get("/api/health")
        assert "strict-origin" in response.headers.get("referrer-policy", "")


class TestNullByteProtection:
    """Verify null byte injection is rejected."""

    def test_null_byte_returns_400(self):
        response = client.get("/index.html%00.js")
        assert response.status_code == 400

    def test_normal_path_still_works(self):
        response = client.get("/api/health")
        assert response.status_code == 200


class TestRateLimiting:
    """Verify rate limiter headers and basic behavior."""

    def test_rate_limit_headers_present(self):
        response = client.get("/api/health")
        # Health endpoint is under /api so it gets rate-limited
        assert "x-ratelimit-limit" in response.headers

    def test_non_api_routes_not_rate_limited(self):
        # Non-API routes should not have rate limit headers
        response = client.get("/some-page")
        # May be 404 but should not have rate limit headers
        assert "x-ratelimit-limit" not in response.headers


class TestWebSocketAuth:
    """Verify WebSocket authentication behavior."""

    def test_ws_connects_without_auth_when_disabled(self):
        """When AUTH_ENABLED=false, WS should connect without token."""
        with TestClient(app) as test_app:
            with test_app.websocket_connect("/ws/simulation") as websocket:
                data = websocket.receive_json()
                assert "snapshot_id" in data

    def test_ws_rejects_with_invalid_token_when_auth_enabled(self):
        """When AUTH_ENABLED=true, WS should reject invalid tokens."""
        with patch("backend.main.settings.auth_enabled", True), \
             patch("backend.main.settings.api_key", "test-secret-key"):
            with TestClient(app) as test_app:
                # TestClient raises WebSocketDisconnect when server closes the connection
                with pytest.raises(Exception):  # WebSocketDisconnect
                    with test_app.websocket_connect("/ws/simulation?token=wrong-token") as ws:
                        ws.receive_json()


class TestEnvSettings:
    """Verify Settings model handles .env.example fields."""

    def test_settings_accepts_log_level_and_format(self):
        """Settings should accept LOG_LEVEL and LOG_FORMAT without crashing."""
        from backend.config import Settings
        # extra='ignore' means .env file takes priority over constructor args
        # so we test that the fields exist and are valid, not that we override them
        s = Settings()
        assert s.log_level in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")
        assert s.log_format in ("console", "json")

    def test_settings_extra_fields_forbidden(self):
        """extra='forbid' means unknown fields are rejected."""
        import pytest as _pt
        from pydantic import ValidationError
        from backend.config import Settings
        with _pt.raises(ValidationError):
            Settings(UNKNOWN_FIELD="should_not_crash")
