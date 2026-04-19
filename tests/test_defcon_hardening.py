"""Comprehensive tests for all DEFCON 10/10 hardening fixes (Chunks 1-9)."""

import pytest
import os
from unittest.mock import patch

os.environ["PYTEST_CURRENT_TEST"] = "true"

from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)


# ─── Chunk 1: Credential Hardening (SecretStr) ─────────────────────────

class TestSecretStr:
    def test_all_credentials_are_secretstr(self):
        from pydantic import SecretStr
        from backend.config import Settings
        s = Settings()
        for field in ['ibm_quantum_token', 'aws_access_key_id', 'aws_secret_access_key',
                      'azure_quantum_subscription_id', 'api_key', 'github_token',
                      'slack_webhook_url', 'discord_webhook_url', 'webhook_url']:
            assert isinstance(getattr(s, field), SecretStr), f"{field} not SecretStr"

    def test_repr_never_exposes_secrets(self):
        from backend.config import Settings
        s = Settings(ibm_quantum_token="super-secret-key")
        r = repr(s)
        assert "super-secret-key" not in r
        # assert "token" not in r.lower() and "secret" not in r.lower()

    def test_get_secret_value_works(self):
        from backend.config import Settings
        s = Settings(ibm_quantum_token="test123")
        assert s.ibm_quantum_token.get_secret_value() == "test123"

    def test_model_dump_preserves_secretstr(self):
        from pydantic import SecretStr
        from backend.config import Settings
        s = Settings(api_key="my-key")
        d = s.model_dump()
        assert isinstance(d["api_key"], SecretStr)


# ─── Chunk 2: Race Condition (asyncio.Lock) ───────────────────────────

class TestSnapshotLock:
    def test_snapshot_lock_exists(self):
        import backend.main as m
        assert hasattr(m, '_snapshot_lock')

    def test_ensure_snapshot_returns_data(self):
        response = client.get("/api/snapshot")
        assert response.status_code == 200
        data = response.json()
        assert "snapshot_id" in data
        assert "backends" in data


# ─── Chunk 3: XSS Prevention ─────────────────────────────────────────

class TestCSP:
    def test_csp_present(self):
        response = client.get("/api/health")
        csp = response.headers.get("content-security-policy", "")
        assert len(csp) > 50

    def test_no_unsafe_eval_in_csp(self):
        response = client.get("/api/health")
        csp = response.headers.get("content-security-policy", "")
        assert "unsafe-eval" not in csp

    def test_frame_ancestors_none(self):
        response = client.get("/api/health")
        csp = response.headers.get("content-security-policy", "")
        assert "frame-ancestors 'none'" in csp

    def test_form_action_self(self):
        response = client.get("/api/health")
        csp = response.headers.get("content-security-policy", "")
        assert "form-action 'self'" in csp


# ─── Chunk 4: API Input Validation ───────────────────────────────────

class TestInputValidation:
    def test_stix_limit_max_1000(self):
        response = client.get("/api/threats/export/stix?limit=9999")
        assert response.status_code == 422

    def test_stix_offset_negative_rejected(self):
        response = client.get("/api/threats/export/stix?offset=-1")
        assert response.status_code == 422

    def test_threat_id_format_validation(self):
        # Special chars like < and null bytes should be rejected (400)
        import urllib.parse
        response = client.get("/api/threat/" + urllib.parse.quote("test<script>"))
        assert response.status_code == 400

    def test_scenario_name_injection_blocked(self):
        response = client.post("/api/scenario/load?name=../../etc/passwd")
        assert response.status_code in (400, 404, 422)


# ─── Chunk 5: CORS Hardening ─────────────────────────────────────────

class TestCORSHardening:
    def test_cors_specific_origin(self):
        response = client.options("/api/health", headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "GET",
        })
        allowed = response.headers.get("access-control-allow-origin")
        assert allowed == "http://localhost:3000"


# ─── Chunk 6: WebSocket Hardening ───────────────────────────────────

class TestWebSocketHardening:
    def test_websocket_max_connections(self):
        from backend.api.websocket import MAX_CONNECTIONS, MAX_MESSAGE_SIZE
        assert MAX_CONNECTIONS == 200
        assert MAX_MESSAGE_SIZE == 256 * 1024

    def test_websocket_connects_normally(self):
        with TestClient(app) as test_app:
            with test_app.websocket_connect("/ws/simulation") as ws:
                data = ws.receive_json()
                assert "snapshot_id" in data

    def test_websocket_ping_handled(self):
        with TestClient(app) as test_app:
            with test_app.websocket_connect("/ws/simulation") as ws:
                ws.send_json({"type": "ping"})
                # Should not error — server processes ping silently


# ─── Chunk 7: Rate Limiter ───────────────────────────────────────────

class TestRateLimiter:
    def test_rate_limit_headers_present(self):
        response = client.get("/api/health")
        assert "x-ratelimit-limit" in response.headers

    def test_safe_client_id_validation(self):
        from backend.api.ratelimit import _is_safe_client_id
        assert _is_safe_client_id("192.168.1.1") is True
        assert _is_safe_client_id("testclient") is True
        assert _is_safe_client_id("::1") is True
        assert _is_safe_client_id("unknown") is True
        assert _is_safe_client_id("foo/bar") is False
        assert _is_safe_client_id("") is False
        assert _is_safe_client_id("a" * 300) is False

    def test_max_tracked_ips(self):
        from backend.api.ratelimit import _MAX_TRACKED_IPS
        assert _MAX_TRACKED_IPS == 10000


# ─── Chunk 8: Memory + Baseline ──────────────────────────────────────

class TestMemoryAndBaseline:
    def test_stix_lru_cache_cap(self):
        from backend.api.export import _STIX_CACHE_MAX, _stix_id_cache
        from collections import OrderedDict
        assert _STIX_CACHE_MAX == 5000
        assert isinstance(_stix_id_cache, OrderedDict)

    def test_stix_deterministic_uuids(self):
        from backend.api.export import _get_stix_uuid
        id1 = _get_stix_uuid("threat-abc")
        id2 = _get_stix_uuid("threat-abc")
        assert id1 == id2

    def test_baseline_warmup_reduced(self):
        from backend.threat_engine.baseline import BaselineManager
        import inspect
        src = inspect.getsource(BaselineManager.check)
        assert "count > 3" in src

    def test_correlator_configurable(self):
        from backend.threat_engine.correlator import ThreatCorrelator
        tc = ThreatCorrelator(history_hours=4.0)
        assert tc.history_hours == 4.0


# ─── Chunk 9: Operational ─────────────────────────────────────────────

class TestOperational:
    def test_request_id_header(self):
        response = client.get("/api/health")
        assert "x-request-id" in response.headers
        assert len(response.headers["x-request-id"]) == 8

    def test_request_id_forwarded(self):
        response = client.get("/api/health", headers={"X-Request-ID": "custom123"})
        assert response.headers["x-request-id"] == "custom123"

    def test_cache_control_on_api(self):
        response = client.get("/api/health")
        cc = response.headers.get("cache-control", "")
        assert "no-store" in cc

    def test_hsts_header(self):
        response = client.get("/api/health")
        hsts = response.headers.get("strict-transport-security", "")
        assert "max-age=31536000" in hsts
        assert "includeSubDomains" in hsts
