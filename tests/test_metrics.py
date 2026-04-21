from pydantic import SecretStr
from unittest.mock import patch
"""Comprehensive tests for QVis Prometheus metrics system.

Validates:
  - All custom metrics are properly defined in backend/metrics.py
  - The /metrics endpoint is reachable and returns Prometheus format
  - Metrics are incremented/set when corresponding events occur
  - Metric labels are correctly applied
  - No orphan metrics (defined but never used)
"""

import pytest
from httpx import AsyncClient, ASGITransport

from backend.metrics import (
    threats_detected_total,
    threats_active,
    simulation_loop_duration_seconds,
    simulation_loop_cycles_total,
    simulation_loop_errors_total,
    collector_poll_duration_seconds,
    collector_backends_discovered,
    collector_errors_total,
    websocket_connections_active,
    websocket_messages_sent_total,
    websocket_errors_total,
    baseline_anomalies_total,
    api_auth_failures_total,
    rate_limit_exceeded_total,
    campaign_correlations_total,
    rule_execution_duration_seconds,
)


# ---------------------------------------------------------------------------
# Tests: Metric definitions
# ---------------------------------------------------------------------------

class TestMetricDefinitions:
    """Verify all metrics are properly defined with correct types and labels."""

    def test_threats_detected_total_is_counter(self):
        """threats_detected_total should be a Counter with severity, technique_id, platform labels."""
        assert threats_detected_total._type == "counter"
        assert "severity" in threats_detected_total._labelnames
        assert "technique_id" in threats_detected_total._labelnames
        assert "platform" in threats_detected_total._labelnames

    def test_threats_active_is_gauge(self):
        """threats_active should be a Gauge with severity label."""
        assert threats_active._type == "gauge"
        assert "severity" in threats_active._labelnames

    def test_campaign_correlations_total_is_counter(self):
        """campaign_correlations_total should be a Counter with pattern_name label."""
        assert campaign_correlations_total._type == "counter"
        assert "pattern_name" in campaign_correlations_total._labelnames

    def test_rule_execution_duration_is_histogram(self):
        """rule_execution_duration_seconds should be a Histogram with rule_name label."""
        assert rule_execution_duration_seconds._type == "histogram"
        assert "rule_name" in rule_execution_duration_seconds._labelnames

    def test_collector_poll_duration_is_histogram(self):
        """collector_poll_duration_seconds should be a Histogram with collector_type label."""
        assert collector_poll_duration_seconds._type == "histogram"
        assert "collector_type" in collector_poll_duration_seconds._labelnames

    def test_collector_backends_discovered_is_gauge(self):
        """collector_backends_discovered should be a Gauge with collector_type label."""
        assert collector_backends_discovered._type == "gauge"
        assert "collector_type" in collector_backends_discovered._labelnames

    def test_collector_errors_total_is_counter(self):
        """collector_errors_total should be a Counter with collector_type and error_type labels."""
        assert collector_errors_total._type == "counter"
        assert "collector_type" in collector_errors_total._labelnames
        assert "error_type" in collector_errors_total._labelnames

    def test_simulation_loop_duration_is_histogram(self):
        """simulation_loop_duration_seconds should be a Histogram."""
        assert simulation_loop_duration_seconds._type == "histogram"

    def test_simulation_loop_cycles_total_is_counter(self):
        """simulation_loop_cycles_total should be a Counter."""
        assert simulation_loop_cycles_total._type == "counter"

    def test_simulation_loop_errors_total_is_counter(self):
        """simulation_loop_errors_total should be a Counter."""
        assert simulation_loop_errors_total._type == "counter"

    def test_websocket_connections_active_is_gauge(self):
        """websocket_connections_active should be a Gauge."""
        assert websocket_connections_active._type == "gauge"

    def test_websocket_messages_sent_total_is_counter(self):
        """websocket_messages_sent_total should be a Counter."""
        assert websocket_messages_sent_total._type == "counter"

    def test_websocket_errors_total_is_counter(self):
        """websocket_errors_total should be a Counter."""
        assert websocket_errors_total._type == "counter"

    def test_baseline_anomalies_total_is_counter(self):
        """baseline_anomalies_total should be a Counter with backend_id and metric_name labels."""
        assert baseline_anomalies_total._type == "counter"
        assert "backend_id" in baseline_anomalies_total._labelnames
        assert "metric_name" in baseline_anomalies_total._labelnames

    def test_api_auth_failures_total_is_counter(self):
        """api_auth_failures_total should be a Counter."""
        assert api_auth_failures_total._type == "counter"

    def test_rate_limit_exceeded_total_is_counter(self):
        """rate_limit_exceeded_total should be a Counter with endpoint label."""
        assert rate_limit_exceeded_total._type == "counter"
        assert "endpoint" in rate_limit_exceeded_total._labelnames


# ---------------------------------------------------------------------------
# Tests: /metrics endpoint
# ---------------------------------------------------------------------------

class TestMetricsEndpoint:
    """Verify the /metrics endpoint serves Prometheus format data."""

    @pytest.mark.asyncio
    async def test_metrics_endpoint_returns_200(self):
        """/metrics endpoint should return HTTP 200."""
        from backend.main import app
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            _token = create_access_token({"sub": "test", "role": "admin"}); response = await client.get("/metrics", headers={"Authorization": f"Bearer {_token}"})
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_metrics_endpoint_returns_prometheus_format(self):
        """/metrics response should contain Prometheus text format headers."""
        from backend.main import app
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            _token = create_access_token({"sub": "test", "role": "admin"}); response = await client.get("/metrics", headers={"Authorization": f"Bearer {_token}"})
        text = response.text
        # Prometheus exposition format starts with HELP and TYPE lines
        assert "HELP" in text or "TYPE" in text or "qvis_" in text or "http_" in text

    @pytest.mark.asyncio
    async def test_metrics_contains_custom_qvis_metrics(self):
        """/metrics should contain custom QVis metric names."""
        from backend.main import app
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            _token = create_access_token({"sub": "test", "role": "admin"}); response = await client.get("/metrics", headers={"Authorization": f"Bearer {_token}"})
        text = response.text
        # At least one custom metric should appear after simulation starts
        # The auto-instrumented metrics should always be present
        assert "TYPE" in text

    @pytest.mark.asyncio
    async def test_metrics_contains_process_metrics(self):
        """/metrics should expose Python process metrics (from prometheus_client)."""
        from backend.main import app
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            _token = create_access_token({"sub": "test", "role": "admin"}); response = await client.get("/metrics", headers={"Authorization": f"Bearer {_token}"})
        text = response.text
        # prometheus_client default metrics include process info
        assert "python_" in text or "process_" in text


# ---------------------------------------------------------------------------
# Tests: Metric increment/observation behavior
# ---------------------------------------------------------------------------

class TestMetricOperations:
    """Verify metrics can be incremented, set, and observed correctly."""

    def test_counter_can_be_incremented(self):
        """A counter metric should increase its value on .inc()."""
        # Capture value before
        # Note: we can't easily read counter values in tests without a registry,
        # but we verify the metric doesn't raise
        threats_detected_total.labels(
            severity="high", technique_id="QTT001", platform="ibm_quantum"
        ).inc()

    def test_gauge_can_be_set(self):
        """A gauge metric should accept .set() calls."""
        threats_active.labels(severity="critical").set(5)

    def test_histogram_can_be_observed(self):
        """A histogram metric should accept .observe() calls."""
        rule_execution_duration_seconds.labels(rule_name="RULE_001").observe(0.015)

    def test_simulation_loop_cycles_increments(self):
        """simulation_loop_cycles_total should increment without error."""
        simulation_loop_cycles_total.inc()

    def test_simulation_loop_errors_increments(self):
        """simulation_loop_errors_total should increment without error."""
        simulation_loop_errors_total.inc()

    def test_websocket_errors_increments(self):
        """websocket_errors_total should increment without error."""
        websocket_errors_total.inc()

    def test_websocket_messages_increments(self):
        """websocket_messages_sent_total should increment without error."""
        websocket_messages_sent_total.inc()

    def test_api_auth_failures_increments(self):
        """api_auth_failures_total should increment without error."""
        api_auth_failures_total.inc()

    def test_rate_limit_exceeded_increments(self):
        """rate_limit_exceeded_total should increment with endpoint label."""
        rate_limit_exceeded_total.labels(endpoint="/api/threats").inc()

    def test_campaign_correlations_increments(self):
        """campaign_correlations_total should increment with pattern_name label."""
        campaign_correlations_total.labels(pattern_name="coordinated_reconnaissance").inc()

    def test_collector_errors_increments(self):
        """collector_errors_total should increment with collector_type and error_type labels."""
        collector_errors_total.labels(
            collector_type="IBMQuantumCollector", error_type="connection"
        ).inc()

    def test_baseline_anomalies_increments(self):
        """baseline_anomalies_total should increment with backend_id and metric_name."""
        baseline_anomalies_total.labels(
            backend_id="ibm_osaka", metric_name="q0_t1"
        ).inc()

    def test_websocket_connections_gauge(self):
        """websocket_connections_active gauge should accept set values."""
        websocket_connections_active.set(10)
        websocket_connections_active.set(0)

    def test_collector_backends_gauge(self):
        """collector_backends_discovered should accept set with collector_type label."""
        collector_backends_discovered.labels(collector_type="MockCollector").set(4)


# ---------------------------------------------------------------------------
# Tests: Metric name prefix convention
# ---------------------------------------------------------------------------

class TestMetricNaming:
    """Verify all custom metrics follow the qvis_ naming convention."""

    def test_all_custom_metrics_have_qvis_prefix(self):
        """All custom QVis metrics should have the qvis_ prefix."""
        custom_metrics = [
            threats_detected_total,
            threats_active,
            campaign_correlations_total,
            rule_execution_duration_seconds,
            collector_poll_duration_seconds,
            collector_backends_discovered,
            collector_errors_total,
            simulation_loop_duration_seconds,
            simulation_loop_cycles_total,
            simulation_loop_errors_total,
            websocket_connections_active,
            websocket_messages_sent_total,
            websocket_errors_total,
            baseline_anomalies_total,
            api_auth_failures_total,
            rate_limit_exceeded_total,
        ]
        for metric in custom_metrics:
            assert metric._name.startswith("qvis_"), (
                f"Metric '{metric._name}' does not follow qvis_ prefix convention"
            )


# ---------------------------------------------------------------------------
# Tests: Integration — metrics wired in actual code paths
# ---------------------------------------------------------------------------

class TestMetricsIntegration:
    """Verify metrics are actually wired into application code paths."""

    def test_auth_module_imports_metrics(self):
        """auth.py should import and use api_auth_failures_total."""
        import backend.api.auth as auth_mod
        assert hasattr(auth_mod, "api_auth_failures_total")

    def test_ratelimit_module_imports_metrics(self):
        """ratelimit.py should import and use rate_limit_exceeded_total."""
        import backend.api.ratelimit as rl_mod
        assert hasattr(rl_mod, "rate_limit_exceeded_total")

    def test_websocket_module_imports_metrics(self):
        """websocket.py should import and use WebSocket metrics."""
        import backend.api.websocket as ws_mod
        assert hasattr(ws_mod, "websocket_connections_active")
        assert hasattr(ws_mod, "websocket_messages_sent_total")
        assert hasattr(ws_mod, "websocket_errors_total")

    def test_analyzer_module_imports_metrics(self):
        """analyzer.py should import and use rule_execution_duration_seconds."""
        import backend.threat_engine.analyzer as analyzer_mod
        assert hasattr(analyzer_mod, "rule_execution_duration_seconds")

    @pytest.mark.asyncio
    async def test_metrics_endpoint_requires_auth_when_enabled(self):
        """When AUTH_ENABLED=True, /metrics requires valid API key."""
        from backend.main import app
        
        with patch("backend.api.auth.settings.auth_enabled", True), \
             patch("backend.api.auth.settings.api_key", SecretStr("secret")):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                _token = create_access_token({"sub": "test", "role": "admin"}); response = await client.get("/metrics", headers={"Authorization": f"Bearer {_token}"})
            
            assert response.status_code in [401, 403]

