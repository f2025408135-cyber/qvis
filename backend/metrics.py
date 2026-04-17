"""
Prometheus metrics definitions for QVis.

All application metrics are defined here as module-level singletons.
Import from this module to record metrics anywhere in the backend.
"""
from prometheus_client import Counter, Histogram, Gauge, Summary
import time


# ─── Detection Metrics ────────────────────────────────────────────────────────

threats_detected_total = Counter(
    "qvis_threats_detected_total",
    "Total number of threat events detected",
    labelnames=["severity", "technique_id", "platform"],
)

threats_active = Gauge(
    "qvis_threats_active",
    "Number of currently active (unresolved) threats",
    labelnames=["severity"],
)

campaign_correlations_total = Counter(
    "qvis_campaign_correlations_total",
    "Total number of campaign correlation events fired",
    labelnames=["pattern_name"],
)

# ─── Rule Execution Metrics ───────────────────────────────────────────────────

rule_execution_duration_seconds = Histogram(
    "qvis_rule_execution_duration_seconds",
    "Time spent executing each detection rule",
    labelnames=["rule_name"],
    buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0],
)

# ─── Collection Metrics ───────────────────────────────────────────────────────

collector_poll_duration_seconds = Histogram(
    "qvis_collector_poll_duration_seconds",
    "Time spent collecting telemetry from quantum platforms",
    labelnames=["collector_type"],
    buckets=[0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0],
)

collector_backends_discovered = Gauge(
    "qvis_collector_backends_discovered",
    "Number of quantum backends discovered in last collection",
    labelnames=["collector_type"],
)

collector_errors_total = Counter(
    "qvis_collector_errors_total",
    "Total collection errors by collector type",
    labelnames=["collector_type", "error_type"],
)

# ─── Simulation Loop Metrics ──────────────────────────────────────────────────

simulation_loop_duration_seconds = Histogram(
    "qvis_simulation_loop_duration_seconds",
    "Full simulation loop cycle duration",
    buckets=[0.1, 0.5, 1.0, 2.5, 5.0, 10.0],
)

simulation_loop_cycles_total = Counter(
    "qvis_simulation_loop_cycles_total",
    "Total simulation loop cycles completed",
)

simulation_loop_errors_total = Counter(
    "qvis_simulation_loop_errors_total",
    "Total simulation loop errors",
)

# ─── WebSocket Metrics ────────────────────────────────────────────────────────

websocket_connections_active = Gauge(
    "qvis_websocket_connections_active",
    "Number of currently active WebSocket connections",
)

websocket_messages_sent_total = Counter(
    "qvis_websocket_messages_sent_total",
    "Total WebSocket broadcast messages sent",
)

websocket_errors_total = Counter(
    "qvis_websocket_errors_total",
    "Total WebSocket send errors",
)

# ─── Baseline Anomaly Metrics ─────────────────────────────────────────────────

baseline_anomalies_total = Counter(
    "qvis_baseline_anomalies_total",
    "Total baseline anomalies detected",
    labelnames=["backend_id", "metric_name"],
)

# ─── API Metrics ──────────────────────────────────────────────────────────────

api_auth_failures_total = Counter(
    "qvis_api_auth_failures_total",
    "Total API authentication failures",
)

rate_limit_exceeded_total = Counter(
    "qvis_rate_limit_exceeded_total",
    "Total rate limit exceeded events",
    labelnames=["endpoint"],
)
