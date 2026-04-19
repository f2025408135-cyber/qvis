"""Main FastAPI application entry point serving QVis API and WebSockets."""

import asyncio
import os
import time
import json
import uuid
import resource
from datetime import datetime, timezone
from contextlib import asynccontextmanager
from typing import List, Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Depends, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request as StarletteRequest

from prometheus_fastapi_instrumentator import Instrumentator
from prometheus_client import make_asgi_app
from backend.metrics import (
    threats_detected_total,
    threats_active,
    simulation_loop_duration_seconds,
    simulation_loop_cycles_total,
    simulation_loop_errors_total,
    collector_backends_discovered,
    collector_errors_total,
    baseline_anomalies_total,
    campaign_correlations_total,
)

from backend.config import settings
from backend.logging_config import configure_logging

# Configure logging immediately after settings are loaded
configure_logging(settings.log_level, settings.log_format)

import structlog
logger = structlog.get_logger(__name__)

from backend.api.websocket import manager
from backend.api.auth import verify_api_key, _hash_key, _get_hashed_key
from backend.api.security_headers import SecurityHeadersMiddleware
from backend.api.ratelimit import RateLimitMiddleware
from backend.threat_engine.analyzer import ThreatAnalyzer
from backend.threat_engine.correlator import ThreatCorrelator
from backend.threat_engine.baseline import BaselineManager
from backend.threat_engine.models import SimulationSnapshot, BackendNode, ThreatEvent, Severity
from backend.threat_engine.rules import load_threshold_config_from_file, set_threshold_config, get_threshold_config
from backend.storage.database import init_db, close_db


from enum import Enum
from pydantic import BaseModel

class HealthStatus(str, Enum):
    healthy = "healthy"
    degraded = "degraded"
    unhealthy = "unhealthy"

class ComponentHealth(BaseModel):
    """Health status of one system component."""
    status: HealthStatus
    message: str
    last_success_at: Optional[datetime] = None
    latency_ms: Optional[float] = None

class HealthResponse(BaseModel):
    """Full system health response."""
    status: HealthStatus
    version: str
    uptime_seconds: float
    components: dict[str, ComponentHealth]
    checked_at: datetime
    # Backward compatibility
    demo_mode: bool
    active_collector: str
    connected_platforms: list[str]

_health_state = {
    "last_collection_at": None,       # datetime | None
    "last_collection_error": None,    # str | None
    "last_broadcast_at": None,        # datetime | None
    "last_engine_cycle_at": None,     # datetime | None
    "startup_time": time.time(),
}

# ─── Application State ─────────────────────────────────────────────────
latest_snapshot: Optional[SimulationSnapshot] = None
_snapshot_lock = asyncio.Lock()
analyzer = ThreatAnalyzer()
correlator = ThreatCorrelator()
baseline_manager = BaselineManager(z_threshold=2.5)
github_scanner = None

# ─── Application version and startup tracking ──────────────────────────
_APP_VERSION = "1.0.0"
_APP_START_TIME = time.monotonic()
_APP_START_TIME_ISO = datetime.now(timezone.utc).isoformat()

# ─── Load calibrated thresholds if calibration_results.json exists ──────
_cal = load_threshold_config_from_file()
if _cal is not None:
    set_threshold_config(_cal)
    logger.info("calibration_loaded", thresholds={k: v for k, v in _cal.__dict__.items() if v is not None})
else:
    logger.info("no_calibration_file_using_defaults")

# ─── Collector Strategy ────────────────────────────────────────────────
if os.environ.get("PYTEST_CURRENT_TEST") or os.environ.get("USE_MOCK") == "true":
    from backend.collectors.mock import MockCollector
    collector = MockCollector()
    collector.is_test = True
    logger.info("using_mock_collector", mode="test")
elif settings.demo_mode:
    # Demo mode: use mock IBM + mock Braket + mock Azure for multi-platform showcase
    from backend.collectors.mock import MockCollector
    from backend.collectors.braket import BraketCollector
    from backend.collectors.azure_quantum import AzureQuantumCollector
    from backend.collectors.aggregator import AggregatorCollector

    mock_ibm = MockCollector()
    mock_braket = BraketCollector()          # Falls back to mock internally
    mock_azure = AzureQuantumCollector()     # Falls back to mock internally
    collector = AggregatorCollector([mock_ibm, mock_braket, mock_azure])
    logger.info("using_aggregated_demo_collector", platforms=["ibm", "braket", "azure"])
elif settings.ibm_quantum_token.get_secret_value():
    # Production: start with IBM, add Braket/Azure if credentials present
    from backend.collectors.ibm import IBMQuantumCollector
    sub_collectors = [IBMQuantumCollector(ibm_token=settings.ibm_quantum_token.get_secret_value())]

    if settings.aws_access_key_id.get_secret_value():
        from backend.collectors.braket import BraketCollector
        sub_collectors.append(BraketCollector(region=settings.aws_default_region))
        logger.info("braket_collector_added")

    if settings.azure_quantum_subscription_id.get_secret_value():
        from backend.collectors.azure_quantum import AzureQuantumCollector
        sub_collectors.append(AzureQuantumCollector(
            subscription_id=settings.azure_quantum_subscription_id.get_secret_value()
        ))
        logger.info("azure_collector_added")

    if len(sub_collectors) > 1:
        from backend.collectors.aggregator import AggregatorCollector
        collector = AggregatorCollector(sub_collectors)
        logger.info("using_aggregated_collector", platforms=len(sub_collectors))
    else:
        collector = sub_collectors[0]
        logger.info("using_ibm_collector", backends="live")

    if settings.github_token.get_secret_value():
        from backend.collectors.github_scanner import GitHubTokenScanner
        github_scanner = GitHubTokenScanner(token=settings.github_token.get_secret_value())
        logger.info("using_github_scanner")
else:
    from backend.collectors.mock import MockCollector
    logger.warning("no_token_configured_using_mock")
    collector = MockCollector()

# ─── Background Simulation Loop ────────────────────────────────────────
async def simulation_loop():
    """Background task continually refreshing telemetry and broadcasting state."""
    global latest_snapshot
    github_last_run = 0
    github_results = []
    cycle_count = 0
    retention_last_run = 0

    while True:
        try:
            cycle_count += 1
            start = time.monotonic()
            logger.info("simulation_loop_start", cycle=cycle_count)
            simulation_loop_cycles_total.inc()

            with simulation_loop_duration_seconds.time():
                snapshot = await collector.collect()
                elapsed = time.monotonic() - start

                # Record collection metrics
                collector_backends_discovered.labels(
                    collector_type=collector.__class__.__name__
                ).set(len(snapshot.backends))

                _health_state["last_collection_at"] = datetime.now(timezone.utc)
                _health_state["last_collection_error"] = None
                logger.info("collection_complete",
                    collector=collector.__class__.__name__,
                    backends_count=len(snapshot.backends),
                    duration_ms=round(elapsed * 1000))

            # Integrate GitHub scanning selectively (every 5 minutes to respect rate limits)
            if github_scanner and (time.time() - github_last_run > 300):
                try:
                    logger.info("running_github_scan")
                    github_results = await github_scanner.scan_for_ibm_tokens()
                    github_last_run = time.time()
                except Exception as e:
                    logger.error("github_scan_loop_error", error=str(e))

            # Always analyze the SimulationSnapshot (not a raw dict) so
            # analyze() returns a SimulationSnapshot — not a bare list.
            enriched_snapshot = analyzer.analyze(snapshot)

            # Record threats_detected_total for each new threat
            for threat in snapshot.threats:
                threats_detected_total.labels(
                    severity=threat.severity.value if hasattr(threat.severity, "value") else str(threat.severity),
                    technique_id=threat.technique_id,
                    platform=threat.platform.value if hasattr(threat.platform, "value") else str(threat.platform),
                ).inc()

            # If GitHub results are present, inject them and re-run only
            # RULE_001 against the raw dict, then merge any new threats.
            if github_results:
                raw_dict = snapshot.model_dump()
                raw_dict["github_search_results"] = github_results
                from backend.threat_engine.rules import RULE_001_credential_leak_github_search
                gh_events = RULE_001_credential_leak_github_search(raw_dict)
                if gh_events:
                    for ev in gh_events:
                        key = (ev.backend_id, ev.technique_id)
                        if key not in analyzer.active_threats:
                            analyzer.active_threats[key] = ev
                            enriched_snapshot.threats.append(ev)
                    enriched_snapshot.threats.sort(
                        key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(
                            x.severity.value if hasattr(x.severity, "value") else str(x.severity), 99
                        )
                    )
                    enriched_snapshot.total_threats = len(enriched_snapshot.threats)
                    logger.info("github_threats_detected", count=len(gh_events))

            latest_snapshot = enriched_snapshot

            # Run adaptive baseline checks on each backend's calibration metrics
            baseline_threats = []
            for backend in enriched_snapshot.backends:
                if not backend.calibration:
                    continue
                for cal in backend.calibration:
                    # Check T1 coherence time
                    z_t1 = baseline_manager.check(backend.id, f"q{cal.qubit_id}_t1", cal.t1_us)
                    if z_t1 is not None:
                        baseline_threats.append(ThreatEvent(
                            id=f"baseline-{backend.id}-q{cal.qubit_id}-t1",
                            technique_id="QTT014",
                            technique_name="Adaptive Baseline Anomaly",
                            severity=Severity.high if abs(z_t1) > 4.0 else Severity.medium,
                            platform=backend.platform,
                            backend_id=backend.id,
                            title=f"T1 anomaly on {backend.id} qubit {cal.qubit_id}",
                            description=f"T1 coherence time deviated {abs(z_t1):.1f} sigma from adaptive baseline.",
                            evidence={"qubit_id": cal.qubit_id, "z_score": round(z_t1, 2), "t1_us": cal.t1_us},
                            detected_at=datetime.now(timezone.utc),
                            visual_effect="calibration_drain",
                            visual_intensity=min(abs(z_t1) / 5.0, 1.0),
                            remediation=["Investigate qubit calibration drift.", "Check for external interference."]
                        ))
                        baseline_anomalies_total.labels(
                            backend_id=backend.id,
                            metric_name=f"q{cal.qubit_id}_t1"
                        ).inc()
                    # Check T2 coherence time
                    z_t2 = baseline_manager.check(backend.id, f"q{cal.qubit_id}_t2", cal.t2_us)
                    if z_t2 is not None:
                        baseline_threats.append(ThreatEvent(
                            id=f"baseline-{backend.id}-q{cal.qubit_id}-t2",
                            technique_id="QTT014",
                            technique_name="Adaptive Baseline Anomaly",
                            severity=Severity.high if abs(z_t2) > 4.0 else Severity.medium,
                            platform=backend.platform,
                            backend_id=backend.id,
                            title=f"T2 anomaly on {backend.id} qubit {cal.qubit_id}",
                            description=f"T2 coherence time deviated {abs(z_t2):.1f} sigma from adaptive baseline.",
                            evidence={"qubit_id": cal.qubit_id, "z_score": round(z_t2, 2), "t2_us": cal.t2_us},
                            detected_at=datetime.now(timezone.utc),
                            visual_effect="calibration_drain",
                            visual_intensity=min(abs(z_t2) / 5.0, 1.0),
                            remediation=["Investigate qubit calibration drift.", "Check for external interference."]
                        ))
                        baseline_anomalies_total.labels(
                            backend_id=backend.id,
                            metric_name=f"q{cal.qubit_id}_t2"
                        ).inc()

            # Build the set of keys that THIS cycle's baseline check produced.
            # Any previously-seen baseline key that is NOT in this set is stale
            # and must be removed so the anomaly doesn't persist forever.
            current_baseline_keys: set = set()
            if baseline_threats:
                for bt in baseline_threats:
                    bl_key = (bt.backend_id, bt.technique_id + bt.id)
                    analyzer.active_threats[bl_key] = bt
                    current_baseline_keys.add(bl_key)
                # Remove stale baseline threats that are no longer anomalous
                stale_keys = [
                    k for k in analyzer.active_threats
                    if k[1].startswith("QTT014baseline-") and k not in current_baseline_keys
                ]
                for sk in stale_keys:
                    del analyzer.active_threats[sk]
                    logger.info("baseline_anomaly_resolved", key=sk)
                enriched_snapshot.threats.extend(baseline_threats)
                enriched_snapshot.total_threats = len(enriched_snapshot.threats)
                logger.info("baseline_anomalies_detected", count=len(baseline_threats))
            else:
                # No baseline anomalies this cycle — clear any lingering ones
                stale_keys = [
                    k for k in analyzer.active_threats
                    if k[1].startswith("QTT014baseline-")
                ]
                for sk in stale_keys:
                    del analyzer.active_threats[sk]
                    logger.info("baseline_anomaly_resolved", key=sk)

            # Run cross-rule correlation on new threats
            campaign_events = correlator.correlate(enriched_snapshot.threats)
            if campaign_events:
                for ce in campaign_events:
                    analyzer.active_threats[(ce.backend_id, ce.technique_id)] = ce
                    campaign_correlations_total.labels(
                        pattern_name=ce.technique_name
                    ).inc()
                enriched_snapshot.threats.extend(campaign_events)
                enriched_snapshot.threats.sort(
                    key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(
                        x.severity.value if hasattr(x.severity, "value") else str(x.severity), 99
                    )
                )
                enriched_snapshot.total_threats = len(enriched_snapshot.threats)
                logger.info("campaigns_detected", count=len(campaign_events))

            # ── Persist new threats and resolve disappeared ones ────────
            try:
                saved = await analyzer.persist_new_threats()
                if saved:
                    logger.info("threats_persisted", count=len(saved))
                # Persist correlation events to their own table
                if campaign_events:
                    from backend.storage.database import save_correlation
                    for ce in campaign_events:
                        try:
                            # Scope techniques and backends to THIS campaign's
                            # backend only — without filtering, threats from
                            # unrelated backends leak into the correlation record.
                            campaign_techniques = ce.evidence.get("techniques_found") or []
                            scoped_techniques = [
                                t.technique_id for t in enriched_snapshot.threats
                                if t.technique_id in campaign_techniques
                                and t.backend_id == ce.backend_id
                            ]
                            scoped_backends = list({
                                t.backend_id for t in enriched_snapshot.threats
                                if t.technique_id in campaign_techniques
                                and t.backend_id == ce.backend_id
                                and t.backend_id
                            })
                            await save_correlation(
                                id=ce.id,
                                pattern_name=ce.technique_name,
                                techniques=scoped_techniques,
                                backends=scoped_backends,
                                detected_at=ce.detected_at.isoformat()
                                    if isinstance(ce.detected_at, datetime)
                                    else str(ce.detected_at),
                                severity=ce.severity.value
                                    if hasattr(ce.severity, "value")
                                    else str(ce.severity),
                            )
                        except Exception as exc:
                            logger.warning("persist_correlation_failed", id=ce.id, error=str(exc))
                resolved = await analyzer.resolve_disappeared_threats()
                if resolved:
                    logger.info("threats_resolved", count=len(resolved))
            except Exception as db_exc:
                logger.warning("persistence_error", error=str(db_exc))

            # Copy-on-write: atomically swap the snapshot so API reads
            # never see a partially-mutated object
            async with _snapshot_lock:
                latest_snapshot = enriched_snapshot.model_copy(deep=False)

            await manager.broadcast_snapshot(enriched_snapshot)
            
            elapsed_ms = round((time.monotonic() - start) * 1000)
            _health_state["last_engine_cycle_at"] = datetime.now(timezone.utc)
            logger.info("simulation_loop_complete",
                cycle=cycle_count,
                threats_active=len(analyzer.active_threats),
                duration_ms=elapsed_ms)

            # Update Prometheus gauges for active threats by severity
            severity_counts = {}
            for threat in analyzer.active_threats.values():
                sev = threat.severity.value if hasattr(threat.severity, "value") else str(threat.severity)
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
            for sev in ("critical", "high", "medium", "low", "info"):
                threats_active.labels(severity=sev).set(severity_counts.get(sev, 0))
            
            # ── Periodic data retention cleanup ────────────────────────
            now_ts = time.time()
            if now_ts - retention_last_run >= settings.retention_cleanup_interval_seconds:
                try:
                    from backend.storage.retention import run_retention_cleanup
                    cleanup_result = await run_retention_cleanup()
                    retention_last_run = now_ts
                    if cleanup_result["threats_deleted"] > 0 or cleanup_result["correlations_deleted"] > 0:
                        logger.info("retention_cleanup_triggered", **cleanup_result)
                except Exception as ret_exc:
                    logger.error("retention_cleanup_loop_error", error=str(ret_exc))
            
            await asyncio.sleep(settings.update_interval_seconds)
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error("simulation_loop_error",
                cycle=cycle_count,
                error=str(e),
                exc_info=True)
            simulation_loop_errors_total.inc()
            await asyncio.sleep(5)

# ─── Lifespan ──────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manages application startup and teardown routines."""

    # Initialise the SQLite database (tables + WAL mode)
    await init_db()
    from backend.storage.database import _db_path as _actual_db_path
    logger.info("database_initialised", path=str(_actual_db_path))

    if "pytest" in str(os.environ):
        logger.info("testing_mode_detected_skipping_loop")
        yield
        await close_db()
        return

    logger.info("starting_simulation_loop")
    task = asyncio.create_task(simulation_loop())

    global latest_snapshot
    try:
        initial = analyzer.analyze(await collector.collect())
        async with _snapshot_lock:
            latest_snapshot = initial
        # Seed active_threats from the initial snapshot so /api/threats/history
        # returns data immediately (before the first simulation loop iteration)
        if initial and initial.threats:
            for threat in initial.threats:
                key = (threat.backend_id, threat.technique_id)
                if key not in analyzer.active_threats:
                    analyzer.active_threats[key] = threat
            logger.info("seeded_active_threats", count=len(analyzer.active_threats))
    except Exception as e:
        logger.error("initial_snapshot_error", error=str(e))

    yield

    task.cancel()
    await close_db()
    logger.info("shutting_down_simulation_loop")

# ─── FastAPI App ───────────────────────────────────────────────────────
app = FastAPI(title="QVis API", lifespan=lifespan)

# Instrument Prometheus metrics
# Instrument Prometheus metrics
instrumentator = Instrumentator().instrument(app)
# We manually expose it below to add authentication





@app.get("/metrics")
async def metrics_endpoint(api_key: str = Depends(verify_api_key)):
    from starlette.responses import Response
    from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

# ─── Request ID Middleware ─────────────────────────────────────────
class RequestIDMiddleware(BaseHTTPMiddleware):
    """Adds a unique X-Request-ID header to every response and binds it
    to structlog context for correlated log tracing."""

    async def dispatch(self, request: StarletteRequest, call_next):
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())[:8]
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(request_id=request_id)
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response


# ─── CORS Middleware ───────────────────────────────────────────────
# Middleware order: RequestID → CORS → Rate Limit → Security Headers
app.add_middleware(RequestIDMiddleware)
_cors_origins_raw = os.getenv("CORS_ORIGINS", "http://localhost:3000")
if _cors_origins_raw.strip() == "*":
    # Wildcard: split into list for Starlette (credentials must be False with *)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=False,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["X-API-Key", "Content-Type", "Authorization"],
    )
else:
    # Specific origins: safe to enable credentials
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[o.strip() for o in _cors_origins_raw.split(",") if o.strip()],
        allow_credentials=True,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["X-API-Key", "Content-Type", "Authorization"],
    )
app.add_middleware(RateLimitMiddleware)
app.add_middleware(SecurityHeadersMiddleware)

# ─── Health Endpoints (not behind auth) ────────────────────────────────

@app.get("/health", response_model=HealthResponse)
async def health_check():
    """
    System readiness check.

    Returns 200 if all components are healthy.
    Returns 200 with status=degraded if non-critical components fail.
    Returns 503 if critical components (database, engine) are unhealthy.
    """
    components = {}
    now = datetime.now(timezone.utc)
    overall = HealthStatus.healthy

    # ── Database Check ────────────────────────────────────────────────
    db_start = time.monotonic()
    try:
        from backend.storage.database import _get_connection
        db = await _get_connection()
        await db.execute("SELECT 1")
        db_latency = (time.monotonic() - db_start) * 1000
        components["database"] = ComponentHealth(
            status=HealthStatus.healthy,
            message="SQLite reachable and writable",
            latency_ms=round(db_latency, 2),
        )
    except Exception as e:
        components["database"] = ComponentHealth(
            status=HealthStatus.unhealthy,
            message=f"Database unreachable: {e}",
        )
        overall = HealthStatus.unhealthy

    # ── Collector Check ───────────────────────────────────────────────
    last_collection = _health_state["last_collection_at"]
    collection_error = _health_state["last_collection_error"]
    max_stale = settings.update_interval_seconds * 2

    if last_collection is None:
        components["collector"] = ComponentHealth(
            status=HealthStatus.degraded,
            message="No collection has completed yet (startup)",
        )
        if overall == HealthStatus.healthy:
            overall = HealthStatus.degraded
    elif collection_error:
        components["collector"] = ComponentHealth(
            status=HealthStatus.degraded,
            message=f"Last collection failed: {collection_error}",
            last_success_at=last_collection,
        )
        if overall == HealthStatus.healthy:
            overall = HealthStatus.degraded
    else:
        age_seconds = (now - last_collection).total_seconds()
        if age_seconds > max_stale:
            components["collector"] = ComponentHealth(
                status=HealthStatus.unhealthy,
                message=f"Collection stale: {age_seconds:.0f}s ago"
                        f" (max {max_stale}s)",
                last_success_at=last_collection,
            )
            overall = HealthStatus.unhealthy
        else:
            components["collector"] = ComponentHealth(
                status=HealthStatus.healthy,
                message=f"Last collection {age_seconds:.0f}s ago",
                last_success_at=last_collection,
            )

    # ── Threat Engine Check ───────────────────────────────────────────
    last_cycle = _health_state["last_engine_cycle_at"]
    if last_cycle is None:
        components["threat_engine"] = ComponentHealth(
            status=HealthStatus.degraded,
            message="No analysis cycle completed yet",
        )
        if overall == HealthStatus.healthy:
            overall = HealthStatus.degraded
    else:
        components["threat_engine"] = ComponentHealth(
            status=HealthStatus.healthy,
            message="Analysis engine running",
            last_success_at=last_cycle,
        )

    # ── WebSocket Check ───────────────────────────────────────────────
    last_broadcast = _health_state["last_broadcast_at"]
    ws_connections = len(manager.active_connections)
    if last_broadcast is None:
        components["websocket"] = ComponentHealth(
            status=HealthStatus.degraded,
            message="No broadcast sent yet",
        )
    else:
        components["websocket"] = ComponentHealth(
            status=HealthStatus.healthy,
            message=f"Broadcasting — {ws_connections} active connections",
            last_success_at=last_broadcast,
        )

    status_code = 503 if overall == HealthStatus.unhealthy else 200
    response_body = HealthResponse(
        status=overall,
        version=_APP_VERSION,
        uptime_seconds=round(time.time() - _health_state["startup_time"], 1),
        components=components,
        checked_at=now,
        demo_mode=settings.demo_mode,
        active_collector=collector.__class__.__name__,
        connected_platforms=[str(p) for p in getattr(collector, "platforms", ["mock"])]
    )

    from fastapi.responses import JSONResponse
    return JSONResponse(
        content=response_body.model_dump(mode="json"),
        status_code=status_code,
    )

@app.get("/ready")
async def readiness_probe():
    """
    Kubernetes readiness probe.
    Returns 200 only when system is ready to receive traffic.
    Returns 503 during startup or when critical components fail.
    """
    health = await health_check()
    if health.status_code == 503:
        from fastapi.responses import JSONResponse
        return JSONResponse({"ready": False}, status_code=503)
    from fastapi.responses import JSONResponse
    return JSONResponse({"ready": True}, status_code=200)

@app.get("/live")
async def liveness_probe():
    """
    Kubernetes liveness probe.
    Returns 200 as long as the process is running.
    """
    from fastapi.responses import JSONResponse
    return JSONResponse({"alive": True}, status_code=200)



async def _ensure_snapshot():
    """Return the latest snapshot, initialising if necessary.

    Uses _snapshot_lock so API reads never observe a partially-built
    snapshot while the simulation loop is writing a new one.
    """
    global latest_snapshot
    async with _snapshot_lock:
        if latest_snapshot is None:
            latest_snapshot = analyzer.analyze(await collector.collect())
        return latest_snapshot


@app.get("/api/snapshot", response_model=SimulationSnapshot)
async def get_snapshot(_auth: None = Depends(verify_api_key)):
    """Returns the most recent fully resolved simulation state."""
    return await _ensure_snapshot()


@app.get("/api/backends", response_model=List[BackendNode])
async def get_backends(_auth: None = Depends(verify_api_key)):
    """Returns the list of all currently tracked quantum backends."""
    snapshot = await _ensure_snapshot()
    return snapshot.backends


@app.get("/api/threats", response_model=List[ThreatEvent])
async def get_threats(severity: Optional[Severity] = None, _auth: None = Depends(verify_api_key)):
    """Returns a list of active threat detections."""
    snapshot = await _ensure_snapshot()
    if severity:
        return [t for t in snapshot.threats if t.severity == severity]
    return snapshot.threats


@app.get("/api/threat/{threat_id}", response_model=ThreatEvent)
async def get_threat_detail(threat_id: str, _auth: None = Depends(verify_api_key)):
    """Retrieves deeply detailed evidence and remediation for a specific threat."""
    # Validate threat_id format: alphanumeric, hyphens, underscores, colons only
    import re
    if not re.match(r'^[a-zA-Z0-9_\-:]+$', threat_id):
        raise HTTPException(status_code=400, detail="Invalid threat ID format")
    if len(threat_id) > 200:
        raise HTTPException(status_code=400, detail="Threat ID too long")
    snapshot = await _ensure_snapshot()
    for threat in snapshot.threats:
        if threat.id == threat_id:
            return threat
    raise HTTPException(status_code=404, detail="Threat not found")

# ─── STIX Export Endpoint ──────────────────────────────────────────────
@app.get("/api/threats/export/stix", tags=["threats"])
async def export_threats_stix(
    limit: Optional[int] = Query(default=None, ge=1, le=1000, description="Max threats to return (1-1000)"),
    offset: int = Query(default=0, ge=0, le=100000, description="Number of threats to skip"),
    _auth: None = Depends(verify_api_key),
):
    """Export active threats as a STIX 2.1 Bundle for SIEM integration.
    Supports pagination via ?limit=N&offset=M query parameters."""
    snapshot = await _ensure_snapshot()
    from backend.api.export import export_stix_bundle
    return export_stix_bundle(snapshot.threats, limit=limit, offset=offset)

# ─── Threat History Endpoint ───────────────────────────────────────────
@app.get("/api/threats/history", tags=["threats"])
async def get_threat_history(
    limit: int = Query(default=100, ge=1, le=1000, description="Max events to return"),
    offset: int = Query(default=0, ge=0, le=100000, description="Events to skip"),
    severity: Optional[str] = Query(default=None, description="Filter by severity"),
    _auth: None = Depends(verify_api_key),
):
    """Returns paginated threat history from the persistent database.

    This endpoint now reads from SQLite, giving all-time visibility
    rather than only the current in-memory window.
    """
    from backend.storage.database import get_threats as db_get_threats
    return await db_get_threats(limit=limit, offset=offset, severity_filter=severity)


# ─── Threat Statistics Endpoint ────────────────────────────────────────
@app.get("/api/threats/stats", tags=["threats"])
async def get_threat_stats_endpoint(_auth: None = Depends(verify_api_key)):
    """Returns aggregated statistics over all persisted threat events.

    Response shape:
    {
        total_all_time: int,
        by_severity: {severity: count, ...},
        by_platform: {platform: count, ...},
        by_technique: {technique_id: count, ...},
        first_detected: str | null,  (ISO-8601)
        last_detected: str | null   (ISO-8601)
    }
    """
    from backend.storage.database import get_threat_stats as db_get_stats
    return await db_get_stats()


# ─── Retention Stats Endpoint ──────────────────────────────────────────
@app.get("/api/admin/retention", tags=["admin"])
async def get_retention_stats_endpoint(_auth: None = Depends(verify_api_key)):
    """Returns data retention statistics and cleanup eligibility.

    Response shape:
    {
        threats_eligible: int,
        correlations_eligible: int,
        total_threats: int,
        total_correlations: int,
        threat_cutoff: str,        (ISO-8601)
        correlation_cutoff: str,   (ISO-8601)
        retention_days_threats: int,
        retention_days_correlations: int
    }
    """
    from backend.storage.retention import get_retention_stats
    return await get_retention_stats()


# ─── Manual Retention Trigger Endpoint ─────────────────────────────────
@app.post("/api/admin/retention/cleanup", tags=["admin"])
async def trigger_retention_cleanup(
    threat_days: Optional[int] = Query(default=None, ge=1, le=3650, description="Override threat retention days"),
    correlation_days: Optional[int] = Query(default=None, ge=1, le=3650, description="Override correlation retention days"),
    _auth: None = Depends(verify_api_key),
):
    """Manually trigger a retention cleanup cycle.

    Optionally override retention days via query parameters.
    Returns a summary of what was deleted.
    """
    from backend.storage.retention import run_retention_cleanup
    result = await run_retention_cleanup(
        threat_days=threat_days,
        correlation_days=correlation_days,
    )
    return result

# ─── Scenario Endpoints ──────────────────────────────────────────────
active_scenario = {"name": None}

@app.post("/api/scenario/load")
async def load_scenario(name: str, _auth: None = Depends(verify_api_key)):
    """Load a pre-recorded attack scenario for playback."""
    import re
    if not re.match(r'^[a-zA-Z0-9_\-]+$', name):
        raise HTTPException(status_code=400, detail="Invalid scenario name")
    if len(name) > 100:
        raise HTTPException(status_code=400, detail="Scenario name too long")
    global collector, active_scenario
    from backend.collectors.scenario import ScenarioCollector
    scenario = ScenarioCollector()
    if scenario.load_scenario(name):
        collector = scenario
        active_scenario["name"] = name
        analyzer.reset()
        correlator.reset()
        logger.info("scenario_loaded", scenario=name)
        return {"status": "loaded", "scenario": name}
    raise HTTPException(status_code=400, detail=f"Unknown scenario: {name}")

@app.get("/api/scenario/list")
async def list_scenarios():
    """List all available scenario names."""
    from backend.collectors.scenario import SCENARIOS
    return {"scenarios": list(SCENARIOS.keys())}

@app.post("/api/scenario/reset")
async def reset_scenario(_auth: None = Depends(verify_api_key)):
    """Reset to the default mock collector after a scenario playback."""
    global collector, active_scenario
    if active_scenario["name"] is None:
        return {"status": "already_default", "message": "No scenario is active"}

    from backend.collectors.mock import MockCollector
    collector = MockCollector()
    active_scenario["name"] = None
    analyzer.reset()
    correlator.reset()
    baseline_manager.reset()
    logger.info("scenario_reset_to_mock")
    return {"status": "reset", "message": "Collector reset to mock mode"}

# ─── WebSocket Endpoint (with optional auth) ──────────────────────────
@app.websocket("/ws/simulation")
async def websocket_endpoint(websocket: WebSocket):
    """Manages full duplex connection handling for live telemetry streams."""
    # WebSocket auth via query param: ws://host/ws/simulation?token=<key>
    if settings.auth_enabled:
        token = websocket.query_params.get("token")
        if not token or not settings.api_key.get_secret_value():
            await websocket.close(code=4001, reason="Authentication required")
            return
        import secrets as _secrets
        expected_hash = _get_hashed_key()
        if not expected_hash or not _secrets.compare_digest(_hash_key(token), expected_hash):
            await websocket.close(code=4003, reason="Invalid token")
            return

    connected = await manager.connect(websocket)
    if not connected:
        return

    # NOTE: message size is enforced by ConnectionManager.validate_message()
    # in the receive loop below.  We intentionally do NOT try to set
    # websocket._max_size because it is a private implementation detail
    # that varies across ASGI servers and may not exist or be writable.

    try:
        snapshot = await _ensure_snapshot()
        await manager.send_personal_message(snapshot.model_dump_json(), websocket)

        while True:
            data = await websocket.receive_text()

            # Validate incoming message size and rate
            if not manager.validate_message(data, websocket):
                logger.warning("websocket_message_rejected", client=id(websocket))
                continue

            try:
                msg = json.loads(data)
                # Restrict to known message types only
                msg_type = msg.get("type")
                if msg_type == "get_snapshot":
                    snap = await _ensure_snapshot()
                    await manager.send_personal_message(snap.model_dump_json(), websocket)
                elif msg_type == "focus_backend":
                    backend_id = msg.get("backend_id")
                    if not backend_id or not isinstance(backend_id, str):
                        continue
                    logger.info("client_focus_backend", backend_id=backend_id)
                    snap = await _ensure_snapshot()
                    for b in snap.backends:
                        if b.id == backend_id:
                            await manager.send_personal_message(
                                json.dumps({"type": "backend_focus_ack", "backend": b.model_dump()}),
                                websocket,
                            )
                            break
                elif msg_type == "ping":
                    # Client heartbeat — no response needed (server sends snapshots)
                    pass
                else:
                    logger.warning("unknown_websocket_message_type", msg_type=msg_type)
            except json.JSONDecodeError:
                logger.warning("invalid_json_websocket_message", raw=data)
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        logger.error("websocket_error", error=str(e))
        manager.disconnect(websocket)

# ─── Frontend Static File Serving ─────────────────────────────────────
# Paths reserved by FastAPI/Starlette — never intercept these
_RESERVED_PATHS = {"docs", "redoc", "openapi.json"}
# Import urllib for URL-encoded path traversal detection
from urllib.parse import unquote

@app.get("/{full_path:path}")
async def serve_frontend(full_path: str):
    """Serves the SPA frontend files. Rejects null bytes and reserved paths."""
    # Let FastAPI handle its own built-in routes
    if full_path in _RESERVED_PATHS:
        raise HTTPException(status_code=404, detail="Not a frontend route")

    # Block null bytes (all variants)
    if "\x00" in full_path or "%00" in full_path.lower():
        raise HTTPException(status_code=400, detail="Invalid path")

    # Block path traversal — check both raw and URL-decoded forms
    decoded = unquote(full_path)
    if ".." in full_path or ".." in decoded:
        raise HTTPException(status_code=403, detail="Path traversal blocked")

    from pathlib import Path
    import mimetypes
    frontend_dir = Path(__file__).parent.parent / "frontend"

    if full_path and (frontend_dir / full_path).is_file():
        from starlette.responses import FileResponse
        media_type = mimetypes.guess_type(full_path)[0] or "application/octet-stream"
        return FileResponse(frontend_dir / full_path, media_type=media_type)

    # SPA fallback: serve index.html for any unmatched route
    index_file = frontend_dir / "index.html"
    if index_file.is_file():
        from starlette.responses import FileResponse
        return FileResponse(index_file)
    raise HTTPException(status_code=404, detail="Frontend not found")


# ─── CLI: Calibration Mode ─────────────────────────────────────────────
# Usage:  python -m backend.main --calibrate [duration_minutes]
#
# Runs the live IBM Quantum collector for the given duration (default 60
# minutes), computes p95-based thresholds, saves them to
# calibration_results.json, and exits.  Requires a valid
# IBM_QUANTUM_TOKEN in the environment.

import sys

def _cli_calibrate_mode() -> bool:
    """Check if --calibrate was passed and handle it. Returns True if
    the process should exit after calibration completes."""
    args = sys.argv[1:]
    if "--calibrate" not in args:
        return False

    idx = args.index("--calibrate")
    duration = 60
    if idx + 1 < len(args):
        try:
            duration = int(args[idx + 1])
        except ValueError:
            pass

    import asyncio as _aio
    from backend.collectors.ibm import IBMQuantumCollector
    from backend.collectors.calibrator import ThresholdCalibrator

    token = os.getenv("IBM_QUANTUM_TOKEN", "")
    if not token:
        logger.error("calibrate_requires_token")
        sys.exit(1)

    logger.info("calibration_mode_starting",
        duration_minutes=duration,
        collector="IBMQuantumCollector",
        output="calibration_results.json")

    collector = IBMQuantumCollector(ibm_token=token)
    cal = ThresholdCalibrator(collector)

    result = _aio.run(cal.calibrate(duration_minutes=duration))
    path = result.save()

    logger.info("calibration_complete", path=path)

    thresholds = {}
    for field in [
        "rule_002_calibration_harvest_ratio",
        "rule_003_identity_gate_ratio",
        "rule_003_max_circuit_gates",
        "rule_005_max_depth_ratio",
        "rule_008_t1_baseline_ratio",
        "rule_009_min_backends_accessed",
        "rule_010_measure_ratio",
        "rule_010_min_circuit_gates",
    ]:
        val = getattr(result, field, None)
        label = field.replace("rule_", "RULE_").replace("_", " ").title()
        thresholds[label] = val if val is not None else "insufficient_data"

    logger.info("recommended_thresholds", **thresholds)
    sys.exit(0)


# Run CLI check before FastAPI app creation so --calibrate exits cleanly
if _cli_calibrate_mode():
    pass  # sys.exit(0) already called inside
