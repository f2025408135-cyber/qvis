"""Main FastAPI application entry point serving QVis API and WebSockets."""

import asyncio
import os
import time
import json
import logging
import structlog
from datetime import datetime, timezone
from contextlib import asynccontextmanager
from typing import List, Optional
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from backend.config import settings
from backend.api.websocket import manager
from backend.api.auth import verify_api_key, _hash_key, _get_hashed_key
from backend.api.security_headers import SecurityHeadersMiddleware
from backend.api.ratelimit import RateLimitMiddleware
from backend.threat_engine.analyzer import ThreatAnalyzer
from backend.threat_engine.correlator import ThreatCorrelator
from backend.threat_engine.baseline import BaselineManager
from backend.threat_engine.models import SimulationSnapshot, BackendNode, ThreatEvent, Severity

# ─── Logging Configuration ─────────────────────────────────────────────
def _configure_logging():
    """Configure structlog based on settings."""
    log_level = settings.log_level.upper()
    log_format = settings.log_format

    # Map string level to Python logging constant
    level_map = {
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARNING": logging.WARNING,
        "ERROR": logging.ERROR,
        "CRITICAL": logging.CRITICAL,
    }
    level = level_map.get(log_level, logging.INFO)

    logging.basicConfig(
        format="%(message)s",
        level=level,
    )

    if log_format == "json":
        structlog.configure(
            processors=[
                structlog.contextvars.merge_contextvars,
                structlog.processors.add_log_level,
                structlog.processors.JSONRenderer(),
            ],
            wrapper_class=structlog.make_filtering_bound_logger(level),
            context_class=dict,
            logger_factory=structlog.PrintLoggerFactory(),
            cache_logger_on_first_use=True,
        )
    else:
        structlog.configure(
            processors=[
                structlog.contextvars.merge_contextvars,
                structlog.processors.add_log_level,
                structlog.dev.ConsoleRenderer(),
            ],
            wrapper_class=structlog.make_filtering_bound_logger(level),
            context_class=dict,
            logger_factory=structlog.PrintLoggerFactory(),
            cache_logger_on_first_use=True,
        )


_configure_logging()
logger = structlog.get_logger()

# ─── Application State ─────────────────────────────────────────────────
latest_snapshot: Optional[SimulationSnapshot] = None
_snapshot_lock = asyncio.Lock()
analyzer = ThreatAnalyzer()
correlator = ThreatCorrelator()
baseline_manager = BaselineManager(z_threshold=2.5)
github_scanner = None

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

    while True:
        try:
            start = time.monotonic()
            snapshot = await collector.collect()
            elapsed = time.monotonic() - start

            logger.info("collection_completed", source=collector.__class__.__name__, elapsed_ms=round(elapsed * 1000))

            # Integrate GitHub scanning selectively (every 5 minutes to respect rate limits)
            if github_scanner and (time.time() - github_last_run > 300):
                try:
                    logger.info("running_github_scan")
                    github_results = await github_scanner.scan_for_ibm_tokens()
                    github_last_run = time.time()
                except Exception as e:
                    logger.error("github_scan_loop_error", error=str(e))

            if github_results:
                raw_dict = snapshot.model_dump()
                raw_dict["github_search_results"] = github_results
                enriched_snapshot = analyzer.analyze(raw_dict)
            else:
                enriched_snapshot = analyzer.analyze(snapshot)

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

            if baseline_threats:
                for bt in baseline_threats:
                    analyzer.active_threats[(bt.backend_id, bt.technique_id + bt.id)] = bt
                enriched_snapshot.threats.extend(baseline_threats)
                enriched_snapshot.total_threats = len(enriched_snapshot.threats)
                logger.info("baseline_anomalies_detected", count=len(baseline_threats))

            # Run cross-rule correlation on new threats
            campaign_events = correlator.correlate(enriched_snapshot.threats)
            if campaign_events:
                for ce in campaign_events:
                    analyzer.active_threats[(ce.backend_id, ce.technique_id)] = ce
                enriched_snapshot.threats.extend(campaign_events)
                enriched_snapshot.threats.sort(
                    key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(
                        x.severity.value if hasattr(x.severity, "value") else str(x.severity), 99
                    )
                )
                enriched_snapshot.total_threats = len(enriched_snapshot.threats)
                logger.info("campaigns_detected", count=len(campaign_events))

            # Copy-on-write: atomically swap the snapshot so API reads
            # never see a partially-mutated object
            async with _snapshot_lock:
                latest_snapshot = enriched_snapshot.model_copy(deep=False)

            await manager.broadcast_snapshot(enriched_snapshot)
            logger.info("snapshot_broadcasted", snapshot_id=enriched_snapshot.snapshot_id)
            await asyncio.sleep(settings.update_interval_seconds)
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error("simulation_loop_error", error=str(e))
            await asyncio.sleep(5)

# ─── Lifespan ──────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manages application startup and teardown routines."""

    if "pytest" in str(os.environ):
        logger.info("testing_mode_detected_skipping_loop")
        yield
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
    logger.info("shutting_down_simulation_loop")

# ─── FastAPI App ───────────────────────────────────────────────────────
app = FastAPI(title="QVis API", lifespan=lifespan)

# Middleware order: CORS → Rate Limit → Security Headers
app.add_middleware(
    CORSMiddleware,
    allow_origins=[os.getenv("CORS_ORIGINS", "http://localhost:3000")],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(RateLimitMiddleware)
app.add_middleware(SecurityHeadersMiddleware)

# ─── Health Endpoint (not behind auth) ────────────────────────────────
@app.get("/api/health")
async def health_check():
    """Validates the API is responsive and running."""
    collector_name = type(collector).__name__
    is_demo = settings.demo_mode or collector_name == "AggregatorCollector"
    platforms = []
    if is_demo:
        if collector_name == "AggregatorCollector":
            platforms = ["ibm_quantum", "amazon_braket", "azure_quantum"]
        else:
            platforms = ["mock"]
    elif settings.ibm_quantum_token.get_secret_value():
        platforms.append("ibm_quantum")
    if settings.aws_access_key_id.get_secret_value():
        platforms.append("amazon_braket")
    if settings.azure_quantum_subscription_id.get_secret_value():
        platforms.append("azure_quantum")
    return {
        "status": "ok",
        "demo_mode": is_demo,
        "active_collector": collector_name,
        "connected_platforms": platforms,
    }

# ─── Snapshot / Threat Endpoints (auth-optional) ──────────────────────
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
    snapshot = await _ensure_snapshot()
    for threat in snapshot.threats:
        if threat.id == threat_id:
            return threat
    raise HTTPException(status_code=404, detail="Threat not found")

# ─── STIX Export Endpoint ──────────────────────────────────────────────
@app.get("/api/threats/export/stix", tags=["threats"])
async def export_threats_stix(
    limit: Optional[int] = None,
    offset: int = 0,
    _auth: None = Depends(verify_api_key),
):
    """Export active threats as a STIX 2.1 Bundle for SIEM integration.
    Supports pagination via ?limit=N&offset=M query parameters."""
    snapshot = await _ensure_snapshot()
    from backend.api.export import export_stix_bundle
    return export_stix_bundle(snapshot.threats, limit=limit, offset=offset)

# ─── Threat History Endpoint ───────────────────────────────────────────
@app.get("/api/threats/history", tags=["threats"])
async def get_threat_history(_auth: None = Depends(verify_api_key)):
    """Returns deduplicated threat history from the analyzer."""
    return [
        t.model_dump() for t in analyzer.active_threats.values()
    ]

# ─── Scenario Endpoints ──────────────────────────────────────────────
active_scenario = {"name": None}

@app.post("/api/scenario/load")
async def load_scenario(name: str, _auth: None = Depends(verify_api_key)):
    """Load a pre-recorded attack scenario for playback."""
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

    await manager.connect(websocket)
    try:
        snapshot = await _ensure_snapshot()
        await manager.send_personal_message(snapshot.model_dump_json(), websocket)

        while True:
            data = await websocket.receive_text()
            try:
                msg = json.loads(data)
                msg_type = msg.get("type")
                if msg_type == "get_snapshot":
                    snap = await _ensure_snapshot()
                    await manager.send_personal_message(snap.model_dump_json(), websocket)
                elif msg_type == "focus_backend":
                    backend_id = msg.get("backend_id")
                    logger.info("client_focus_backend", backend_id=backend_id)
                    snap = await _ensure_snapshot()
                    for b in snap.backends:
                        if b.id == backend_id:
                            await manager.send_personal_message(
                                json.dumps({"type": "backend_focus_ack", "backend": b.model_dump()}),
                                websocket,
                            )
                            break
                else:
                    logger.warning("unknown_websocket_message", message=msg)
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

@app.get("/{full_path:path}")
async def serve_frontend(full_path: str):
    """Serves the SPA frontend files. Rejects null bytes and reserved paths."""
    # Let FastAPI handle its own built-in routes
    if full_path in _RESERVED_PATHS:
        raise HTTPException(status_code=404, detail="Not a frontend route")

    if "\x00" in full_path:
        raise HTTPException(status_code=400, detail="Invalid path")

    # Block path traversal attempts
    if ".." in full_path:
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
