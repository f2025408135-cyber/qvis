"""Main FastAPI application entry point serving QVis API and WebSockets."""

import asyncio
import os
import json
import structlog
from contextlib import asynccontextmanager
from typing import List, Optional
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from backend.config import settings
from backend.api.websocket import manager
from backend.threat_engine.analyzer import ThreatAnalyzer
from backend.threat_engine.models import SimulationSnapshot, BackendNode, ThreatEvent, Severity

logger = structlog.get_logger()

latest_snapshot: Optional[SimulationSnapshot] = None
analyzer = ThreatAnalyzer()

# Determine collector strategy based on environment config.
if os.environ.get("PYTEST_CURRENT_TEST") or settings.demo_mode:
    from backend.collectors.mock import MockCollector
    collector = MockCollector()
    if os.environ.get("PYTEST_CURRENT_TEST"):
        collector.is_test = True
    logger.info("using_mock_collector", mode="demo_or_test")
elif settings.ibm_quantum_token:
    from backend.collectors.ibm import IBMQuantumCollector
    collector = IBMQuantumCollector(ibm_token=settings.ibm_quantum_token)
    logger.info("using_ibm_collector", backends="live")
else:
    from backend.collectors.mock import MockCollector
    logger.warning("no_token_configured_using_mock")
    collector = MockCollector()

async def simulation_loop():
    """Background task continually refreshing telemetry and broadcasting state."""
    global latest_snapshot
    while True:
        try:
            snapshot = await collector.collect()
            enriched_snapshot = analyzer.analyze(snapshot)
            latest_snapshot = enriched_snapshot
            await manager.broadcast_snapshot(enriched_snapshot)
            logger.info("snapshot_broadcasted", snapshot_id=enriched_snapshot.snapshot_id)
            await asyncio.sleep(settings.update_interval_seconds)
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error("simulation_loop_error", error=str(e))
            await asyncio.sleep(5)

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manages application startup and teardown routines."""
    
    is_testing = bool(os.environ.get("PYTEST_CURRENT_TEST")) or "pytest" in os.environ.get("_", "")
    
    if is_testing:
        logger.info("testing_mode_detected_skipping_loop")
        yield
        return
        
    logger.info("starting_simulation_loop")
    task = asyncio.create_task(simulation_loop())
    
    global latest_snapshot
    try:
        latest_snapshot = analyzer.analyze(await collector.collect())
    except Exception as e:
        logger.error("initial_snapshot_error", error=str(e))
        
    yield
    
    task.cancel()
    logger.info("shutting_down_simulation_loop")

app = FastAPI(title="QVis API", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[os.getenv("CORS_ORIGINS", "http://localhost:3000")],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/api/health")
async def health_check():
    """Validates the API is responsive and running."""
    return {
        "status": "ok",
        "demo_mode": settings.demo_mode,
        "active_collector": "mock" if type(collector).__name__ == "MockCollector" else "ibm_quantum",
        "connected_platforms": ["mock"] if settings.demo_mode else ["ibm_quantum"] if settings.ibm_quantum_token else []
    }

async def _ensure_snapshot():
    global latest_snapshot
    if latest_snapshot is None:
        latest_snapshot = analyzer.analyze(await collector.collect())
    return latest_snapshot

@app.get("/api/snapshot", response_model=SimulationSnapshot)
async def get_snapshot():
    """Returns the most recent fully resolved simulation state."""
    return await _ensure_snapshot()

@app.get("/api/backends", response_model=List[BackendNode])
async def get_backends():
    """Returns the list of all currently tracked quantum backends."""
    snapshot = await _ensure_snapshot()
    return snapshot.backends

@app.get("/api/threats", response_model=List[ThreatEvent])
async def get_threats(severity: Optional[Severity] = None):
    """Returns a list of active threat detections."""
    snapshot = await _ensure_snapshot()
    if severity:
        return [t for t in snapshot.threats if t.severity == severity]
    return snapshot.threats

@app.get("/api/threat/{threat_id}", response_model=ThreatEvent)
async def get_threat_detail(threat_id: str):
    """Retrieves deeply detailed evidence and remediation for a specific threat."""
    snapshot = await _ensure_snapshot()
    for threat in snapshot.threats:
        if threat.id == threat_id:
            return threat
    raise HTTPException(status_code=404, detail="Threat not found")

@app.websocket("/ws/simulation")
async def websocket_endpoint(websocket: WebSocket):
    """Manages full duplex connection handling for live telemetry streams."""
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
                            await manager.send_personal_message(json.dumps({"type": "backend_focus_ack", "backend": b.model_dump()}), websocket)
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
