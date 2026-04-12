import asyncio
import os
import structlog
from contextlib import asynccontextmanager
from typing import List, Optional
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from backend.config import settings
from backend.api.websocket import manager
from backend.collectors.mock import MockCollector
from backend.threat_engine.analyzer import ThreatAnalyzer
from backend.threat_engine.models import SimulationSnapshot, BackendNode, ThreatEvent, Severity

logger = structlog.get_logger()

latest_snapshot: Optional[SimulationSnapshot] = None
collector = MockCollector() 
analyzer = ThreatAnalyzer()

async def simulation_loop():
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
    return {
        "status": "ok",
        "demo_mode": settings.demo_mode,
        "connected_platforms": ["mock"] if settings.demo_mode else []
    }

@app.get("/api/snapshot", response_model=SimulationSnapshot)
async def get_snapshot():
    if latest_snapshot is None:
        return analyzer.analyze(await collector.collect())
    return latest_snapshot

@app.get("/api/backends", response_model=List[BackendNode])
async def get_backends():
    snapshot = latest_snapshot
    if snapshot is None:
        snapshot = analyzer.analyze(await collector.collect())
    return snapshot.backends

@app.get("/api/threats", response_model=List[ThreatEvent])
async def get_threats(severity: Optional[Severity] = None):
    snapshot = latest_snapshot
    if snapshot is None:
        snapshot = analyzer.analyze(await collector.collect())
    if severity:
        return [t for t in snapshot.threats if t.severity == severity]
    return snapshot.threats

@app.get("/api/threat/{threat_id}", response_model=ThreatEvent)
async def get_threat_detail(threat_id: str):
    snapshot = latest_snapshot
    if snapshot is None:
        snapshot = analyzer.analyze(await collector.collect())
    for threat in snapshot.threats:
        if threat.id == threat_id:
            return threat
    raise HTTPException(status_code=404, detail="Threat not found")

@app.websocket("/ws/simulation")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        # Prevent broadcast storm: send only to the connecting client
        if latest_snapshot:
            await websocket.send_text(latest_snapshot.model_dump_json())
        else:
            snapshot = analyzer.analyze(await collector.collect())
            await websocket.send_text(snapshot.model_dump_json())
            
        while True:
            # Handle incoming messages from the client
            data = await websocket.receive_json()
            msg_type = data.get("type")
            if msg_type == "get_snapshot":
                if latest_snapshot:
                    await websocket.send_text(latest_snapshot.model_dump_json())
            elif msg_type == "focus_backend":
                backend_id = data.get("backend_id")
                # Stub for more complex interaction
                logger.info("client_focus_backend", backend_id=backend_id)
            else:
                logger.warning("unknown_websocket_message", message=data)
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        logger.error("websocket_error", error=str(e))
        manager.disconnect(websocket)
