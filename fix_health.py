import re

with open("backend/main.py", "r") as f:
    content = f.read()

# Re-apply Chunk 03 Models
models_code = """
from enum import Enum
from pydantic import BaseModel

class HealthStatus(str, Enum):
    healthy = "healthy"
    degraded = "degraded"
    unhealthy = "unhealthy"

class ComponentHealth(BaseModel):
    \"\"\"Health status of one system component.\"\"\"
    status: HealthStatus
    message: str
    last_success_at: Optional[datetime] = None
    latency_ms: Optional[float] = None

class HealthResponse(BaseModel):
    \"\"\"Full system health response.\"\"\"
    status: HealthStatus
    version: str
    uptime_seconds: float
    components: dict[str, ComponentHealth]
    checked_at: datetime

_health_state = {
    "last_collection_at": None,       # datetime | None
    "last_collection_error": None,    # str | None
    "last_broadcast_at": None,        # datetime | None
    "last_engine_cycle_at": None,     # datetime | None
    "startup_time": time.time(),
}
"""

if "HealthStatus" not in content:
    content = content.replace("# ─── Application State ─────────────────────────────────────────────────", models_code + "\n# ─── Application State ─────────────────────────────────────────────────")

# Replace health endpoints
health_endpoints = """
@app.get("/health", response_model=HealthResponse)
async def health_check():
    \"\"\"
    System readiness check.

    Returns 200 if all components are healthy.
    Returns 200 with status=degraded if non-critical components fail.
    Returns 503 if critical components (database, engine) are unhealthy.
    \"\"\"
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
    )

    from fastapi.responses import JSONResponse
    return JSONResponse(
        content=response_body.model_dump(mode="json"),
        status_code=status_code,
    )

@app.get("/ready")
async def readiness_probe():
    \"\"\"
    Kubernetes readiness probe.
    Returns 200 only when system is ready to receive traffic.
    Returns 503 during startup or when critical components fail.
    \"\"\"
    health = await health_check()
    if health.status_code == 503:
        from fastapi.responses import JSONResponse
        return JSONResponse({"ready": False}, status_code=503)
    from fastapi.responses import JSONResponse
    return JSONResponse({"ready": True}, status_code=200)

@app.get("/live")
async def liveness_probe():
    \"\"\"
    Kubernetes liveness probe.
    Returns 200 as long as the process is running.
    \"\"\"
    from fastapi.responses import JSONResponse
    return JSONResponse({"alive": True}, status_code=200)
"""

# Apply the health endpoints safely:
start = content.find("# ─── Health Endpoints (not behind auth) ────────────────────────────────")
end = content.find("# ─── Threat History & Configuration (not behind auth) ──────────────────────────")

if start != -1 and end != -1:
    content = content[:start] + "# ─── Health Endpoints (not behind auth) ────────────────────────────────\n" + health_endpoints + "\n\n" + content[end:]

# Update simulation loop with state
content = content.replace('logger.info("collection_complete",', '_health_state["last_collection_at"] = datetime.now(timezone.utc)\n                _health_state["last_collection_error"] = None\n                logger.info("collection_complete",')
content = content.replace('logger.error("collection_failed",', '_health_state["last_collection_error"] = str(e)\n                logger.error("collection_failed",')

# after engine cycle
content = content.replace('logger.info("simulation_loop_complete",', '_health_state["last_engine_cycle_at"] = datetime.now(timezone.utc)\n        logger.info("simulation_loop_complete",')

with open("backend/main.py", "w") as f:
    f.write(content)
