import re
with open("tests/test_fallbacks.py", "r") as f:
    content = f.read()

# Since `active_collector` and `connected_platforms` were part of backward compatibility for the `/api/health` endpoint, we need to ensure `/health` has them or fix the test to expect it.
# Wait, the prompt says "Returns overall status, version, uptime, database connectivity, collector health, and platform information. Backward-compatible with existing fields (status, demo_mode, active_collector, connected_platforms)."
# My health check doesn't include these fields. I need to add them to `HealthResponse` model and logic.

with open("backend/main.py", "r") as f:
    main_content = f.read()

# Add backward-compatible fields to HealthResponse
models_update = """
class HealthResponse(BaseModel):
    \"\"\"Full system health response.\"\"\"
    status: HealthStatus
    version: str
    uptime_seconds: float
    components: dict[str, ComponentHealth]
    checked_at: datetime
    # Backward compatibility
    demo_mode: bool
    active_collector: str
    connected_platforms: list[str]
"""
main_content = re.sub(r'class HealthResponse\(BaseModel\):\n.*?    checked_at: datetime', models_update.strip(), main_content, flags=re.DOTALL)

# Add them to response_body = HealthResponse(...)
logic_update = """
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
"""
main_content = re.sub(r'    response_body = HealthResponse\(\n.*?    \)', logic_update.strip(), main_content, flags=re.DOTALL)

with open("backend/main.py", "w") as f:
    f.write(main_content)

