import re
with open("backend/main.py", "r") as f:
    content = f.read()

# Replace any lingering imports and function calls of old `backend.storage.database`
content = content.replace("from backend.storage.database import get_threat_stats", "    pass")
content = content.replace("from backend.storage.database import get_threats", "    pass")

# Remove remaining db calls
content = re.sub(
    r'@app\.get\("/api/threats/history".*?@app\.get\("/api/admin/retention"',
    """
@app.get("/api/threats/history", tags=["threats"])
async def get_threat_history(
    limit: int = Query(default=100, ge=1, le=1000, description="Max events to return"),
    severity: Optional[str] = Query(default=None, description="Filter by severity"),
    _auth: None = Depends(verify_api_key),
):
    \"\"\"Returns paginated, historically persisted threat events.\"\"\"
    threats = await db.get_recent_threats(limit=limit, severity=severity)
    return threats

@app.get("/api/threats/stats", tags=["threats"])
async def get_threat_stats_endpoint(_auth: None = Depends(verify_api_key)):
    \"\"\"Returns aggregated statistics over all persisted threat events.\"\"\"
    stats = await db.get_threat_stats()
    return stats

@app.get("/api/admin/retention"
""",
    content,
    flags=re.DOTALL
)

with open("backend/main.py", "w") as f:
    f.write(content)

