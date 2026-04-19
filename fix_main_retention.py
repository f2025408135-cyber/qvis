import re

with open("backend/main.py", "r") as f:
    content = f.read()

# Add the import and task launcher in the `lifespan` manager, right near where `simulation_loop` starts.
import_str = "from backend.tasks.retention import retention_loop\n"

if import_str not in content:
    content = content.replace("from backend.config import settings", import_str + "from backend.config import settings")

task_start_str = """    logger.info("starting_retention_loop")
    retention_task = asyncio.create_task(
        retention_loop(
            db=db,
            retention_days=settings.threat_retention_days,
            check_interval_hours=settings.retention_check_interval_hours,
        ),
        name="retention_loop",
    )"""

content = content.replace("    task = asyncio.create_task(simulation_loop())", "    task = asyncio.create_task(simulation_loop())\n" + task_start_str)
content = content.replace("    task.cancel()", "    task.cancel()\n    retention_task.cancel()")

# Replace `get_retention_stats_endpoint`
api_str = """
@app.post("/api/admin/retention/run", tags=["admin"])
async def run_retention_now(_auth: None = Depends(verify_api_key)):
    \"\"\"
    Manually trigger a retention cleanup cycle.
    Requires authentication. Returns count of deleted records.
    \"\"\"
    deleted = await db.delete_threats_older_than(
        settings.threat_retention_days
    )
    return {"deleted": deleted, "retention_days": settings.threat_retention_days}
"""

content = re.sub(r'@app\.get\("/api/admin/retention".*?(?=@app\.get\("/api/scenario/list"\))', api_str + "\n\n", content, flags=re.DOTALL)

with open("backend/main.py", "w") as f:
    f.write(content)
