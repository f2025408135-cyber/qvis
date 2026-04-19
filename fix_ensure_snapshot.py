import re
with open("backend/main.py", "r") as f:
    content = f.read()

ensure_snapshot_str = """
async def _ensure_snapshot():
    \"\"\"Return the latest snapshot, initialising if necessary.

    Uses _snapshot_lock so API reads never observe a partially-built
    snapshot while the simulation loop is writing a new one.
    \"\"\"
    global latest_snapshot
    async with _snapshot_lock:
        if latest_snapshot is None:
            latest_snapshot = analyzer.analyze(await collector.collect())
        return latest_snapshot


"""

content = content.replace("@app.get(\"/api/snapshot\"", ensure_snapshot_str + "@app.get(\"/api/snapshot\"")

with open("backend/main.py", "w") as f:
    f.write(content)
