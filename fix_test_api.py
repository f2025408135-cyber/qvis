import re
with open("backend/main.py", "r") as f:
    content = f.read()

# `active_scenario` is missing from the global state block.
state_block = """
_snapshot_lock = asyncio.Lock()
analyzer = ThreatAnalyzer()
correlator = ThreatCorrelator()
baseline_manager = BaselineManager(z_threshold=2.5)
github_scanner = None
active_scenario = {"name": None}
"""
content = content.replace("github_scanner = None", "github_scanner = None\nactive_scenario = {\"name\": None}")

# Why did test_load_and_reset_scenario fail with 405 Method Not Allowed?
# Wait, let's see what `test_load_and_reset_scenario` calls: `client.post("/api/scenario/load?name=recon")`. Is it `load`?
# In chunk 14 it says `POST /api/scenarios/{name}/start`. Wait, let's check `main.py`
