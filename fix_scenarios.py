import re
with open("backend/main.py", "r") as f:
    content = f.read()

# Oh, the regex might have removed the new implementations I had added recently instead of the old ones!
# Let me rewrite all three methods at the correct spot!
scenario_endpoints = """
@app.post("/api/scenario/load")
async def load_scenario(name: str, _auth: None = Depends(verify_api_key)):
    \"\"\"Load a pre-recorded attack scenario for playback.\"\"\"
    import re
    if not re.match(r'^[a-zA-Z0-9_\\-]+$', name):
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
    \"\"\"List all available scenario names.\"\"\"
    from backend.collectors.scenario import SCENARIOS
    return {"scenarios": list(SCENARIOS.keys())}

@app.post("/api/scenario/reset")
async def reset_scenario(_auth: None = Depends(verify_api_key)):
    \"\"\"Reset to the default mock collector after a scenario playback.\"\"\"
    global collector, active_scenario
    if active_scenario.get("name") is None:
        return {"status": "already_default", "message": "No scenario is active"}

    from backend.collectors.mock import MockCollector
    collector = MockCollector()
    active_scenario["name"] = None
    analyzer.reset()
    correlator.reset()
    baseline_manager.reset()
    logger.info("scenario_reset_to_mock")
    return {"status": "reset", "message": "Collector reset to mock mode"}
"""

# Let's completely replace the scenario endpoints
content = re.sub(
    r'@app\.post\("/api/scenario/load"\).*?@app\.get\("/\{full_path:path\}"\)',
    scenario_endpoints.strip() + '\n\n@app.get("/{full_path:path}")',
    content,
    flags=re.DOTALL
)

with open("backend/main.py", "w") as f:
    f.write(content)
