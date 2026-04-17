"""Tests for Phase 5.3: Scenario collector and replay mode."""

import os
import pytest
import asyncio

os.environ["PYTEST_CURRENT_TEST"] = "true"

from backend.collectors.scenario import ScenarioCollector, SCENARIOS


def _run(coro):
    """Helper to run async functions in sync tests."""
    return asyncio.get_event_loop().run_until_complete(coro)


class TestScenarioCollector:
    def test_scenario_collector_lists_available_scenarios(self):
        assert "recon" in SCENARIOS
        assert "credential_exploit" in SCENARIOS
        assert "ddos_circuit" in SCENARIOS

    def test_scenarios_are_callable_builders(self):
        """SCENARIOS values are builder functions that return lists of snapshot dicts."""
        for name, builder in SCENARIOS.items():
            assert callable(builder), f"{name} should be a callable builder"
            steps = builder()
            assert isinstance(steps, list), f"{name} builder should return a list"
            assert len(steps) >= 2, f"{name} should have at least 2 steps"

    def test_load_valid_scenario(self):
        sc = ScenarioCollector()
        assert sc.load_scenario("recon") is True

    def test_load_invalid_scenario(self):
        sc = ScenarioCollector()
        assert sc.load_scenario("nonexistent") is False

    def test_collect_returns_snapshot(self):
        sc = ScenarioCollector()
        sc.load_scenario("recon")
        snapshot = _run(sc.collect())
        assert snapshot.snapshot_id is not None
        assert len(snapshot.backends) > 0

    def test_collect_advances_through_scenario_steps(self):
        sc = ScenarioCollector()
        sc.load_scenario("recon")
        s1 = _run(sc.collect())
        s2 = _run(sc.collect())
        assert s1.snapshot_id != s2.snapshot_id

    def test_scenario_resets_after_completion(self):
        sc = ScenarioCollector()
        sc.load_scenario("recon")
        steps = sc.steps
        for _ in range(len(steps)):
            _run(sc.collect())
        s_after_reset = _run(sc.collect())
        assert s_after_reset is not None

    def test_credential_exploit_scenario_has_credential_threat(self):
        sc = ScenarioCollector()
        sc.load_scenario("credential_exploit")
        found = False
        for _ in range(len(sc.steps) + 2):
            snapshot = _run(sc.collect())
            for t in snapshot.threats:
                if t.technique_id == "QTT007":
                    found = True
                    break
            if found:
                break
        assert found, "credential_exploit scenario should contain QTT007 threat"

    def test_recon_scenario_has_campaign_event(self):
        sc = ScenarioCollector()
        sc.load_scenario("recon")
        found = False
        for _ in range(len(sc.steps) + 2):
            snapshot = _run(sc.collect())
            for t in snapshot.threats:
                if "CORR:" in t.technique_id:
                    found = True
                    break
            if found:
                break
        assert found, "recon scenario should contain a CORR campaign event"


class TestScenarioAPIEndpoints:
    def test_list_scenarios(self):
        from fastapi.testclient import TestClient
        from backend.main import app
        client = TestClient(app)
        response = client.get("/api/scenario/list")
        assert response.status_code == 200
        data = response.json()
        assert "scenarios" in data
        assert "recon" in data["scenarios"]
        assert "credential_exploit" in data["scenarios"]
        assert "ddos_circuit" in data["scenarios"]
