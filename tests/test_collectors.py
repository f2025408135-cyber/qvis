import pytest
import asyncio
from backend.collectors.mock import MockCollector
from backend.threat_engine.models import SimulationSnapshot

@pytest.fixture
def mock_collector():
    return MockCollector()

@pytest.mark.asyncio
async def test_mock_collector_returns_simulation_snapshot(mock_collector):
    snapshot = await mock_collector.collect()
    assert isinstance(snapshot, SimulationSnapshot)

@pytest.mark.asyncio
async def test_mock_collector_has_4_backends(mock_collector):
    snapshot = await mock_collector.collect()
    assert len(snapshot.backends) == 4

@pytest.mark.asyncio
async def test_mock_collector_has_expected_threat_events(mock_collector):
    snapshot = await mock_collector.collect()
    assert len(snapshot.threats) == 4
    threat_ids = [t.id for t in snapshot.threats]
    assert "threat-1" in threat_ids
    assert "threat-2" in threat_ids

@pytest.mark.asyncio
async def test_all_threat_events_have_valid_visual_effects(mock_collector):
    snapshot = await mock_collector.collect()
    valid_effects = [
        "timing_ring", "particle_leak", "color_bleed", "vortex",
        "calibration_drain", "interference", "none"
    ]
    for threat in snapshot.threats:
        assert threat.visual_effect in valid_effects
