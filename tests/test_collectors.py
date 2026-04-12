import pytest
import asyncio
from backend.collectors.mock import MockCollector
from backend.collectors.ibm import IBMQuantumCollector
from backend.threat_engine.models import SimulationSnapshot
from unittest.mock import patch, MagicMock
import sys

@pytest.fixture
def mock_collector():
    collector = MockCollector()
    collector.is_test = True
    return collector

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

@pytest.mark.asyncio
async def test_ibm_collector_returns_empty_when_no_token():
    collector = IBMQuantumCollector("")
    snapshot = await collector.collect()
    assert len(snapshot.backends) == 0
    assert snapshot.snapshot_id == "empty-snapshot"

@pytest.mark.asyncio
async def test_ibm_collector_returns_simulation_snapshot():
    # We must mock qiskit_ibm_runtime so it doesn't fail import if not installed
    mock_qiskit = MagicMock()
    mock_service_class = MagicMock()
    mock_qiskit.QiskitRuntimeService = mock_service_class
    sys.modules['qiskit_ibm_runtime'] = mock_qiskit
    
    try:
        mock_service_instance = mock_service_class.return_value
        
        mock_backend = MagicMock()
        mock_backend.name = "ibm_fake"
        mock_backend.num_qubits = 5
        mock_backend.simulator = False
        mock_status = MagicMock()
        mock_status.operational = True
        mock_backend.status.return_value = mock_status
        
        mock_service_instance.backends.return_value = [mock_backend]
        
        collector = IBMQuantumCollector("fake-token")
        snapshot = await collector.collect()
        
        assert isinstance(snapshot, SimulationSnapshot)
        assert len(snapshot.backends) == 1
        assert snapshot.backends[0].name == "ibm_fake"
        assert snapshot.backends[0].num_qubits == 5
    finally:
        del sys.modules['qiskit_ibm_runtime']

