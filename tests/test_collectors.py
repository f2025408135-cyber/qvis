import pytest
import asyncio
from backend.collectors.mock import MockCollector
from backend.collectors.ibm import IBMQuantumCollector
from backend.threat_engine.models import SimulationSnapshot, Severity
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
        
        # In IBM collector we safely do await asyncio.to_thread(backend.status)
        # So we just mock the return value of that call. 
        mock_status = MagicMock()
        mock_status.operational = True
        mock_backend.status = lambda: mock_status
        
        mock_config = MagicMock()
        mock_config.n_qubits = 5
        mock_config.simulator = False
        mock_config.max_experiments = 100
        mock_backend.configuration = lambda: mock_config
        
        class MockParam:
            def __init__(self, name, value):
                self.name = name
                self.value = value

        mock_props = MagicMock()
        mock_props.qubits = [[MockParam("T1", 0.000025), MockParam("T2", 0.000050), MockParam("readout_error", 0.06)]]
        # Avoid MagicMock vs Float error by ensuring properties is a function returning the mock object
        mock_backend.properties = lambda: mock_props
        
        # Same for backends and jobs
        mock_service_instance.backends = lambda: [mock_backend]
        mock_service_instance.jobs = lambda **kwargs: []
        
        collector = IBMQuantumCollector("fake-token")
        snapshot = await collector.collect()
        
        assert isinstance(snapshot, SimulationSnapshot)
        assert len(snapshot.backends) == 1
        assert snapshot.backends[0].name == "ibm_fake"
        assert snapshot.backends[0].num_qubits == 5
        assert len(snapshot.backends[0].calibration) == 1
        
        assert snapshot.backends[0].threat_level == Severity.high
    finally:
        del sys.modules['qiskit_ibm_runtime']

@pytest.mark.asyncio
async def test_ibm_collector_auth_failure_graceful_degradation():
    mock_qiskit = MagicMock()
    mock_service_class = MagicMock()
    mock_service_class.side_effect = Exception("Auth failed")
    mock_qiskit.QiskitRuntimeService = mock_service_class
    sys.modules['qiskit_ibm_runtime'] = mock_qiskit
    
    try:
        collector = IBMQuantumCollector("bad-token")
        snapshot = await collector.collect()
        
        assert len(snapshot.backends) == 0
        assert snapshot.snapshot_id == "empty-snapshot"
        assert snapshot.collection_metadata["degraded"] == True
    finally:
        del sys.modules['qiskit_ibm_runtime']
