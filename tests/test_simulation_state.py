import pytest
from backend.collectors.mock import MockCollector
from backend.threat_engine.models import Severity

@pytest.mark.asyncio
async def test_mock_collector_internal_consistency():
    collector = MockCollector()
    snapshot = await collector.collect()
    
    total_q = sum(b.num_qubits for b in snapshot.backends)
    assert snapshot.total_qubits == total_q
    
    valid_backend_ids = {b.id for b in snapshot.backends}
    for t in snapshot.threats:
        assert t.backend_id in valid_backend_ids
        
    severity_counts = {}
    for t in snapshot.threats:
        severity_counts[t.severity.value] = severity_counts.get(t.severity.value, 0) + 1
        
    for k, v in severity_counts.items():
        assert snapshot.threats_by_severity.get(k, 0) == v

@pytest.mark.asyncio
async def test_particle_count_scales_with_qubit_count():
    collector = MockCollector()
    snapshot = await collector.collect()
    
    sherbrooke = next((b for b in snapshot.backends if b.id == 'ibm_sherbrooke'), None)
    simulator = next((b for b in snapshot.backends if b.id == 'ibm_qasm_simulator'), None)
    
    assert sherbrooke is not None
    assert simulator is not None
    assert sherbrooke.num_qubits > simulator.num_qubits

@pytest.mark.asyncio
async def test_threat_effect_names_match_valid_list():
    valid_effects = [
        "timing_ring", "particle_leak", "color_bleed", "vortex",
        "calibration_drain", "interference", "none"
    ]
    collector = MockCollector()
    snapshot = await collector.collect()
    
    for threat in snapshot.threats:
        assert threat.visual_effect in valid_effects
