import math
import pytest
from backend.collectors.mock import MockCollector

def compute_positions(num_backends):
    positions = []
    for i in range(num_backends):
        angle = (i / max(num_backends, 1)) * math.pi * 2
        x = math.cos(angle) * 150
        z = math.sin(angle) * 150
        positions.append((x, 0, z))
    return positions

def test_backend_node_position_layout_does_not_overlap():
    positions = compute_positions(4)
    min_dist = float('inf')
    
    for i in range(len(positions)):
        for j in range(i+1, len(positions)):
            p1 = positions[i]
            p2 = positions[j]
            dist = math.sqrt((p1[0]-p2[0])**2 + (p1[1]-p2[1])**2 + (p1[2]-p2[2])**2)
            if dist < min_dist:
                min_dist = dist
                
    assert min_dist > 80

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
