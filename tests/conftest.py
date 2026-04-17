"""Shared test fixtures for QVis threat engine tests.

Centralises common builders so every test file uses the same canonical
data shapes, reducing duplication and guaranteeing consistency when
source interfaces evolve.
"""

import pytest
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List

from backend.threat_engine.models import (
    BackendNode,
    QubitCalibration,
    Severity,
    Platform,
    SimulationSnapshot,
    ThreatEvent,
)


# ────────────────────────────────────────────────────────────────────
#  Qubit & backend builders
# ────────────────────────────────────────────────────────────────────

def _make_qubit(
    qubit_id: int = 0,
    t1_us: float = 100.0,
    t2_us: float = 80.0,
    readout_error: float = 0.02,
    gate_error_cx: float = 0.01,
) -> QubitCalibration:
    return QubitCalibration(
        qubit_id=qubit_id,
        t1_us=t1_us,
        t2_us=t2_us,
        readout_error=readout_error,
        gate_error_cx=gate_error_cx,
    )


@pytest.fixture
def sample_ibm_backend() -> BackendNode:
    """A typical healthy IBM Quantum backend with 5 qubits."""
    return BackendNode(
        id="ibm_osaka",
        name="IBM Osaka",
        platform=Platform.ibm_quantum,
        num_qubits=5,
        is_simulator=False,
        operational=True,
        calibration=[_make_qubit(qid) for qid in range(5)],
        api_surface_score=0.65,
        threat_level=Severity.low,
        position_hint=(1.0, 2.0, 3.0),
    )


# ────────────────────────────────────────────────────────────────────
#  Calibration data
# ────────────────────────────────────────────────────────────────────

@pytest.fixture
def normal_calibration_data() -> Dict[str, Dict[str, float]]:
    """Baseline calibration for 5 qubits (t1_us = 100 each).

    Mirrors the shape expected by RULE_008:
        ``data["baseline_calibration"]["0"]["t1_us"]``
    """
    return {
        str(qid): {"t1_us": 100.0, "t2_us": 80.0}
        for qid in range(5)
    }


# ────────────────────────────────────────────────────────────────────
#  Threat event builders
# ────────────────────────────────────────────────────────────────────

def _make_threat(
    technique_id: str = "QTT001",
    technique_name: str = "Test Threat",
    severity: Severity = Severity.medium,
    platform: Platform = Platform.ibm_quantum,
    backend_id: str = "test_backend",
    detected_at: datetime | None = None,
) -> ThreatEvent:
    return ThreatEvent(
        id="test-event-001",
        technique_id=technique_id,
        technique_name=technique_name,
        severity=severity,
        platform=platform,
        backend_id=backend_id,
        title=f"Test: {technique_name}",
        description="Synthetic threat event for testing.",
        evidence={"source": "test"},
        detected_at=detected_at or datetime.now(timezone.utc),
        visual_effect="none",
        visual_intensity=0.5,
        remediation=["Review and investigate."],
    )


@pytest.fixture
def sample_threat_events() -> List[ThreatEvent]:
    """A handful of diverse threat events for correlator/analyzer tests."""
    now = datetime.now(timezone.utc)
    return [
        _make_threat("QTT003", "Timing Oracle", Severity.high, backend_id="backend_a", detected_at=now),
        _make_threat("QTT002", "Calibration Harvesting", Severity.medium, backend_id="backend_a", detected_at=now),
        _make_threat("QTT004", "Tenant Probing", Severity.high, backend_id="backend_b", detected_at=now),
        _make_threat("QTT006", "IP Extraction", Severity.critical, backend_id="backend_b", detected_at=now),
        _make_threat("QTT007", "Credential Exposure", Severity.critical, backend_id="backend_c", detected_at=now - timedelta(minutes=45)),
    ]


# ────────────────────────────────────────────────────────────────────
#  Snapshot builder
# ────────────────────────────────────────────────────────────────────

@pytest.fixture
def mock_snapshot(sample_ibm_backend) -> SimulationSnapshot:
    """An empty snapshot wired to *sample_ibm_backend*."""
    return SimulationSnapshot(
        snapshot_id="test-snap-001",
        generated_at=datetime.now(timezone.utc),
        backends=[sample_ibm_backend],
        threats=[],
        entanglement_pairs=[],
        total_qubits=sample_ibm_backend.num_qubits,
        total_threats=0,
        threats_by_severity={},
        platform_health={"ibm_quantum": 0.95},
    )


# ────────────────────────────────────────────────────────────────────
#  Threshold config isolation
# ────────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _reset_threshold_config():
    """Every test starts with the module-level threshold config cleared
    so that one test's custom config never leaks into another."""
    from backend.threat_engine.rules import set_threshold_config
    set_threshold_config(None)
    yield
    set_threshold_config(None)


@pytest.fixture(autouse=True)
def _reset_rate_limiter_state():
    """Every test starts with a clean rate limiter state so that one test's
    tracked IPs don't leak into the next (preventing flaky tests)."""
    import backend.api.ratelimit as _rl
    saved_windows = _rl._rate_windows
    saved_count = _rl._ip_count
    _rl._rate_windows = _rl.defaultdict(dict)  # Must preserve defaultdict type
    _rl._ip_count = 0
    yield
    _rl._rate_windows = saved_windows
    _rl._ip_count = saved_count
