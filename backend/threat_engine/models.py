from enum import Enum
from typing import Optional, Dict, List, Tuple, Any
from datetime import datetime
from pydantic import BaseModel, Field

class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"

class Platform(str, Enum):
    ibm_quantum = "ibm_quantum"
    amazon_braket = "amazon_braket"
    azure_quantum = "azure_quantum"

class QubitCalibration(BaseModel):
    qubit_id: int
    t1_us: float
    t2_us: float
    readout_error: float
    gate_error_cx: Optional[float] = None

class BackendNode(BaseModel):
    id: str
    name: str
    platform: Platform
    num_qubits: int
    is_simulator: bool
    operational: bool
    calibration: List[QubitCalibration]
    api_surface_score: float
    threat_level: Severity
    position_hint: Optional[Tuple[float, float, float]] = None

class ThreatEvent(BaseModel):
    id: str
    technique_id: str
    technique_name: str
    severity: Severity
    platform: Platform
    backend_id: Optional[str] = None
    title: str
    description: str
    evidence: dict
    detected_at: datetime
    visual_effect: str
    visual_intensity: float
    remediation: List[str]

class SimulationSnapshot(BaseModel):
    snapshot_id: str
    generated_at: datetime
    backends: List[BackendNode]
    threats: List[ThreatEvent]
    entanglement_pairs: List[Tuple[str, str]]
    total_qubits: int
    total_threats: int
    threats_by_severity: Dict[str, int]
    platform_health: Dict[str, float]
    
    # We must allow extra fields because the threat analyzer rules look for raw 
    # platform telemetry mixed into the snapshot dictionary
    model_config = {
        "extra": "allow"
    }
