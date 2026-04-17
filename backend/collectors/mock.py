import uuid
import random
import copy
from datetime import datetime, timezone
from backend.threat_engine.models import SimulationSnapshot
from backend.collectors.base import BaseCollector

MOCK_DATA = {
  "snapshot_id": "mock-snapshot-001",
  "generated_at": "2023-10-27T10:00:00Z",
  "backends": [
    {
      "id": "ibm_sherbrooke",
      "name": "ibm_sherbrooke",
      "platform": "ibm_quantum",
      "num_qubits": 127,
      "is_simulator": False,
      "operational": True,
      "calibration": [
        {"qubit_id": 0, "t1_us": 100.0, "t2_us": 80.0, "readout_error": 0.01, "gate_error_cx": 0.005}
      ],
      "api_surface_score": 0.8,
      "threat_level": "critical",
      "position_hint": None
    },
    {
      "id": "ibm_kyoto",
      "name": "ibm_kyoto",
      "platform": "ibm_quantum",
      "num_qubits": 127,
      "is_simulator": False,
      "operational": True,
      "calibration": [
        {"qubit_id": 0, "t1_us": 90.0, "t2_us": 70.0, "readout_error": 0.015, "gate_error_cx": 0.008}
      ],
      "api_surface_score": 0.5,
      "threat_level": "medium",
      "position_hint": None
    },
    {
      "id": "ibm_brisbane",
      "name": "ibm_brisbane",
      "platform": "ibm_quantum",
      "num_qubits": 127,
      "is_simulator": False,
      "operational": True,
      "calibration": [
        {"qubit_id": 0, "t1_us": 110.0, "t2_us": 90.0, "readout_error": 0.009, "gate_error_cx": 0.004}
      ],
      "api_surface_score": 0.2,
      "threat_level": "info",
      "position_hint": None
    },
    {
      "id": "ibm_qasm_simulator",
      "name": "ibm_qasm_simulator",
      "platform": "ibm_quantum",
      "num_qubits": 32,
      "is_simulator": True,
      "operational": True,
      "calibration": [],
      "api_surface_score": 0.9,
      "threat_level": "medium",
      "position_hint": None
    }
  ],
  "threats": [
    {
      "id": "threat-1",
      "technique_id": "QTT007",
      "technique_name": "Credential Exposure",
      "severity": "critical",
      "platform": "ibm_quantum",
      "backend_id": "ibm_sherbrooke",
      "title": "Credential exposure in public notebook",
      "description": "A valid IBM Quantum API token was found in a public GitHub repository.",
      "evidence": {
        "repo": "github.com/example/qml-tutorial",
        "file": "tutorial.ipynb",
        "line": 23,
        "pattern": "QiskitRuntimeService(token="
      },
      "detected_at": "2023-10-27T09:45:00Z",
      "visual_effect": "particle_leak",
      "visual_intensity": 0.9,
      "remediation": [
        "Revoke the exposed token immediately in the IBM Quantum portal.",
        "Scrub the token from the Git history using BFG or git-filter-repo.",
        "Use environment variables (.env files) for token storage."
      ]
    },
    {
      "id": "threat-2",
      "technique_id": "QTT003",
      "technique_name": "Timing Oracle",
      "severity": "high",
      "platform": "ibm_quantum",
      "backend_id": "ibm_sherbrooke",
      "title": "Job timing oracle pattern detected",
      "description": "Repeated submission of identity-heavy circuits, suggesting an attempt to characterize system noise or timing patterns.",
      "evidence": {
        "job_count": 47,
        "avg_depth": 1.2,
        "identity_ratio": 0.89
      },
      "detected_at": "2023-10-27T09:50:00Z",
      "visual_effect": "timing_ring",
      "visual_intensity": 0.7,
      "remediation": [
        "Review user job history for anomalous patterns.",
        "Implement rate limiting for low-depth, identity-heavy circuits."
      ]
    },
    {
      "id": "threat-3",
      "technique_id": "QTT002",
      "technique_name": "Calibration Harvesting",
      "severity": "medium",
      "platform": "ibm_quantum",
      "backend_id": "ibm_sherbrooke",
      "title": "Systematic calibration data harvesting",
      "description": "High frequency of backend properties requests without corresponding job submissions.",
      "evidence": {
        "calibration_requests_last_hour": 150,
        "job_submissions_last_hour": 2
      },
      "detected_at": "2023-10-27T09:55:00Z",
      "visual_effect": "calibration_drain",
      "visual_intensity": 0.5,
      "remediation": [
        "Monitor for unauthorized automated access to properties endpoints.",
        "Implement fair-use limits on metadata endpoints."
      ]
    },
    {
      "id": "threat-4",
      "technique_id": "QTT008",
      "technique_name": "Resource Exhaustion",
      "severity": "medium",
      "platform": "ibm_quantum",
      "backend_id": "ibm_qasm_simulator",
      "title": "Resource exhaustion circuit pattern",
      "description": "Circuit submitted with extremely high depth approaching maximum limits.",
      "evidence": {
        "job_depth": 9800,
        "max_allowed_depth": 10000
      },
      "detected_at": "2023-10-27T09:58:00Z",
      "visual_effect": "interference",
      "visual_intensity": 0.4,
      "remediation": [
        "Reject circuits exceeding practical depth limits.",
        "Review user allocation limits."
      ]
    }
  ],
  "entanglement_pairs": [
    ["ibm_sherbrooke", "ibm_kyoto"],
    ["ibm_kyoto", "ibm_brisbane"]
  ],
  "total_qubits": 413,
  "total_threats": 4,
  "threats_by_severity": {
    "critical": 1,
    "high": 1,
    "medium": 2,
    "low": 0,
    "info": 0
  },
  "platform_health": {
    "ibm_quantum": 0.75
  }
}

class MockCollector(BaseCollector):
    def __init__(self):
        self.base_data = copy.deepcopy(MOCK_DATA)
        self.is_test = False # flag for deterministic tests

    async def collect(self) -> SimulationSnapshot:
        if self.is_test:
            # Always return a fresh clean copy of base mock data so tests pass deterministically
            data = copy.deepcopy(MOCK_DATA)
            data["snapshot_id"] = str(uuid.uuid4())
            now_iso = datetime.now(timezone.utc).isoformat()
            data["generated_at"] = now_iso
            # Update threat timestamps to current time so correlator works
            for threat in data.get("threats", []):
                threat["detected_at"] = now_iso
            return SimulationSnapshot(**data)

        data = copy.deepcopy(self.base_data)

        data["snapshot_id"] = str(uuid.uuid4())
        now_iso = datetime.now(timezone.utc).isoformat()
        data["generated_at"] = now_iso
        # Update threat timestamps to current time so correlator works
        for threat in data.get("threats", []):
            threat["detected_at"] = now_iso

        for backend in data["backends"]:
            variation = random.uniform(-0.1, 0.1)
            backend["api_surface_score"] = max(0.0, min(1.0, backend["api_surface_score"] + variation))
            
            for cal in backend["calibration"]:
                cal["t1_us"] = cal["t1_us"] * random.uniform(0.95, 1.05)

        if random.random() < 0.2:
            if len(data["threats"]) > 4 and random.random() > 0.5:
                removed = data["threats"].pop(random.randrange(len(data["threats"])))
                data["total_threats"] -= 1
                sev_key = removed["severity"]
                data["threats_by_severity"][sev_key] = max(0, data["threats_by_severity"].get(sev_key, 0) - 1)
            elif len(data["threats"]) < 10:
                if data["threats"]:
                    new_threat = copy.deepcopy(random.choice(data["threats"]))
                    new_threat["id"] = f"threat-{uuid.uuid4()}"
                    data["threats"].append(new_threat)
                    data["total_threats"] += 1
                    sev_key = new_threat["severity"]
                    data["threats_by_severity"][sev_key] = data["threats_by_severity"].get(sev_key, 0) + 1

        self.base_data = data 
        
        return SimulationSnapshot(**data)
