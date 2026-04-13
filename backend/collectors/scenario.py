"""
ScenarioCollector — plays back pre-recorded attack sequences for demonstration.

Extends BaseCollector with three built-in scenarios:
  - 'recon':            Progressive reconnaissance campaign (calibration harvest → timing oracle → campaign correlation)
  - 'credential_exploit': Credential exposure leading to active exploitation (credential leak → timing oracle → pre-attack staging)
  - 'ddos_circuit':      Resource exhaustion DDoS (escalating circuit depth attacks across backends)

Each scenario is a list of snapshot dicts returned sequentially via collect().
Resets to the beginning when all snapshots have been played.
"""

import uuid
import copy
from datetime import datetime, timezone, timedelta
from backend.threat_engine.models import SimulationSnapshot
from backend.collectors.base import BaseCollector


def _make_backend(bid, name, platform, qubits, is_sim=False, t1=100.0, t2=80.0, ro_err=0.01, gate_err=0.005, threat_level="info", api_score=0.3):
    return {
        "id": bid,
        "name": name,
        "platform": platform,
        "num_qubits": qubits,
        "is_simulator": is_sim,
        "operational": True,
        "calibration": [
            {"qubit_id": 0, "t1_us": t1, "t2_us": t2, "readout_error": ro_err, "gate_error_cx": gate_err}
        ] if not is_sim else [],
        "api_surface_score": api_score,
        "threat_level": threat_level,
        "position_hint": None,
    }


def _make_threat(tid, technique_id, technique_name, severity, platform, backend_id,
                 title, description, evidence, visual_effect, visual_intensity, remediation, minutes_ago=0):
    return {
        "id": tid,
        "technique_id": technique_id,
        "technique_name": technique_name,
        "severity": severity,
        "platform": platform,
        "backend_id": backend_id,
        "title": title,
        "description": description,
        "evidence": evidence,
        "detected_at": (datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)).isoformat(),
        "visual_effect": visual_effect,
        "visual_intensity": visual_intensity,
        "remediation": remediation,
    }


def _base_snapshot():
    """Return a clean baseline snapshot with no threats."""
    return {
        "snapshot_id": str(uuid.uuid4()),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "backends": [
            _make_backend("ibm_sherbrooke", "ibm_sherbrooke", "ibm_quantum", 127,
                          t1=100.0, t2=80.0, ro_err=0.01, gate_err=0.005, threat_level="info", api_score=0.3),
            _make_backend("ibm_kyoto", "ibm_kyoto", "ibm_quantum", 127,
                          t1=90.0, t2=70.0, ro_err=0.015, gate_err=0.008, threat_level="info", api_score=0.2),
            _make_backend("ibm_brisbane", "ibm_brisbane", "ibm_quantum", 127,
                          t1=110.0, t2=90.0, ro_err=0.009, gate_err=0.004, threat_level="info", api_score=0.1),
            _make_backend("ibm_qasm_simulator", "ibm_qasm_simulator", "ibm_quantum", 32,
                          is_sim=True, threat_level="info", api_score=0.4),
        ],
        "threats": [],
        "entanglement_pairs": [
            ["ibm_sherbrooke", "ibm_kyoto"],
            ["ibm_kyoto", "ibm_brisbane"],
        ],
        "total_qubits": 413,
        "total_threats": 0,
        "threats_by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        "platform_health": {"ibm_quantum": 1.0},
    }


# ─── Scenario Definitions ──────────────────────────────────────────────

SCENARIOS = {}


def _build_recon_scenario():
    """Progressive reconnaissance: calibration harvest → timing oracle → campaign correlation."""
    steps = []

    # Step 1: Clean baseline
    s1 = _base_snapshot()
    steps.append(s1)

    # Step 2: Calibration harvesting detected on ibm_kyoto
    s2 = _base_snapshot()
    s2["backends"][1]["threat_level"] = "medium"
    s2["threats"] = [
        _make_threat(
            "scenario-recon-1", "QTT002", "Calibration Harvesting", "medium",
            "ibm_quantum", "ibm_kyoto",
            "Systematic calibration data harvesting",
            "High frequency of backend properties requests without corresponding job submissions.",
            {"calibration_requests_last_hour": 150, "job_submissions_last_hour": 2},
            "calibration_drain", 0.5,
            ["Implement fair-use limits on metadata endpoints."], minutes_ago=5
        ),
    ]
    s2["total_threats"] = 1
    s2["threats_by_severity"] = {"critical": 0, "high": 0, "medium": 1, "low": 0, "info": 0}
    s2["platform_health"]["ibm_quantum"] = 0.85
    steps.append(s2)

    # Step 3: Timing oracle appears on ibm_sherbrooke
    s3 = _base_snapshot()
    s3["backends"][0]["threat_level"] = "high"
    s3["backends"][1]["threat_level"] = "medium"
    s3["threats"] = [
        _make_threat(
            "scenario-recon-2", "QTT002", "Calibration Harvesting", "medium",
            "ibm_quantum", "ibm_kyoto",
            "Systematic calibration data harvesting",
            "High frequency of backend properties requests without corresponding job submissions.",
            {"calibration_requests_last_hour": 150, "job_submissions_last_hour": 2},
            "calibration_drain", 0.5,
            ["Implement fair-use limits on metadata endpoints."], minutes_ago=15
        ),
        _make_threat(
            "scenario-recon-3", "QTT003", "Timing Oracle", "high",
            "ibm_quantum", "ibm_sherbrooke",
            "Job timing oracle pattern detected",
            "Repeated submission of identity-heavy circuits, suggesting timing characterization.",
            {"job_count": 47, "avg_depth": 1.2, "identity_ratio": 0.89},
            "timing_ring", 0.7,
            ["Implement rate limiting for low-depth circuits."], minutes_ago=3
        ),
    ]
    s3["total_threats"] = 2
    s3["threats_by_severity"] = {"critical": 0, "high": 1, "medium": 1, "low": 0, "info": 0}
    s3["platform_health"]["ibm_quantum"] = 0.7
    steps.append(s3)

    # Step 4: Campaign correlation detected (coordinated recon)
    s4 = _base_snapshot()
    s4["backends"][0]["threat_level"] = "critical"
    s4["backends"][1]["threat_level"] = "medium"
    s4["threats"] = [
        _make_threat(
            "scenario-recon-4", "QTT002", "Calibration Harvesting", "medium",
            "ibm_quantum", "ibm_kyoto",
            "Systematic calibration data harvesting",
            "High frequency of backend properties requests without corresponding job submissions.",
            {"calibration_requests_last_hour": 150, "job_submissions_last_hour": 2},
            "calibration_drain", 0.5,
            ["Implement fair-use limits on metadata endpoints."], minutes_ago=25
        ),
        _make_threat(
            "scenario-recon-5", "QTT003", "Timing Oracle", "high",
            "ibm_quantum", "ibm_sherbrooke",
            "Job timing oracle pattern detected",
            "Repeated submission of identity-heavy circuits, suggesting timing characterization.",
            {"job_count": 47, "avg_depth": 1.2, "identity_ratio": 0.89},
            "timing_ring", 0.7,
            ["Implement rate limiting for low-depth circuits."], minutes_ago=13
        ),
        _make_threat(
            "scenario-recon-6", "CORR:ibm_sherbrooke:Coordinated Reconnaissance",
            "Coordinated Reconnaissance", "critical",
            "ibm_quantum", "ibm_sherbrooke",
            "Campaign: Coordinated Reconnaissance",
            "Coordinated timing and calibration reconnaissance detected — likely a targeted QPU characterization campaign.",
            {
                "pattern_name": "Coordinated Reconnaissance",
                "techniques_found": ["QTT003", "QTT002"],
                "backend_id": "ibm_sherbrooke",
                "window_minutes": 30,
                "triggering_threats": [
                    {"id": "scenario-recon-5", "technique": "QTT003", "severity": "high"},
                    {"id": "scenario-recon-4", "technique": "QTT002", "severity": "medium"},
                ],
            },
            "campaign", 0.9,
            ["Investigate correlated activity as a coordinated campaign."], minutes_ago=1
        ),
    ]
    s4["total_threats"] = 3
    s4["threats_by_severity"] = {"critical": 1, "high": 1, "medium": 1, "low": 0, "info": 0}
    s4["platform_health"]["ibm_quantum"] = 0.5
    steps.append(s4)

    return steps


def _build_credential_exploit_scenario():
    """Credential exposure leading to active exploitation."""
    steps = []

    # Step 1: Clean
    steps.append(_base_snapshot())

    # Step 2: Credential exposure detected
    s2 = _base_snapshot()
    s2["backends"][0]["threat_level"] = "critical"
    s2["threats"] = [
        _make_threat(
            "scenario-cred-1", "QTT017", "Credential Exposure", "critical",
            "ibm_quantum", "ibm_sherbrooke",
            "Credential exposure in public notebook",
            "A valid IBM Quantum API token was found in a public GitHub repository.",
            {"repo": "github.com/example/qml-tutorial", "file": "tutorial.ipynb", "line": 23,
             "pattern": "QiskitRuntimeService(token="},
            "particle_leak", 0.9,
            ["Revoke the exposed token immediately.", "Scrub token from Git history."], minutes_ago=5
        ),
    ]
    s2["total_threats"] = 1
    s2["threats_by_severity"] = {"critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0}
    s2["platform_health"]["ibm_quantum"] = 0.6
    steps.append(s2)

    # Step 3: Timing oracle probes appear (using leaked credentials)
    s3 = _base_snapshot()
    s3["backends"][0]["threat_level"] = "critical"
    s3["threats"] = [
        _make_threat(
            "scenario-cred-2", "QTT017", "Credential Exposure", "critical",
            "ibm_quantum", "ibm_sherbrooke",
            "Credential exposure in public notebook",
            "A valid IBM Quantum API token was found in a public GitHub repository.",
            {"repo": "github.com/example/qml-tutorial", "file": "tutorial.ipynb", "line": 23},
            "particle_leak", 0.9,
            ["Revoke the exposed token immediately."], minutes_ago=30
        ),
        _make_threat(
            "scenario-cred-3", "QTT003", "Timing Oracle", "high",
            "ibm_quantum", "ibm_sherbrooke",
            "Job timing oracle pattern detected",
            "Repeated submission of identity-heavy circuits using exposed credentials.",
            {"job_count": 47, "avg_depth": 1.2, "identity_ratio": 0.89, "auth_source": "exposed_token"},
            "timing_ring", 0.7,
            ["Revoke the exposed token immediately."], minutes_ago=5
        ),
    ]
    s3["total_threats"] = 2
    s3["threats_by_severity"] = {"critical": 1, "high": 1, "medium": 0, "low": 0, "info": 0}
    s3["platform_health"]["ibm_quantum"] = 0.4
    steps.append(s3)

    # Step 4: Pre-attack staging campaign correlation
    s4 = _base_snapshot()
    s4["backends"][0]["threat_level"] = "critical"
    s4["backends"][1]["threat_level"] = "medium"
    s4["threats"] = [
        _make_threat(
            "scenario-cred-4", "QTT017", "Credential Exposure", "critical",
            "ibm_quantum", "ibm_sherbrooke",
            "Credential exposure in public notebook",
            "A valid IBM Quantum API token was found in a public GitHub repository.",
            {"repo": "github.com/example/qml-tutorial", "file": "tutorial.ipynb", "line": 23},
            "particle_leak", 0.9,
            ["Revoke the exposed token immediately."], minutes_ago=60
        ),
        _make_threat(
            "scenario-cred-5", "QTT003", "Timing Oracle", "high",
            "ibm_quantum", "ibm_sherbrooke",
            "Job timing oracle pattern detected",
            "Repeated submission of identity-heavy circuits using exposed credentials.",
            {"job_count": 47, "avg_depth": 1.2, "identity_ratio": 0.89},
            "timing_ring", 0.7,
            ["Revoke the exposed token immediately."], minutes_ago=35
        ),
        _make_threat(
            "scenario-cred-6", "CORR:ibm_sherbrooke:Pre-Attack Staging",
            "Pre-Attack Staging", "critical",
            "ibm_quantum", "ibm_sherbrooke",
            "Campaign: Pre-Attack Staging",
            "Credential exposure followed by timing oracle probes — possible active exploitation using leaked credentials.",
            {
                "pattern_name": "Pre-Attack Staging",
                "techniques_found": ["QTT017", "QTT003"],
                "backend_id": "ibm_sherbrooke",
                "window_minutes": 60,
                "triggering_threats": [
                    {"id": "scenario-cred-4", "technique": "QTT017", "severity": "critical"},
                    {"id": "scenario-cred-5", "technique": "QTT003", "severity": "high"},
                ],
            },
            "campaign", 0.9,
            ["Investigate as a coordinated campaign.", "Block the compromised credentials."], minutes_ago=1
        ),
    ]
    s4["total_threats"] = 3
    s4["threats_by_severity"] = {"critical": 2, "high": 1, "medium": 0, "low": 0, "info": 0}
    s4["platform_health"]["ibm_quantum"] = 0.25
    steps.append(s4)

    return steps


def _build_ddos_circuit_scenario():
    """Resource exhaustion / DDoS-style circuit attack escalating across backends."""
    steps = []

    # Step 1: Clean
    steps.append(_base_snapshot())

    # Step 2: Moderate circuit depth on simulator
    s2 = _base_snapshot()
    s2["backends"][3]["threat_level"] = "medium"
    s2["threats"] = [
        _make_threat(
            "scenario-ddos-1", "QTT008", "Resource Exhaustion", "medium",
            "ibm_quantum", "ibm_qasm_simulator",
            "Resource exhaustion circuit pattern",
            "Circuit submitted with high depth approaching limits on simulator.",
            {"job_depth": 5000, "max_allowed_depth": 10000},
            "interference", 0.4,
            ["Reject circuits exceeding practical depth limits."], minutes_ago=5
        ),
    ]
    s2["total_threats"] = 1
    s2["threats_by_severity"] = {"critical": 0, "high": 0, "medium": 1, "low": 0, "info": 0}
    s2["platform_health"]["ibm_quantum"] = 0.85
    steps.append(s2)

    # Step 3: Escalating depth attacks on real backends
    s3 = _base_snapshot()
    s3["backends"][0]["threat_level"] = "high"
    s3["backends"][1]["threat_level"] = "medium"
    s3["backends"][2]["threat_level"] = "low"
    s3["backends"][3]["threat_level"] = "high"
    s3["threats"] = [
        _make_threat(
            "scenario-ddos-2", "QTT008", "Resource Exhaustion", "high",
            "ibm_quantum", "ibm_qasm_simulator",
            "Critical resource exhaustion on simulator",
            "Circuit at 9800 depth submitted — at maximum limits.",
            {"job_depth": 9800, "max_allowed_depth": 10000},
            "interference", 0.7,
            ["Reject circuits exceeding depth limits."], minutes_ago=15
        ),
        _make_threat(
            "scenario-ddos-3", "QTT008", "Resource Exhaustion", "medium",
            "ibm_quantum", "ibm_sherbrooke",
            "Deep circuit submission on hardware",
            "Multiple high-depth circuits submitted simultaneously.",
            {"job_count": 12, "avg_depth": 5000, "max_depth": 7500},
            "interference", 0.5,
            ["Review user allocation limits."], minutes_ago=3
        ),
        _make_threat(
            "scenario-ddos-4", "QTT008", "Resource Exhaustion", "low",
            "ibm_quantum", "ibm_brisbane",
            "Abnormal queue buildup",
            "Unusual number of queued jobs blocking normal operations.",
            {"queued_jobs": 45, "normal_queue": 10},
            "interference", 0.3,
            ["Monitor queue patterns."], minutes_ago=1
        ),
    ]
    s3["total_threats"] = 3
    s3["threats_by_severity"] = {"critical": 0, "high": 1, "medium": 1, "low": 1, "info": 0}
    s3["platform_health"]["ibm_quantum"] = 0.5
    steps.append(s3)

    # Step 4: Full platform-wide DDoS with resource abuse chain correlation
    s4 = _base_snapshot()
    s4["backends"][0]["threat_level"] = "critical"
    s4["backends"][1]["threat_level"] = "high"
    s4["backends"][2]["threat_level"] = "medium"
    s4["backends"][3]["threat_level"] = "critical"
    s4["threats"] = [
        _make_threat(
            "scenario-ddos-5", "QTT008", "Resource Exhaustion", "critical",
            "ibm_quantum", "ibm_qasm_simulator",
            "Simulator capacity exhausted",
            "All simulator resources consumed by repeated deep-circuit submissions.",
            {"job_depth": 9999, "max_allowed_depth": 10000, "concurrent_jobs": 50},
            "interference", 0.9,
            ["Emergency: block abusive user."], minutes_ago=25
        ),
        _make_threat(
            "scenario-ddos-6", "QTT008", "Resource Exhaustion", "high",
            "ibm_quantum", "ibm_sherbrooke",
            "Hardware backend queue overwhelmed",
            "Massive queue of deep circuits blocking all other users.",
            {"job_count": 80, "avg_depth": 6000, "queue_wait_hours": 12},
            "interference", 0.8,
            ["Emergency action required."], minutes_ago=13
        ),
        _make_threat(
            "scenario-ddos-7", "QTT008", "Resource Exhaustion", "medium",
            "ibm_quantum", "ibm_brisbane",
            "Spillover attack detected",
            "Queue overflow from sherbrooke spilling into brisbane backend.",
            {"queued_jobs": 90, "spillover_source": "ibm_sherbrooke"},
            "interference", 0.5,
            ["Cross-backend attack in progress."], minutes_ago=5
        ),
        _make_threat(
            "scenario-ddos-8", "CORR:ibm_sherbrooke:Resource Abuse Chain",
            "Resource Abuse Chain", "high",
            "ibm_quantum", "ibm_sherbrooke",
            "Campaign: Resource Abuse Chain",
            "Resource exhaustion combined with privilege escalation attempts.",
            {
                "pattern_name": "Resource Abuse Chain",
                "techniques_found": ["QTT008", "QTT005"],
                "backend_id": "ibm_sherbrooke",
                "window_minutes": 30,
                "triggering_threats": [
                    {"id": "scenario-ddos-6", "technique": "QTT008", "severity": "high"},
                ],
            },
            "campaign", 0.9,
            ["Block all related users immediately."], minutes_ago=1
        ),
    ]
    s4["total_threats"] = 4
    s4["threats_by_severity"] = {"critical": 1, "high": 2, "medium": 1, "low": 0, "info": 0}
    s4["platform_health"]["ibm_quantum"] = 0.15
    steps.append(s4)

    return steps


# Register all scenarios
SCENARIOS["recon"] = _build_recon_scenario
SCENARIOS["credential_exploit"] = _build_credential_exploit_scenario
SCENARIOS["ddos_circuit"] = _build_ddos_circuit_scenario


class ScenarioCollector(BaseCollector):
    """Plays back pre-recorded attack sequences step by step."""

    def __init__(self):
        self.current_scenario_name = None
        self.steps = []
        self.step_index = 0

    def load_scenario(self, name: str) -> bool:
        """Load a named scenario. Returns True if found, False otherwise."""
        builder = SCENARIOS.get(name)
        if builder is None:
            return False
        self.current_scenario_name = name
        self.steps = builder()
        self.step_index = 0
        return True

    async def collect(self) -> SimulationSnapshot:
        """Return the next snapshot in the current scenario sequence."""
        if not self.steps:
            # No scenario loaded — return a clean baseline
            return SimulationSnapshot(**_base_snapshot())

        # Get current step, deep copy to avoid mutation
        step_data = copy.deepcopy(self.steps[self.step_index])

        # Assign fresh snapshot metadata
        step_data["snapshot_id"] = str(uuid.uuid4())
        step_data["generated_at"] = datetime.now(timezone.utc).isoformat()

        # Advance index, reset to beginning when exhausted
        self.step_index += 1
        if self.step_index >= len(self.steps):
            self.step_index = 0

        return SimulationSnapshot(**step_data)
