"""Detection rules for quantum-specific threats.

Every rule is a pure function:  (raw_data: dict) -> list[ThreatEvent].

Thresholds are configurable via a ``ThresholdConfig`` dataclass.  When
``threshold_config`` is *None* (the default) every rule falls back to its
hardcoded conservative defaults so existing behaviour is preserved.  A
``ThresholdConfig`` is built automatically from ``calibration_results.json``
on startup when the file is present.

Rules access thresholds exclusively via ``_cfg('field_name', default)``
which centralises the None-guard logic so that no rule ever needs a
manual ``if config else None`` check.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field, fields
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from backend.threat_engine.models import ThreatEvent, Severity, Platform

# ─── Calibration results path (same location used by calibrator.py) ────
_CALIBRATION_FILE = Path(__file__).resolve().parent.parent.parent / "calibration_results.json"


# ─── Threshold configuration ────────────────────────────────────────────

@dataclass
class ThresholdConfig:
    """Overrides for detection-rule thresholds.

    Any field left as ``None`` means "use the hardcoded default".
    """
    # RULE_002: calibration harvest ratio (default 3.0)
    rule_002_calibration_harvest_ratio: Optional[float] = None
    # RULE_003: identity gate ratio (default 0.7)
    rule_003_identity_gate_ratio: Optional[float] = None
    # RULE_003: max circuit gates for oracle pattern (default 20)
    rule_003_max_circuit_gates: Optional[int] = None
    # RULE_004: max failed access attempts (default 5)
    rule_004_max_failed_attempts: Optional[int] = None
    # RULE_005: max depth ratio (default 0.85)
    rule_005_max_depth_ratio: Optional[float] = None
    # RULE_006: max sequential 404 count (default 10)
    rule_006_max_sequential_404: Optional[int] = None
    # RULE_007: max admin 403 count (default 3)
    rule_007_max_admin_403: Optional[int] = None
    # RULE_008: T1 baseline ratio — current must be above this fraction
    # of the historical baseline (default 0.6)
    rule_008_t1_baseline_ratio: Optional[float] = None
    # RULE_009: min backends accessed (default 3)
    rule_009_min_backends_accessed: Optional[int] = None
    # RULE_010: max measurement-to-gate ratio (default 0.5)
    rule_010_measure_ratio: Optional[float] = None
    # RULE_010: min circuit gates to consider (default 10)
    rule_010_min_circuit_gates: Optional[int] = None
    # Set of rule function names that are enabled.  When None, all rules run.
    # Example: {"RULE_002_calibration_harvest_rate", "RULE_003_timing_oracle_job_pattern"}
    enabled_rules: Optional[set] = None


# ─── Module-level config (set once at startup) ─────────────────────────

_threshold_config: Optional[ThresholdConfig] = None


def set_threshold_config(cfg: Optional[ThresholdConfig]) -> None:
    """Install a global threshold configuration.

    Called by main.py on startup if calibration_results.json exists.
    Pass ``None`` to clear back to hardcoded defaults.
    """
    global _threshold_config
    _threshold_config = cfg


def get_threshold_config() -> Optional[ThresholdConfig]:
    return _threshold_config


def load_threshold_config_from_file(path: Optional[str] = None) -> Optional[ThresholdConfig]:
    """Read calibration_results.json and build a ThresholdConfig.

    Fields that are ``null`` in the JSON (not enough data collected) are
    left as ``None`` in the config so the rule falls back to its default.
    """
    target = Path(path) if path else _CALIBRATION_FILE
    if not target.is_file():
        return None
    try:
        import json
        data = json.loads(target.read_text())
    except Exception:
        return None

    return ThresholdConfig(
        rule_002_calibration_harvest_ratio=data.get("rule_002_calibration_harvest_ratio"),
        rule_003_identity_gate_ratio=data.get("rule_003_identity_gate_ratio"),
        rule_003_max_circuit_gates=data.get("rule_003_max_circuit_gates"),
        rule_004_max_failed_attempts=data.get("rule_004_max_failed_attempts"),
        rule_005_max_depth_ratio=data.get("rule_005_max_depth_ratio"),
        rule_006_max_sequential_404=data.get("rule_006_max_sequential_404"),
        rule_007_max_admin_403=data.get("rule_007_max_admin_403"),
        rule_008_t1_baseline_ratio=data.get("rule_008_t1_baseline_ratio"),
        rule_009_min_backends_accessed=data.get("rule_009_min_backends_accessed"),
        rule_010_measure_ratio=data.get("rule_010_measure_ratio"),
        rule_010_min_circuit_gates=data.get("rule_010_min_circuit_gates"),
        enabled_rules=set(data["enabled_rules"]) if data.get("enabled_rules") else None,
    )


# ─── Helper to resolve a threshold (config > default) ──────────────────

def _cfg(attr_name: str, default: Any) -> Any:
    """Return the value of *attr_name* from the global ThresholdConfig, or *default*.

    This centralises the ``_threshold_config is not None`` guard so that
    individual rules simply call ``_cfg('field_name', default)`` without
    any manual None checks.
    """
    if _threshold_config is None:
        return default
    value = getattr(_threshold_config, attr_name, None)
    return value if value is not None else default


# ═══════════════════════════════════════════════════════════════════════
#  DETECTION RULES
# ═══════════════════════════════════════════════════════════════════════

def RULE_001_credential_leak_github_search(data: Dict[str, Any]) -> List[ThreatEvent]:
    """Detect exposed quantum API tokens in public GitHub repositories.

    Threshold: N/A — any valid-looking token match triggers an alert.
    """
    events = []
    github_results = data.get('github_search_results', [])
    for result in github_results:
        pattern = result.get('pattern', '')
        if 'token=' in pattern and 'YOUR_TOKEN' not in pattern and 'PLACEHOLDER' not in pattern.upper():
            events.append(ThreatEvent(
                id=str(uuid.uuid4()),
                technique_id="QTT007",
                technique_name="Credential Exposure",
                severity=Severity.critical,
                platform=Platform(data.get('platform', 'ibm_quantum')),
                backend_id=data.get('backend_id'),
                title="Credential exposure in public repository",
                description="A valid API token was found in a public repository.",
                evidence={**result, "rule_name": "RULE_001_credential_leak_github_search", "threshold_used": "N/A (any match triggers)"},
                detected_at=datetime.now(timezone.utc),
                visual_effect="particle_leak",
                visual_intensity=0.9,
                remediation=["Revoke the exposed token.", "Remove from repository."]
            ))
    return events


def RULE_002_calibration_harvest_rate(data: Dict[str, Any]) -> List[ThreatEvent]:
    """Detect systematic extraction of backend calibration data.

    Threshold (configurable):  calibration_requests / job_submissions > *threshold*
    Default: 3.0
    """
    log = data.get('api_access_log', {})
    cal_requests = log.get('calibration_requests_last_hour', 0)
    job_submissions = log.get('job_submissions_last_hour', 0)

    ratio = cal_requests / max(job_submissions, 1)
    threshold = _cfg('rule_002_calibration_harvest_ratio', 3.0)

    if ratio > threshold:
        return [ThreatEvent(
            id=str(uuid.uuid4()),
            technique_id="QTT002",
            technique_name="Calibration Harvesting",
            severity=Severity.medium,
            platform=Platform(data.get('platform', 'ibm_quantum')),
            backend_id=data.get('backend_id'),
            title="Systematic calibration data harvesting",
            description="High frequency of backend properties requests.",
            evidence={"ratio": ratio, "cal_requests": cal_requests, "rule_name": "RULE_002_calibration_harvest_rate", "threshold_used": threshold},
            detected_at=datetime.now(timezone.utc),
            visual_effect="calibration_drain",
            visual_intensity=min(ratio/10, 1.0),
            remediation=["Implement rate limiting on metadata endpoints."]
        )]
    return []


def RULE_003_timing_oracle_job_pattern(data: Dict[str, Any]) -> List[ThreatEvent]:
    """Detect repeated submission of identity-heavy circuits.

    Thresholds (configurable):
      identity_ratio > *threshold_ratio*   Default: 0.7
      total_gates   < *max_gates*         Default: 20
    """
    jobs = data.get('recent_jobs', [])
    id_threshold = _cfg('rule_003_identity_gate_ratio', 0.7)
    gate_max = _cfg('rule_003_max_circuit_gates', 20)

    events = []
    for job in jobs:
        hist = job.get('gate_histogram', {})
        total = sum(hist.values())
        id_count = hist.get('id', 0)
        ratio = id_count / max(total, 1)

        if ratio > id_threshold and total < gate_max:
            events.append(ThreatEvent(
                id=str(uuid.uuid4()),
                technique_id="QTT003",
                technique_name="Timing Oracle",
                severity=Severity.high,
                platform=Platform(data.get('platform', 'ibm_quantum')),
                backend_id=data.get('backend_id'),
                title="Job timing oracle pattern detected",
                description="Repeated submission of identity-heavy circuits.",
                evidence={"job_id": job.get('job_id'), "identity_ratio": ratio, "rule_name": "RULE_003_timing_oracle_job_pattern", "threshold_used": {"identity_gate_ratio": id_threshold, "max_circuit_gates": gate_max}},
                detected_at=datetime.now(timezone.utc),
                visual_effect="timing_ring",
                visual_intensity=ratio,
                remediation=["Review user job history for anomalous patterns."]
            ))
    return events


def RULE_004_cross_tenant_id_probing(data: Dict[str, Any]) -> List[ThreatEvent]:
    """Detect cross-tenant job ID probing.

    Threshold (configurable):  failed attempts > *threshold*   Default: 5
    """
    attempts = data.get('failed_job_access_attempts', [])
    threshold = _cfg('rule_004_max_failed_attempts', 5)

    if len(attempts) > threshold:
        return [ThreatEvent(
            id=str(uuid.uuid4()),
            technique_id="QTT004",
            technique_name="Tenant Probing",
            severity=Severity.high,
            platform=Platform(data.get('platform', 'ibm_quantum')),
            backend_id=data.get('backend_id'),
            title="Cross-tenant job ID probing",
            description="Multiple unauthorized job access attempts.",
            evidence={"attempt_count": len(attempts), "rule_name": "RULE_004_cross_tenant_id_probing", "threshold_used": threshold},
            detected_at=datetime.now(timezone.utc),
            visual_effect="color_bleed",
            visual_intensity=min(len(attempts)/20, 1.0),
            remediation=["Block offending IP/User."]
        )]
    return []


def RULE_005_resource_exhaustion_circuit(data: Dict[str, Any]) -> List[ThreatEvent]:
    """Detect circuits exceeding a safe fraction of the backend's max depth.

    Threshold (configurable):  depth/max_depth > *threshold*   Default: 0.85
    """
    jobs = data.get('recent_jobs', [])
    threshold = _cfg('rule_005_max_depth_ratio', 0.85)

    events = []
    for job in jobs:
        depth = job.get('depth', 0)
        max_depth = job.get('max_allowed_depth', 1)
        ratio = depth / max(max_depth, 1)
        if ratio > threshold:
            events.append(ThreatEvent(
                id=str(uuid.uuid4()),
                technique_id="QTT008",
                technique_name="Resource Exhaustion",
                severity=Severity.medium,
                platform=Platform(data.get('platform', 'ibm_quantum')),
                backend_id=data.get('backend_id'),
                title="Resource exhaustion circuit pattern",
                description="Extremely high depth circuit submitted.",
                evidence={"depth": depth, "max_depth": max_depth, "rule_name": "RULE_005_resource_exhaustion_circuit", "threshold_used": threshold},
                detected_at=datetime.now(timezone.utc),
                visual_effect="interference",
                visual_intensity=min(ratio, 1.0),
                remediation=["Reject overly deep circuits."]
            ))
    return events


def RULE_006_ip_extraction_idor(data: Dict[str, Any]) -> List[ThreatEvent]:
    """Detect large-scale sequential IDOR enumeration.

    Threshold (configurable):  sequential_404_count > *threshold*   Default: 10
    """
    log = data.get('api_error_log', {})
    count_404 = log.get('sequential_404_count', 0)
    threshold = _cfg('rule_006_max_sequential_404', 10)

    if count_404 > threshold:
        return [ThreatEvent(
            id=str(uuid.uuid4()),
            technique_id="QTT006",
            technique_name="IP Extraction",
            severity=Severity.critical,
            platform=Platform(data.get('platform', 'ibm_quantum')),
            backend_id=data.get('backend_id'),
            title="Sequential IDOR probe pattern detected",
            description="High volume of 404 errors on job endpoints.",
            evidence={"sequential_404_count": count_404, "rule_name": "RULE_006_ip_extraction_idor", "threshold_used": threshold},
            detected_at=datetime.now(timezone.utc),
            visual_effect="vortex",
            visual_intensity=0.8,
            remediation=["Implement stricter rate limits.", "Review authorization logic."]
        )]
    return []


def RULE_007_token_scope_violation(data: Dict[str, Any]) -> List[ThreatEvent]:
    """Detect repeated access denied on admin endpoints.

    Threshold (configurable):  403_on_admin_count > *threshold*   Default: 3
    """
    log = data.get('api_error_log', {})
    count_403 = log.get('403_on_admin_count', 0)
    threshold = _cfg('rule_007_max_admin_403', 3)

    if count_403 > threshold:
        return [ThreatEvent(
            id=str(uuid.uuid4()),
            technique_id="QTT005",
            technique_name="Scope Violation",
            severity=Severity.high,
            platform=Platform(data.get('platform', 'ibm_quantum')),
            backend_id=data.get('backend_id'),
            title="Token scope violation attempt",
            description="Repeated access denied to admin endpoints.",
            evidence={"403_count": count_403, "rule_name": "RULE_007_token_scope_violation", "threshold_used": threshold},
            detected_at=datetime.now(timezone.utc),
            visual_effect="interference",
            visual_intensity=0.5,
            remediation=["Review token scope assignments.", "Monitor user."]
        )]
    return []


def RULE_008_backend_health_anomaly(data: Dict[str, Any]) -> List[ThreatEvent]:
    """Detect significant T1 coherence time drops from historical baseline.

    Threshold (configurable):  current_t1 < baseline_t1 * *ratio*   Default: 0.6
    """
    baseline = data.get('baseline_calibration', {})
    current = data.get('calibration', [])
    events = []

    t1_ratio = _cfg('rule_008_t1_baseline_ratio', 0.6)

    for c in current:
        qid = str(c.get('qubit_id'))
        if qid in baseline:
            base_t1 = baseline[qid].get('t1_us', 1)
            curr_t1 = c.get('t1_us', base_t1)

            if curr_t1 < (base_t1 * t1_ratio):
                events.append(ThreatEvent(
                    id=str(uuid.uuid4()),
                    technique_id="QTT010",
                    technique_name="Hardware Degradation",
                    severity=Severity.info,
                    platform=Platform(data.get('platform', 'ibm_quantum')),
                    backend_id=data.get('backend_id'),
                    title=f"Qubit {qid} health anomaly",
                    description="Significant drop in T1 coherence time.",
                    evidence={"qubit_id": qid, "baseline_t1": base_t1, "current_t1": curr_t1, "rule_name": "RULE_008_backend_health_anomaly", "threshold_used": t1_ratio},
                    detected_at=datetime.now(timezone.utc),
                    visual_effect="calibration_drain",
                    visual_intensity=0.3,
                    remediation=["Recalibrate backend."]
                ))
    return events


def RULE_009_concurrent_multi_backend_probing(data: Dict[str, Any]) -> List[ThreatEvent]:
    """Detect concurrent access to multiple backends from same source.

    Threshold (configurable):  backends_accessed >= *threshold*   Default: 3
    """
    jobs = data.get('recent_jobs', [])
    backends_accessed = set()
    for job in jobs:
        bid = job.get('backend_id', '')
        if bid:
            backends_accessed.add(bid)

    threshold = _cfg('rule_009_min_backends_accessed', 3)

    if len(backends_accessed) >= threshold:
        return [ThreatEvent(
            id=str(uuid.uuid4()),
            technique_id="QTT001",
            technique_name="Multi-Backend Reconnaissance",
            severity=Severity.high,
            platform=Platform(data.get('platform', 'ibm_quantum')),
            backend_id=data.get('backend_id'),
            title="Concurrent multi-backend probing detected",
            description=f"Activity detected across {len(backends_accessed)} backends simultaneously.",
            evidence={"backends_accessed": list(backends_accessed), "rule_name": "RULE_009_concurrent_multi_backend_probing", "threshold_used": threshold},
            detected_at=datetime.now(timezone.utc),
            visual_effect="color_bleed",
            visual_intensity=min(len(backends_accessed) / 5, 1.0),
            remediation=["Investigate user for coordinated reconnaissance."]
        )]
    return []


def RULE_010_anomalous_circuit_composition(data: Dict[str, Any]) -> List[ThreatEvent]:
    """Detect circuits with unusually high measurement-to-gate ratios.

    Thresholds (configurable):
      measure_ratio > *ratio_threshold*   Default: 0.5
      total_gates   > *min_gates*         Default: 10
    """
    jobs = data.get('recent_jobs', [])
    ratio_threshold = _cfg('rule_010_measure_ratio', 0.5)
    gate_min = _cfg('rule_010_min_circuit_gates', 10)

    events = []
    for job in jobs:
        hist = job.get('gate_histogram', {})
        total = sum(hist.values())
        if total < 5:
            continue

        measure_count = hist.get('measure', 0)
        measure_ratio = measure_count / max(total, 1)

        if measure_ratio > ratio_threshold and total > gate_min:
            events.append(ThreatEvent(
                id=str(uuid.uuid4()),
                technique_id="QTT009",
                technique_name="Anomalous Circuit",
                severity=Severity.medium,
                platform=Platform(data.get('platform', 'ibm_quantum')),
                backend_id=data.get('backend_id'),
                title="Anomalous circuit composition detected",
                description="Circuit has unusually high measurement-to-gate ratio suggesting data exfiltration.",
                evidence={"gate_histogram": hist, "measure_ratio": round(measure_ratio, 3), "rule_name": "RULE_010_anomalous_circuit_composition", "threshold_used": {"measure_ratio": ratio_threshold, "min_circuit_gates": gate_min}},
                detected_at=datetime.now(timezone.utc),
                visual_effect="interference",
                visual_intensity=measure_ratio,
                remediation=["Review circuit purpose and user intent."]
            ))
    return events


# ─── Rule registry (unchanged interface) ────────────────────────────────

ALL_RULES = [
    RULE_001_credential_leak_github_search,
    RULE_002_calibration_harvest_rate,
    RULE_003_timing_oracle_job_pattern,
    RULE_004_cross_tenant_id_probing,
    RULE_005_resource_exhaustion_circuit,
    RULE_006_ip_extraction_idor,
    RULE_007_token_scope_violation,
    RULE_008_backend_health_anomaly,
    RULE_009_concurrent_multi_backend_probing,
    RULE_010_anomalous_circuit_composition,
]


def get_active_rules() -> list:
    """Return the list of rules that should be evaluated.

    If ``enabled_rules`` is set in the global ThresholdConfig, only those
    rules whose ``__name__`` appears in the set are returned.  Otherwise
    all rules in ``ALL_RULES`` are returned.
    """
    if _threshold_config is not None and _threshold_config.enabled_rules is not None:
        return [r for r in ALL_RULES if r.__name__ in _threshold_config.enabled_rules]
    return list(ALL_RULES)
