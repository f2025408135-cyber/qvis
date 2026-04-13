import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any
from backend.threat_engine.models import ThreatEvent, Severity, Platform

def RULE_001_credential_leak_github_search(data: Dict[str, Any]) -> List[ThreatEvent]:
    events = []
    github_results = data.get('github_search_results', [])
    for result in github_results:
        pattern = result.get('pattern', '')
        if 'token=' in pattern and 'YOUR_TOKEN' not in pattern and 'PLACEHOLDER' not in pattern.upper():
            events.append(ThreatEvent(
                id=str(uuid.uuid4()),
                technique_id="QTT017",
                technique_name="Credential Exposure",
                severity=Severity.critical,
                platform=Platform(data.get('platform', 'ibm_quantum')),
                backend_id=data.get('backend_id'),
                title="Credential exposure in public repository",
                description="A valid API token was found in a public repository.",
                evidence=result,
                detected_at=datetime.now(timezone.utc),
                visual_effect="particle_leak",
                visual_intensity=0.9,
                remediation=["Revoke the exposed token.", "Remove from repository."]
            ))
    return events

def RULE_002_calibration_harvest_rate(data: Dict[str, Any]) -> List[ThreatEvent]:
    log = data.get('api_access_log', {})
    cal_requests = log.get('calibration_requests_last_hour', 0)
    job_submissions = log.get('job_submissions_last_hour', 0)
    
    ratio = cal_requests / max(job_submissions, 1)
    if ratio > 3.0:
        return [ThreatEvent(
            id=str(uuid.uuid4()),
            technique_id="QTT002",
            technique_name="Calibration Harvesting",
            severity=Severity.medium,
            platform=Platform(data.get('platform', 'ibm_quantum')),
            backend_id=data.get('backend_id'),
            title="Systematic calibration data harvesting",
            description="High frequency of backend properties requests.",
            evidence={"ratio": ratio, "cal_requests": cal_requests},
            detected_at=datetime.now(timezone.utc),
            visual_effect="calibration_drain",
            visual_intensity=min(ratio/10, 1.0),
            remediation=["Implement rate limiting on metadata endpoints."]
        )]
    return []

def RULE_003_timing_oracle_job_pattern(data: Dict[str, Any]) -> List[ThreatEvent]:
    jobs = data.get('recent_jobs', [])
    for job in jobs:
        hist = job.get('gate_histogram', {})
        total = sum(hist.values())
        id_count = hist.get('id', 0)
        ratio = id_count / max(total, 1)
        
        if ratio > 0.7 and total < 20:
            return [ThreatEvent(
                id=str(uuid.uuid4()),
                technique_id="QTT003",
                technique_name="Timing Oracle",
                severity=Severity.high,
                platform=Platform(data.get('platform', 'ibm_quantum')),
                backend_id=data.get('backend_id'),
                title="Job timing oracle pattern detected",
                description="Repeated submission of identity-heavy circuits.",
                evidence={"job_id": job.get('job_id'), "identity_ratio": ratio},
                detected_at=datetime.now(timezone.utc),
                visual_effect="timing_ring",
                visual_intensity=ratio,
                remediation=["Review user job history for anomalous patterns."]
            )]
    return []

def RULE_004_cross_tenant_id_probing(data: Dict[str, Any]) -> List[ThreatEvent]:
    attempts = data.get('failed_job_access_attempts', [])
    if len(attempts) > 5:
        return [ThreatEvent(
            id=str(uuid.uuid4()),
            technique_id="QTT009",
            technique_name="Tenant Probing",
            severity=Severity.high,
            platform=Platform(data.get('platform', 'ibm_quantum')),
            backend_id=data.get('backend_id'),
            title="Cross-tenant job ID probing",
            description="Multiple unauthorized job access attempts.",
            evidence={"attempt_count": len(attempts)},
            detected_at=datetime.now(timezone.utc),
            visual_effect="color_bleed",
            visual_intensity=min(len(attempts)/20, 1.0),
            remediation=["Block offending IP/User."]
        )]
    return []

def RULE_005_resource_exhaustion_circuit(data: Dict[str, Any]) -> List[ThreatEvent]:
    jobs = data.get('recent_jobs', [])
    for job in jobs:
        depth = job.get('depth', 0)
        max_depth = job.get('max_allowed_depth', 1)
        ratio = depth / max(max_depth, 1)
        if ratio > 0.85:
            return [ThreatEvent(
                id=str(uuid.uuid4()),
                technique_id="QTT008",
                technique_name="Resource Exhaustion",
                severity=Severity.medium,
                platform=Platform(data.get('platform', 'ibm_quantum')),
                backend_id=data.get('backend_id'),
                title="Resource exhaustion circuit pattern",
                description="Extremely high depth circuit submitted.",
                evidence={"depth": depth, "max_depth": max_depth},
                detected_at=datetime.now(timezone.utc),
                visual_effect="interference",
                visual_intensity=min(ratio, 1.0),
                remediation=["Reject overly deep circuits."]
            )]
    return []

def RULE_006_ip_extraction_idor(data: Dict[str, Any]) -> List[ThreatEvent]:
    log = data.get('api_error_log', {})
    count_404 = log.get('sequential_404_count', 0)
    if count_404 > 10:
        return [ThreatEvent(
            id=str(uuid.uuid4()),
            technique_id="QTT011",
            technique_name="IP Extraction",
            severity=Severity.critical,
            platform=Platform(data.get('platform', 'ibm_quantum')),
            backend_id=data.get('backend_id'),
            title="Sequential IDOR probe pattern detected",
            description="High volume of 404 errors on job endpoints.",
            evidence={"sequential_404_count": count_404},
            detected_at=datetime.now(timezone.utc),
            visual_effect="vortex",
            visual_intensity=0.8,
            remediation=["Implement stricter rate limits.", "Review authorization logic."]
        )]
    return []

def RULE_007_token_scope_violation(data: Dict[str, Any]) -> List[ThreatEvent]:
    log = data.get('api_error_log', {})
    count_403 = log.get('403_on_admin_count', 0)
    if count_403 > 3:
        return [ThreatEvent(
            id=str(uuid.uuid4()),
            technique_id="QTT005",
            technique_name="Scope Violation",
            severity=Severity.high,
            platform=Platform(data.get('platform', 'ibm_quantum')),
            backend_id=data.get('backend_id'),
            title="Token scope violation attempt",
            description="Repeated access denied to admin endpoints.",
            evidence={"403_count": count_403},
            detected_at=datetime.now(timezone.utc),
            visual_effect="interference",
            visual_intensity=0.5,
            remediation=["Review token scope assignments.", "Monitor user."]
        )]
    return []

def RULE_008_backend_health_anomaly(data: Dict[str, Any]) -> List[ThreatEvent]:
    baseline = data.get('baseline_calibration', {})
    current = data.get('calibration', [])
    events = []
    
    for c in current:
        qid = str(c.get('qubit_id'))
        if qid in baseline:
            base_t1 = baseline[qid].get('t1_us', 1)
            curr_t1 = c.get('t1_us', base_t1)
            
            if curr_t1 < (base_t1 * 0.6):
                events.append(ThreatEvent(
                    id=str(uuid.uuid4()),
                    technique_id="HEALTH",
                    technique_name="Hardware Degradation",
                    severity=Severity.info,
                    platform=Platform(data.get('platform', 'ibm_quantum')),
                    backend_id=data.get('backend_id'),
                    title=f"Qubit {qid} health anomaly",
                    description="Significant drop in T1 coherence time.",
                    evidence={"qubit_id": qid, "baseline_t1": base_t1, "current_t1": curr_t1},
                    detected_at=datetime.now(timezone.utc),
                    visual_effect="calibration_drain",
                    visual_intensity=0.3,
                    remediation=["Recalibrate backend."]
                ))
    return events

def RULE_009_concurrent_multi_backend_probing(data: Dict[str, Any]) -> List[ThreatEvent]:
    """Detect concurrent access to multiple backends from same source."""
    jobs = data.get('recent_jobs', [])
    backends_accessed = set()
    for job in jobs:
        bid = job.get('backend_id', '')
        if bid:
            backends_accessed.add(bid)

    if len(backends_accessed) >= 3:
        return [ThreatEvent(
            id=str(uuid.uuid4()),
            technique_id="QTT012",
            technique_name="Multi-Backend Reconnaissance",
            severity=Severity.high,
            platform=Platform(data.get('platform', 'ibm_quantum')),
            backend_id=data.get('backend_id'),
            title="Concurrent multi-backend probing detected",
            description=f"Activity detected across {len(backends_accessed)} backends simultaneously.",
            evidence={"backends_accessed": list(backends_accessed)},
            detected_at=datetime.now(timezone.utc),
            visual_effect="color_bleed",
            visual_intensity=min(len(backends_accessed) / 5, 1.0),
            remediation=["Investigate user for coordinated reconnaissance."]
        )]
    return []

def RULE_010_anomalous_circuit_composition(data: Dict[str, Any]) -> List[ThreatEvent]:
    """Detect circuits with unusual gate compositions that don't match known algorithms."""
    jobs = data.get('recent_jobs', [])
    for job in jobs:
        hist = job.get('gate_histogram', {})
        total = sum(hist.values())
        if total < 5:
            continue

        measure_count = hist.get('measure', 0)
        measure_ratio = measure_count / max(total, 1)

        if measure_ratio > 0.5 and total > 10:
            return [ThreatEvent(
                id=str(uuid.uuid4()),
                technique_id="QTT013",
                technique_name="Anomalous Circuit",
                severity=Severity.medium,
                platform=Platform(data.get('platform', 'ibm_quantum')),
                backend_id=data.get('backend_id'),
                title="Anomalous circuit composition detected",
                description="Circuit has unusually high measurement-to-gate ratio suggesting data exfiltration.",
                evidence={"gate_histogram": hist, "measure_ratio": round(measure_ratio, 3)},
                detected_at=datetime.now(timezone.utc),
                visual_effect="interference",
                visual_intensity=measure_ratio,
                remediation=["Review circuit purpose and user intent."]
            )]
    return []

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
