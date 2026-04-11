import pytest
from datetime import datetime, timezone, timedelta
from backend.threat_engine.rules import (
    RULE_001_credential_leak_github_search,
    RULE_002_calibration_harvest_rate,
    RULE_003_timing_oracle_job_pattern,
    RULE_006_ip_extraction_idor,
    ALL_RULES
)
from backend.threat_engine.analyzer import ThreatAnalyzer
from backend.threat_engine.models import Severity

def test_rule_001_detects_credential_exposure_in_search_results():
    data = {
        "github_search_results": [
            {"repo": "test", "pattern": "QiskitRuntimeService(token='valid123')"}
        ]
    }
    events = RULE_001_credential_leak_github_search(data)
    assert len(events) == 1
    assert events[0].technique_id == "QTT017"

def test_rule_001_ignores_placeholder_tokens():
    data = {
        "github_search_results": [
            {"repo": "test", "pattern": "QiskitRuntimeService(token='YOUR_TOKEN')"},
            {"repo": "test2", "pattern": "QiskitRuntimeService(token='PLACEHOLDER')"}
        ]
    }
    events = RULE_001_credential_leak_github_search(data)
    assert len(events) == 0

def test_rule_002_detects_high_calibration_request_ratio():
    data = {
        "api_access_log": {
            "calibration_requests_last_hour": 100,
            "job_submissions_last_hour": 10
        }
    }
    events = RULE_002_calibration_harvest_rate(data)
    assert len(events) == 1
    assert events[0].technique_id == "QTT002"
    assert events[0].visual_effect == "calibration_drain"

def test_rule_002_ignores_normal_ratio():
    data = {
        "api_access_log": {
            "calibration_requests_last_hour": 20,
            "job_submissions_last_hour": 10
        }
    }
    events = RULE_002_calibration_harvest_rate(data)
    assert len(events) == 0

def test_rule_003_detects_identity_heavy_circuit():
    data = {
        "recent_jobs": [
            {
                "job_id": "123",
                "gate_histogram": {"id": 15, "cx": 2}
            }
        ]
    }
    events = RULE_003_timing_oracle_job_pattern(data)
    assert len(events) == 1
    assert events[0].technique_id == "QTT003"

def test_rule_003_ignores_legitimate_algorithm_circuit():
    data = {
        "recent_jobs": [
            {
                "job_id": "123",
                "gate_histogram": {"id": 5, "cx": 25, "rz": 50} 
            }
        ]
    }
    events = RULE_003_timing_oracle_job_pattern(data)
    assert len(events) == 0

def test_rule_006_detects_sequential_404_idor_pattern():
    data = {"api_error_log": {"sequential_404_count": 12}}
    events = RULE_006_ip_extraction_idor(data)
    assert len(events) == 1
    assert events[0].technique_id == "QTT011"
    assert events[0].visual_effect == "vortex"

def test_analyzer_deduplicates_same_technique_within_window():
    analyzer = ThreatAnalyzer()
    data = {
        "backend_id": "backend_1",
        "api_error_log": {"sequential_404_count": 12}
    }
    
    events1 = analyzer.analyze(data)
    assert len(events1) == 1
    id1 = events1[0].id
    
    events2 = analyzer.analyze(data)
    assert len(events2) == 1
    id2 = events2[0].id
    
    assert id1 == id2

def test_analyzer_sorts_by_severity_critical_first():
    analyzer = ThreatAnalyzer()
    data = {
        "backend_id": "backend_1",
        "api_error_log": {"sequential_404_count": 12},
        "recent_jobs": [
            {
                "depth": 95, "max_allowed_depth": 100
            }
        ]
    }
    events = analyzer.analyze(data)
    assert len(events) == 2
    assert events[0].severity == Severity.critical
    assert events[1].severity == Severity.medium

def test_threat_events_all_have_valid_visual_effects():
    data = {
        "github_search_results": [{"pattern": "token='valid'"}],
        "api_access_log": {"calibration_requests_last_hour": 100, "job_submissions_last_hour": 10},
        "recent_jobs": [
            {"gate_histogram": {"id": 15, "cx": 2}},
            {"depth": 95, "max_allowed_depth": 100}
        ],
        "failed_job_access_attempts": [1,2,3,4,5,6],
        "api_error_log": {"sequential_404_count": 12, "403_on_admin_count": 5},
        "calibration": [{"qubit_id": 0, "t1_us": 10}],
        "baseline_calibration": {"0": {"t1_us": 100}}
    }
    
    events = []
    for rule in ALL_RULES:
        events.extend(rule(data))
        
    valid_effects = [
        "timing_ring", "particle_leak", "color_bleed", "vortex",
        "calibration_drain", "interference", "none"
    ]
    
    for event in events:
        assert event.visual_effect in valid_effects
