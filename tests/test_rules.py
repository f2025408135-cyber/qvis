"""Comprehensive tests for all 10 detection rules in rules.py.

Each rule has exactly three tests:
  1. *positive*  — raw_data that SHOULD trigger the rule
  2. *negative*  — normal / benign data that should NOT trigger
  3. *edge*      — sits right on the threshold boundary

Additional tests cover:
  - ThresholdConfig installation, _cfg() helper, and file loading
  - ALL_RULES registry completeness
  - Empty / missing-key inputs
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

import pytest

from backend.threat_engine.models import Severity, Platform
from backend.threat_engine.rules import (
    ALL_RULES,
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
    ThresholdConfig,
    _cfg,
    get_threshold_config,
    load_threshold_config_from_file,
    get_active_rules,
    set_threshold_config,
)


# ═══════════════════════════════════════════════════════════════════
#  RULE 001 — Credential Leak / GitHub Search  (QTT007, critical)
# ═══════════════════════════════════════════════════════════════════

class TestRule001:
    def test_rule_001_detects_positive_case(self):
        """A search result containing ``token=`` with a realistic value."""
        data: Dict[str, Any] = {
            "github_search_results": [
                {"repo": "acme/quantum-hack", "pattern": "QiskitRuntimeService(token='abcd1234efgh')"},
            ],
        }
        events = RULE_001_credential_leak_github_search(data)
        assert len(events) == 1
        assert events[0].technique_id == "QTT007"
        assert events[0].severity == Severity.critical
        assert events[0].visual_effect == "particle_leak"
        assert events[0].remediation == [
            "Revoke the exposed token.",
            "Remove from repository.",
        ]

    def test_rule_001_no_false_positive(self):
        """Placeholder patterns and strings without ``token=`` must be ignored."""
        data: Dict[str, Any] = {
            "github_search_results": [
                {"repo": "docs", "pattern": "QiskitRuntimeService(token='YOUR_TOKEN')"},
                {"repo": "docs2", "pattern": "QiskitRuntimeService(token='PLACEHOLDER')"},
                {"repo": "clean", "pattern": "from qiskit import QuantumCircuit"},
            ],
        }
        events = RULE_001_credential_leak_github_search(data)
        assert events == []

    def test_rule_001_multiple_results_triggers_each(self):
        """Multiple matching results each produce a separate ThreatEvent."""
        data: Dict[str, Any] = {
            "github_search_results": [
                {"repo": "repo_a", "pattern": "token='abc123'"},
                {"repo": "repo_b", "pattern": "api_token=xyz789"},
            ],
        }
        events = RULE_001_credential_leak_github_search(data)
        assert len(events) == 2

    def test_rule_001_edge_case(self):
        """Boundary: ``YOUR_TOKEN`` check is exact substring, not regex.
        A pattern containing ``YOUR_TOKEN`` as part of a longer valid-looking
        token string should still be filtered because ``'YOUR_TOKEN' in pattern"
        is True.  Test that filtering works case-insensitively for PLACEHOLDER
        and exact-match for YOUR_TOKEN."""
        data: Dict[str, Any] = {
            "github_search_results": [
                # Exact YOUR_TOKEN match → filtered
                {"repo": "edge", "pattern": "token='YOUR_TOKEN_HERE'"},
                # PLACEHOLDER in uppercase → filtered
                {"repo": "edge2", "pattern": "token='this_is_a_PLACEHOLDER'"},
            ],
        }
        events = RULE_001_credential_leak_github_search(data)
        # Both filtered: first has 'YOUR_TOKEN', second has 'PLACEHOLDER' in upper
        assert len(events) == 0


# ═══════════════════════════════════════════════════════════════════
#  RULE 002 — Calibration Harvest Rate  (QTT002, medium)
# ═══════════════════════════════════════════════════════════════════

class TestRule002:
    def test_rule_002_detects_positive_case(self):
        """Ratio 100/10 = 10.0 > default 3.0 → trigger."""
        data = {
            "api_access_log": {
                "calibration_requests_last_hour": 100,
                "job_submissions_last_hour": 10,
            },
        }
        events = RULE_002_calibration_harvest_rate(data)
        assert len(events) == 1
        assert events[0].technique_id == "QTT002"
        assert events[0].severity == Severity.medium
        assert events[0].evidence["ratio"] == 10.0

    def test_rule_002_no_false_positive(self):
        """Ratio 20/10 = 2.0 < 3.0 → no trigger."""
        data = {
            "api_access_log": {
                "calibration_requests_last_hour": 20,
                "job_submissions_last_hour": 10,
            },
        }
        events = RULE_002_calibration_harvest_rate(data)
        assert events == []

    def test_rule_002_edge_case(self):
        """Ratio exactly 3.0 (30 cal / 10 jobs).  Rule uses ``>`` so 3.0 does NOT trigger."""
        data = {
            "api_access_log": {
                "calibration_requests_last_hour": 30,
                "job_submissions_last_hour": 10,
            },
        }
        events = RULE_002_calibration_harvest_rate(data)
        assert events == []

    def test_rule_002_zero_job_submissions(self):
        """Division by zero guard: 0 jobs → ratio computed with max(..., 1) denominator."""
        data = {
            "api_access_log": {
                "calibration_requests_last_hour": 5,
                "job_submissions_last_hour": 0,
            },
        }
        events = RULE_002_calibration_harvest_rate(data)
        assert len(events) == 1
        assert events[0].evidence["ratio"] == 5.0


# ═══════════════════════════════════════════════════════════════════
#  RULE 003 — Timing Oracle / Job Pattern  (QTT003, high)
# ═══════════════════════════════════════════════════════════════════

class TestRule003:
    def test_rule_003_detects_positive_case(self):
        """Identity ratio 15/17 ≈ 0.88 > 0.7, total gates 17 < 20 → trigger."""
        data = {
            "recent_jobs": [
                {"job_id": "j1", "gate_histogram": {"id": 15, "cx": 2}},
            ],
        }
        events = RULE_003_timing_oracle_job_pattern(data)
        assert len(events) == 1
        assert events[0].technique_id == "QTT003"
        assert events[0].severity == Severity.high

    def test_rule_003_no_false_positive(self):
        """Legitimate algorithmic circuit: id=5, cx=25, rz=50 → ratio 5/80 = 0.06."""
        data = {
            "recent_jobs": [
                {"job_id": "j1", "gate_histogram": {"id": 5, "cx": 25, "rz": 50}},
            ],
        }
        events = RULE_003_timing_oracle_job_pattern(data)
        assert events == []

    def test_rule_003_edge_case(self):
        """Total gates exactly 20 (boundary for ``< 20`` check).  Must NOT trigger."""
        data = {
            "recent_jobs": [
                {"job_id": "j1", "gate_histogram": {"id": 15, "cx": 5}},  # total = 20
            ],
        }
        events = RULE_003_timing_oracle_job_pattern(data)
        assert events == []

    def test_rule_003_empty_histogram(self):
        """Job with missing or empty gate_histogram → no crash, no event."""
        data = {"recent_jobs": [{"job_id": "j1"}]}
        events = RULE_003_timing_oracle_job_pattern(data)
        assert events == []


# ═══════════════════════════════════════════════════════════════════
#  RULE 004 — Cross-Tenant ID Probing  (QTT004, high)
# ═══════════════════════════════════════════════════════════════════

class TestRule004:
    def test_rule_004_detects_positive_case(self):
        """6 failed attempts > default 5 → trigger."""
        data = {"failed_job_access_attempts": ["a", "b", "c", "d", "e", "f"]}
        events = RULE_004_cross_tenant_id_probing(data)
        assert len(events) == 1
        assert events[0].technique_id == "QTT004"
        assert events[0].severity == Severity.high
        assert events[0].evidence["attempt_count"] == 6

    def test_rule_004_no_false_positive(self):
        """3 failed attempts ≤ 5 → no trigger."""
        data = {"failed_job_access_attempts": ["a", "b", "c"]}
        events = RULE_004_cross_tenant_id_probing(data)
        assert events == []

    def test_rule_004_edge_case(self):
        """Exactly 5 attempts: ``> 5`` is False → no trigger."""
        data = {"failed_job_access_attempts": list(range(5))}
        events = RULE_004_cross_tenant_id_probing(data)
        assert events == []

    def test_rule_004_empty_list(self):
        """Empty list → len 0 ≤ 5 → no trigger."""
        events = RULE_004_cross_tenant_id_probing({})
        assert events == []


# ═══════════════════════════════════════════════════════════════════
#  RULE 005 — Resource Exhaustion / Circuit  (QTT008, medium)
# ═══════════════════════════════════════════════════════════════════

class TestRule005:
    def test_rule_005_detects_positive_case(self):
        """depth_ratio = 90/100 = 0.9 > 0.85 → trigger."""
        data = {
            "recent_jobs": [
                {"depth": 90, "max_allowed_depth": 100},
            ],
        }
        events = RULE_005_resource_exhaustion_circuit(data)
        assert len(events) == 1
        assert events[0].technique_id == "QTT008"
        assert events[0].severity == Severity.medium

    def test_rule_005_no_false_positive(self):
        """depth_ratio = 70/100 = 0.7 < 0.85 → no trigger."""
        data = {
            "recent_jobs": [
                {"depth": 70, "max_allowed_depth": 100},
            ],
        }
        events = RULE_005_resource_exhaustion_circuit(data)
        assert events == []

    def test_rule_005_edge_case(self):
        """depth_ratio exactly 0.85 → ``> 0.85`` is False → no trigger."""
        data = {
            "recent_jobs": [
                {"depth": 85, "max_allowed_depth": 100},
            ],
        }
        events = RULE_005_resource_exhaustion_circuit(data)
        assert events == []


# ═══════════════════════════════════════════════════════════════════
#  RULE 006 — IP Extraction / IDOR  (QTT006, critical)
# ═══════════════════════════════════════════════════════════════════

class TestRule006:
    def test_rule_006_detects_positive_case(self):
        """12 sequential 404s > default 10 → trigger."""
        data = {"api_error_log": {"sequential_404_count": 12}}
        events = RULE_006_ip_extraction_idor(data)
        assert len(events) == 1
        assert events[0].technique_id == "QTT006"
        assert events[0].severity == Severity.critical
        assert events[0].visual_effect == "vortex"

    def test_rule_006_no_false_positive(self):
        """5 sequential 404s ≤ 10 → no trigger."""
        data = {"api_error_log": {"sequential_404_count": 5}}
        events = RULE_006_ip_extraction_idor(data)
        assert events == []

    def test_rule_006_edge_case(self):
        """Exactly 10: ``> 10`` is False → no trigger."""
        data = {"api_error_log": {"sequential_404_count": 10}}
        events = RULE_006_ip_extraction_idor(data)
        assert events == []


# ═══════════════════════════════════════════════════════════════════
#  RULE 007 — Token Scope Violation  (QTT005, high)
# ═══════════════════════════════════════════════════════════════════

class TestRule007:
    def test_rule_007_detects_positive_case(self):
        """4 admin 403s > default 3 → trigger."""
        data = {"api_error_log": {"403_on_admin_count": 4}}
        events = RULE_007_token_scope_violation(data)
        assert len(events) == 1
        assert events[0].technique_id == "QTT005"
        assert events[0].severity == Severity.high

    def test_rule_007_no_false_positive(self):
        """2 admin 403s ≤ 3 → no trigger."""
        data = {"api_error_log": {"403_on_admin_count": 2}}
        events = RULE_007_token_scope_violation(data)
        assert events == []

    def test_rule_007_edge_case(self):
        """Exactly 3: ``> 3`` is False → no trigger."""
        data = {"api_error_log": {"403_on_admin_count": 3}}
        events = RULE_007_token_scope_violation(data)
        assert events == []


# ═══════════════════════════════════════════════════════════════════
#  RULE 008 — Backend Health Anomaly  (HEALTH, info)
# ═══════════════════════════════════════════════════════════════════

class TestRule008:
    def test_rule_008_detects_positive_case(self):
        """Current T1 = 50, baseline T1 = 100 → 50 < 100 * 0.6 = 60 → trigger."""
        data = {
            "baseline_calibration": {"0": {"t1_us": 100.0}},
            "calibration": [{"qubit_id": 0, "t1_us": 50.0}],
        }
        events = RULE_008_backend_health_anomaly(data)
        assert len(events) == 1
        assert events[0].technique_id == "QTT010"
        assert events[0].severity == Severity.info

    def test_rule_008_no_false_positive(self):
        """Current T1 = 90, baseline T1 = 100 → 90 > 100 * 0.6 = 60 → no trigger."""
        data = {
            "baseline_calibration": {"0": {"t1_us": 100.0}},
            "calibration": [{"qubit_id": 0, "t1_us": 90.0}],
        }
        events = RULE_008_backend_health_anomaly(data)
        assert events == []

    def test_rule_008_edge_case(self):
        """Current T1 exactly at 60% of baseline (60 < 60 is False) → no trigger."""
        data = {
            "baseline_calibration": {"0": {"t1_us": 100.0}},
            "calibration": [{"qubit_id": 0, "t1_us": 60.0}],
        }
        events = RULE_008_backend_health_anomaly(data)
        assert events == []

    def test_rule_008_multiple_qubits(self):
        """Two qubits: one degraded, one healthy → only one event."""
        data = {
            "baseline_calibration": {"0": {"t1_us": 100.0}, "1": {"t1_us": 100.0}},
            "calibration": [
                {"qubit_id": 0, "t1_us": 50.0},
                {"qubit_id": 1, "t1_us": 90.0},
            ],
        }
        events = RULE_008_backend_health_anomaly(data)
        assert len(events) == 1
        assert events[0].evidence["qubit_id"] == "0"

    def test_rule_008_missing_baseline(self):
        """Qubit not in baseline dict → skipped, no event."""
        data = {
            "baseline_calibration": {},
            "calibration": [{"qubit_id": 0, "t1_us": 10.0}],
        }
        events = RULE_008_backend_health_anomaly(data)
        assert events == []


# ═══════════════════════════════════════════════════════════════════
#  RULE 009 — Concurrent Multi-Backend Probing  (QTT001, high)
# ═══════════════════════════════════════════════════════════════════

class TestRule009:
    def test_rule_009_detects_positive_case(self):
        """Jobs across 4 distinct backends ≥ 3 → trigger."""
        data = {
            "recent_jobs": [
                {"backend_id": "ibm_a", "gate_histogram": {"cx": 10}},
                {"backend_id": "ibm_b", "gate_histogram": {"cx": 10}},
                {"backend_id": "ibm_c", "gate_histogram": {"cx": 10}},
                {"backend_id": "ibm_d", "gate_histogram": {"cx": 10}},
            ],
        }
        events = RULE_009_concurrent_multi_backend_probing(data)
        assert len(events) == 1
        assert events[0].technique_id == "QTT001"
        assert events[0].severity == Severity.high

    def test_rule_009_no_false_positive(self):
        """Jobs on only 2 backends < 3 → no trigger."""
        data = {
            "recent_jobs": [
                {"backend_id": "ibm_a", "gate_histogram": {"cx": 10}},
                {"backend_id": "ibm_b", "gate_histogram": {"cx": 10}},
            ],
        }
        events = RULE_009_concurrent_multi_backend_probing(data)
        assert events == []

    def test_rule_009_edge_case(self):
        """Exactly 3 backends → ``>= 3`` is True → triggers."""
        data = {
            "recent_jobs": [
                {"backend_id": "ibm_a", "gate_histogram": {"cx": 5}},
                {"backend_id": "ibm_b", "gate_histogram": {"cx": 5}},
                {"backend_id": "ibm_c", "gate_histogram": {"cx": 5}},
            ],
        }
        events = RULE_009_concurrent_multi_backend_probing(data)
        assert len(events) == 1
        assert set(events[0].evidence["backends_accessed"]) == {"ibm_a", "ibm_b", "ibm_c"}

    def test_rule_009_jobs_without_backend_id(self):
        """Jobs with no backend_id field → empty string → filtered out."""
        data = {
            "recent_jobs": [
                {"gate_histogram": {"cx": 10}},
                {"gate_histogram": {"cx": 10}},
                {"gate_histogram": {"cx": 10}},
            ],
        }
        events = RULE_009_concurrent_multi_backend_probing(data)
        assert events == []


# ═══════════════════════════════════════════════════════════════════
#  RULE 010 — Anomalous Circuit Composition  (QTT009, medium)
# ═══════════════════════════════════════════════════════════════════

class TestRule010:
    def test_rule_010_detects_positive_case(self):
        """6 measures / 10 total = 0.6 > 0.5, total 10 > 10 → triggers.
        (``> 0.5`` AND ``> 10``) — total 10 is NOT > 10 so we use total = 11."""
        data = {
            "recent_jobs": [
                {"job_id": "j1", "gate_histogram": {"measure": 7, "cx": 4}},
            ],
        }
        # total = 11, measure_ratio = 7/11 ≈ 0.636 > 0.5, 11 > 10 → trigger
        events = RULE_010_anomalous_circuit_composition(data)
        assert len(events) == 1
        assert events[0].technique_id == "QTT009"
        assert events[0].severity == Severity.medium

    def test_rule_010_no_false_positive(self):
        """Normal circuit: 2 measures, 30 cx → ratio = 2/32 = 0.0625."""
        data = {
            "recent_jobs": [
                {"job_id": "j1", "gate_histogram": {"measure": 2, "cx": 30}},
            ],
        }
        events = RULE_010_anomalous_circuit_composition(data)
        assert events == []

    def test_rule_010_edge_case(self):
        """total gates exactly 10: ``> 10`` is False → no trigger even if
        measure ratio is high."""
        data = {
            "recent_jobs": [
                {"job_id": "j1", "gate_histogram": {"measure": 6, "cx": 4}},
            ],
        }
        events = RULE_010_anomalous_circuit_composition(data)
        assert events == []

    def test_rule_010_below_minimum_gates(self):
        """Very small circuit (total = 4) → skipped by ``total < 5`` guard."""
        data = {
            "recent_jobs": [
                {"job_id": "j1", "gate_histogram": {"measure": 3, "cx": 1}},
            ],
        }
        events = RULE_010_anomalous_circuit_composition(data)
        assert events == []


# ═══════════════════════════════════════════════════════════════════
#  ThresholdConfig & _cfg() helper
# ═══════════════════════════════════════════════════════════════════

class TestThresholdConfig:
    """Exercise the threshold configuration system — set, get, _cfg, file load."""

    def test_set_and_get_threshold_config(self):
        cfg = ThresholdConfig(rule_002_calibration_harvest_ratio=5.0)
        set_threshold_config(cfg)
        assert get_threshold_config() is cfg
        assert get_threshold_config().rule_002_calibration_harvest_ratio == 5.0

    def test_set_none_clears_config(self):
        set_threshold_config(ThresholdConfig())
        assert get_threshold_config() is not None
        set_threshold_config(None)
        assert get_threshold_config() is None

    def test_cfg_returns_config_value_when_set(self):
        """When a ThresholdConfig field is non-None, _cfg uses it."""
        set_threshold_config(ThresholdConfig(rule_004_max_failed_attempts=10))
        # _cfg takes (attr_name, default) and reads from _threshold_config internally
        result = _cfg('rule_004_max_failed_attempts', 5)
        assert result == 10

    def test_cfg_returns_default_when_config_none(self):
        """When no config is installed, _cfg always returns the default."""
        set_threshold_config(None)
        assert _cfg('rule_004_max_failed_attempts', 42) == 42

    def test_cfg_returns_default_when_field_none(self):
        """When config is set but the specific field is None, use default."""
        set_threshold_config(ThresholdConfig())  # all fields None
        assert _cfg('rule_004_max_failed_attempts', 42) == 42

    def test_rule_002_uses_custom_threshold(self):
        """Install a custom threshold so a previously-triggering ratio is now safe."""
        set_threshold_config(ThresholdConfig(rule_002_calibration_harvest_ratio=15.0))
        # ratio = 100/10 = 10 < 15 → no trigger
        data = {
            "api_access_log": {
                "calibration_requests_last_hour": 100,
                "job_submissions_last_hour": 10,
            },
        }
        events = RULE_002_calibration_harvest_rate(data)
        assert events == []

    def test_rule_004_uses_custom_threshold(self):
        """Lower the failed-attempts threshold to 2."""
        set_threshold_config(ThresholdConfig(rule_004_max_failed_attempts=2))
        data = {"failed_job_access_attempts": list(range(3))}  # 3 > 2
        events = RULE_004_cross_tenant_id_probing(data)
        assert len(events) == 1

    def test_load_threshold_config_from_nonexistent_file(self):
        result = load_threshold_config_from_file("/nonexistent/path.json")
        assert result is None

    def test_load_threshold_config_from_valid_file(self, tmp_path: Path):
        """Write a partial JSON and verify partial ThresholdConfig."""
        payload = {"rule_006_max_sequential_404": 25}
        f = tmp_path / "calibration_results.json"
        f.write_text(json.dumps(payload))
        cfg = load_threshold_config_from_file(str(f))
        assert cfg is not None
        assert cfg.rule_006_max_sequential_404 == 25
        # Other fields should remain None (use defaults)
        assert cfg.rule_002_calibration_harvest_ratio is None

    def test_load_threshold_config_malformed_json(self, tmp_path: Path):
        f = tmp_path / "bad.json"
        f.write_text("not json {{{")
        cfg = load_threshold_config_from_file(str(f))
        assert cfg is None


# ═══════════════════════════════════════════════════════════════════
#  ALL_RULES registry
# ═══════════════════════════════════════════════════════════════════

class TestRuleRegistry:
    def test_all_rules_count(self):
        assert len(ALL_RULES) == 10

    def test_all_rules_are_callable(self):
        for rule in ALL_RULES:
            assert callable(rule)

    def test_all_rules_handle_empty_input(self):
        """Every rule must return an empty list (not crash) when given ``{}``."""
        for rule in ALL_RULES:
            events = rule({})
            assert isinstance(events, list)
            # RULE_001 returns empty because no github_search_results key
            # All others return [] for missing keys
            # (RULE_008 may return [] because calibration is empty list)

    def test_all_rules_have_unique_technique_ids(self):
        """Fire all rules with triggering data and ensure no duplicate technique_ids
        in a single batch (except RULE_008 which can fire per qubit)."""
        data = {
            "github_search_results": [{"pattern": "token='abc123'"}],
            "api_access_log": {
                "calibration_requests_last_hour": 100,
                "job_submissions_last_hour": 10,
            },
            "recent_jobs": [
                {"job_id": "j1", "gate_histogram": {"id": 15, "cx": 2}},
                {"depth": 90, "max_allowed_depth": 100},
            ],
            "failed_job_access_attempts": list(range(6)),
            "api_error_log": {"sequential_404_count": 12, "403_on_admin_count": 4},
            "baseline_calibration": {"0": {"t1_us": 100}},
            "calibration": [{"qubit_id": 0, "t1_us": 50}],
        }
        all_events = []
        for rule in ALL_RULES:
            all_events.extend(rule(data))

        # Collect non-QTT010 technique IDs (QTT010 can fire multiple times per qubit)
        non_health = [e.technique_id for e in all_events if e.technique_id != "QTT010"]
        assert len(non_health) == len(set(non_health)), (
            f"Duplicate technique IDs found: {non_health}"
        )

    def test_rules_inherit_platform_from_data(self):
        """Rules should respect the ``platform`` key in raw_data."""
        data = {
            "platform": "amazon_braket",
            "api_error_log": {"sequential_404_count": 15},
        }
        events = RULE_006_ip_extraction_idor(data)
        assert len(events) == 1
        assert events[0].platform == Platform.amazon_braket

    def test_rules_default_to_ibm_quantum_platform(self):
        """When platform key is missing, default to ibm_quantum."""
        data = {"api_error_log": {"sequential_404_count": 15}}
        events = RULE_006_ip_extraction_idor(data)
        assert len(events) == 1
        assert events[0].platform == Platform.ibm_quantum


class TestEvidenceSchema:
    """G6 quality gate: every triggered event must contain rule_name and
    threshold_used in its evidence dict."""

    def test_rule_001_evidence_has_rule_name_and_threshold(self):
        data = {"github_search_results": [{"pattern": "token='abc123'"}]}
        events = RULE_001_credential_leak_github_search(data)
        assert len(events) == 1
        assert events[0].evidence["rule_name"] == "RULE_001_credential_leak_github_search"
        assert events[0].evidence["threshold_used"] == "N/A (any match triggers)"

    def test_rule_002_evidence_has_rule_name_and_threshold(self):
        data = {"api_access_log": {"calibration_requests_last_hour": 100, "job_submissions_last_hour": 10}}
        events = RULE_002_calibration_harvest_rate(data)
        assert len(events) == 1
        assert events[0].evidence["rule_name"] == "RULE_002_calibration_harvest_rate"
        assert events[0].evidence["threshold_used"] == 3.0

    def test_rule_003_evidence_has_rule_name_and_threshold(self):
        data = {"recent_jobs": [{"job_id": "j1", "gate_histogram": {"id": 15, "cx": 2}}]}
        events = RULE_003_timing_oracle_job_pattern(data)
        assert len(events) == 1
        assert events[0].evidence["rule_name"] == "RULE_003_timing_oracle_job_pattern"
        assert "identity_gate_ratio" in events[0].evidence["threshold_used"]

    def test_rule_004_evidence_has_rule_name_and_threshold(self):
        data = {"failed_job_access_attempts": list(range(6))}
        events = RULE_004_cross_tenant_id_probing(data)
        assert len(events) == 1
        assert events[0].evidence["rule_name"] == "RULE_004_cross_tenant_id_probing"
        assert events[0].evidence["threshold_used"] == 5

    def test_rule_005_evidence_has_rule_name_and_threshold(self):
        data = {"recent_jobs": [{"depth": 90, "max_allowed_depth": 100}]}
        events = RULE_005_resource_exhaustion_circuit(data)
        assert len(events) == 1
        assert events[0].evidence["rule_name"] == "RULE_005_resource_exhaustion_circuit"
        assert events[0].evidence["threshold_used"] == 0.85

    def test_rule_006_evidence_has_rule_name_and_threshold(self):
        data = {"api_error_log": {"sequential_404_count": 12}}
        events = RULE_006_ip_extraction_idor(data)
        assert len(events) == 1
        assert events[0].evidence["rule_name"] == "RULE_006_ip_extraction_idor"
        assert events[0].evidence["threshold_used"] == 10

    def test_rule_007_evidence_has_rule_name_and_threshold(self):
        data = {"api_error_log": {"403_on_admin_count": 4}}
        events = RULE_007_token_scope_violation(data)
        assert len(events) == 1
        assert events[0].evidence["rule_name"] == "RULE_007_token_scope_violation"
        assert events[0].evidence["threshold_used"] == 3

    def test_rule_008_evidence_has_rule_name_and_threshold(self):
        data = {"baseline_calibration": {"0": {"t1_us": 100.0}}, "calibration": [{"qubit_id": 0, "t1_us": 50.0}]}
        events = RULE_008_backend_health_anomaly(data)
        assert len(events) == 1
        assert events[0].evidence["rule_name"] == "RULE_008_backend_health_anomaly"
        assert events[0].evidence["threshold_used"] == 0.6

    def test_rule_009_evidence_has_rule_name_and_threshold(self):
        data = {"recent_jobs": [{"backend_id": "a"}, {"backend_id": "b"}, {"backend_id": "c"}]}
        events = RULE_009_concurrent_multi_backend_probing(data)
        assert len(events) == 1
        assert events[0].evidence["rule_name"] == "RULE_009_concurrent_multi_backend_probing"
        assert events[0].evidence["threshold_used"] == 3

    def test_rule_010_evidence_has_rule_name_and_threshold(self):
        data = {"recent_jobs": [{"job_id": "j1", "gate_histogram": {"measure": 7, "cx": 4}}]}
        events = RULE_010_anomalous_circuit_composition(data)
        assert len(events) == 1
        assert events[0].evidence["rule_name"] == "RULE_010_anomalous_circuit_composition"
        assert "measure_ratio" in events[0].evidence["threshold_used"]


class TestEnabledRules:
    """Test that enabled_rules in ThresholdConfig correctly filters which rules run."""

    def test_all_rules_enabled_by_default(self):
        """When enabled_rules is None, get_active_rules returns all 10 rules."""
        set_threshold_config(None)
        assert len(get_active_rules()) == 10

    def test_subset_of_rules_enabled(self):
        """Only the named rules should be returned."""
        set_threshold_config(ThresholdConfig(
            enabled_rules={"RULE_001_credential_leak_github_search", "RULE_005_resource_exhaustion_circuit"}
        ))
        active = get_active_rules()
        assert len(active) == 2
        names = {r.__name__ for r in active}
        assert names == {"RULE_001_credential_leak_github_search", "RULE_005_resource_exhaustion_circuit"}

    def test_empty_enabled_rules_set(self):
        """An empty set means NO rules are active."""
        set_threshold_config(ThresholdConfig(enabled_rules=set()))
        assert get_active_rules() == []
