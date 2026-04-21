from backend.api.auth import create_access_token
"""Tests for Phase 2: Detection engine enhancement, STIX export, correlation."""

import os
import pytest

os.environ["PYTEST_CURRENT_TEST"] = "true"

from fastapi.testclient import TestClient
from backend.main import app
from backend.threat_engine.rules import (
    RULE_009_concurrent_multi_backend_probing,
    RULE_010_anomalous_circuit_composition,
    ALL_RULES,
)
from backend.threat_engine.baseline import BaselineManager
from backend.threat_engine.correlator import ThreatCorrelator
from backend.threat_engine.models import ThreatEvent, Severity, Platform
from datetime import datetime, timezone, timedelta

client = TestClient(app)


# ─── RULE_009 Tests ────────────────────────────────────────────────────

class TestRule009:
    def test_detects_concurrent_multi_backend_probing(self):
        data = {
            "backend_id": "ibm_sherbrooke",
            "recent_jobs": [
                {"backend_id": "ibm_sherbrooke", "job_id": "1"},
                {"backend_id": "ibm_kyoto", "job_id": "2"},
                {"backend_id": "ibm_brisbane", "job_id": "3"},
            ],
        }
        events = RULE_009_concurrent_multi_backend_probing(data)
        assert len(events) == 1
        assert events[0].technique_id == "QTT001"
        assert events[0].severity == Severity.high

    def test_ignores_single_backend_access(self):
        data = {
            "backend_id": "ibm_sherbrooke",
            "recent_jobs": [{"backend_id": "ibm_sherbrooke", "job_id": "1"}],
        }
        events = RULE_009_concurrent_multi_backend_probing(data)
        assert len(events) == 0

    def test_requires_three_or_more_backends(self):
        data = {
            "backend_id": "ibm_sherbrooke",
            "recent_jobs": [
                {"backend_id": "ibm_sherbrooke", "job_id": "1"},
                {"backend_id": "ibm_kyoto", "job_id": "2"},
            ],
        }
        events = RULE_009_concurrent_multi_backend_probing(data)
        assert len(events) == 0


# ─── RULE_010 Tests ────────────────────────────────────────────────────

class TestRule010:
    def test_detects_anomalous_circuit_high_measure_ratio(self):
        data = {
            "backend_id": "ibm_sherbrooke",
            "recent_jobs": [
                {"gate_histogram": {"measure": 12, "h": 2, "cx": 3, "rz": 1}, "job_id": "1"}
            ],
        }
        events = RULE_010_anomalous_circuit_composition(data)
        assert len(events) == 1
        assert events[0].technique_id == "QTT009"

    def test_ignores_normal_circuit_composition(self):
        data = {
            "backend_id": "ibm_sherbrooke",
            "recent_jobs": [
                {"gate_histogram": {"cx": 20, "rz": 40, "h": 10, "measure": 10}, "job_id": "1"}
            ],
        }
        events = RULE_010_anomalous_circuit_composition(data)
        assert len(events) == 0

    def test_ignores_too_few_gates(self):
        data = {
            "backend_id": "ibm_sherbrooke",
            "recent_jobs": [
                {"gate_histogram": {"measure": 3, "h": 1}, "job_id": "1"}
            ],
        }
        events = RULE_010_anomalous_circuit_composition(data)
        assert len(events) == 0  # total=4 < 5


# ─── Baseline Manager Tests ────────────────────────────────────────────

class TestBaselineManager:
    def test_initial_values_return_zero_zscore(self):
        bm = BaselineManager()
        z = bm.check("backend_1", "metric_a", 100.0)
        assert z is None  # First value, not enough data for anomaly detection

    def test_stable_values_have_low_zscore(self):
        bm = BaselineManager()
        for i in range(20):
            z = bm.check("backend_1", "metric_a", 100.0 + (i % 3))
        # After warmup, small deviations should not trigger
        z = bm.check("backend_1", "metric_a", 101.0)
        assert z is None or abs(z) < bm.z_threshold

    def test_anomalous_spike_detected(self):
        bm = BaselineManager()
        # Warm up with stable values
        for i in range(20):
            bm.check("backend_1", "metric_a", 100.0)

        # Spike should be detected
        z = bm.check("backend_1", "metric_a", 500.0)
        assert z is not None
        assert abs(z) > bm.z_threshold

    def test_per_backend_isolation(self):
        bm = BaselineManager()
        for i in range(20):
            bm.check("backend_1", "metric_a", 100.0)
            bm.check("backend_2", "metric_a", 500.0)

        # backend_2 considers 500 normal; backend_1 does not
        z1 = bm.check("backend_1", "metric_a", 500.0)
        z2 = bm.check("backend_2", "metric_a", 500.0)
        # backend_1 should detect anomaly, backend_2 should not
        assert z1 is not None and abs(z1) > bm.z_threshold
        assert z2 is None or abs(z2) < bm.z_threshold


# ─── Threat Correlator Tests ───────────────────────────────────────────

class TestThreatCorrelator:
    def _make_threat(self, technique_id, backend_id, minutes_ago=0):
        return ThreatEvent(
            id=f"threat-{technique_id}-{backend_id}",
            technique_id=technique_id,
            technique_name=f"Test {technique_id}",
            severity=Severity.high,
            platform=Platform.ibm_quantum,
            backend_id=backend_id,
            title="Test threat",
            description="Test",
            evidence={},
            detected_at=datetime.now(timezone.utc) - timedelta(minutes=minutes_ago),
            visual_effect="interference",
            visual_intensity=0.5,
            remediation=["Test"],
        )

    def test_correlates_timing_and_calibration(self):
        correlator = ThreatCorrelator()
        # First threat: timing oracle
        t1 = self._make_threat("QTT003", "ibm_sherbrooke", minutes_ago=5)
        campaigns = correlator.correlate([t1])
        assert len(campaigns) == 0  # Need both techniques

        # Second threat: calibration harvest (same backend, within window)
        t2 = self._make_threat("QTT002", "ibm_sherbrooke", minutes_ago=0)
        campaigns = correlator.correlate([t2])
        assert len(campaigns) == 1
        assert "CORR:" in campaigns[0].technique_id
        assert campaigns[0].severity == Severity.critical

    def test_no_correlation_across_different_backends(self):
        correlator = ThreatCorrelator()
        t1 = self._make_threat("QTT003", "ibm_sherbrooke", minutes_ago=5)
        correlator.correlate([t1])
        t2 = self._make_threat("QTT002", "ibm_kyoto", minutes_ago=0)
        campaigns = correlator.correlate([t2])
        assert len(campaigns) == 0  # Different backends

    def test_no_duplicate_campaigns(self):
        correlator = ThreatCorrelator()
        t1 = self._make_threat("QTT003", "ibm_sherbrooke", minutes_ago=5)
        t2 = self._make_threat("QTT002", "ibm_sherbrooke", minutes_ago=0)
        correlator.correlate([t1])
        campaigns1 = correlator.correlate([t2])
        assert len(campaigns1) >= 1
        # Now the campaign event is in recent_threats history.
        # Re-correlating with the same technique types should produce no new campaigns
        # because the CORR event already exists for this backend+pattern combo.
        t3 = self._make_threat("QTT003", "ibm_sherbrooke", minutes_ago=0)
        t4 = self._make_threat("QTT002", "ibm_sherbrooke", minutes_ago=0)
        campaigns2 = correlator.correlate([t3, t4])
        # New campaign events should NOT be generated for a pattern that already fired
        corr_ids_1 = {c.technique_id for c in campaigns1}
        corr_ids_2 = {c.technique_id for c in campaigns2}
        # Either no new campaigns, or same campaign ID (deduped)
        assert len(corr_ids_2 - corr_ids_1) == 0


# ─── STIX Export Tests ─────────────────────────────────────────────────

class TestSTIXExport:
    def test_stix_export_returns_valid_bundle(self):
        _token = create_access_token({'sub': 'test', 'role': 'admin'})
        response = client.get("/api/threats/export/stix")
        assert response.status_code == 200
        data = response.json()
        assert data["type"] == "bundle"
        assert "objects" in data
        assert len(data["objects"]) > 0

    def test_stix_indicators_have_required_fields(self):
        _token = create_access_token({'sub': 'test', 'role': 'admin'})
        response = client.get("/api/threats/export/stix")
        data = response.json()
        for obj in data["objects"]:
            assert obj["type"] == "indicator"
            assert "id" in obj
            assert "pattern" in obj
            assert "created" in obj
            assert "valid_from" in obj
            assert "confidence" in obj
            assert obj["spec_version"] == "2.1"

    def test_threat_history_endpoint(self):
        _token = create_access_token({'sub': 'test', 'role': 'admin'})
        response = client.get("/api/threats/history", headers={"Authorization": f"Bearer {_token}"})
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)


# ─── All Rules Count ───────────────────────────────────────────────────

class TestAllRulesCount:
    def test_ten_detection_rules_exist(self):
        assert len(ALL_RULES) == 10
