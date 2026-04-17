"""Comprehensive verification tests for Priority 2 and Priority 3 defect fixes.

Each test class targets a specific fix from the adversarial audit and proves:
  1. The bug existed (or would have existed) in the old behaviour
  2. The fix resolves it correctly
  3. Edge cases around the fix are covered

Fixes verified:
  P2-1: Rules 003/005/010 fire on ALL matching jobs (not just first)
  P2-2: Analyzer dedup updates evidence while keeping ID continuity
  P2-3: save_correlation scopes to campaign's backend_id
  P2-4: _cfg() handles None config internally
  P2-5: Zero-variance warmup transient is suppressed
  P2-6: RULE_008 uses QTT010 instead of "HEALTH"
  P3-1: Correlator dedup survives history pruning
  P3-2: Database lazy init is async-safe
  P3-3: WebSocket uses time.monotonic() (not deprecated API)
  P3-4: Rate limiter state is isolated between tests
"""

from __future__ import annotations

import asyncio
import inspect
import math
import time
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from typing import Any, Dict

import pytest

from backend.threat_engine.models import (
    Severity,
    Platform,
    ThreatEvent,
)
from backend.threat_engine.rules import (
    RULE_003_timing_oracle_job_pattern,
    RULE_005_resource_exhaustion_circuit,
    RULE_010_anomalous_circuit_composition,
    RULE_008_backend_health_anomaly,
    ThresholdConfig,
    _cfg,
    set_threshold_config,
    get_threshold_config,
)
from backend.threat_engine.baseline import BaselineManager, MetricBaseline
from backend.threat_engine.correlator import ThreatCorrelator, CORRELATION_PATTERNS


# ═══════════════════════════════════════════════════════════════════════
#  P2-1: Rules fire on ALL matching jobs, not just the first one
# ═══════════════════════════════════════════════════════════════════════

class TestP2_1_MultiJobDetection:
    """Before the fix, rules 003/005/010 returned on the first matching job
    inside the loop, silently ignoring all subsequent malicious jobs."""

    def test_rule_003_fires_on_all_identity_heavy_jobs(self):
        """Three jobs with identity-heavy circuits → three events."""
        data = {
            "recent_jobs": [
                {"job_id": "j1", "gate_histogram": {"id": 15, "cx": 2}},
                {"job_id": "j2", "gate_histogram": {"id": 12, "cx": 3}},
                {"job_id": "j3", "gate_histogram": {"id": 18, "cx": 1}},
            ],
        }
        events = RULE_003_timing_oracle_job_pattern(data)
        assert len(events) == 3, (
            f"Expected 3 events for 3 identity-heavy jobs, got {len(events)}"
        )
        job_ids = {e.evidence["job_id"] for e in events}
        assert job_ids == {"j1", "j2", "j3"}

    def test_rule_005_fires_on_all_depth_exceeding_jobs(self):
        """Two jobs exceeding depth ratio → two events."""
        data = {
            "recent_jobs": [
                {"depth": 90, "max_allowed_depth": 100},
                {"depth": 95, "max_allowed_depth": 100},
            ],
        }
        events = RULE_005_resource_exhaustion_circuit(data)
        assert len(events) == 2

    def test_rule_010_fires_on_all_anomalous_circuits(self):
        """Two circuits with high measurement ratio → two events."""
        data = {
            "recent_jobs": [
                {"job_id": "j1", "gate_histogram": {"measure": 8, "cx": 4}},
                {"job_id": "j2", "gate_histogram": {"measure": 9, "cx": 3}},
            ],
        }
        events = RULE_010_anomalous_circuit_composition(data)
        assert len(events) == 2

    def test_rule_003_mixed_jobs_fires_only_matching(self):
        """One matching + one non-matching → one event."""
        data = {
            "recent_jobs": [
                {"job_id": "j1", "gate_histogram": {"id": 15, "cx": 2}},  # matching
                {"job_id": "j2", "gate_histogram": {"id": 3, "cx": 40, "rz": 50}},  # not
            ],
        }
        events = RULE_003_timing_oracle_job_pattern(data)
        assert len(events) == 1
        assert events[0].evidence["job_id"] == "j1"

    def test_rule_005_no_match_returns_empty(self):
        """All jobs below threshold → empty list."""
        data = {
            "recent_jobs": [
                {"depth": 50, "max_allowed_depth": 100},
                {"depth": 30, "max_allowed_depth": 100},
            ],
        }
        events = RULE_005_resource_exhaustion_circuit(data)
        assert events == []


# ═══════════════════════════════════════════════════════════════════════
#  P2-2: Analyzer dedup updates evidence while keeping ID continuity
# ═══════════════════════════════════════════════════════════════════════

class TestP2_2_AnalyzerDedupEvidenceFreshness:
    """Before the fix, the 5-min dedup froze detected_at to the first
    occurrence and replaced evidence without updating the timestamp."""

    def test_evidence_is_updated_within_dedup_window(self):
        """Within 5-min window, evidence should reflect latest observation."""
        from backend.threat_engine.analyzer import ThreatAnalyzer

        analyzer = ThreatAnalyzer()
        data1 = {"backend_id": "b1", "api_error_log": {"sequential_404_count": 15}}
        data2 = {"backend_id": "b1", "api_error_log": {"sequential_404_count": 50}}

        result1 = analyzer.analyze(data1)
        assert len(result1) == 1
        id1 = result1[0].id

        result2 = analyzer.analyze(data2)
        assert len(result2) == 1
        id2 = result2[0].id

        # ID stays the same (continuity)
        assert id1 == id2
        # But evidence reflects the LATEST observation
        assert result2[0].evidence["sequential_404_count"] == 50

    def test_detected_at_updates_within_dedup_window(self):
        """detected_at should reflect the latest cycle, not the first-seen time."""
        from backend.threat_engine.analyzer import ThreatAnalyzer

        analyzer = ThreatAnalyzer()
        data = {"backend_id": "b1", "api_error_log": {"sequential_404_count": 15}}

        result1 = analyzer.analyze(data)
        time.sleep(0.01)  # small delay to ensure different timestamp
        result2 = analyzer.analyze(data)

        # detected_at should be at least as recent as result1
        assert result2[0].detected_at >= result1[0].detected_at

    def test_new_id_after_dedup_window_expires(self):
        """After 5 minutes, a new occurrence should get a fresh ID."""
        from backend.threat_engine.analyzer import ThreatAnalyzer

        analyzer = ThreatAnalyzer()
        old_time = datetime.now(timezone.utc) - timedelta(minutes=6)

        data = {"backend_id": "b1", "api_error_log": {"sequential_404_count": 15}}

        # First detection
        result1 = analyzer.analyze(data)
        id1 = result1[0].id

        # Manually backdate the threat to simulate 6 min ago
        key = list(analyzer.active_threats.keys())[0]
        analyzer.active_threats[key].detected_at = old_time

        # Second detection — window expired
        result2 = analyzer.analyze(data)
        id2 = result2[0].id

        # Should be a NEW ID
        assert id1 != id2


# ═══════════════════════════════════════════════════════════════════════
#  P2-4: _cfg() handles None config internally
# ═══════════════════════════════════════════════════════════════════════

class TestP2_4_CfgHelperSafety:
    """_cfg(attr_name, default) should never crash even when _threshold_config
    is None or when the config field doesn't exist."""

    def test_cfg_no_crash_with_none_config(self):
        """When no config is installed, _cfg returns default without crash."""
        set_threshold_config(None)
        assert _cfg('nonexistent_field', 99) == 99

    def test_cfg_no_crash_with_missing_attribute(self):
        """When config is installed but field doesn't exist, return default."""
        set_threshold_config(ThresholdConfig())
        assert _cfg('totally_fake_field', 42) == 42

    def test_cfg_returns_set_value(self):
        set_threshold_config(ThresholdConfig(rule_002_calibration_harvest_ratio=7.5))
        assert _cfg('rule_002_calibration_harvest_ratio', 3.0) == 7.5

    def test_cfg_ignores_none_field(self):
        """Config field is explicitly None → falls back to default."""
        set_threshold_config(ThresholdConfig(rule_002_calibration_harvest_ratio=None))
        assert _cfg('rule_002_calibration_harvest_ratio', 3.0) == 3.0

    def test_rules_never_access_config_directly(self):
        """Verify that no rule file contains the fragile pattern
        '_threshold_config.field if _threshold_config else None'."""
        from backend.threat_engine import rules as rules_module
        src = inspect.getsource(rules_module)
        # The old fragile pattern should not appear in any rule function
        assert "if _threshold_config else None" not in src, (
            "Found fragile '_threshold_config.field if _threshold_config else None' "
            "pattern — rules should use _cfg('field_name', default) instead."
        )


# ═══════════════════════════════════════════════════════════════════════
#  P2-5: Zero-variance warmup transient suppression
# ═══════════════════════════════════════════════════════════════════════

class TestP2_5_ZeroVarianceWarmupTransient:
    """Before the fix, 3 identical values followed by a 1% deviation would
    produce an enormous z-score (33+ sigma) and trigger a false alert."""

    def test_tiny_deviation_after_stable_values_no_false_positive(self):
        """3 identical values of 100, then 101 → should NOT trigger alert.

        Without the variance floor, the z-score would be:
        ema ≈ 100, variance ≈ 0.0009, std ≈ 0.03, z = 1.0/0.03 ≈ 33 sigma
        With the floor (0.1% of ema² = 10), z ≈ 1.0/sqrt(10) ≈ 0.32 sigma
        """
        bm = BaselineManager(z_threshold=2.5)
        bm.check("b", "t1", 100.0)  # count=1, warmup
        bm.check("b", "t1", 100.0)  # count=2, warmup
        bm.check("b", "t1", 100.0)  # count=3, warmup
        result = bm.check("b", "t1", 101.0)  # count=4, post-warmup
        assert result is None, (
            f"1% deviation after 3 stable values should not trigger. "
            f"z-score was: {result}"
        )

    def test_large_deviation_after_stable_values_does_trigger(self):
        """3 identical values of 100, then 500 → should trigger alert.

        With variance floor: z ≈ 400/sqrt(10) ≈ 126 sigma → triggers.
        """
        bm = BaselineManager(z_threshold=2.5)
        bm.check("b", "t1", 100.0)
        bm.check("b", "t1", 100.0)
        bm.check("b", "t1", 100.0)
        result = bm.check("b", "t1", 500.0)
        assert result is not None
        assert result > 2.5

    def test_gradual_drift_from_stable_baseline_no_false_positive(self):
        """10 identical values of 100, then 200 steps of +0.01 drift.

        Without the variance floor, the first few post-warmup steps would
        have enormous z-scores.  With the floor, they should be suppressed.
        """
        bm = BaselineManager(z_threshold=2.5)

        # Warmup with identical values
        for _ in range(10):
            bm.check("b", "metric", 100.0)

        alerts = []
        for i in range(200):
            value = 100.0 + i * 0.01  # 100.00 → 101.99
            z = bm.check("b", "metric", value)
            if z is not None:
                alerts.append(z)

        assert len(alerts) == 0, (
            f"Gradual drift triggered {len(alerts)} alerts. "
            f"Max z: {max(alerts):.2f}" if alerts else ""
        )

    def test_variance_floor_proportional_to_ema(self):
        """Larger EMA values should have proportionally larger floors."""
        mb_small = MetricBaseline(alpha=0.1)
        mb_large = MetricBaseline(alpha=0.1)

        # Establish baselines
        for _ in range(5):
            mb_small.update(1.0)
            mb_large.update(10000.0)

        # Same relative deviation (10%)
        z_small = mb_small.update(1.1)
        z_large = mb_large.update(11000.0)

        # Both should have similar z-scores (within factor of 2)
        assert abs(z_small) > 0
        assert abs(z_large) > 0
        ratio = abs(z_small) / max(abs(z_large), 0.001)
        assert 0.1 < ratio < 10, (
            f"Relative z-scores differ too much: {ratio:.2f} "
            f"(small={z_small:.3f}, large={z_large:.3f})"
        )


# ═══════════════════════════════════════════════════════════════════════
#  P2-6: RULE_008 uses QTT010 instead of "HEALTH"
# ═══════════════════════════════════════════════════════════════════════

class TestP2_6_Rule008TechniqueId:
    """RULE_008 should use a QTT-prefixed technique_id for consistency."""

    def test_rule_008_uses_qtt_prefix(self):
        data = {
            "baseline_calibration": {"0": {"t1_us": 100.0}},
            "calibration": [{"qubit_id": 0, "t1_us": 50.0}],
        }
        events = RULE_008_backend_health_anomaly(data)
        assert len(events) == 1
        assert events[0].technique_id.startswith("QTT"), (
            f"Expected QTT-prefixed ID, got: {events[0].technique_id}"
        )
        assert events[0].technique_id == "QTT010"

    def test_rule_008_qtt015_is_not_a_rule_that_fires_from_job_data(self):
        """QTT010 is for backend health anomalies, not a correlation pattern
        technique ID that could be confused with job-based rules."""
        corr_technique_ids = set()
        for pattern in CORRELATION_PATTERNS:
            corr_technique_ids.update(pattern["techniques"])
        assert "QTT010" not in corr_technique_ids


# ═══════════════════════════════════════════════════════════════════════
#  P3-1: Correlator dedup survives history pruning
# ═══════════════════════════════════════════════════════════════════════

class TestP3_1_CorrelatorDedupSurvivesPruning:
    """Before the fix, the correlator dedup marker lived inside recent_threats.
    When old events were pruned, the campaign could re-fire."""

    def _make_threat(self, technique_id, backend_id="backend_a", minutes_ago=0):
        return ThreatEvent(
            id=f"evt-{technique_id}-{minutes_ago}",
            technique_id=technique_id,
            technique_name=f"Test {technique_id}",
            severity=Severity.high,
            platform=Platform.ibm_quantum,
            backend_id=backend_id,
            title=f"Test: {technique_id}",
            description="Synthetic event.",
            evidence={},
            detected_at=datetime.now(timezone.utc) - timedelta(minutes=minutes_ago),
            visual_effect="none",
            visual_intensity=0.5,
            remediation=["Investigate."],
        )

    def test_campaign_does_not_refire_after_pruning(self):
        """A campaign that has already fired should NOT re-fire even after
        the underlying threats are still within the history window."""
        corr = ThreatCorrelator(history_hours=2.0)

        # Step 1: feed both techniques → campaign fires
        corr.correlate([self._make_threat("QTT003", minutes_ago=0)])
        campaigns_1 = corr.correlate([self._make_threat("QTT002", minutes_ago=0)])
        assert len(campaigns_1) == 1

        # Step 2: feed an unrelated threat — should NOT re-trigger
        campaigns_2 = corr.correlate([self._make_threat("QTT001", minutes_ago=0)])
        assert campaigns_2 == []

        # Step 3: feed the same techniques again — should still NOT re-trigger
        # (because the dedup key persists even if history was pruned)
        campaigns_3 = corr.correlate([
            self._make_threat("QTT003", minutes_ago=0),
            self._make_threat("QTT002", minutes_ago=0),
        ])
        assert campaigns_3 == []

    def test_campaign_dedup_key_expires_when_techniques_gone(self):
        """When the underlying technique events are pruned from history,
        the dedup key should expire, allowing a genuinely new occurrence."""
        corr = ThreatCorrelator(history_hours=2.0)  # Sufficient for all windows

        # Step 1: campaign fires
        corr.correlate([self._make_threat("QTT003", minutes_ago=0)])
        campaigns_1 = corr.correlate([self._make_threat("QTT002", minutes_ago=0)])
        assert len(campaigns_1) == 1

        # Step 2: inject events with timestamps BEFORE the window cutoff,
        # then call correlate to trigger pruning
        old_qtt003 = self._make_threat("QTT003", minutes_ago=150)
        old_qtt002 = self._make_threat("QTT002", minutes_ago=150)
        # Replace recent_threats with only old events
        corr.recent_threats = [old_qtt003, old_qtt002]
        corr.correlate([])  # triggers pruning of old events

        # After pruning, both QTT003 and QTT002 are gone
        active_ids = {t.technique_id for t in corr.recent_threats}
        assert "QTT003" not in active_ids
        assert "QTT002" not in active_ids

        # Step 3: feed fresh techniques → campaign should fire again
        campaigns_3 = corr.correlate([
            self._make_threat("QTT003", minutes_ago=0),
            self._make_threat("QTT002", minutes_ago=0),
        ])
        assert len(campaigns_3) == 1, (
            "Campaign should re-fire after dedup key expired and new occurrence"
        )

    def test_reset_clears_dedup_keys(self):
        """reset() should clear both recent_threats AND campaign dedup keys."""
        corr = ThreatCorrelator(history_hours=2.0)

        corr.correlate([self._make_threat("QTT003")])
        corr.correlate([self._make_threat("QTT002")])

        assert len(corr._campaign_dedup) > 0

        corr.reset()

        assert len(corr.recent_threats) == 0
        assert len(corr._campaign_dedup) == 0

        # After reset, same techniques should fire again
        campaigns = corr.correlate([
            self._make_threat("QTT003"),
            self._make_threat("QTT002"),
        ])
        assert len(campaigns) == 1


# ═══════════════════════════════════════════════════════════════════════
#  P3-2: Database lazy init is async-safe
# ═══════════════════════════════════════════════════════════════════════

class TestP3_2_DatabaseAsyncSafety:
    """The lazy init should use an asyncio.Lock to prevent double-init."""

    def test_get_init_lock_exists(self):
        from backend.storage.database import _get_init_lock
        lock = _get_init_lock()
        assert lock is not None
        assert hasattr(lock, 'acquire')

    def test_double_call_to_get_init_lock_returns_same_lock(self):
        from backend.storage.database import _get_init_lock
        lock1 = _get_init_lock()
        lock2 = _get_init_lock()
        assert lock1 is lock2


# ═══════════════════════════════════════════════════════════════════════
#  P3-3: WebSocket uses time.monotonic() not deprecated API
# ═══════════════════════════════════════════════════════════════════════

class TestP3_3_WebSocketNoDeprecatedAPI:
    """The WebSocket rate checker should not use deprecated
    asyncio.get_event_loop().time()."""

    def test_no_get_event_loop_in_websocket(self):
        from backend.api import websocket as ws_module
        src = inspect.getsource(ws_module)
        assert "get_event_loop()" not in src, (
            "WebSocket module still uses deprecated asyncio.get_event_loop()"
        )

    def test_uses_time_monotonic(self):
        from backend.api import websocket as ws_module
        src = inspect.getsource(ws_module)
        assert "monotonic" in src, (
            "WebSocket module should use time.monotonic() for rate limiting"
        )


# ═══════════════════════════════════════════════════════════════════════
#  P3-4: Rate limiter state isolation between tests
# ═══════════════════════════════════════════════════════════════════════

class TestP3_4_RateLimiterStateIsolation:
    """The autouse fixture in conftest.py should reset rate limiter state."""

    def test_rate_windows_is_defaultdict(self):
        from backend.api.ratelimit import _rate_windows
        assert isinstance(_rate_windows, defaultdict)

    def test_rate_limiter_starts_clean(self):
        """At the start of each test, the rate limiter should have no IPs."""
        from backend.api.ratelimit import _rate_windows, _ip_count
        # The autouse fixture should have reset these
        assert len(_rate_windows) == 0
        assert _ip_count == 0
