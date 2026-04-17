"""Comprehensive tests for the ThreatCorrelator in correlator.py.

Four correlation patterns, each tested with:
  1. *positive* — both techniques present within the time window
  2. *negative — outside window* — techniques present but separated beyond the window
  3. *negative — missing technique* — only one of the two techniques present

Additional coverage:
  - Deduplication (same pattern on same backend fires only once)
  - History pruning (old events evicted)
  - Empty input
  - Cross-backend isolation

IMPORTANT: The correlator internally uses ``datetime.now(timezone.utc)`` for
window calculations.  To test the "outside window" case we must inject the
first event with a ``detected_at`` far enough in the *past* so that when
the second correlate call runs (a few ms later), the first event falls
outside the pattern's window.
"""

from __future__ import annotations

from datetime import datetime, timezone, timedelta
from typing import List

import pytest

from backend.threat_engine.correlator import (
    CORRELATION_PATTERNS,
    ThreatCorrelator,
)
from backend.threat_engine.models import Severity, Platform, ThreatEvent


# ────────────────────────────────────────────────────────────────────
#  Helpers
# ────────────────────────────────────────────────────────────────────

def _threat(
    technique_id: str,
    backend_id: str = "backend_a",
    severity: Severity = Severity.high,
    detected_at: datetime | None = None,
) -> ThreatEvent:
    """Build a minimal ThreatEvent for correlation testing."""
    return ThreatEvent(
        id=f"evt-{technique_id}-{backend_id}",
        technique_id=technique_id,
        technique_name=f"Test {technique_id}",
        severity=severity,
        platform=Platform.ibm_quantum,
        backend_id=backend_id,
        title=f"Test: {technique_id}",
        description="Synthetic event for correlator tests.",
        evidence={},
        detected_at=detected_at or datetime.now(timezone.utc),
        visual_effect="none",
        visual_intensity=0.5,
        remediation=["Investigate."],
    )


def _old_threat(
    technique_id: str,
    backend_id: str = "backend_a",
    minutes_ago: float = 60.0,
) -> ThreatEvent:
    """Create a threat event with ``detected_at`` set to ``minutes_ago``
    in the past relative to *now*.  Use enough minutes to exceed the
    correlator's pattern window."""
    return _threat(
        technique_id,
        backend_id=backend_id,
        detected_at=datetime.now(timezone.utc) - timedelta(minutes=minutes_ago),
    )


# ═══════════════════════════════════════════════════════════════════
#  Pattern 1 — Coordinated Reconnaissance  (QTT003 + QTT002, 30 min, critical)
# ═══════════════════════════════════════════════════════════════════

class TestCoordinatedReconnaissance:
    """QTT003 (Timing Oracle) + QTT002 (Calibration Harvesting) → critical."""

    def test_positive_both_within_window(self):
        corr = ThreatCorrelator(history_hours=2.0)

        # Feed QTT003 now
        corr.correlate([_threat("QTT003", "backend_a")])

        # Feed QTT002 a moment later (still within 30-min window)
        campaigns = corr.correlate([_threat("QTT002", "backend_a")])

        assert len(campaigns) == 1
        assert campaigns[0].severity == Severity.critical
        assert "Coordinated Reconnaissance" in campaigns[0].technique_id
        assert campaigns[0].backend_id == "backend_a"

    def test_negative_outside_window(self):
        """QTT003 was 45 minutes ago — beyond the 30-min pattern window."""
        corr = ThreatCorrelator(history_hours=2.0)

        # Inject old QTT003 event directly into history
        old = _old_threat("QTT003", "backend_a", minutes_ago=45)
        corr.recent_threats.append(old)

        # Now feed QTT002 — correlator checks window from datetime.now()
        campaigns = corr.correlate([_threat("QTT002", "backend_a")])

        assert campaigns == []

    def test_negative_missing_technique(self):
        corr = ThreatCorrelator()
        corr.correlate([_threat("QTT003", "backend_a")])
        campaigns = corr.correlate([_threat("QTT009", "backend_a")])
        assert campaigns == []


# ═══════════════════════════════════════════════════════════════════
#  Pattern 2 — Pre-Attack Staging  (QTT007 + QTT003, 60 min, critical)
# ═══════════════════════════════════════════════════════════════════

class TestPreAttackStaging:
    """QTT007 (Credential Exposure) + QTT003 (Timing Oracle) → critical."""

    def test_positive_both_within_window(self):
        corr = ThreatCorrelator(history_hours=2.0)

        corr.correlate([_threat("QTT007", "backend_b")])
        campaigns = corr.correlate([_threat("QTT003", "backend_b")])

        assert len(campaigns) == 1
        assert campaigns[0].severity == Severity.critical
        assert "Pre-Attack Staging" in campaigns[0].technique_id

    def test_negative_outside_window(self):
        """QTT007 was 90 minutes ago — beyond the 60-min pattern window."""
        corr = ThreatCorrelator(history_hours=3.0)

        old = _old_threat("QTT007", "backend_b", minutes_ago=90)
        corr.recent_threats.append(old)

        campaigns = corr.correlate([_threat("QTT003", "backend_b")])
        assert campaigns == []

    def test_negative_missing_technique(self):
        corr = ThreatCorrelator()
        corr.correlate([_threat("QTT007", "backend_b")])
        campaigns = corr.correlate([_threat("QTT002", "backend_b")])
        assert campaigns == []


# ═══════════════════════════════════════════════════════════════════
#  Pattern 3 — Enumeration Campaign  (QTT004 + QTT006, 15 min, critical)
# ═══════════════════════════════════════════════════════════════════

class TestEnumerationCampaign:
    """QTT004 (Tenant Probing) + QTT006 (IP Extraction) → critical."""

    def test_positive_both_within_window(self):
        corr = ThreatCorrelator(history_hours=2.0)

        corr.correlate([_threat("QTT004", "backend_c")])
        campaigns = corr.correlate([_threat("QTT006", "backend_c")])

        assert len(campaigns) == 1
        assert campaigns[0].severity == Severity.critical
        assert "Enumeration Campaign" in campaigns[0].technique_id

    def test_negative_outside_window(self):
        """QTT004 was 20 minutes ago — beyond the 15-min pattern window."""
        corr = ThreatCorrelator(history_hours=2.0)

        old = _old_threat("QTT004", "backend_c", minutes_ago=20)
        corr.recent_threats.append(old)

        campaigns = corr.correlate([_threat("QTT006", "backend_c")])
        assert campaigns == []

    def test_negative_missing_technique(self):
        corr = ThreatCorrelator()
        corr.correlate([_threat("QTT004", "backend_c")])
        campaigns = corr.correlate([_threat("QTT003", "backend_c")])
        assert campaigns == []


# ═══════════════════════════════════════════════════════════════════
#  Pattern 4 — Resource Abuse Chain  (QTT008 + QTT005, 30 min, high)
# ═══════════════════════════════════════════════════════════════════

class TestResourceAbuseChain:
    """QTT008 (Resource Exhaustion) + QTT005 (Scope Violation) → high."""

    def test_positive_both_within_window(self):
        corr = ThreatCorrelator(history_hours=2.0)

        corr.correlate([_threat("QTT008", "backend_d")])
        campaigns = corr.correlate([_threat("QTT005", "backend_d")])

        assert len(campaigns) == 1
        assert campaigns[0].severity == Severity.high
        assert "Resource Abuse Chain" in campaigns[0].technique_id

    def test_negative_outside_window(self):
        """QTT008 was 45 minutes ago — beyond the 30-min pattern window."""
        corr = ThreatCorrelator(history_hours=2.0)

        old = _old_threat("QTT008", "backend_d", minutes_ago=45)
        corr.recent_threats.append(old)

        campaigns = corr.correlate([_threat("QTT005", "backend_d")])
        assert campaigns == []

    def test_negative_missing_technique(self):
        corr = ThreatCorrelator()
        corr.correlate([_threat("QTT008", "backend_d")])
        campaigns = corr.correlate([_threat("QTT007", "backend_d")])
        assert campaigns == []


# ═══════════════════════════════════════════════════════════════════
#  Deduplication, history, and edge cases
# ═══════════════════════════════════════════════════════════════════

class TestCorrelatorBehaviour:
    """Behavioural tests: dedup, pruning, reset, empty input."""

    def test_same_pattern_same_backend_fires_only_once(self):
        """Once both techniques are in history and a campaign has been returned,
        feeding an *unrelated* technique should NOT re-trigger the pattern because
        the quick-check on line 80 of correlator.py requires the new threats to
        intersect the pattern's required technique set."""
        corr = ThreatCorrelator(history_hours=2.0)

        # First call: feed QTT003 → no campaign (QTT002 missing)
        corr.correlate([_threat("QTT003", "dup_back")])

        # Second call: feed QTT002 → campaign fires
        campaigns_1 = corr.correlate([_threat("QTT002", "dup_back")])
        assert len(campaigns_1) == 1

        # Third call: feed an unrelated technique → no campaign because
        # neither QTT003 nor QTT002 is in the new input threats
        campaigns_2 = corr.correlate([_threat("QTT001", "dup_back")])
        assert campaigns_2 == []

    def test_cross_backend_isolation(self):
        """Same techniques on different backends should NOT correlate."""
        corr = ThreatCorrelator(history_hours=2.0)

        corr.correlate([_threat("QTT003", "backend_x")])
        campaigns = corr.correlate([_threat("QTT002", "backend_y")])

        assert campaigns == []

    def test_empty_input(self):
        corr = ThreatCorrelator()
        assert corr.correlate([]) == []

    def test_reset_clears_history(self):
        corr = ThreatCorrelator(history_hours=2.0)

        corr.correlate([_threat("QTT003", "backend_a")])
        corr.reset()

        campaigns = corr.correlate([_threat("QTT002", "backend_a")])
        assert campaigns == []

    def test_history_pruning_removes_old_events(self):
        """Events older than history_hours should be evicted and not correlate.
        NOTE: history_hours is auto-corrected to >= 1.0 (longest window is 60 min),
        so we must use an event old enough to exceed the auto-corrected window."""
        corr = ThreatCorrelator(history_hours=2.0)  # Well above minimum

        # Insert an event older than 2 hours — it will be pruned
        old_event = _old_threat("QTT003", "backend_a", minutes_ago=150)
        corr.recent_threats.append(old_event)

        # Correlate with QTT002 — old QTT003 should have been pruned
        campaigns = corr.correlate([_threat("QTT002", "backend_a")])
        assert campaigns == []

    def test_max_history_caps_entries(self):
        """When history exceeds max_history, oldest entries are dropped."""
        corr = ThreatCorrelator(history_hours=2.0, max_history=3)

        for i in range(5):
            corr.correlate([_threat("QTT001", "backend_z")])

        assert len(corr.recent_threats) <= 3

    def test_campaign_event_evidence_structure(self):
        """Campaign events should contain triggering_threats in evidence."""
        corr = ThreatCorrelator(history_hours=2.0)

        corr.correlate([_threat("QTT004", "ev_back")])
        campaigns = corr.correlate([_threat("QTT006", "ev_back")])

        assert len(campaigns) == 1
        evidence = campaigns[0].evidence
        assert "pattern_name" in evidence
        assert "techniques_found" in evidence
        assert "window_minutes" in evidence
        assert "triggering_threats" in evidence
        assert len(evidence["triggering_threats"]) == 2

    def test_campaign_visual_effect(self):
        corr = ThreatCorrelator(history_hours=2.0)

        corr.correlate([_threat("QTT003", "vis_back")])
        campaigns = corr.correlate([_threat("QTT002", "vis_back")])

        assert len(campaigns) == 1
        assert campaigns[0].visual_effect == "campaign"
        assert campaigns[0].visual_intensity == 0.9

    def test_correlation_patterns_constant(self):
        """CORRELATION_PATTERNS should list exactly 4 patterns."""
        assert len(CORRELATION_PATTERNS) == 4
        for p in CORRELATION_PATTERNS:
            assert "name" in p
            assert "techniques" in p
            assert len(p["techniques"]) == 2
            assert "window_minutes" in p
            assert "escalated_severity" in p
            assert "description" in p
