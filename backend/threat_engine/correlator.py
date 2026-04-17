"""Cross-rule correlation for detecting coordinated quantum attacks."""

import uuid
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Optional

from backend.threat_engine.models import ThreatEvent, Severity, Platform

# Correlation patterns: if these technique pairs appear on the same backend
# within a time window, escalate to a correlated campaign
CORRELATION_PATTERNS = [
    {
        "name": "Coordinated Reconnaissance",
        "techniques": ["QTT003", "QTT002"],
        "window_minutes": 30,
        "escalated_severity": Severity.critical,
        "description": "Coordinated timing and calibration reconnaissance detected — likely a targeted QPU characterization campaign.",
    },
    {
        "name": "Pre-Attack Staging",
        "techniques": ["QTT007", "QTT003"],
        "window_minutes": 60,
        "escalated_severity": Severity.critical,
        "description": "Credential exposure followed by timing oracle probes — possible active exploitation using leaked credentials.",
    },
    {
        "name": "Enumeration Campaign",
        "techniques": ["QTT004", "QTT006"],
        "window_minutes": 15,
        "escalated_severity": Severity.critical,
        "description": "Systematic tenant probing combined with IDOR enumeration — active unauthorized access campaign.",
    },
    {
        "name": "Resource Abuse Chain",
        "techniques": ["QTT008", "QTT005"],
        "window_minutes": 30,
        "escalated_severity": Severity.high,
        "description": "Resource exhaustion combined with privilege escalation attempts.",
    },
]


class ThreatCorrelator:
    """Detects multi-stage attacks by correlating threat events across rules."""

    def __init__(self, history_hours: float = 2.0, max_history: int = 500):
        self.recent_threats: List[ThreatEvent] = []
        self.max_history = max_history
        # Validate that history_hours is at least as long as the
        # longest correlation window so patterns can actually fire.
        _max_window = max(p["window_minutes"] for p in CORRELATION_PATTERNS)
        _min_hours = _max_window / 60.0
        if history_hours < _min_hours:
            import structlog as _sl
            _sl.get_logger().warning(
                "correlator_history_too_short",
                requested_hours=history_hours,
                minimum_hours=round(_min_hours, 2),
                auto_corrected=True,
            )
            history_hours = _min_hours
        self.history_hours = history_hours
        # Track campaign dedup keys independently from recent_threats so
        # that pruning old events doesn't allow the same campaign to re-fire.
        self._campaign_dedup: set = set()

    def correlate(self, new_threats: List[ThreatEvent]) -> List[ThreatEvent]:
        """Check new threats against recent history for correlation patterns.
        Returns list of new correlated campaign events."""
        self.recent_threats.extend(new_threats)

        now = datetime.now(timezone.utc)

        # Prune old history (configurable window)
        cutoff = now - timedelta(hours=self.history_hours)
        self.recent_threats = [
            t for t in self.recent_threats if t.detected_at > cutoff
        ][-self.max_history:]

        # Also prune campaign dedup keys: if none of the underlying threats
        # for a pattern still exist in recent_threats, the campaign dedup
        # marker should expire so a genuinely new occurrence can fire.
        active_technique_ids = {t.technique_id for t in self.recent_threats}
        expired_keys = {
            key for key in self._campaign_dedup
            if not any(tid in active_technique_ids for tid in self._techniques_for_key(key))
        }
        self._campaign_dedup -= expired_keys

        campaigns = []
        for pattern in CORRELATION_PATTERNS:
            campaigns.extend(self._check_pattern(pattern, new_threats, now))

        return campaigns

    @staticmethod
    def _techniques_for_key(pattern_key: str) -> set:
        """Extract technique IDs from a CORR:backend:pattern key.

        Parses the key using the known delimiter format
        ``CORR:{backend_id}:{pattern_name}`` and looks up
        CORRELATION_PATTERNS for the exact name (not suffix match).
        """
        # Key format: CORR:{backend_id}:{pattern_name}
        # Split on the first two colons to isolate the pattern name.
        parts = pattern_key.split(":", 2)
        if len(parts) < 3:
            return set()
        pattern_name = parts[2]
        for p in CORRELATION_PATTERNS:
            if p["name"] == pattern_name:
                return set(p["techniques"])
        return set()

    def _check_pattern(self, pattern: dict, new_threats: List[ThreatEvent], now: datetime) -> List[ThreatEvent]:
        """Check if new threats complete a correlation pattern."""
        required_techniques = set(pattern["techniques"])
        window = timedelta(minutes=pattern["window_minutes"])

        # Only check backends that received new threats
        new_backend_ids = {t.backend_id for t in new_threats if t.backend_id}
        new_technique_ids = {t.technique_id for t in new_threats}

        # Quick check: if none of the new threats match any required technique, skip
        if not required_techniques.intersection(new_technique_ids):
            return []

        campaigns = []

        for backend_id in new_backend_ids:
            # Collect all threats for this backend within the window
            backend_threats = [
                t for t in self.recent_threats
                if t.backend_id == backend_id
                and t.technique_id in required_techniques
                and t.detected_at > now - window
            ]

            # Check if all required techniques are present
            found_techniques = {t.technique_id for t in backend_threats}
            if required_techniques.issubset(found_techniques):
                # Generate a campaign correlation ID to avoid duplicates
                pattern_key = f"CORR:{backend_id}:{pattern['name']}"
                # Use the separate dedup set so that pruning recent_threats
                # doesn't allow the same campaign to re-fire within the
                # correlator's history window.
                if pattern_key in self._campaign_dedup:
                    continue

                self._campaign_dedup.add(pattern_key)

                campaign_event = ThreatEvent(
                    id=str(uuid.uuid4()),
                    technique_id=pattern_key,
                    technique_name=pattern["name"],
                    severity=pattern["escalated_severity"],
                    platform=backend_threats[0].platform if backend_threats else Platform.ibm_quantum,
                    backend_id=backend_id,
                    title=f"Campaign: {pattern['name']}",
                    description=pattern["description"],
                    evidence={
                        "pattern_name": pattern["name"],
                        "techniques_found": list(found_techniques),
                        "backend_id": backend_id,
                        "window_minutes": pattern["window_minutes"],
                        "triggering_threats": [
                            {"id": t.id, "technique": t.technique_id, "severity": t.severity.value}
                            for t in backend_threats
                        ],
                    },
                    detected_at=datetime.now(timezone.utc),
                    visual_effect="campaign",
                    visual_intensity=0.9,
                    remediation=[
                        "Investigate correlated activity as a coordinated campaign.",
                        "Review all involved techniques for a multi-stage attack.",
                        "Consider blocking the source if confirmed malicious.",
                    ],
                )
                campaigns.append(campaign_event)

        return campaigns

    def reset(self):
        """Clear all correlation history and dedup markers."""
        self.recent_threats.clear()
        self._campaign_dedup.clear()
