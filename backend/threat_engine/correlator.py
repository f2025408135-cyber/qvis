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
        "techniques": ["QTT017", "QTT003"],
        "window_minutes": 60,
        "escalated_severity": Severity.critical,
        "description": "Credential exposure followed by timing oracle probes — possible active exploitation using leaked credentials.",
    },
    {
        "name": "Enumeration Campaign",
        "techniques": ["QTT009", "QTT011"],
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

    def __init__(self):
        self.recent_threats: List[ThreatEvent] = []
        self.max_history = 500

    def correlate(self, new_threats: List[ThreatEvent]) -> List[ThreatEvent]:
        """Check new threats against recent history for correlation patterns.
        Returns list of new correlated campaign events."""
        self.recent_threats.extend(new_threats)

        now = datetime.now(timezone.utc)

        # Prune old history (keep last 2 hours)
        cutoff = now - timedelta(hours=2)
        self.recent_threats = [
            t for t in self.recent_threats if t.detected_at > cutoff
        ][-self.max_history:]

        campaigns = []
        for pattern in CORRELATION_PATTERNS:
            campaigns.extend(self._check_pattern(pattern, new_threats, now))

        return campaigns

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
                # Check if we already generated a campaign for this
                existing = [
                    t for t in self.recent_threats
                    if t.technique_id == pattern_key
                    and t.backend_id == backend_id
                ]
                if existing:
                    continue

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
        """Clear all correlation history."""
        self.recent_threats.clear()
