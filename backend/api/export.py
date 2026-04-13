"""STIX 2.1 threat intelligence export for SIEM integration."""

from datetime import datetime, timezone
from typing import List, Dict, Any

from backend.threat_engine.models import ThreatEvent


def _severity_to_confidence(severity) -> int:
    """Map severity to STIX confidence score (0-100)."""
    mapping = {
        "critical": 95,
        "high": 80,
        "medium": 60,
        "low": 40,
        "info": 20,
    }
    return mapping.get(severity.value if hasattr(severity, "value") else str(severity), 50)


def threat_to_stix_indicator(threat: ThreatEvent) -> Dict[str, Any]:
    """Convert a QVis ThreatEvent to a STIX 2.1 Indicator object."""
    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": f"indicator--{threat.id}",
        "created": threat.detected_at.isoformat() if hasattr(threat.detected_at, 'isoformat') else str(threat.detected_at),
        "modified": datetime.now(timezone.utc).isoformat(),
        "name": threat.title,
        "description": threat.description,
        "indicator_types": ["anomalous-activity"],
        "pattern": f"[x-quantum-threat:technique_id = '{threat.technique_id}']",
        "pattern_type": "stix",
        "valid_from": threat.detected_at.isoformat() if hasattr(threat.detected_at, 'isoformat') else str(threat.detected_at),
        "labels": [
            threat.severity.value if hasattr(threat.severity, "value") else str(threat.severity),
            threat.platform.value if hasattr(threat.platform, "value") else str(threat.platform),
        ],
        "confidence": _severity_to_confidence(threat.severity),
        "extensions": {
            "x-qvis-threat": {
                "backend_id": threat.backend_id,
                "visual_effect": threat.visual_effect,
                "visual_intensity": threat.visual_intensity,
                "remediation": threat.remediation,
                "evidence": threat.evidence,
            }
        },
    }


def export_stix_bundle(threats: List[ThreatEvent]) -> Dict[str, Any]:
    """Export all threats as a STIX 2.1 Bundle."""
    return {
        "type": "bundle",
        "id": f"bundle--qvis-export-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
        "objects": [threat_to_stix_indicator(t) for t in threats],
    }
