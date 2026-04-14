"""STIX 2.1 threat intelligence export for SIEM integration."""

import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

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


# Cache mapping from threat IDs to stable STIX UUIDs (within a server lifecycle)
_stix_id_cache: Dict[str, str] = {}


def _get_stix_uuid(threat_id: str) -> str:
    """Return a stable UUID-based STIX ID for a given threat ID.
    Uses a cache so the same threat always gets the same STIX ID within
    a server lifecycle, but IDs are proper UUIDs per STIX 2.1 spec."""
    if threat_id not in _stix_id_cache:
        _stix_id_cache[threat_id] = str(uuid.uuid5(uuid.NAMESPACE_URL, f"qvis:threat:{threat_id}"))
    return _stix_id_cache[threat_id]


def threat_to_stix_indicator(threat: ThreatEvent) -> Dict[str, Any]:
    """Convert a QVis ThreatEvent to a STIX 2.1 Indicator object."""
    stix_uuid = _get_stix_uuid(threat.id)
    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": f"indicator--{stix_uuid}",
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


def export_stix_bundle(threats: List[ThreatEvent], limit: Optional[int] = None, offset: int = 0) -> Dict[str, Any]:
    """Export threats as a STIX 2.1 Bundle with optional pagination.

    Args:
        threats: List of threat events to export.
        limit: Maximum number of indicators to include (None = all).
        offset: Number of threats to skip from the beginning.
    """
    # Apply pagination
    paginated = threats[offset:]
    if limit is not None:
        paginated = paginated[:limit]

    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid5(uuid.NAMESPACE_URL, f'qvis:bundle:{datetime.now(timezone.utc).isoformat()}')}",
        "objects": [threat_to_stix_indicator(t) for t in paginated],
        "x_qvis_pagination": {
            "total": len(threats),
            "offset": offset,
            "limit": limit,
            "returned": len(paginated),
        },
    }
