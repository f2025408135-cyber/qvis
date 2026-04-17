"""STIX 2.1 threat intelligence export for SIEM integration."""

import uuid
from collections import OrderedDict
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


# LRU cache mapping from threat IDs to stable STIX UUIDs (capped at 5000 entries)
_STIX_CACHE_MAX = 5000
_stix_id_cache: OrderedDict[str, str] = OrderedDict()


def _get_stix_uuid(threat_id: str) -> str:
    """Return a stable UUID-based STIX ID for a given threat ID.

    Uses an LRU cache (capped at _STIX_CACHE_MAX) so the same threat
    always gets the same STIX ID within a server lifecycle, while
    preventing unbounded memory growth on long-running servers.
    """
    if threat_id in _stix_id_cache:
        # Move to end (most recently used)
        _stix_id_cache.move_to_end(threat_id)
        return _stix_id_cache[threat_id]

    # Evict oldest entries if at capacity
    while len(_stix_id_cache) >= _STIX_CACHE_MAX:
        _stix_id_cache.popitem(last=False)

    stix_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"qvis:threat:{threat_id}"))
    _stix_id_cache[threat_id] = stix_id
    return stix_id


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

    # Use a content-hash-based bundle ID for deterministic deduplication
    # across repeated exports of the same threat set.
    _content_key = ":".join(sorted(t.id for t in paginated)) or "empty"
    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid5(uuid.NAMESPACE_URL, f'qvis:bundle:{_content_key}')}",
        "objects": [threat_to_stix_indicator(t) for t in paginated],
        "x_qvis_pagination": {
            "total": len(threats),
            "offset": offset,
            "limit": limit,
            "returned": len(paginated),
        },
    }
