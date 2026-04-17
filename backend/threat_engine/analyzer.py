from typing import List, Dict, Any, Union, Optional, Set
from datetime import datetime, timezone, timedelta
import time
import structlog

from backend.threat_engine.models import ThreatEvent, Severity, SimulationSnapshot
from backend.threat_engine.rules import ALL_RULES, get_active_rules
from backend.metrics import rule_execution_duration_seconds

logger = structlog.get_logger(__name__)

class ThreatAnalyzer:
    def __init__(self):
        self.active_threats: Dict[tuple, ThreatEvent] = {}
        # Track which threat IDs have already been persisted so we don't
        # INSERT the same event on every cycle.  Only genuinely NEW threats
        # (first-seen keys) get saved, and only keys that vanish get resolved.
        self._persisted_ids: Set[str] = set()

    def _severity_rank(self, severity: Severity) -> int:
        ranks = {
            Severity.critical: 0,
            Severity.high: 1,
            Severity.medium: 2,
            Severity.low: 3,
            Severity.info: 4
        }
        return ranks.get(severity, 99)

    def analyze(self, snapshot: Union[SimulationSnapshot, Dict[str, Any]]) -> Union[SimulationSnapshot, List[ThreatEvent]]:
        if isinstance(snapshot, dict):
            raw_data = snapshot
            is_dict_mode = True
        else:
            raw_data = snapshot.model_dump()
            is_dict_mode = False
        
        new_events = []
        for rule in get_active_rules():
            rule_start = time.monotonic()
            events = rule(raw_data)
            elapsed_ms = round((time.monotonic() - rule_start) * 1000)

            rule_execution_duration_seconds.labels(
                rule_name=rule.__name__
            ).observe((time.monotonic() - rule_start))
            
            logger.info("rule_executed",
                rule_name=rule.__name__,
                threats_found=len(events),
                duration_ms=elapsed_ms)
            
            new_events.extend(events)
        
        current_time = datetime.now(timezone.utc)
        
        for event in new_events:
            key = (event.backend_id, event.technique_id)
            if key in self.active_threats:
                existing = self.active_threats[key]
                if current_time - existing.detected_at < timedelta(minutes=5):
                    # Keep the original ID for UI continuity, but remove
                    # it from _persisted_ids so the updated evidence/
                    # severity gets re-persisted this cycle.
                    event.id = existing.id
                    self.active_threats[key] = event
                    self._persisted_ids.discard(event.id)
                else:
                    # Window expired — treat as a new occurrence
                    self.active_threats[key] = event
            else:
                self.active_threats[key] = event
            
            # Log each detected threat
            logger.info("threat_detected",
                technique_id=event.technique_id,
                severity=event.severity.value if hasattr(event.severity, "value") else str(event.severity),
                backend_id=event.backend_id)
                
        sorted_events = sorted(self.active_threats.values(), key=lambda x: self._severity_rank(x.severity))
        
        if is_dict_mode:
            return sorted_events

        existing_event_ids = {t.id for t in snapshot.threats}
        merged_threats = list(snapshot.threats)
        
        for e in sorted_events:
            if e.id not in existing_event_ids:
                merged_threats.append(e)
                existing_event_ids.add(e.id)
                
        snapshot.threats = sorted(merged_threats, key=lambda x: self._severity_rank(x.severity))
        snapshot.total_threats = len(snapshot.threats)
        
        severity_counts = {}
        for t in snapshot.threats:
            severity_counts[t.severity.value] = severity_counts.get(t.severity.value, 0) + 1
        snapshot.threats_by_severity = severity_counts

        return snapshot

    async def persist_new_threats(self) -> List[str]:
        """Save any active threats that haven't been persisted yet.

        Returns the list of threat IDs that were persisted in this call.
        This should be called after each analysis cycle.
        """
        from backend.storage.database import save_threat

        newly_persisted: List[str] = []
        for event in self.active_threats.values():
            if event.id not in self._persisted_ids:
                try:
                    await save_threat(
                        id=event.id,
                        technique_id=event.technique_id,
                        severity=event.severity.value
                            if hasattr(event.severity, "value")
                            else str(event.severity),
                        platform=event.platform.value
                            if hasattr(event.platform, "value")
                            else str(event.platform),
                        backend_id=event.backend_id,
                        title=event.title,
                        description=event.description,
                        evidence=event.evidence,
                        detected_at=event.detected_at.isoformat()
                            if isinstance(event.detected_at, datetime)
                            else str(event.detected_at),
                        visual_effect=event.visual_effect,
                        visual_intensity=event.visual_intensity,
                        remediation=event.remediation,
                    )
                    self._persisted_ids.add(event.id)
                    newly_persisted.append(event.id)
                except Exception as exc:
                    logger.warning("persist_threat_failed", threat_id=event.id, error=str(exc))
        return newly_persisted

    async def resolve_disappeared_threats(self) -> List[str]:
        """Mark any previously-persisted threats that are no longer active
        as resolved in the database.

        Returns the list of threat IDs that were resolved.
        """
        from backend.storage.database import resolve_threat

        current_ids = {t.id for t in self.active_threats.values()}
        resolved: List[str] = []

        for old_id in list(self._persisted_ids):
            if old_id not in current_ids:
                try:
                    was_resolved = await resolve_threat(old_id)
                    if was_resolved:
                        resolved.append(old_id)
                    # Whether or not the row was actually updated (it may
                    # already be resolved), remove from the tracking set so
                    # we don't keep checking it every cycle.
                    self._persisted_ids.discard(old_id)
                except Exception as exc:
                    logger.warning("resolve_threat_failed", threat_id=old_id, error=str(exc))
        return resolved

    def reset(self):
        self.active_threats = {}
        self._persisted_ids.clear()
