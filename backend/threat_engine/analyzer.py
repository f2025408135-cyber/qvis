from typing import List, Dict, Any, Union
from datetime import datetime, timezone, timedelta
from backend.threat_engine.models import ThreatEvent, Severity, SimulationSnapshot
from backend.threat_engine.rules import ALL_RULES

class ThreatAnalyzer:
    def __init__(self):
        self.active_threats: Dict[tuple, ThreatEvent] = {}
        
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
        for rule in ALL_RULES:
            events = rule(raw_data)
            new_events.extend(events)
            
        current_time = datetime.now(timezone.utc)
        
        for event in new_events:
            key = (event.backend_id, event.technique_id)
            if key in self.active_threats:
                existing = self.active_threats[key]
                if current_time - existing.detected_at < timedelta(minutes=5):
                    event.id = existing.id
                    event.detected_at = existing.detected_at
                    self.active_threats[key] = event
                else:
                    self.active_threats[key] = event
            else:
                self.active_threats[key] = event
                
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

    def reset(self):
        self.active_threats = {}
