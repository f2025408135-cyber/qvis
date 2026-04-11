from typing import List, Dict, Any
from datetime import datetime, timezone, timedelta
from backend.threat_engine.models import ThreatEvent, Severity
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

    def analyze(self, raw_data: Dict[str, Any]) -> List[ThreatEvent]:
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
        return sorted_events

    def reset(self):
        self.active_threats = {}
