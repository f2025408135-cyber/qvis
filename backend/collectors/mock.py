import json
import os
import uuid
from datetime import datetime, timezone
from backend.threat_engine.models import SimulationSnapshot
from backend.collectors.base import BaseCollector

class MockCollector(BaseCollector):
    def __init__(self):
        self.ibm_data_path = os.path.join("demo", "mock_ibm_data.json")
        self.braket_data_path = os.path.join("demo", "mock_braket_data.json")

    async def collect(self) -> SimulationSnapshot:
        with open(self.ibm_data_path, 'r') as f:
            ibm_data = json.load(f)

        ibm_data["snapshot_id"] = str(uuid.uuid4())
        ibm_data["generated_at"] = datetime.now(timezone.utc).isoformat()

        return SimulationSnapshot(**ibm_data)
