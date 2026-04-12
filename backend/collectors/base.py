from abc import ABC, abstractmethod
from typing import Dict, Any
from backend.threat_engine.models import SimulationSnapshot

class BaseCollector(ABC):
    @abstractmethod
    async def collect(self) -> SimulationSnapshot:
        pass
