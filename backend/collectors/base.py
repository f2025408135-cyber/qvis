from abc import ABC, abstractmethod
from typing import Dict, Any

class BaseCollector(ABC):
    @abstractmethod
    async def collect(self) -> Dict[str, Any]:
        pass
