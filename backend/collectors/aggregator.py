"""Aggregator collector — merges snapshots from multiple platform collectors."""

import uuid
import time
import structlog
import asyncio
from datetime import datetime, timezone
from typing import List

from backend.collectors.base import BaseCollector
from backend.threat_engine.models import SimulationSnapshot

logger = structlog.get_logger(__name__)


class AggregatorCollector(BaseCollector):
    """Runs multiple collectors in parallel and merges their snapshots."""

    def __init__(self, collectors: List[BaseCollector]):
        self.collectors = collectors

    async def collect(self) -> SimulationSnapshot:
        """Run all collectors concurrently, merge results into a single snapshot."""
        start_time = time.monotonic()
        tasks = [c.collect() for c in self.collectors]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        all_backends = []
        all_threats = []
        all_entanglement = []
        platform_health = {}
        errors = []

        for result in results:
            if isinstance(result, Exception):
                errors.append(str(result))
                logger.error("aggregator_sub_collector_failed", error=str(result))
                continue
            all_backends.extend(result.backends)
            all_threats.extend(result.threats)
            all_entanglement.extend(result.entanglement_pairs)
            platform_health.update(result.platform_health)

        severity_counts = {}
        for t in all_threats:
            sev = t.severity.value if hasattr(t.severity, "value") else str(t.severity)
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        elapsed_ms = round((time.monotonic() - start_time) * 1000)
        logger.info("collection_complete",
            collector=self.__class__.__name__,
            backends_count=len(all_backends),
            duration_ms=elapsed_ms)

        return SimulationSnapshot(
            snapshot_id=str(uuid.uuid4()),
            generated_at=datetime.now(timezone.utc),
            backends=all_backends,
            threats=all_threats,
            entanglement_pairs=all_entanglement,
            total_qubits=sum(b.num_qubits for b in all_backends),
            total_threats=len(all_threats),
            threats_by_severity=severity_counts,
            platform_health=platform_health,
        )
