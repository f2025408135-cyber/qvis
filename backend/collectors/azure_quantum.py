"""Azure Quantum collector — read-only workspace and target metadata."""

import uuid
import structlog
import asyncio
from datetime import datetime, timezone
from typing import List, Optional

from backend.collectors.base import BaseCollector
from backend.threat_engine.models import (
    SimulationSnapshot, BackendNode, Platform, Severity, QubitCalibration
)

logger = structlog.get_logger()


class AzureQuantumCollector(BaseCollector):
    """Pulls target (backend) metadata from Azure Quantum.

    Requires: pip install azure-quantum
    Environment: AZURE_QUANTUM_SUBSCRIPTION_ID (+ Azure CLI auth or env creds)
    """

    def __init__(self, subscription_id: str = "", resource_group: str = "", workspace: str = "", location: str = "eastus"):
        self.subscription_id = subscription_id
        self.resource_group = resource_group
        self.workspace = workspace
        self.location = location
        self._workspace_client = None
        self._cached_snapshot: Optional[SimulationSnapshot] = None

    async def collect(self) -> SimulationSnapshot:
        """Fetch Azure Quantum workspace targets and build a snapshot."""
        try:
            if not self.subscription_id:
                logger.warning("azure_subscription_not_set_using_mock")
                return self._mock_azure_snapshot()

            from azure.quantum import Workspace

            if self._workspace_client is None:
                self._workspace_client = Workspace(
                    subscription_id=self.subscription_id,
                    resource_group=self.resource_group,
                    name=self.workspace,
                    location=self.location,
                )

            targets = await asyncio.to_thread(self._workspace_client.get_targets)

            nodes: List[BackendNode] = []
            for target in targets:
                name = getattr(target, "name", "unknown")
                provider = getattr(target, "provider_id", "unknown")
                status = getattr(target, "current_availability", "Unknown")
                avg_queue = getattr(target, "average_queue_time", 0)

                # Azure Quantum doesn't always expose qubit counts via the SDK
                # Use known values for common targets
                qubit_map = {
                    "ionq.qpu": 11,
                    "ionq.qpu.aria-1": 25,
                    "quantinuum.qpu.h1-1": 20,
                    "quantinuum.qpu.h1-2": 20,
                    "rigetti.qpu.ankaa-2": 84,
                }
                num_qubits = qubit_map.get(name, 0)

                node = BackendNode(
                    id=f"azure_{name.replace('.', '_').replace('-', '_')}",
                    name=f"{name} ({provider})",
                    platform=Platform.azure_quantum,
                    num_qubits=num_qubits,
                    is_simulator=("simulator" in name.lower()),
                    operational=(status == "Available"),
                    calibration=[],
                    api_surface_score=0.5,
                    threat_level=Severity.info if status == "Available" else Severity.medium,
                    position_hint=None,
                )
                nodes.append(node)

            snapshot = SimulationSnapshot(
                snapshot_id=str(uuid.uuid4()),
                generated_at=datetime.now(timezone.utc),
                backends=nodes,
                threats=[],
                entanglement_pairs=[],
                total_qubits=sum(n.num_qubits for n in nodes),
                total_threats=0,
                threats_by_severity={},
                platform_health={"azure_quantum": 1.0 if any(n.operational for n in nodes) else 0.0},
            )

            self._cached_snapshot = snapshot
            logger.info("azure_collection_complete", target_count=len(nodes))
            return snapshot

        except ImportError:
            logger.warning("azure_quantum_sdk_not_installed_using_mock")
            return self._mock_azure_snapshot()
        except Exception as e:
            logger.error("azure_collector_error", error=str(e))
            if self._cached_snapshot:
                return self._cached_snapshot
            return self._mock_azure_snapshot()

    def _mock_azure_snapshot(self) -> SimulationSnapshot:
        """Return a realistic mock Azure Quantum snapshot for demo mode."""
        nodes = [
            BackendNode(
                id="azure_ionq_aria_1",
                name="Aria-1 (IonQ)",
                platform=Platform.azure_quantum,
                num_qubits=25,
                is_simulator=False,
                operational=True,
                calibration=[
                    QubitCalibration(qubit_id=0, t1_us=1e6, t2_us=5e5, readout_error=0.004, gate_error_cx=0.005),
                ],
                api_surface_score=0.5,
                threat_level=Severity.info,
                position_hint=None,
            ),
            BackendNode(
                id="azure_quantinuum_h1_1",
                name="H1-1 (Quantinuum)",
                platform=Platform.azure_quantum,
                num_qubits=20,
                is_simulator=False,
                operational=True,
                calibration=[
                    QubitCalibration(qubit_id=0, t1_us=1e7, t2_us=3e6, readout_error=0.002, gate_error_cx=0.003),
                ],
                api_surface_score=0.4,
                threat_level=Severity.info,
                position_hint=None,
            ),
        ]
        return SimulationSnapshot(
            snapshot_id=str(uuid.uuid4()),
            generated_at=datetime.now(timezone.utc),
            backends=nodes,
            threats=[],
            entanglement_pairs=[],
            total_qubits=45,
            total_threats=0,
            threats_by_severity={},
            platform_health={"azure_quantum": 1.0},
        )
