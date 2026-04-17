"""AWS Braket collector — read-only device metadata and status."""

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


class BraketCollector(BaseCollector):
    """Pulls device metadata from Amazon Braket.

    Requires: pip install amazon-braket-sdk boto3
    Environment: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_DEFAULT_REGION
    """

    def __init__(self, region: str = "us-east-1"):
        self.region = region
        self._client = None
        self._cached_snapshot: Optional[SimulationSnapshot] = None

    def _get_client(self):
        """Lazy-init the Braket client."""
        if self._client is None:
            try:
                import boto3
                self._client = boto3.client("braket", region_name=self.region)
            except ImportError:
                logger.error("boto3_not_installed")
                raise
        return self._client

    async def collect(self) -> SimulationSnapshot:
        """Fetch all Braket device summaries and build a snapshot."""
        try:
            client = self._get_client()

            # List devices (runs in thread to avoid blocking the event loop)
            response = await asyncio.to_thread(
                client.search_devices,
                filters=[{"name": "deviceType", "values": ["QPU"]}],
            )
            devices = response.get("devices", [])

            nodes: List[BackendNode] = []
            for device in devices:
                arn = device.get("deviceArn", "")
                name = device.get("deviceName", arn.split("/")[-1])
                status = device.get("deviceStatus", "OFFLINE")
                provider = device.get("providerName", "unknown")

                # Fetch detailed device properties
                num_qubits = 0
                cal_data: List[QubitCalibration] = []
                try:
                    detail = await asyncio.to_thread(
                        client.get_device, deviceArn=arn
                    )
                    import json
                    props = json.loads(detail.get("deviceCapabilities", "{}"))

                    # Extract qubit count from paradigm
                    paradigm = props.get("paradigm", {})
                    num_qubits = paradigm.get("qubitCount", 0)

                    # Extract calibration data if available
                    provider_props = props.get("provider", {})
                    specs = provider_props.get("specs", {})
                    one_qubit = specs.get("oneQubitProperties", {})
                    for qid_str, qprops in one_qubit.items():
                        try:
                            qid = int(qid_str)
                            fidelity_data = qprops.get("oneQubitFidelity", [])
                            if not fidelity_data:
                                continue
                            fidelity = fidelity_data[0].get("fidelity", None)
                            if fidelity is None:
                                continue
                            ro_err = 1.0 - fidelity
                            # NOTE: Fidelity alone cannot reliably predict T1/T2.
                            # Different qubit technologies (superconducting, ion
                            # trap, photonic) have vastly different coherence
                            # characteristics.  We record readout_error (derived
                            # from fidelity) but set T1/T2 to defaults rather
                            # than fabricating a number from a linear heuristic.
                            t1_us = 100.0  # Conservative default placeholder
                            t2_us = t1_us * 0.7
                            cal_data.append(QubitCalibration(
                                qubit_id=qid,
                                t1_us=round(t1_us, 2),
                                t2_us=round(t2_us, 2),
                                readout_error=round(ro_err, 5),
                                gate_error_cx=None,
                            ))
                        except (ValueError, IndexError, KeyError):
                            continue
                except Exception as e:
                    logger.debug("braket_device_detail_failed", device=name, error=str(e))

                # Determine threat level based on status
                threat_level = Severity.info
                if status != "ONLINE":
                    threat_level = Severity.medium

                node = BackendNode(
                    id=f"braket_{name.lower().replace(' ', '_')}",
                    name=name,
                    platform=Platform.amazon_braket,
                    num_qubits=num_qubits,
                    is_simulator=False,
                    operational=(status == "ONLINE"),
                    calibration=cal_data[:5],  # Limit to first 5 qubits for perf
                    api_surface_score=0.5,
                    threat_level=threat_level,
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
                platform_health={"amazon_braket": 1.0 if any(n.operational for n in nodes) else 0.0},
            )

            self._cached_snapshot = snapshot
            logger.info("braket_collection_complete", device_count=len(nodes))
            return snapshot

        except ImportError:
            logger.warning("braket_sdk_not_installed_using_mock")
            return self._mock_braket_snapshot()
        except Exception as e:
            logger.error("braket_collector_error", error=str(e))
            if self._cached_snapshot:
                return self._cached_snapshot
            return self._mock_braket_snapshot()

    def _mock_braket_snapshot(self) -> SimulationSnapshot:
        """Return a realistic mock Braket snapshot for demo mode."""
        nodes = [
            BackendNode(
                id="braket_lucy",
                name="Lucy (OQC)",
                platform=Platform.amazon_braket,
                num_qubits=8,
                is_simulator=False,
                operational=True,
                calibration=[
                    QubitCalibration(qubit_id=0, t1_us=95.0, t2_us=62.0, readout_error=0.02, gate_error_cx=0.012),
                    QubitCalibration(qubit_id=1, t1_us=88.0, t2_us=58.0, readout_error=0.025, gate_error_cx=0.015),
                ],
                api_surface_score=0.4,
                threat_level=Severity.info,
                position_hint=None,
            ),
            BackendNode(
                id="braket_aria",
                name="Aria (IonQ)",
                platform=Platform.amazon_braket,
                num_qubits=25,
                is_simulator=False,
                operational=True,
                calibration=[
                    QubitCalibration(qubit_id=0, t1_us=1e6, t2_us=0.5e6, readout_error=0.005, gate_error_cx=0.006),
                ],
                api_surface_score=0.6,
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
            total_qubits=33,
            total_threats=0,
            threats_by_severity={},
            platform_health={"amazon_braket": 1.0},
        )
