"""Live IBM Quantum data collector pulling real telemetry via Qiskit."""

import structlog
import asyncio
import uuid
import time
from typing import Dict, Any, List
from backend.collectors.base import BaseCollector
from backend.threat_engine.models import SimulationSnapshot, BackendNode, Platform, Severity, QubitCalibration
from datetime import datetime, timezone

logger = structlog.get_logger()

class IBMQuantumCollector(BaseCollector):
    """Collector handling direct API interaction with the IBM Quantum service."""

    def __init__(self, ibm_token: str):
        """Initializes the collector.
        
        Args:
            ibm_token: Auth token for IBM Quantum's API.
        """
        self.ibm_token = ibm_token
        self.service = None
        self.calibration_requests = {}
        self.cached_last_snapshot = None
        
    async def collect(self) -> SimulationSnapshot:
        """Fetches live hardware layout and calibration metrics from IBM.
        
        Returns:
            A SimulationSnapshot populated with current backend states.
        """
        start_time = time.monotonic()
        
        if not self.ibm_token:
            logger.warning("IBM_QUANTUM_TOKEN not set, skipping real collection.")
            return self._empty_snapshot()
            
        try:
            from qiskit_ibm_runtime import QiskitRuntimeService
            
            if not self.service:
                try:
                    self.service = QiskitRuntimeService(token=self.ibm_token, channel="ibm_quantum")
                except Exception as e:
                    logger.error("ibm_auth_error", error=str(e))
                    if self.cached_last_snapshot:
                        logger.warning("using_cached_snapshot_after_auth_failure")
                        degraded = self.cached_last_snapshot.model_copy()
                        degraded.generated_at = datetime.now(timezone.utc)
                        if not degraded.collection_metadata:
                            degraded.collection_metadata = {}
                        degraded.collection_metadata["degraded"] = True
                        return degraded
                    return self._empty_snapshot()
                
            # Safely check if backends property/method needs to be awaited depending on Qiskit version/mock status
            backends_call = getattr(self.service, "backends")
            if callable(backends_call):
                backends = await asyncio.to_thread(backends_call)
            else:
                backends = backends_call
            
            nodes = []
            job_history = []
            
            for backend in backends:
                backend_name = backend.name
                
                operational = False
                n_qubits = 0
                is_simulator = False
                cal_data = []
                
                try:
                    status_call = getattr(backend, "status")
                    status = await asyncio.to_thread(status_call) if callable(status_call) else status_call
                    operational = status.operational
                    
                    config_call = getattr(backend, "configuration")
                    config = await asyncio.to_thread(config_call) if callable(config_call) else config_call
                    n_qubits = getattr(config, 'n_qubits', getattr(backend, 'num_qubits', 0))
                    is_simulator = getattr(config, 'simulator', getattr(backend, 'simulator', False))
                    
                    self.calibration_requests[backend_name] = self.calibration_requests.get(backend_name, 0) + 1
                    
                    if not is_simulator:
                        props_call = getattr(backend, "properties")
                        props = await asyncio.to_thread(props_call) if callable(props_call) else props_call
                        if props and hasattr(props, 'qubits'):
                            for q_idx, qubit in enumerate(props.qubits):
                                t1 = next((item.value for item in qubit if item.name == "T1"), 0.0)
                                t2 = next((item.value for item in qubit if item.name == "T2"), 0.0)
                                readout = next((item.value for item in qubit if item.name == "readout_error"), 0.0)
                                
                                cx_err = 0.0
                                if hasattr(props, 'gates'):
                                    for gate in props.gates:
                                        if gate.gate == "cx" and q_idx in gate.qubits:
                                            cx_err = next((item.value for item in gate.parameters if item.name == "gate_error"), 0.0)
                                            break
                                
                                if t1 < 1.0: t1 *= 1e6
                                if t2 < 1.0: t2 *= 1e6
                                # Guard: reject clearly corrupt values
                                # (e.g. a real 0.5 us T1 would become 500000 us
                                # which is physically implausible for
                                # superconducting qubits).  Cap at 10 seconds.
                                if t1 > 10_000_000 or t2 > 10_000_000:
                                    logger.debug(
                                        "implausible_coherence_value_skipped",
                                        backend=backend_name, qubit=q_idx,
                                        t1_us=t1, t2_us=t2,
                                    )
                                    continue
                                
                                cal_data.append(QubitCalibration(
                                    qubit_id=q_idx,
                                    t1_us=float(t1),
                                    t2_us=float(t2),
                                    readout_error=float(readout),
                                    gate_error_cx=float(cx_err)
                                ))
                except Exception as e:
                    logger.debug("backend_property_fetch_failed", backend=backend_name, error=str(e))
                
                try:
                    jobs_call = getattr(self.service, "jobs")
                    if callable(jobs_call):
                        jobs = await asyncio.to_thread(jobs_call, limit=10, backend_name=backend_name)
                    else:
                        jobs = []
                    config = locals().get('config')  # None if inner try-block failed
                    for j in jobs:
                        job_info = {
                            "job_id": j.job_id() if callable(j.job_id) else j.job_id,
                            "backend_id": backend_name,
                            "status": j.status().name if callable(j.status) else j.status,
                            "max_allowed_depth": getattr(config, 'max_experiments', 100) if config else 100
                        }
                        try:
                            circuits = j.inputs.get("circuits", [])
                            if circuits and isinstance(circuits, list) and len(circuits) > 0:
                                circ = circuits[0]
                                if hasattr(circ, 'depth'):
                                    job_info["depth"] = circ.depth() if callable(circ.depth) else circ.depth
                                if hasattr(circ, 'count_ops'):
                                    ops = circ.count_ops() if callable(circ.count_ops) else circ.count_ops
                                    job_info["gate_histogram"] = dict(ops)
                        except Exception:
                            pass
                        job_history.append(job_info)
                except Exception as e:
                    logger.debug("job_history_fetch_failed", backend=backend_name, error=str(e))
                
                threat_level = Severity.info
                if cal_data:
                    for cal in cal_data:
                        # Parens required: Python's `and` binds tighter than
                        # `or`, so without them the readout_error check
                        # fires independently of the t1_us > 0 guard.
                        if cal.t1_us > 0 and (cal.t1_us < 30.0 or cal.readout_error > 0.05):
                            threat_level = Severity.high
                            break
                        elif cal.t1_us > 0 and (cal.t1_us < 60.0 or cal.readout_error > 0.02):
                            threat_level = Severity.medium
                
                api_surface_score = (n_qubits / 127.0) * (1.0 if is_simulator else 0.7)
                api_surface_score = min(1.0, max(0.0, api_surface_score))
                
                node = BackendNode(
                    id=backend_name,
                    name=backend_name,
                    platform=Platform.ibm_quantum,
                    num_qubits=n_qubits,
                    is_simulator=is_simulator,
                    operational=operational,
                    calibration=cal_data,
                    api_surface_score=api_surface_score,
                    threat_level=threat_level,
                    position_hint=None
                )
                nodes.append(node)
                
            elapsed_time = time.monotonic() - start_time
            
            snapshot = SimulationSnapshot(
                snapshot_id=str(uuid.uuid4()),
                generated_at=datetime.now(timezone.utc),
                backends=nodes,
                threats=[],
                entanglement_pairs=[],
                total_qubits=sum(n.num_qubits for n in nodes),
                total_threats=0,
                threats_by_severity={},
                platform_health={"ibm_quantum": 1.0},
                job_history=job_history,
                calibration_request_count=self.calibration_requests,
                collection_metadata={
                    "source": "IBMQuantumCollector",
                    "elapsed_ms": int(elapsed_time * 1000),
                    "degraded": False
                }
            )
            
            self.cached_last_snapshot = snapshot
            return snapshot
            
        except Exception as e:
            logger.error("ibm_collector_error", error=str(e))
            
            if self.cached_last_snapshot:
                logger.warning("using_cached_snapshot_due_to_error")
                degraded_snapshot = self.cached_last_snapshot.model_copy()
                degraded_snapshot.generated_at = datetime.now(timezone.utc)
                if not degraded_snapshot.collection_metadata:
                    degraded_snapshot.collection_metadata = {}
                degraded_snapshot.collection_metadata["degraded"] = True
                return degraded_snapshot
                
            return self._empty_snapshot()

    def _empty_snapshot(self) -> SimulationSnapshot:
        """Helper to generate an empty snapshot on failure.
        
        Returns:
            A zeroed-out SimulationSnapshot indicating no connections.
        """
        return SimulationSnapshot(
            snapshot_id="empty-snapshot",
            generated_at=datetime.now(timezone.utc),
            backends=[],
            threats=[],
            entanglement_pairs=[],
            total_qubits=0,
            total_threats=0,
            threats_by_severity={},
            platform_health={},
            job_history=[],
            calibration_request_count={},
            collection_metadata={"degraded": True}
        )
