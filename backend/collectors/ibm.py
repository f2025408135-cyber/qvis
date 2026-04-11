import structlog
from typing import Dict, Any
from backend.collectors.base import BaseCollector

logger = structlog.get_logger()

class IBMQuantumCollector(BaseCollector):
    def __init__(self, ibm_token: str):
        self.ibm_token = ibm_token
        self.service = None
        
    async def collect(self) -> Dict[str, Any]:
        if not self.ibm_token:
            logger.warning("IBM_QUANTUM_TOKEN not set, skipping real collection.")
            return {}
            
        try:
            from qiskit_ibm_runtime import QiskitRuntimeService
            
            if not self.service:
                self.service = QiskitRuntimeService(token=self.ibm_token, channel="ibm_quantum")
                
            backends = self.service.backends()
            
            raw_data = {
                "platform": "ibm_quantum",
                "backends": [],
                "api_error_log": {},
                "api_access_log": {},
                "failed_job_access_attempts": [],
                "recent_jobs": [],
                "github_search_results": []
            }
            
            for backend in backends:
                b_info = {
                    "id": backend.name,
                    "name": backend.name,
                    "num_qubits": backend.num_qubits,
                    "is_simulator": backend.simulator,
                    "operational": backend.status().operational,
                }
                raw_data["backends"].append(b_info)
                
            return raw_data
            
        except Exception as e:
            logger.error("ibm_collector_error", error=str(e))
            return {}
