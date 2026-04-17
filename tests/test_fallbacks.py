"""Tests for fallback system — FallbackManager, ToastManager, PerformanceMonitor."""

import pytest


class TestFallbackManagerConcepts:
    """Test fallback logic concepts that don't require a browser environment.
    
    The FallbackManager, ToastManager, and PerformanceMonitor are browser-only
    JS modules. These tests verify the backend continues to function correctly
    regardless of frontend state — e.g., empty snapshots, degraded metadata.
    """

    @pytest.mark.asyncio
    async def test_empty_snapshot_is_valid_payload(self):
        """Verify the system produces a valid snapshot even with zero backends."""
        from backend.threat_engine.models import SimulationSnapshot
        from datetime import datetime, timezone

        snapshot = SimulationSnapshot(
            snapshot_id="empty-fallback",
            generated_at=datetime.now(timezone.utc),
            backends=[],
            threats=[],
            entanglement_pairs=[],
            total_qubits=0,
            total_threats=0,
            threats_by_severity={},
            platform_health={},
            collection_metadata={"degraded": True, "source": "fallback"}
        )

        assert snapshot.snapshot_id == "empty-fallback"
        assert snapshot.total_qubits == 0
        assert snapshot.total_threats == 0
        assert snapshot.collection_metadata["degraded"] is True
        # Serialization round-trip (the frontend JSON.parse path)
        json_str = snapshot.model_dump_json()
        parsed = SimulationSnapshot.model_validate_json(json_str)
        assert parsed.snapshot_id == snapshot.snapshot_id

    @pytest.mark.asyncio
    async def test_degraded_metadata_survives_roundtrip(self):
        """Ensure degraded collection metadata survives serialization round-trip."""
        from backend.collectors.ibm import IBMQuantumCollector

        collector = IBMQuantumCollector("")
        snapshot = await collector.collect()

        assert snapshot.collection_metadata["degraded"] is True
        json_str = snapshot.model_dump_json()
        parsed_dict = __import__('json').loads(json_str)
        assert parsed_dict["collection_metadata"]["degraded"] is True

    @pytest.mark.asyncio
    async def test_ibm_collector_caches_and_returns_degraded_on_failure(self):
        """Verify the IBM collector returns a degraded cached snapshot on repeated failure."""
        from backend.collectors.ibm import IBMQuantumCollector
        from unittest.mock import MagicMock
        import sys

        mock_qiskit = MagicMock()
        mock_service_class = MagicMock()
        mock_qiskit.QiskitRuntimeService = mock_service_class
        sys.modules['qiskit_ibm_runtime'] = mock_qiskit

        try:
            # First call succeeds
            mock_service_instance = mock_service_class.return_value
            mock_backend = MagicMock()
            mock_backend.name = "ibm_test"
            mock_backend.num_qubits = 5
            mock_backend.simulator = False
            mock_status = MagicMock()
            mock_status.operational = True
            mock_backend.status = lambda: mock_status
            mock_config = MagicMock()
            mock_config.n_qubits = 5
            mock_config.simulator = False
            mock_config.max_experiments = 100
            mock_backend.configuration = lambda: mock_config
            mock_backend.properties = lambda: MagicMock(qubits=[])
            mock_service_instance.backends = lambda: [mock_backend]
            mock_service_instance.jobs = lambda **kwargs: []

            collector = IBMQuantumCollector("fake-token")
            snapshot1 = await collector.collect()
            assert snapshot1.collection_metadata["degraded"] is False
            assert len(snapshot1.backends) == 1

            # Second call: force service to None so it re-creates
            collector.service = None
            mock_service_class.side_effect = Exception("Network error")
            snapshot2 = await collector.collect()
            assert snapshot2.collection_metadata["degraded"] is True
            assert len(snapshot2.backends) == 1  # Cached data
            assert snapshot2.backends[0].name == "ibm_test"
        finally:
            del sys.modules['qiskit_ibm_runtime']

    @pytest.mark.asyncio
    async def test_mock_collector_is_test_mode_deterministic(self):
        """Verify test mode returns deterministic data for fallback scenarios."""
        from backend.collectors.mock import MockCollector

        collector = MockCollector()
        collector.is_test = True

        snap1 = await collector.collect()
        snap2 = await collector.collect()

        # Same backends, same threats, same counts
        assert len(snap1.backends) == len(snap2.backends)
        assert len(snap1.threats) == len(snap2.threats)
        assert snap1.total_qubits == snap2.total_qubits

        # But different snapshot IDs (timestamps differ)
        assert snap1.snapshot_id != snap2.snapshot_id

    @pytest.mark.asyncio
    async def test_snapshot_with_extra_fields_serializes(self):
        """Extra fields (from collector metadata) must survive serialization."""
        from backend.threat_engine.models import SimulationSnapshot
        from backend.collectors.mock import MockCollector
        from datetime import datetime, timezone

        collector = MockCollector()
        collector.is_test = True
        snapshot = await collector.collect()

        # Add extra fields that collectors inject
        snapshot.job_history = [{"job_id": "test-123"}]
        snapshot.calibration_request_count = {"ibm_sherbrooke": 5}
        snapshot.collection_metadata = {
            "source": "IBMQuantumCollector",
            "elapsed_ms": 1234,
            "degraded": False
        }

        # Must serialize without error
        json_str = snapshot.model_dump_json()
        parsed = __import__('json').loads(json_str)

        assert "job_history" in parsed
        assert parsed["job_history"][0]["job_id"] == "test-123"
        assert parsed["collection_metadata"]["elapsed_ms"] == 1234

    @pytest.mark.asyncio
    async def test_websocket_manager_broadcast_empty_snapshot(self):
        """WebSocket broadcast must handle empty snapshots without error."""
        from backend.api.websocket import manager
        from backend.threat_engine.models import SimulationSnapshot
        from datetime import datetime, timezone

        snapshot = SimulationSnapshot(
            snapshot_id="broadcast-test",
            generated_at=datetime.now(timezone.utc),
            backends=[],
            threats=[],
            entanglement_pairs=[],
            total_qubits=0,
            total_threats=0,
            threats_by_severity={},
            platform_health={},
            collection_metadata={"degraded": True}
        )

        # broadcast_snapshot should work even with no connections
        await manager.broadcast_snapshot(snapshot)

        assert len(manager.active_connections) == 0

    @pytest.mark.asyncio
    async def test_health_endpoint_includes_connected_platforms(self):
        """Health endpoint must reflect collector state for frontend fallback logic."""
        from fastapi.testclient import TestClient
        import os
        os.environ["PYTEST_CURRENT_TEST"] = "true"

        from backend.main import app

        # Force reload with mock collector
        client = TestClient(app)
        response = client.get("/api/health")
        data = response.json()

        assert "status" in data
        assert "active_collector" in data
        assert "connected_platforms" in data
        assert isinstance(data["connected_platforms"], list)
        assert "demo_mode" in data
