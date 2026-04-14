"""Tests for multi-platform collectors and aggregator."""

import pytest
import asyncio
from backend.collectors.braket import BraketCollector
from backend.collectors.azure_quantum import AzureQuantumCollector
from backend.collectors.aggregator import AggregatorCollector
from backend.collectors.mock import MockCollector
from backend.threat_engine.models import SimulationSnapshot


class TestBraketCollector:
    """Tests for the AWS Braket collector."""

    @pytest.mark.asyncio
    async def test_braket_mock_fallback_returns_snapshot(self):
        """Braket collector returns a valid mock snapshot when SDK is unavailable."""
        collector = BraketCollector()
        snapshot = await collector.collect()
        assert isinstance(snapshot, SimulationSnapshot)
        assert len(snapshot.backends) > 0

    @pytest.mark.asyncio
    async def test_braket_mock_has_correct_platform(self):
        """Braket mock backends have platform=amazon_braket."""
        collector = BraketCollector()
        snapshot = await collector.collect()
        for backend in snapshot.backends:
            assert backend.platform.value == "amazon_braket"

    @pytest.mark.asyncio
    async def test_braket_mock_has_calibration_data(self):
        """Braket mock backends include calibration data."""
        collector = BraketCollector()
        snapshot = await collector.collect()
        has_cal = any(len(b.calibration) > 0 for b in snapshot.backends)
        assert has_cal, "At least one Braket backend should have calibration data"

    @pytest.mark.asyncio
    async def test_braket_mock_backends_have_ids(self):
        """All Braket mock backends have non-empty IDs."""
        collector = BraketCollector()
        snapshot = await collector.collect()
        for b in snapshot.backends:
            assert b.id, f"Backend {b.name} has empty ID"
            assert b.id.startswith("braket_"), f"Braket backend ID should start with 'braket_': {b.id}"


class TestAzureQuantumCollector:
    """Tests for the Azure Quantum collector."""

    @pytest.mark.asyncio
    async def test_azure_mock_fallback_returns_snapshot(self):
        """Azure collector returns a valid mock snapshot when SDK is unavailable."""
        collector = AzureQuantumCollector()
        snapshot = await collector.collect()
        assert isinstance(snapshot, SimulationSnapshot)
        assert len(snapshot.backends) > 0

    @pytest.mark.asyncio
    async def test_azure_mock_has_correct_platform(self):
        """Azure mock backends have platform=azure_quantum."""
        collector = AzureQuantumCollector()
        snapshot = await collector.collect()
        for backend in snapshot.backends:
            assert backend.platform.value == "azure_quantum"

    @pytest.mark.asyncio
    async def test_azure_mock_has_qubit_counts(self):
        """Azure mock backends report qubit counts."""
        collector = AzureQuantumCollector()
        snapshot = await collector.collect()
        total = sum(b.num_qubits for b in snapshot.backends)
        assert total > 0, "Azure backends should report nonzero qubit counts"

    @pytest.mark.asyncio
    async def test_azure_mock_backends_have_ids(self):
        """All Azure mock backends have non-empty IDs prefixed correctly."""
        collector = AzureQuantumCollector()
        snapshot = await collector.collect()
        for b in snapshot.backends:
            assert b.id, f"Backend {b.name} has empty ID"
            assert b.id.startswith("azure_"), f"Azure backend ID should start with 'azure_': {b.id}"


class TestAggregatorCollector:
    """Tests for the multi-platform aggregator."""

    @pytest.mark.asyncio
    async def test_aggregator_merges_all_platforms(self):
        """Aggregator combines backends from multiple collectors."""
        mock_ibm = MockCollector()
        mock_ibm.is_test = True
        braket = BraketCollector()
        azure = AzureQuantumCollector()
        aggregator = AggregatorCollector([mock_ibm, braket, azure])

        snapshot = await aggregator.collect()
        assert isinstance(snapshot, SimulationSnapshot)

        platforms = {b.platform.value for b in snapshot.backends}
        assert "ibm_quantum" in platforms, "Missing IBM Quantum backends"
        assert "amazon_braket" in platforms, "Missing Amazon Braket backends"
        assert "azure_quantum" in platforms, "Missing Azure Quantum backends"

    @pytest.mark.asyncio
    async def test_aggregator_total_qubits(self):
        """Aggregator correctly sums total qubits across all platforms."""
        mock_ibm = MockCollector()
        mock_ibm.is_test = True
        braket = BraketCollector()
        azure = AzureQuantumCollector()
        aggregator = AggregatorCollector([mock_ibm, braket, azure])

        snapshot = await aggregator.collect()
        expected = sum(b.num_qubits for b in snapshot.backends)
        assert snapshot.total_qubits == expected

    @pytest.mark.asyncio
    async def test_aggregator_handles_collector_failure(self):
        """Aggregator continues even if one sub-collector raises an exception."""

        class FailingCollector(MockCollector):
            async def collect(self):
                raise RuntimeError("Simulated failure")

        mock_ibm = MockCollector()
        mock_ibm.is_test = True
        failing = FailingCollector()
        aggregator = AggregatorCollector([mock_ibm, failing])

        snapshot = await aggregator.collect()
        assert isinstance(snapshot, SimulationSnapshot)
        assert len(snapshot.backends) > 0, "Should still have backends from the working collector"

    @pytest.mark.asyncio
    async def test_aggregator_snapshot_has_valid_id(self):
        """Aggregated snapshot has a unique UUID snapshot_id."""
        mock = MockCollector()
        mock.is_test = True
        aggregator = AggregatorCollector([mock])
        s1 = await aggregator.collect()
        s2 = await aggregator.collect()
        assert s1.snapshot_id != s2.snapshot_id
