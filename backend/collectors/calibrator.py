"""Threshold calibrator that learns real baseline values from live IBM Quantum data.

Runs the collector for a configurable duration, recording every metric that
the detection rules use, and computes per-backend p95 values.  These
become the recommended thresholds that override the hardcoded defaults in
rules.py when calibration_results.json is present.

Only operates in live mode with a real IBM Quantum token.
"""

from __future__ import annotations

import asyncio
import json
import math
import os
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import structlog

logger = structlog.get_logger(__name__)

# Path where calibration results are persisted
_CALIBRATION_FILE = Path(__file__).resolve().parent.parent.parent / "calibration_results.json"


# ─── Data classes for per-metric sample collection ──────────────────────

@dataclass
class MetricSamples:
    """Rolling list of observed values for a single metric."""
    values: List[float] = field(default_factory=list)

    def record(self, value: float) -> None:
        self.values.append(value)

    def p95(self) -> Optional[float]:
        """Return the 95th percentile, or None if fewer than 5 samples."""
        if len(self.values) < 5:
            return None
        sorted_vals = sorted(self.values)
        idx = int(math.ceil(0.95 * len(sorted_vals))) - 1
        idx = max(0, min(idx, len(sorted_vals) - 1))
        return sorted_vals[idx]

    def mean(self) -> Optional[float]:
        if not self.values:
            return None
        return sum(self.values) / len(self.values)

    def count(self) -> int:
        return len(self.values)


@dataclass
class CalibrationResult:
    """Outcome of a calibration run.

    Each field is a dictionary mapping rule IDs to their recommended
    threshold values.  Fields set to None indicate that not enough data
    was collected to recommend a threshold for that rule.
    """
    calibrated_at: str
    duration_minutes: int
    samples_collected: int
    backends_observed: List[str]
    # Per-rule recommended thresholds (None = use hardcoded default)
    rule_002_calibration_harvest_ratio: Optional[float] = None
    rule_003_identity_gate_ratio: Optional[float] = None
    rule_003_max_circuit_gates: Optional[int] = None
    rule_004_max_failed_attempts: Optional[int] = None
    rule_005_max_depth_ratio: Optional[float] = None
    rule_006_max_sequential_404: Optional[int] = None
    rule_007_max_admin_403: Optional[int] = None
    rule_008_t1_baseline_ratio: Optional[float] = None
    rule_009_min_backends_accessed: Optional[int] = None
    rule_010_measure_ratio: Optional[float] = None
    rule_010_min_circuit_gates: Optional[int] = None
    # Raw p95 / mean data for auditability
    raw_metrics: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "CalibrationResult":
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})

    def save(self, path: Optional[str] = None) -> str:
        """Serialize to JSON and write to disk. Returns the path used."""
        target = Path(path) if path else _CALIBRATION_FILE
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(self.to_dict(), indent=2))
        logger.info("calibration_saved", path=str(target))
        return str(target)

    @classmethod
    def load(cls, path: Optional[str] = None) -> Optional["CalibrationResult"]:
        """Load from JSON. Returns None if file does not exist or is invalid."""
        target = Path(path) if path else _CALIBRATION_FILE
        if not target.is_file():
            return None
        try:
            d = json.loads(target.read_text())
            return cls.from_dict(d)
        except Exception as exc:
            logger.warning("calibration_load_failed", path=str(target), error=str(exc))
            return None


# ─── The calibrator itself ─────────────────────────────────────────────

class ThresholdCalibrator:
    """Observes live IBM Quantum telemetry to learn empirical thresholds.

    Usage::

        from backend.collectors.ibm import IBMQuantumCollector
        collector = IBMQuantumCollector(ibm_token="...")
        cal = ThresholdCalibrator(collector)
        result = await cal.calibrate(duration_minutes=60)
        result.save()
    """

    def __init__(self, collector) -> None:
        self.collector = collector

        # Metric buckets keyed by backend_id
        self._cal_harvest_ratios: Dict[str, MetricSamples] = {}
        self._identity_gate_ratios: Dict[str, MetricSamples] = {}
        self._circuit_total_gates: Dict[str, MetricSamples] = {}
        self._depth_ratios: Dict[str, MetricSamples] = {}
        self._measure_ratios: Dict[str, MetricSamples] = {}
        self._backends_per_window: MetricSamples = MetricSamples()
        self._jobs_per_backend_per_window: Dict[str, MetricSamples] = {}
        self._cal_requests_per_window: Dict[str, MetricSamples] = {}
        self._t1_values: Dict[str, MetricSamples] = {}  # (backend, qubit) -> values

        self._samples_collected = 0
        self._backends_observed: set = set()

    # ── Main entry point ────────────────────────────────────────────

    async def calibrate(self, duration_minutes: int = 60) -> CalibrationResult:
        """Run the calibration loop.

        Collects a snapshot every 30 seconds for *duration_minutes*,
        extracts every metric the rules use, and then computes p95-based
        thresholds.
        """
        interval = 30  # seconds between collections
        max_iterations = (duration_minutes * 60) // interval

        logger.info(
            "calibration_starting",
            duration_minutes=duration_minutes,
            interval_seconds=interval,
            max_iterations=max_iterations,
        )

        iteration = 0
        start = time.monotonic()

        try:
            while iteration < max_iterations:
                try:
                    snapshot = await self.collector.collect()
                    self._extract_metrics(snapshot)
                    self._samples_collected += 1
                except Exception as exc:
                    logger.warning("calibration_collection_error", iteration=iteration, error=str(exc))

                iteration += 1
                elapsed = time.monotonic() - start
                remaining = max(0, (duration_minutes * 60) - elapsed)
                logger.info(
                    "calibration_progress",
                    iteration=iteration,
                    total=max_iterations,
                    elapsed_s=round(elapsed),
                    remaining_s=round(remaining),
                    backends=len(self._backends_observed),
                )
                await asyncio.sleep(interval)

        except asyncio.CancelledError:
            logger.info("calibration_cancelled", iteration=iteration)

        elapsed_total = time.monotonic() - start
        result = self._compute_results(duration_minutes)
        logger.info(
            "calibration_complete",
            elapsed_s=round(elapsed_total),
            samples=self._samples_collected,
            thresholds={k: v for k, v in asdict(result).items() if v is not None and k.startswith("rule_")},
        )
        return result

    # ── Metric extraction from a single snapshot ────────────────────

    def _ensure(self, bucket: dict, key: str) -> MetricSamples:
        if key not in bucket:
            bucket[key] = MetricSamples()
        return bucket[key]

    def _extract_metrics(self, snapshot: Any) -> None:
        """Pull every observable metric from a SimulationSnapshot."""
        raw = snapshot.model_dump() if hasattr(snapshot, "model_dump") else snapshot

        backends = raw.get("backends", [])
        jobs = raw.get("job_history", [])

        # ── Per-backend metrics ────────────────────────────────────
        backend_job_counts: Dict[str, int] = {}
        backend_cal_requests: Dict[str, int] = {}

        for be in backends:
            bid = be.get("id", "unknown") if isinstance(be, dict) else be.id
            self._backends_observed.add(bid)

            # T1 values for baseline health rule
            cal_list = be.get("calibration", []) if isinstance(be, dict) else (
                [c.model_dump() for c in be.calibration] if be.calibration else []
            )
            for q in cal_list:
                qid = str(q.get("qubit_id")) if isinstance(q, dict) else str(q.qubit_id)
                t1 = q.get("t1_us", 0) if isinstance(q, dict) else q.t1_us
                if t1 > 0:
                    key = f"{bid}:q{qid}"
                    self._ensure(self._t1_values, key).record(t1)

            # Calibration request counts
            cal_req = raw.get("calibration_request_count", {})
            if isinstance(cal_req, dict):
                backend_cal_requests[bid] = cal_req.get(bid, 0)

        # ── Per-job metrics ─────────────────────────────────────────
        for job in jobs:
            bid = job.get("backend_id", "unknown")
            backend_job_counts[bid] = backend_job_counts.get(bid, 0) + 1

            hist = job.get("gate_histogram", {})
            if not hist or not isinstance(hist, dict):
                continue

            total_gates = sum(hist.values())
            if total_gates == 0:
                continue

            # Identity gate ratio (RULE_003)
            id_count = hist.get("id", 0)
            self._ensure(self._identity_gate_ratios, bid).record(id_count / total_gates)
            self._ensure(self._circuit_total_gates, bid).record(float(total_gates))

            # Measure gate ratio (RULE_010)
            measure_count = hist.get("measure", 0)
            self._ensure(self._measure_ratios, bid).record(measure_count / total_gates)

            # Depth ratio (RULE_005)
            depth = job.get("depth", 0)
            max_depth = job.get("max_allowed_depth", 1)
            if max_depth > 0:
                self._ensure(self._depth_ratios, bid).record(depth / max_depth)

        # ── Per-window aggregate metrics ────────────────────────────
        # Calibration harvest ratio: cal_requests / max(jobs, 1) per backend
        for bid in self._backends_observed:
            jobs_count = backend_job_counts.get(bid, 0)
            cal_count = backend_cal_requests.get(bid, 0)
            ratio = cal_count / max(jobs_count, 1)
            self._ensure(self._cal_harvest_ratios, bid).record(ratio)
            self._ensure(self._jobs_per_backend_per_window, bid).record(float(jobs_count))

        # Number of distinct backends accessed this window (RULE_009)
        self._backends_per_window.record(float(len(backend_job_counts)))

    # ── Compute final thresholds from collected samples ────────────

    def _compute_results(self, duration_minutes: int) -> CalibrationResult:
        """Derive recommended thresholds from p95 of observed metrics."""
        result = CalibrationResult(
            calibrated_at=datetime.now(timezone.utc).isoformat(),
            duration_minutes=duration_minutes,
            samples_collected=self._samples_collected,
            backends_observed=sorted(self._backends_observed),
        )

        raw: Dict[str, Dict[str, Any]] = {}

        # RULE_002: Calibration harvest ratio — p95 across all backends
        all_cal_ratios = self._aggregate_samples(self._cal_harvest_ratios)
        if all_cal_ratios:
            p95 = all_cal_ratios.p95()
            if p95 is not None:
                # Recommend a threshold above normal but below attack patterns.
                # Use p95 * 1.5 so we don't flag normal heavy users.
                result.rule_002_calibration_harvest_ratio = round(p95 * 1.5, 2)
                raw["rule_002"] = {"p95": round(p95, 4), "mean": round(all_cal_ratios.mean() or 0, 4), "n": all_cal_ratios.count()}

        # RULE_003: Identity gate ratio and max circuit gates
        all_id_ratios = self._aggregate_samples(self._identity_gate_ratios)
        all_gate_counts = self._aggregate_samples(self._circuit_total_gates)
        if all_id_ratios:
            p95 = all_id_ratios.p95()
            if p95 is not None:
                result.rule_003_identity_gate_ratio = round(p95, 2)
                raw["rule_003_ratio"] = {"p95": round(p95, 4), "mean": round(all_id_ratios.mean() or 0, 4), "n": all_id_ratios.count()}
        if all_gate_counts:
            # We want the low end: small circuits are typical for oracle attacks.
            # Use p5 (inverse of p95) to find what "small" means.
            p5 = self._percentile(all_gate_counts.values, 0.05)
            if p5 is not None:
                result.rule_003_max_circuit_gates = max(5, int(p5))
                raw["rule_003_gates"] = {"p5": round(p5, 1), "mean": round(all_gate_counts.mean() or 0, 1), "n": all_gate_counts.count()}

        # RULE_004: Failed access attempts — we can't observe these from
        # live data (no audit log).  Keep None → use hardcoded default.

        # RULE_005: Depth ratio
        all_depth = self._aggregate_samples(self._depth_ratios)
        if all_depth:
            p95 = all_depth.p95()
            if p95 is not None:
                result.rule_005_max_depth_ratio = round(p95, 2)
                raw["rule_005"] = {"p95": round(p95, 4), "mean": round(all_depth.mean() or 0, 4), "n": all_depth.count()}

        # RULE_006 / RULE_007: Error counts — not observable from normal
        # API telemetry.  Keep None → use hardcoded defaults.

        # RULE_008: T1 baseline ratio — use p5 of T1 values as the floor
        all_t1 = MetricSamples()
        for samples in self._t1_values.values():
            all_t1.values.extend(samples.values)
        if all_t1.count() >= 20:
            mean_t1 = all_t1.mean() or 100.0
            p5_t1 = self._percentile(all_t1.values, 0.05)
            if p5_t1 and mean_t1 > 0:
                result.rule_008_t1_baseline_ratio = round(p5_t1 / mean_t1, 2)
                raw["rule_008"] = {"mean_t1": round(mean_t1, 1), "p5_t1": round(p5_t1, 1), "ratio": round(p5_t1 / mean_t1, 3), "n": all_t1.count()}

        # RULE_009: Backends per window
        if self._backends_per_window.count() >= 5:
            p95 = self._backends_per_window.p95()
            if p95 is not None:
                # Ceiling to int — if users normally touch 2 backends,
                # flag when someone touches more than that.
                result.rule_009_min_backends_accessed = max(2, int(math.ceil(p95)))
                raw["rule_009"] = {"p95": round(p95, 2), "mean": round(self._backends_per_window.mean() or 0, 2), "n": self._backends_per_window.count()}

        # RULE_010: Measure ratio and min circuit gates
        all_measure = self._aggregate_samples(self._measure_ratios)
        if all_measure:
            p95 = all_measure.p95()
            if p95 is not None:
                result.rule_010_measure_ratio = round(p95, 2)
                raw["rule_010_ratio"] = {"p95": round(p95, 4), "mean": round(all_measure.mean() or 0, 4), "n": all_measure.count()}
        if all_gate_counts:
            p5 = self._percentile(all_gate_counts.values, 0.05)
            if p5 is not None:
                result.rule_010_min_circuit_gates = max(5, int(p5))
                raw["rule_010_gates"] = {"p5": round(p5, 1), "n": all_gate_counts.count()}

        result.raw_metrics = raw
        return result

    # ── Helpers ────────────────────────────────────────────────────

    @staticmethod
    def _aggregate_samples(per_backend: Dict[str, MetricSamples]) -> MetricSamples:
        """Merge per-backend MetricSamples into a single combined one."""
        combined = MetricSamples()
        for samples in per_backend.values():
            combined.values.extend(samples.values)
        return combined

    @staticmethod
    def _percentile(values: List[float], quantile: float) -> Optional[float]:
        """Compute an arbitrary percentile from a sorted list."""
        if len(values) < 5:
            return None
        s = sorted(values)
        idx = int(math.ceil(quantile * len(s))) - 1
        idx = max(0, min(idx, len(s) - 1))
        return s[idx]
