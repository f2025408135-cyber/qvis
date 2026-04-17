"""Adaptive baseline detection using exponential moving averages."""

import math
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, Optional


@dataclass
class MetricBaseline:
    """Tracks EMA and standard deviation for a single metric."""
    ema: float = 0.0
    ema_variance: float = 0.0
    count: int = 0
    alpha: float = 0.1  # Smoothing factor

    # Minimum variance floor: prevents the warmup-transient false-positive
    # where 3+ identical values produce variance ≈ 0, causing a tiny
    # deviation to generate an enormous z-score (e.g. 33-sigma for a
    # 1 % drift).  We enforce a floor so that the first few post-warmup
    # samples can't spike above the alert threshold unless the deviation
    # is genuinely large relative to the metric's own scale.
    variance_floor_factor: float = 0.001  # 0.1 % of ema²

    def update(self, value: float) -> float:
        """Update baseline and return z-score of new value."""
        if self.count == 0:
            self.ema = value
            self.ema_variance = 0.0
            self.count = 1
            return 0.0

        self.count += 1
        diff = value - self.ema
        self.ema += self.alpha * diff
        self.ema_variance = (1 - self.alpha) * (self.ema_variance + self.alpha * diff * diff)

        # Enforce a variance floor proportional to EMA² so that
        # perfectly-stable metrics don't produce astronomical z-scores
        # on the first post-warmup sample that deviates even slightly.
        ema_abs = abs(self.ema) if self.ema != 0 else 1.0
        min_variance = self.variance_floor_factor * ema_abs * ema_abs
        effective_variance = max(self.ema_variance, min_variance)

        std = math.sqrt(effective_variance)
        z_score = diff / std if std > 0 else 0.0
        return z_score


class BaselineManager:
    """Manages per-backend, per-metric rolling baselines."""

    def __init__(self, z_threshold: float = 2.5, variance_floor_factor: float = 0.001):
        self.baselines: Dict[str, MetricBaseline] = defaultdict(MetricBaseline)
        self.z_threshold = z_threshold
        self.variance_floor_factor = variance_floor_factor

    def check(self, backend_id: str, metric_name: str, value: float) -> Optional[float]:
        """Update baseline and return z-score if anomalous (|z| > threshold), else None."""
        key = f"{backend_id}:{metric_name}"
        # Ensure the baseline uses the manager's variance_floor_factor
        baseline = self.baselines[key]
        if baseline.variance_floor_factor != self.variance_floor_factor:
            baseline.variance_floor_factor = self.variance_floor_factor
        z = baseline.update(value)
        # Reduced warmup from 10 to 3 (~90s at 30s interval) to shrink detection blind spot
        if baseline.count > 3 and abs(z) > self.z_threshold:
            return z
        return None

    def reset(self):
        """Clear all learned baselines."""
        self.baselines.clear()
