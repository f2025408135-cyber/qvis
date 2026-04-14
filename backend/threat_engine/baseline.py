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

        std = math.sqrt(self.ema_variance) if self.ema_variance > 0 else 1.0
        z_score = diff / std if std > 0 else 0.0
        return z_score


class BaselineManager:
    """Manages per-backend, per-metric rolling baselines."""

    def __init__(self, z_threshold: float = 2.5):
        self.baselines: Dict[str, MetricBaseline] = defaultdict(MetricBaseline)
        self.z_threshold = z_threshold

    def check(self, backend_id: str, metric_name: str, value: float) -> Optional[float]:
        """Update baseline and return z-score if anomalous (|z| > threshold), else None."""
        key = f"{backend_id}:{metric_name}"
        z = self.baselines[key].update(value)
        # Reduced warmup from 10 to 3 (~90s at 30s interval) to shrink detection blind spot
        if self.baselines[key].count > 3 and abs(z) > self.z_threshold:
            return z
        return None

    def reset(self):
        """Clear all learned baselines."""
        self.baselines.clear()
