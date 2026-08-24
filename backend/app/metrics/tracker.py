"""
Rolling metrics tracker for real-time reporting: per-packet/flow latency
(mean, p50, p95, p99, max) and throughput (packets or flows per second).
Thread/async-safe enough for single-process FastAPI + asyncio use.
"""
from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field

from app.config import settings


@dataclass
class MetricsSnapshot:
    count: int
    latency_mean_ms: float
    latency_p50_ms: float
    latency_p95_ms: float
    latency_p99_ms: float
    latency_max_ms: float
    throughput_per_sec: float
    within_budget_pct: float


class MetricsTracker:
    def __init__(self, window_size: int | None = None) -> None:
        self._window = window_size or settings.metrics_window_size
        self._latencies: deque[float] = deque(maxlen=self._window)
        self._timestamps: deque[float] = deque(maxlen=self._window)
        self._total_processed = 0

    def record(self, latency_ms: float) -> None:
        now = time.perf_counter()
        self._latencies.append(latency_ms)
        self._timestamps.append(now)
        self._total_processed += 1

    def snapshot(self) -> MetricsSnapshot:
        if not self._latencies:
            return MetricsSnapshot(0, 0, 0, 0, 0, 0, 0, 100.0)

        sorted_lat = sorted(self._latencies)
        n = len(sorted_lat)

        def pct(p: float) -> float:
            idx = min(n - 1, int(round(p * (n - 1))))
            return sorted_lat[idx]

        span = self._timestamps[-1] - self._timestamps[0]
        throughput = (n - 1) / span if span > 0 else 0.0

        within_budget = sum(1 for l in self._latencies if l <= settings.inference_latency_budget_ms)
        within_budget_pct = 100.0 * within_budget / n

        return MetricsSnapshot(
            count=self._total_processed,
            latency_mean_ms=sum(sorted_lat) / n,
            latency_p50_ms=pct(0.50),
            latency_p95_ms=pct(0.95),
            latency_p99_ms=pct(0.99),
            latency_max_ms=sorted_lat[-1],
            throughput_per_sec=throughput,
            within_budget_pct=within_budget_pct,
        )

    def reset(self) -> None:
        self._latencies.clear()
        self._timestamps.clear()
        self._total_processed = 0


# Separate trackers per pipeline so live/replay/upload stats don't mix
live_metrics = MetricsTracker()
replay_metrics = MetricsTracker()
upload_metrics = MetricsTracker()
