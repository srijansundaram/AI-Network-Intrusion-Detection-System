"""Pydantic models for WebSocket/API payloads."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal, Optional

from pydantic import BaseModel, Field


class AlertMessage(BaseModel):
    type: Literal["alert"] = "alert"
    source: Literal["live", "replay", "upload"]
    flow_id: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    label: str
    is_malicious: bool
    confidence: float
    latency_ms: float
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class MetricsMessage(BaseModel):
    type: Literal["metrics"] = "metrics"
    source: Literal["live", "replay", "upload"]
    count: int
    latency_mean_ms: float
    latency_p50_ms: float
    latency_p95_ms: float
    latency_p99_ms: float
    latency_max_ms: float
    throughput_per_sec: float
    within_budget_pct: float
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class StatusMessage(BaseModel):
    type: Literal["status"] = "status"
    source: Literal["live", "replay", "upload"]
    state: str
    detail: Optional[str] = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
