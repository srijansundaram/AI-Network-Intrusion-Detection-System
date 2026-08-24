"""Request/response models for REST endpoints."""
from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class CaptureStartRequest(BaseModel):
    interface: Optional[str] = Field(None, description="Network interface, e.g. eth0. Defaults to config value.")
    bpf_filter: Optional[str] = Field(None, description="Optional BPF filter, e.g. 'tcp or udp'")


class CaptureStatusResponse(BaseModel):
    running: bool
    interface: Optional[str] = None
    packets_captured: int = 0


class ReplayStartRequest(BaseModel):
    filename: str = Field(..., description="Filename of a previously uploaded pcap in the pcap directory")
    speed: float = Field(1.0, gt=0, description="Playback speed multiplier. 1.0 = real-time, 2.0 = 2x speed")
    loop: bool = False


class ReplayStatusResponse(BaseModel):
    running: bool
    filename: Optional[str] = None
    packets_replayed: int = 0


class UploadResponse(BaseModel):
    filename: str
    flows_processed: int
    malicious_flows: int
    benign_flows: int
    processing_time_ms: float


class HealthResponse(BaseModel):
    status: str
    model_loaded: bool
    active_websockets: int
    
class PredictRequest(BaseModel):
    features: list[float]


class PredictResponse(BaseModel):
    label: str
    is_malicious: bool
    confidence: float
    latency_ms: float
    total_latency_ms: float