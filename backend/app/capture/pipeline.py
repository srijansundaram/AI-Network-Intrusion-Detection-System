"""
Shared processing pipeline used by live capture, PCAP replay, and PCAP upload:

    pcap chunk -> CICFlowMeter feature extraction -> per-flow inference
    -> metrics tracking -> WebSocket alert broadcast

Keeping this in one place means all three data paths report metrics and
alerts identically.
"""
from __future__ import annotations

from pathlib import Path
from typing import Literal

import pandas as pd

from app.core.logging_config import get_logger
from app.core.websocket_manager import manager
from app.features.cicflow_extractor import extract_features_from_pcap, feature_matrix
from app.inference.engine import engine
from app.metrics.tracker import MetricsTracker
from app.schemas.alerts import AlertMessage, MetricsMessage

logger = get_logger(__name__)

Source = Literal["live", "replay", "upload"]


async def process_pcap_file(pcap_path: Path, source: Source, tracker: MetricsTracker) -> dict:
    """
    Runs the full pipeline on one pcap file (a live-capture rolling window,
    a replay chunk, or a full uploaded file). Returns a summary dict.
    """
    df = await extract_features_from_pcap(pcap_path)
    if df.empty:
        return {"flows_processed": 0, "malicious_flows": 0, "benign_flows": 0}

    X = feature_matrix(df)
    malicious = 0
    benign = 0

    for idx, row in X.iterrows():
        prediction = engine.predict_one(row)
        tracker.record(prediction.latency_ms)

        if prediction.is_malicious:
            malicious += 1
        else:
            benign += 1

        meta = df.loc[idx]
        alert = AlertMessage(
            source=source,
            flow_id=str(meta.get("Flow ID", "")) or None,
            src_ip=str(meta.get("Source IP", "")) or None,
            dst_ip=str(meta.get("Destination IP", "")) or None,
            dst_port=int(meta["Destination Port"]) if "Destination Port" in meta and pd.notna(meta["Destination Port"]) else None,
            label=prediction.label,
            is_malicious=prediction.is_malicious,
            confidence=prediction.confidence,
            latency_ms=prediction.latency_ms,
        )
        # Only broadcast malicious flows as "alerts" to avoid flooding the UI with
        # benign traffic; every flow still counts toward metrics.
        if prediction.is_malicious:
            await manager.broadcast(alert.model_dump())

    snap = tracker.snapshot()
    await manager.broadcast(
        MetricsMessage(
            source=source,
            count=snap.count,
            latency_mean_ms=snap.latency_mean_ms,
            latency_p50_ms=snap.latency_p50_ms,
            latency_p95_ms=snap.latency_p95_ms,
            latency_p99_ms=snap.latency_p99_ms,
            latency_max_ms=snap.latency_max_ms,
            throughput_per_sec=snap.throughput_per_sec,
            within_budget_pct=snap.within_budget_pct,
        ).model_dump()
    )

    return {"flows_processed": len(X), "malicious_flows": malicious, "benign_flows": benign}
