"""
Shared processing pipeline used by live capture, PCAP replay, and PCAP upload:

    pcap chunk -> CICFlowMeter feature extraction -> per-flow inference
    -> metrics tracking -> WebSocket alert broadcast

Keeping this in one place means all three data paths report metrics and
alerts identically to Member C's frontend dashboard.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

import pandas as pd

from app.core.logging_config import get_logger
from app.core.websocket_manager import manager
from app.features.cicflow_extractor import extract_features_from_pcap
from app.inference.engine import engine
from app.metrics.tracker import MetricsTracker
from app.schemas.alerts import MetricsMessage

logger = get_logger(__name__)

Source = Literal["live", "replay", "upload"]
_alert_counter = 0


async def process_pcap_file(pcap_path: Path, source: Source, tracker: MetricsTracker) -> dict:
    """
    Runs the full pipeline on one pcap file (a live-capture rolling window,
    a replay chunk, or a full uploaded file). Returns a summary dict and
    streams alerts over the WebSocket to Member C's dashboard.
    """
    global _alert_counter

    df = await extract_features_from_pcap(pcap_path)
    if df.empty:
        return {"flows_processed": 0, "malicious_flows": 0, "benign_flows": 0}

    malicious = 0
    benign = 0

    for idx, row in df.iterrows():
        # Pass row directly to engine which extracts 32 features and handles column normalization
        prediction = engine.predict_one(row)
        tracker.record(prediction.latency_ms)

        if prediction.is_malicious:
            malicious += 1
        else:
            benign += 1

        _alert_counter += 1

        # Extract network flow metadata
        src_ip = str(row.get("Source IP", row.get("src_ip", "192.168.1.100")))
        dst_ip = str(row.get("Destination IP", row.get("dst_ip", "10.0.0.5")))
        port_raw = row.get("Destination Port", row.get("dst_port", 80))
        try:
            port = int(port_raw) if pd.notna(port_raw) else 80
        except (ValueError, TypeError):
            port = 80

        # Construct alert dictionary with exact schema required by Member C's normalizeAlert in api.js
        alert_payload = {
            "id": _alert_counter,
            "type": "alert",
            "source": source,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "port": port,
            "dst_port": port,
            "label": prediction.label,
            "is_malicious": prediction.is_malicious,
            "confidence": prediction.confidence,
            "latency_ms": round(prediction.latency_ms, 2),
            "probabilities": prediction.probabilities_15,
            "rf_probabilities": prediction.rf_probabilities_15,
            "lstm_probabilities": prediction.lstm_probabilities_15,
            "top_features": prediction.top_features,
            "lime_features": prediction.lime_features,
            "class_probabilities": prediction.class_probabilities_9,
        }

        # Broadcast all malicious alerts, and sample benign flows (to keep live dashboard summary cards updated)
        # For replay and upload, broadcast all flows to give full viva visibility
        should_broadcast = prediction.is_malicious or source in ("replay", "upload") or (_alert_counter % 3 == 0)
        if should_broadcast:
            await manager.broadcast({
                "type": "alert",
                "data": alert_payload,
                **alert_payload,
            })
            # Small yield to let WebSocket messages flush smoothly in high-speed replay
            if source in ("replay", "upload") and len(df) > 20:
                await asyncio.sleep(0.01)

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

    return {"flows_processed": len(df), "malicious_flows": malicious, "benign_flows": benign}
