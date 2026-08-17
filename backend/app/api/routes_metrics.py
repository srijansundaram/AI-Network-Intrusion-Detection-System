"""Real-time metrics endpoints: latency and throughput per pipeline source."""
from __future__ import annotations

from fastapi import APIRouter

from app.metrics.tracker import live_metrics, replay_metrics, upload_metrics

router = APIRouter(prefix="/metrics", tags=["metrics"])


@router.get("")
async def all_metrics() -> dict:
    return {
        "live": live_metrics.snapshot().__dict__,
        "replay": replay_metrics.snapshot().__dict__,
        "upload": upload_metrics.snapshot().__dict__,
    }


@router.get("/live")
async def live_metrics_snapshot() -> dict:
    return live_metrics.snapshot().__dict__


@router.get("/replay")
async def replay_metrics_snapshot() -> dict:
    return replay_metrics.snapshot().__dict__


@router.get("/upload")
async def upload_metrics_snapshot() -> dict:
    return upload_metrics.snapshot().__dict__
