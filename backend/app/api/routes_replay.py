"""PCAP replay control endpoints (E8: simulate live traffic from a saved capture)."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

from app.capture.pcap_replay import replay_controller
from app.schemas.requests import ReplayStartRequest, ReplayStatusResponse

router = APIRouter(prefix="/replay", tags=["replay"])


@router.post("/start", response_model=ReplayStatusResponse)
async def start_replay(req: ReplayStartRequest) -> ReplayStatusResponse:
    try:
        await replay_controller.start(filename=req.filename, speed=req.speed, loop=req.loop)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    return ReplayStatusResponse(
        running=replay_controller.running,
        filename=replay_controller.filename,
        packets_replayed=replay_controller.packets_replayed,
    )


@router.post("/stop", response_model=ReplayStatusResponse)
async def stop_replay() -> ReplayStatusResponse:
    await replay_controller.stop()
    return ReplayStatusResponse(
        running=replay_controller.running,
        filename=replay_controller.filename,
        packets_replayed=replay_controller.packets_replayed,
    )


@router.get("/status", response_model=ReplayStatusResponse)
async def replay_status() -> ReplayStatusResponse:
    return ReplayStatusResponse(
        running=replay_controller.running,
        filename=replay_controller.filename,
        packets_replayed=replay_controller.packets_replayed,
    )
