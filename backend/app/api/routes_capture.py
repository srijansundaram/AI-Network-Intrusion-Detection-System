"""Live capture control endpoints."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

from app.capture.live_capture import live_capture
from app.schemas.requests import CaptureStartRequest, CaptureStatusResponse

router = APIRouter(prefix="/capture", tags=["capture"])


@router.post("/start", response_model=CaptureStatusResponse)
async def start_capture(req: CaptureStartRequest) -> CaptureStatusResponse:
    try:
        await live_capture.start(interface=req.interface, bpf_filter=req.bpf_filter)
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to start capture: {exc}") from exc

    return CaptureStatusResponse(
        running=live_capture.running,
        interface=live_capture.interface,
        packets_captured=live_capture.packets_captured,
    )


@router.post("/stop", response_model=CaptureStatusResponse)
async def stop_capture() -> CaptureStatusResponse:
    await live_capture.stop()
    return CaptureStatusResponse(
        running=live_capture.running,
        interface=live_capture.interface,
        packets_captured=live_capture.packets_captured,
    )


@router.get("/status", response_model=CaptureStatusResponse)
async def capture_status() -> CaptureStatusResponse:
    return CaptureStatusResponse(
        running=live_capture.running,
        interface=live_capture.interface,
        packets_captured=live_capture.packets_captured,
    )
