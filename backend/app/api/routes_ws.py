"""WebSocket endpoint for live alert / metrics streaming to dashboards."""
from __future__ import annotations

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.core.logging_config import get_logger
from app.core.websocket_manager import manager

router = APIRouter(tags=["websocket"])
logger = get_logger(__name__)


@router.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket) -> None:
    await manager.connect(websocket)
    try:
        while True:
            # We don't expect inbound messages, but keep the receive loop
            # alive so we detect disconnects promptly. Ignore any content sent.
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    except Exception:
        logger.exception("WebSocket error")
    finally:
        await manager.disconnect(websocket)
