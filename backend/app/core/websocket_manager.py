"""
Manages active WebSocket connections and broadcasts alert / metric events
to every connected client (e.g. a live dashboard).
"""
from __future__ import annotations

import asyncio
import json
from typing import Any

from fastapi import WebSocket

from app.core.logging_config import get_logger

logger = get_logger(__name__)


class ConnectionManager:
    def __init__(self) -> None:
        self._connections: set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        async with self._lock:
            self._connections.add(websocket)
        logger.info("WebSocket connected (total=%d)", len(self._connections))

    async def disconnect(self, websocket: WebSocket) -> None:
        async with self._lock:
            self._connections.discard(websocket)
        logger.info("WebSocket disconnected (total=%d)", len(self._connections))

    async def broadcast(self, payload: dict[str, Any]) -> None:
        """Send a JSON payload to every connected client. Drops dead sockets silently."""
        if not self._connections:
            return
        message = json.dumps(payload, default=str)
        dead: list[WebSocket] = []
        async with self._lock:
            targets = list(self._connections)
        for ws in targets:
            try:
                await ws.send_text(message)
            except Exception:
                dead.append(ws)
        if dead:
            async with self._lock:
                for ws in dead:
                    self._connections.discard(ws)

    @property
    def active_count(self) -> int:
        return len(self._connections)


# Single shared instance used across the whole app
manager = ConnectionManager()
