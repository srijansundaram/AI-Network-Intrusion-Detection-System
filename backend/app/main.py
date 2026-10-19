"""
NIDS Backend — FastAPI entrypoint.

Wires together: REST endpoints (capture, replay, upload, metrics),
a WebSocket for live alert streaming, and startup/shutdown hooks that
load the trained model and cleanly stop any running capture/replay.
"""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import (
    routes_capture,
    routes_metrics,
    routes_predict,
    routes_replay,
    routes_upload,
    routes_ws,
)
from app.capture.live_capture import live_capture
from app.capture.pcap_replay import replay_controller
from app.config import settings
from app.core.logging_config import configure_logging, get_logger
from app.core.websocket_manager import manager
from app.inference.model_loader import load_artifacts
from app.schemas.requests import HealthResponse

configure_logging()
logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting %s ...", settings.app_name)
    try:
        load_artifacts()
    except FileNotFoundError as exc:
        # Don't crash the whole API if the model isn't in place yet — endpoints
        # that need it will error clearly, but /health and docs still work,
        # which is useful while other team members finish the model.
        logger.warning("Model not loaded at startup: %s", exc)

    yield

    logger.info("Shutting down %s ...", settings.app_name)
    await live_capture.stop()
    await replay_controller.stop()


app = FastAPI(title=settings.app_name, lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(routes_capture.router, prefix=settings.api_prefix)
app.include_router(routes_predict.router, prefix=settings.api_prefix)
app.include_router(routes_replay.router, prefix=settings.api_prefix)
app.include_router(routes_upload.router, prefix=settings.api_prefix)
app.include_router(routes_metrics.router, prefix=settings.api_prefix)
app.include_router(routes_ws.router)  # WS path is /ws/alerts, no REST prefix


@app.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    from app.inference import model_loader
    bundle = model_loader._bundle
    is_loaded = bundle is not None and (bundle.rf is not None or bundle.lstm is not None)
    return HealthResponse(
        status="ok",
        model_loaded=is_loaded,
        active_websockets=manager.active_count,
    )


@app.get("/")
async def root() -> dict:
    return {
        "service": settings.app_name,
        "docs": "/docs",
        "health": "/health",
        "websocket": "/ws/alerts",
    }
