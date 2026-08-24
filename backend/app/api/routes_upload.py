"""
PCAP file upload endpoint: accepts an uploaded .pcap/.pcapng file, feeds it
through the same feature-extraction + inference pipeline used by live
capture and replay, and returns a summary (also broadcasting per-flow
alerts over the WebSocket as they're found).
"""
from __future__ import annotations

import time
import uuid
from pathlib import Path

from fastapi import APIRouter, HTTPException, UploadFile, File

from app.capture.pipeline import process_pcap_file
from app.config import settings
from app.core.logging_config import get_logger
from app.metrics.tracker import upload_metrics
from app.schemas.requests import UploadResponse

router = APIRouter(prefix="/upload", tags=["upload"])
logger = get_logger(__name__)

ALLOWED_SUFFIXES = {".pcap", ".pcapng", ".cap"}
MAX_UPLOAD_BYTES = 500 * 1024 * 1024  # 500MB


@router.post("", response_model=UploadResponse)
async def upload_pcap(file: UploadFile = File(...)) -> UploadResponse:
    suffix = Path(file.filename or "").suffix.lower()
    if suffix not in ALLOWED_SUFFIXES:
        raise HTTPException(status_code=400, detail=f"Unsupported file type '{suffix}'. Expected one of {ALLOWED_SUFFIXES}")

    dest_path = settings.upload_dir / f"{uuid.uuid4().hex}_{Path(file.filename).name}"

    size = 0
    t0 = time.perf_counter()
    with open(dest_path, "wb") as out:
        while chunk := await file.read(1024 * 1024):
            size += len(chunk)
            if size > MAX_UPLOAD_BYTES:
                out.close()
                dest_path.unlink(missing_ok=True)
                raise HTTPException(status_code=413, detail="File too large (max 500MB)")
            out.write(chunk)

    try:
        summary = await process_pcap_file(dest_path, "upload", upload_metrics)
    except Exception as exc:
        logger.exception("Failed to process uploaded pcap")
        raise HTTPException(status_code=500, detail=f"Feature extraction/inference failed: {exc}") from exc
    finally:
        # Keep the raw upload around under pcap_dir if you want it replayable;
        # here we move it there instead of deleting it outright.
        archived = settings.pcap_dir / dest_path.name
        if dest_path.exists():
            dest_path.rename(archived)

    elapsed_ms = (time.perf_counter() - t0) * 1000.0

    return UploadResponse(
        filename=file.filename or dest_path.name,
        flows_processed=summary["flows_processed"],
        malicious_flows=summary["malicious_flows"],
        benign_flows=summary["benign_flows"],
        processing_time_ms=elapsed_ms,
    )
