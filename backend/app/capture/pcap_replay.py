"""
PCAP replay pipeline (E8): plays back a pre-recorded pcap file as simulated
live traffic, respecting (or scaling) original inter-packet timing, and feeds
the same rolling-window pipeline used by live capture.
"""
from __future__ import annotations

import asyncio
import uuid
from pathlib import Path

from scapy.all import PcapReader, wrpcap

from app.capture.pipeline import process_pcap_file
from app.config import settings
from app.core.logging_config import get_logger
from app.core.websocket_manager import manager
from app.metrics.tracker import replay_metrics
from app.schemas.alerts import StatusMessage

logger = get_logger(__name__)


class ReplayController:
    def __init__(self) -> None:
        self._running = False
        self._task: asyncio.Task | None = None
        self._filename: str | None = None
        self._packets_replayed = 0

    @property
    def running(self) -> bool:
        return self._running

    @property
    def filename(self) -> str | None:
        return self._filename

    @property
    def packets_replayed(self) -> int:
        return self._packets_replayed

    async def start(self, filename: str, speed: float = 1.0, loop: bool = False) -> None:
        if self._running:
            raise RuntimeError("A replay is already running")

        pcap_path = settings.pcap_dir / filename
        if not pcap_path.exists():
            raise FileNotFoundError(f"pcap not found: {pcap_path}")

        self._filename = filename
        self._packets_replayed = 0
        self._running = True
        self._task = asyncio.create_task(self._run(pcap_path, speed, loop))

        logger.info("Replay started: file=%s speed=%.2fx loop=%s", filename, speed, loop)
        await manager.broadcast(
            StatusMessage(source="replay", state="started", detail=f"file={filename} speed={speed}x").model_dump()
        )

    async def stop(self) -> None:
        if not self._running:
            return
        self._running = False
        if self._task is not None:
            self._task.cancel()
            self._task = None
        logger.info("Replay stopped. Packets replayed=%d", self._packets_replayed)
        await manager.broadcast(
            StatusMessage(source="replay", state="stopped", detail=f"total_packets={self._packets_replayed}").model_dump()
        )

    async def _run(self, pcap_path: Path, speed: float, loop: bool) -> None:
        try:
            while True:
                await self._replay_once(pcap_path, speed)
                if not loop or not self._running:
                    break
            self._running = False
            await manager.broadcast(StatusMessage(source="replay", state="completed").model_dump())
        except asyncio.CancelledError:
            pass
        except Exception:
            logger.exception("Replay failed")
            self._running = False
            await manager.broadcast(StatusMessage(source="replay", state="error").model_dump())

    async def _replay_once(self, pcap_path: Path, speed: float) -> None:
        buffer: list = []
        last_ts: float | None = None
        window_start = asyncio.get_event_loop().time()

        with PcapReader(str(pcap_path)) as reader:
            for packet in reader:
                if not self._running:
                    return

                pkt_ts = float(packet.time)
                if last_ts is not None:
                    delay = (pkt_ts - last_ts) / max(speed, 1e-6)
                    if delay > 0:
                        await asyncio.sleep(min(delay, 2.0))  # cap pathological gaps
                last_ts = pkt_ts

                buffer.append(packet)
                self._packets_replayed += 1

                now = asyncio.get_event_loop().time()
                if now - window_start >= settings.flow_flush_interval_sec:
                    await self._flush(buffer)
                    buffer = []
                    window_start = now

        if buffer:
            await self._flush(buffer)

    async def _flush(self, packets: list) -> None:
        if not packets:
            return
        chunk_path = settings.pcap_dir / f"replay_{uuid.uuid4().hex}.pcap"
        await asyncio.to_thread(wrpcap, str(chunk_path), packets)
        try:
            summary = await process_pcap_file(chunk_path, "replay", replay_metrics)
            logger.info("Replay window processed: %s", summary)
        except Exception:
            logger.exception("Failed to process replay window")
        finally:
            chunk_path.unlink(missing_ok=True)


replay_controller = ReplayController()
