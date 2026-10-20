"""
Live packet capture from a network interface using Scapy's AsyncSniffer.

Design: rather than doing per-packet flow reconstruction ourselves, we let
Scapy sniff into a rolling pcap file on disk in fixed-size time windows, then
hand each completed window off to the shared pipeline (which uses
CICFlowMeter for the actual flow assembly + feature extraction). This keeps
one codepath for feature extraction across live/replay/upload and avoids
duplicating CICFlowMeter's flow-timeout logic.

Requires elevated privileges (root, or CAP_NET_RAW/CAP_NET_ADMIN) to sniff.
"""
from __future__ import annotations

import asyncio
import time
import uuid
from pathlib import Path

from scapy.all import AsyncSniffer, wrpcap

from app.utils.network_interface import pick_interface
from app.capture.pipeline import process_pcap_file
from app.config import settings
from app.core.logging_config import get_logger
from app.core.websocket_manager import manager
from app.metrics.tracker import live_metrics
from app.schemas.alerts import StatusMessage

logger = get_logger(__name__)


class LiveCaptureController:
    """Singleton-style controller — start/stop live capture from the API layer."""

    def __init__(self) -> None:
        self._sniffer: AsyncSniffer | None = None
        self._interface: str | None = None
        self._packet_count = 0
        self._flush_task: asyncio.Task | None = None
        self._running = False
        self._buffer: list = []
        self._buffer_lock = asyncio.Lock()

    @property
    def running(self) -> bool:
        return self._running

    @property
    def interface(self) -> str | None:
        return self._interface

    @property
    def packets_captured(self) -> int:
        return self._packet_count

    def _on_packet(self, packet) -> None:
        self._packet_count += 1
        # AsyncSniffer's prn callback runs in a background thread, not the
        # event loop — so just buffer; the flush loop (on the event loop)
        # periodically drains this list.
        self._buffer.append(packet)

    async def start(self, interface: str | None = None, bpf_filter: str | None = None) -> None:
        if self._running:
            raise RuntimeError("Live capture is already running")

        self._interface = interface or pick_interface() or settings.default_interface
        self._packet_count = 0
        self._buffer = []

        self._sniffer = AsyncSniffer(
            iface=self._interface,
            filter=bpf_filter,
            prn=self._on_packet,
            store=False,
        )
        self._sniffer.start()
        self._running = True
        self._flush_task = asyncio.create_task(self._flush_loop())

        logger.info("Live capture started on interface=%s", self._interface)
        await manager.broadcast(
            StatusMessage(source="live", state="started", detail=f"interface={self._interface}").model_dump()
        )

    async def stop(self) -> None:
        if not self._running:
            return
        self._running = False

        if self._sniffer is not None:
            self._sniffer.stop()
            self._sniffer = None

        if self._flush_task is not None:
            self._flush_task.cancel()
            self._flush_task = None

        logger.info("Live capture stopped. Total packets captured=%d", self._packet_count)
        await manager.broadcast(
            StatusMessage(source="live", state="stopped", detail=f"total_packets={self._packet_count}").model_dump()
        )

    async def _flush_loop(self) -> None:
        """Every flow_flush_interval_sec, write buffered packets to a pcap and
        run them through the feature extraction + inference pipeline."""
        try:
            while self._running:
                await asyncio.sleep(settings.flow_flush_interval_sec)
                async with self._buffer_lock:
                    packets, self._buffer = self._buffer, []

                if not packets:
                    continue

                pcap_path = settings.pcap_dir / f"live_{uuid.uuid4().hex}.pcap"
                await asyncio.to_thread(wrpcap, str(pcap_path), packets)

                try:
                    summary = await process_pcap_file(pcap_path, "live", live_metrics)
                    logger.info("Live window processed: %s", summary)
                except Exception:
                    logger.exception("Failed to process live capture window")
                finally:
                    pcap_path.unlink(missing_ok=True)
        except asyncio.CancelledError:
            pass


live_capture = LiveCaptureController()
