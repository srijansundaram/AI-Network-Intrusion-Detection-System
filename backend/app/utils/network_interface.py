
"""
Utility for auto-selecting a live-capture network interface on Windows.
Prefers Ethernet → Wi-Fi → USB tethering, then other active adapters.
"""

import psutil
import socket
from typing import Optional


def _is_up(iface: str) -> bool:
    """True if the interface is up and has an IPv4 address."""
    stats = psutil.net_if_stats().get(iface)
    if not stats or not stats.isup:
        return False

    addrs = psutil.net_if_addrs().get(iface, [])
    return any(
        a.family == socket.AF_INET
        for a in addrs
    )


def _score_iface(name: str) -> int:
    """Higher score means higher priority."""
    lname = name.lower()

    if "ethernet" in lname:
        return 30
    if "wi-fi" in lname or "wifi" in lname or "wireless" in lname:
        return 20
    if any(ch.isdigit() for ch in name):
        return 10

    return 0


def pick_interface() -> Optional[str]:
    """Return the best active interface name, or None."""
    candidates = [
        iface for iface in psutil.net_if_addrs()
        if _is_up(iface)
    ]

    if not candidates:
        return None

    candidates.sort(key=lambda n: (-_score_iface(n), n))
    return candidates[0]
