"""
Utility for auto‑selecting a live‑capture network interface on Windows.

The function `pick_interface()` returns the name of the interface that
should be used by the capture service.  It prefers Ethernet → Wi‑Fi →
USB‑tethering, but will gracefully fall back to any active adapter.
"""
import psutil
from typing import Optional


def _is_up(iface: str) -> bool:
    """True if the interface is up and has at least one IPv4 address."""
    stats = psutil.net_if_stats().get(iface)
    if not stats or not stats.isup:
        return False
    addrs = psutil.net_if_addrs().get(iface, [])
    return any(a.family == psutil.AF_LINK or a.family == psutil.AF_INET for a in addrs)


def _score_iface(name: str) -> int:
    """
    Higher score → higher priority.
    * Ethernet → 30
    * Wi‑Fi   → 20
    * USB‑tether (contains a digit) → 10
    * Anything else → 0
    """
    lname = name.lower()
    if "ethernet" in lname:
        return 30
    if "wi‑fi" in lname or "wifi" in lname or "wireless" in lname:
        return 20
    if any(ch.isdigit() for ch in name):
        return 10
    return 0


def pick_interface() -> Optional[str]:
    """
    Return the best interface name, or None if none are up.
    """
    candidates = [i for i in psutil.net_if_addrs() if _is_up(i)]
    if not candidates:
        return None

    # Sort by our priority score (desc) then alphabetically for determinism
    candidates.sort(key=lambda n: (-_score_iface(n), n))
    return candidates[0]