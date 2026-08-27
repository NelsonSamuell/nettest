"""Passive capture.

Listens on one interface for a fixed duration and parses what arrives. It never
transmits, and it never keeps a frame: scapy is told store=False, so each packet
is dissected into metadata by :mod:`l2check.parse` and then discarded. Nothing
in this module can write a payload to disk.
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable

from scapy.sendrecv import sniff

from l2check import wireless
from l2check.models import Capture
from l2check.parse import parse_frame

DEFAULT_DURATION = 120


def interface_mac(interface: str) -> str:
    """Return the interface's own MAC, used to tell our traffic from a peer's."""
    path = Path("/sys/class/net") / interface / "address"
    if not path.exists():
        return ""
    return path.read_text().strip().lower()


def interface_cidr(interface: str) -> str:
    """Return the interface's IPv4 address in CIDR form, or an empty string."""
    from scapy.arch import get_if_addr
    from scapy.config import conf

    address = get_if_addr(interface)
    if not address or address == "0.0.0.0":
        return ""
    for route in conf.route.routes:
        network, netmask, _, iface, _, _ = route
        if iface == interface and netmask not in (0, 0xFFFFFFFF) and network:
            bits = bin(netmask).count("1")
            return "%s/%d" % (address, bits)
    return "%s/24" % address


def capture(
    interface: str,
    duration: int = DEFAULT_DURATION,
    stop_filter: Callable[[object], bool] | None = None,
) -> Capture:
    """Listen on interface for duration seconds and return the metadata seen."""
    if duration <= 0:
        raise ValueError("duration must be positive")
    result = Capture(interface=interface, duration=duration)
    own = interface_mac(interface)
    if own:
        result.local_macs.add(own)
    # Read-only, sends nothing, and returns None on a wired interface.
    result.wireless = wireless.read_link(interface)
    sniff(
        iface=interface,
        timeout=duration,
        store=False,
        prn=lambda packet: parse_frame(packet, result),
        stop_filter=stop_filter,
    )
    return result
