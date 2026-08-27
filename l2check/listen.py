"""Passive capture.

Listens on one interface for a fixed duration and parses what arrives. It never
transmits, and it never keeps a frame: scapy is told store=False, so each packet
is dissected into metadata by :mod:`l2check.parse` and then discarded. Nothing
in this module can write a payload to disk.
"""

from __future__ import annotations

from typing import Callable

from scapy.sendrecv import sniff

from l2check.models import Capture
from l2check.parse import parse_frame

DEFAULT_DURATION = 120


def capture(
    interface: str,
    duration: int = DEFAULT_DURATION,
    stop_filter: Callable[[object], bool] | None = None,
) -> Capture:
    """Listen on interface for duration seconds and return the metadata seen."""
    if duration <= 0:
        raise ValueError("duration must be positive")
    result = Capture(interface=interface, duration=duration)
    sniff(
        iface=interface,
        timeout=duration,
        store=False,
        prn=lambda packet: parse_frame(packet, result),
        stop_filter=stop_filter,
    )
    return result
