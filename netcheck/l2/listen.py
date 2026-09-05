"""Passive layer 2 capture.

Transmits nothing. Each frame is dissected into metadata and discarded, so
nothing accumulates and no payload reaches disk.
"""

from __future__ import annotations

from netcheck.l2.parse import Capture, parse_frame
from netcheck.platform.sockets import capture_frames

DEFAULT_DURATION = 120


def listen(interface: str, duration: int = DEFAULT_DURATION) -> Capture:
    """Watch one interface for a fixed time and return what was seen."""
    if duration <= 0:
        raise ValueError("duration must be positive")
    capture = Capture(interface=interface, duration=duration)
    capture_frames(interface, duration, lambda frame: parse_frame(frame, capture))
    return capture
