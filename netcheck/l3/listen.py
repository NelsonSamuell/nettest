"""Layer 3 passive capture.

There is no second socket. The layer 2 capture loop dispatches into the layer 3
parsers, so one pass over the wire feeds both.
"""

from __future__ import annotations

from netcheck.l2.listen import listen as listen_l2
from netcheck.models import Capture
from netcheck.platform import interfaces as interfaces_module


def listen(interface: str, duration: int) -> Capture:
    """Watch one interface and return both layers of metadata."""
    capture = listen_l2(interface, duration)
    capture.local_network = interfaces_module.local_network(interface)
    return capture
