"""L2A03 port security threshold.

Addresses are introduced one at a time with a fixed gap, which is the opposite
of a CAM overflow: the point is to find the configured limit, not to exceed the
table. The default is 50 addresses at one every 200 milliseconds, and the hard
cap of 500 is enforced by the gate before the probe starts.
"""

from __future__ import annotations

import time

from l2check import frames, posture
from l2check.authorisation import ActiveSession, link_state
from l2check.models import Capture
from l2check.posture import INDETERMINATE, PRESENT, ProbeResult

GAP_SECONDS = 0.2
SETTLE_SECONDS = 1.0
DOWN_STATES = ("down", "lowerlayerdown", "notpresent")
# ARP probes are addressed to an unassigned link local address, so nothing on
# the segment has any reason to answer them.
TARGET_IP = "169.254.255.254"


def run(session: ActiveSession, capture: Capture) -> ProbeResult:
    """L2A03. Introduce MAC addresses one at a time until the port reacts."""
    limit = min(session.max_macs, session.frames_remaining)
    before = link_state(session.interface)
    session.link_change_expected = True

    sent = 0
    for mac in frames.unique_macs(limit, start=0x1000):
        session.send(frames.arp_probe(mac, TARGET_IP))
        sent += 1
        time.sleep(GAP_SECONDS)
        current = link_state(session.interface)
        if current != before and current in DOWN_STATES:
            return ProbeResult(
                "L2A03",
                posture.PORT_SECURITY,
                PRESENT,
                "L2A03 active probe",
                "the port went %s at address %d" % (current, sent),
                frames_sent=sent,
            )

    time.sleep(SETTLE_SECONDS)
    session.link_change_expected = False
    return ProbeResult(
        "L2A03",
        posture.PORT_SECURITY,
        INDETERMINATE,
        "L2A03 active probe",
        "no reaction after %d addresses; a limit above %d, or a restrict or "
        "protect action that drops silently, both look like this from the port"
        % (sent, sent),
        frames_sent=sent,
    )
