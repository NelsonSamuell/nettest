"""L2A05, Dynamic ARP Inspection.

One gratuitous ARP for one address the operator has confirmed unused. The check
refuses unless that address is supplied, does not answer a liveness check, and
did not appear in the passive capture, because announcing an address that is in
use is the one way this could disturb a host.

There is no repetition, no reply handling and no forwarding. The tool announces
once and asks a consenting observer on the segment whether the announcement
arrived. Without an observer the result is INDETERMINATE, because nothing
observable happens at the sending port either way.
"""

from __future__ import annotations

from scapy.layers.l2 import ARP

from netcheck.l2 import frames
from netcheck.models import ABSENT, INDETERMINATE, NO_OBSERVER, PREREQUISITE_MISSING, PRESENT, UNTESTED

LIVENESS_SECONDS = 3
OBSERVER_SECONDS = 5


def run(context) -> tuple:
    """Announce one unused address and ask an observer whether it arrived."""
    address = context.test_ip
    if not address:
        return (
            UNTESTED,
            "L2A05",
            "%s: --test-ip is required and must be an address confirmed unused"
            % PREREQUISITE_MISSING,
        )
    if context.capture and address in context.capture.observed_ips():
        return (
            UNTESTED,
            "L2A05",
            "%s: %s appeared in the passive capture, so it is not unused"
            % (PREREQUISITE_MISSING, address),
        )

    source = frames.probe_mac(5)
    replies, sniffer = context.collect(
        LIVENESS_SECONDS,
        lambda pkt: ARP in pkt and pkt[ARP].op == 2 and pkt[ARP].psrc == address,
    )
    context.send_frames(frames.arp_probe(source, address))
    context.sleeper(LIVENESS_SECONDS)
    sniffer.stop()
    if replies:
        return (
            UNTESTED,
            "L2A05",
            "%s: %s answered a liveness check, so it is in use"
            % (PREREQUISITE_MISSING, address),
        )

    context.send_frames(frames.gratuitous_arp(source, address))

    if not context.observer:
        return (
            INDETERMINATE,
            "L2A05",
            "%s: one announcement for %s was sent, but whether it crossed the "
            "switch cannot be seen from the sending port" % (NO_OBSERVER, address),
        )

    seen = context.ask_observer("ARP:" + address, OBSERVER_SECONDS)
    if seen is None:
        return (
            INDETERMINATE,
            "L2A05",
            "the observer at %s did not answer, so delivery is unknown" % context.observer,
        )
    if seen:
        return ABSENT, "L2A05", "the observer saw an unsolicited claim for %s" % address
    return PRESENT, "L2A05", "the observer did not see the claim for %s" % address
