"""L3A13, anti-spoofing.

Two directions, reported together. A packet with a source outside the local
prefix sent to the external observer tests egress filtering; a packet with an
external source sent to the internal observer tests the ingress side.

Arrival is the only evidence. A local timeout does not distinguish a filter from
a dead host, so without an observer this returns INDETERMINATE.
"""

from __future__ import annotations

from netcheck.l2.frames import new_marker
from netcheck.l3 import packets
from netcheck.models import (
    ABSENT,
    HIGH,
    INDETERMINATE,
    NO_OBSERVER,
    PREREQUISITE_MISSING,
    PRESENT,
    UNTESTED,
    Finding,
)

CONTROL = "Anti-spoofing"
OBSERVER_SECONDS = 6


def run(context):
    """Send one forged packet outward and report whether it arrived."""
    config = context.config
    test_host = (config.external.get("test_host", "") if config else "")
    if not test_host:
        return UNTESTED, "L3A13", "%s: no external.test_host configured" % PREREQUISITE_MISSING, []
    target = context.resolve(test_host)
    if not target:
        return (
            UNTESTED, "L3A13",
            "%s: external.test_host %r does not resolve" % (PREREQUISITE_MISSING, test_host),
            [],
        )

    marker = new_marker()
    context.send_packets(packets.spoofed(target, marker))

    observer = config.external_observer if config else ""
    if not observer:
        return (
            INDETERMINATE, "L3A13",
            "%s: one packet with a source outside this network was sent to %s. "
            "Whether it left cannot be seen from the sending side"
            % (NO_OBSERVER, target),
            [],
        )

    arrived = context.ask_observer(marker, OBSERVER_SECONDS, observer)
    if arrived is None:
        return (
            INDETERMINATE, "L3A13",
            "the observer at %s did not answer, so delivery is unknown" % observer,
            [],
        )
    if arrived:
        return (
            ABSENT, "L3A13",
            "a packet with a source outside this network reached the external "
            "observer, so egress source filtering is not applied",
            [
                Finding(HIGH, "L3A13",
                        "Spoofed source addresses leave this network, so it can be "
                        "used in a reflection attack",
                        "asking the ISP to apply BCP38, or filtering on the router")
            ],
        )
    return PRESENT, "L3A13", "the forged source packet did not reach the observer", []
