"""L2A03, port security threshold.

Addresses are introduced one at a time with a fixed gap, which is the opposite
of an address table overflow: the point is to find the configured limit, not to
exceed the table. The default is 50 at one every 200 milliseconds and the hard
cap of 500 is enforced before the check starts.
"""

from __future__ import annotations

from netcheck.l2 import frames
from netcheck.models import INDETERMINATE, PRESENT
from netcheck.platform import interfaces as interfaces_module

GAP_SECONDS = 0.2
SETTLE_SECONDS = 1.0
# An unassigned link local address, so nothing on the segment has a reason to
# answer these.
TARGET_IP = "169.254.255.254"


def run(context) -> tuple:
    """Introduce addresses one at a time until the port reacts."""
    from netcheck.budget import LAYER2

    limit = min(context.max_macs, context.budget.remaining(LAYER2))
    entry = interfaces_module.interface_named(context.interface)
    before = bool(entry and entry.up)
    context.expect_link_change = True

    sent = 0
    for mac in frames.unique_macs(limit, start=0x1000):
        context.send_frames(frames.arp_probe(mac, TARGET_IP))
        sent += 1
        context.sleeper(GAP_SECONDS)
        entry = interfaces_module.interface_named(context.interface)
        if before and not (entry and entry.up):
            return PRESENT, "L2A03", "the port went down at address %d" % sent

    context.sleeper(SETTLE_SECONDS)
    context.expect_link_change = False
    return (
        INDETERMINATE,
        "L2A03",
        "no reaction after %d addresses. A limit above %d, or a restrict or "
        "protect action that drops silently, both look like this from the port"
        % (sent, sent),
    )
