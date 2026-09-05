"""L2A02, BPDU Guard verification.

Why this check cannot change the topology
-----------------------------------------

A spanning tree root election compares bridge identifiers, and a bridge
identifier is the two byte priority field followed by the bridge address. The
priority is compared first and lower wins, so a bridge advertising a numerically
higher priority loses to the current root whatever address it carries. There is
no tie to break and no path cost that can rescue it.

So the check reads the root priority L2P03 observed, asks
:func:`netcheck.l2.frames.worse_bridge_priority` for the next valid priority
strictly above it, and advertises that. A switch that processes the frame keeps
the root it already has. The topology change flag is left clear, so the frame
cannot trigger an address table flush either.

That safety property depends entirely on knowing the current root priority. If
the passive capture never saw a BPDU there is no value to be worse than, and the
check refuses to run rather than guess. Guessing the worst valid priority would
usually be safe, and would be wrong the one time it was not.

What is then measured is the switch's reaction, not the network's: BPDU Guard
err-disables a port the instant any BPDU arrives on it, so the link going down
is the positive result.
"""

from __future__ import annotations

from netcheck.l2 import frames
from netcheck.l2.frames import UnsafeFrameError
from netcheck.models import ABSENT, PREREQUISITE_MISSING, PRESENT, UNTESTED
from netcheck.platform import interfaces as interfaces_module

WATCH_SECONDS = 15
POLL_SECONDS = 0.5

CONTROL = "BPDU Guard"
IDENTIFIER = "L2A02"


def run(context) -> tuple[str, str, str]:
    """Send one losing BPDU and watch for the port being err-disabled."""
    observed = context.capture.observed_root_priority() if context.capture else None
    try:
        frame = frames.bpdu_losing_config(observed, frames.probe_mac(2))
    except UnsafeFrameError as error:
        return UNTESTED, IDENTIFIER, "%s: %s" % (PREREQUISITE_MISSING, error)

    entry = interfaces_module.interface_named(context.interface)
    before = bool(entry and entry.up)
    # The reaction being measured is the link dropping, so the abort watcher
    # must not treat it as the unexpected change that halts the run.
    context.expect_link_change = True
    context.send_frames(frame)

    deadline = context.clock() + WATCH_SECONDS
    while context.clock() < deadline:
        context.sleeper(POLL_SECONDS)
        entry = interfaces_module.interface_named(context.interface)
        if before and not (entry and entry.up):
            return (
                PRESENT,
                IDENTIFIER,
                "the port went down within %d seconds of one BPDU, which is a "
                "BPDU Guard err-disable" % WATCH_SECONDS,
            )

    context.expect_link_change = False
    return (
        ABSENT,
        IDENTIFIER,
        "the link stayed up for %d seconds after a BPDU with priority %d, worse "
        "than the observed root priority %d"
        % (WATCH_SECONDS, frames.worse_bridge_priority(observed), observed),
    )
