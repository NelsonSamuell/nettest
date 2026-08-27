"""L2A02 BPDU Guard verification.

Why this probe cannot change the topology
-----------------------------------------

A spanning tree root election compares bridge identifiers, and a bridge
identifier is the two byte priority field followed by the bridge MAC address.
The priority is compared first and lower wins, so a bridge advertising a
numerically higher priority loses to the current root no matter what MAC it
carries. There is no tie to break and no path cost that can rescue it.

So the probe reads the root priority observed passively, asks
:func:`l2check.frames.worse_bridge_priority` for the next valid priority
strictly above it, and advertises that. A switch that processes the frame keeps
the root it already has. The topology change flag is left clear, so the frame
cannot trigger a CAM flush either.

That safety property depends entirely on knowing the current root priority. If
the passive capture never saw a BPDU, there is no value to be worse than, and
the probe refuses to run rather than guessing. Guessing 61440 would usually be
safe and would be wrong the one time it was not.

What the probe then measures is the switch's reaction, not the network's: BPDU
Guard err-disables a port the instant any BPDU arrives on it, so the link going
down is the positive result.
"""

from __future__ import annotations

import time

from l2check import frames, posture
from l2check.authorisation import ActiveSession, link_state
from l2check.frames import UnsafeFrameError
from l2check.models import Capture
from l2check.posture import ABSENT, PRESENT, UNTESTED, ProbeResult

WATCH_SECONDS = 15
POLL_SECONDS = 0.5
DOWN_STATES = ("down", "lowerlayerdown", "notpresent")


def run(session: ActiveSession, capture: Capture) -> ProbeResult:
    """L2A02. Send one losing BPDU and watch for the port being err-disabled."""
    observed = capture.observed_root_priority()
    try:
        frame = frames.bpdu_losing_config(observed, frames.probe_mac(2))
    except UnsafeFrameError as error:
        return ProbeResult(
            "L2A02",
            posture.BPDU_GUARD,
            UNTESTED,
            "L2A02 refused",
            "%s; run a passive capture that sees a BPDU first" % error,
        )

    before = link_state(session.interface)
    # The reaction being measured is the link dropping, so the session must not
    # treat that as the unexpected link change that halts the run.
    session.link_change_expected = True
    session.send(frame)

    deadline = time.monotonic() + WATCH_SECONDS
    while time.monotonic() < deadline:
        time.sleep(POLL_SECONDS)
        current = link_state(session.interface)
        if current != before and current in DOWN_STATES:
            return ProbeResult(
                "L2A02",
                posture.BPDU_GUARD,
                PRESENT,
                "L2A02 active probe",
                "the port went %s within %.1f seconds of one BPDU, which is a "
                "BPDU Guard err-disable"
                % (current, WATCH_SECONDS - (deadline - time.monotonic())),
                frames_sent=1,
            )

    session.link_change_expected = False
    return ProbeResult(
        "L2A02",
        posture.BPDU_GUARD,
        ABSENT,
        "L2A02 active probe",
        "the link stayed %s for %d seconds after a BPDU with priority %d, worse "
        "than the observed root priority %d"
        % (before, WATCH_SECONDS, frames.worse_bridge_priority(observed), observed),
        frames_sent=1,
    )
