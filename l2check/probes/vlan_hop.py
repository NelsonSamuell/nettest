"""L2A06 double tagging reachability.

Three ICMP echo requests carrying two 802.1Q tags. The outer tag is the native
VLAN of the trunk, which is what makes the first tag get stripped and the frame
appear on the inner VLAN; the payload is a marker and nothing else.

The attack is one way by construction, so no reply is expected and a silent port
proves nothing. Success is only ever reported when a consenting observer on the
target segment confirms the marker arrived. Without one the result is
INDETERMINATE, and the probe does not claim a negative.
"""

from __future__ import annotations

from l2check import frames, posture
from l2check.session import ActiveSession
from l2check.models import Capture
from l2check.observe import ask_observer
from l2check.posture import ABSENT, INDETERMINATE, PRESENT, UNTESTED, ProbeResult

FRAME_COUNT = 3
DEFAULT_NATIVE_VLAN = 1
OBSERVER_SECONDS = 5
SOURCE_IP = "0.0.0.0"


def _refused(detail: str) -> ProbeResult:
    return ProbeResult("L2A06", posture.VLAN_PRUNING, UNTESTED, "L2A06 refused", detail)


def native_vlan(capture: Capture) -> int:
    """The native VLAN to use as the outer tag, from CDP if it disclosed one."""
    for record in capture.discovery:
        if record.native_vlan is not None:
            return record.native_vlan
    return DEFAULT_NATIVE_VLAN


def run(session: ActiveSession, capture: Capture) -> ProbeResult:
    """L2A06. Send three double tagged echo requests toward the target VLAN."""
    if session.target_vlan is None:
        return _refused("--target-vlan is required")
    if not session.test_ip:
        return _refused("--test-ip is required as the address inside the target VLAN")

    outer = native_vlan(capture)
    if outer == session.target_vlan:
        return _refused(
            "the target VLAN %d is the native VLAN, so a double tagged frame has "
            "nowhere to hop to" % outer
        )

    marker = frames.new_marker()
    batch = [
        frames.double_tagged_icmp(
            frames.probe_mac(6),
            "ff:ff:ff:ff:ff:ff",
            outer,
            session.target_vlan,
            SOURCE_IP,
            session.test_ip,
            marker,
        )
    ] * FRAME_COUNT
    session.send(batch)

    if not session.observer:
        return ProbeResult(
            "L2A06",
            posture.VLAN_PRUNING,
            INDETERMINATE,
            "L2A06, no observer supplied",
            "%d frames tagged %d inside %d were sent toward %s; one way delivery "
            "cannot be confirmed from the sending side"
            % (FRAME_COUNT, session.target_vlan, outer, session.test_ip),
            frames_sent=FRAME_COUNT,
        )

    seen = ask_observer(session.observer, marker, timeout=OBSERVER_SECONDS)
    if seen is None:
        return ProbeResult(
            "L2A06",
            posture.VLAN_PRUNING,
            INDETERMINATE,
            "L2A06, observer unreachable",
            "the observer at %s did not answer, so delivery is unknown" % session.observer,
            frames_sent=FRAME_COUNT,
        )
    if seen:
        return ProbeResult(
            "L2A06",
            posture.VLAN_PRUNING,
            ABSENT,
            "L2A06 active probe",
            "the observer on VLAN %d received a frame sent from this port through "
            "native VLAN %d" % (session.target_vlan, outer),
            frames_sent=FRAME_COUNT,
        )
    return ProbeResult(
        "L2A06",
        posture.VLAN_PRUNING,
        PRESENT,
        "L2A06 active probe",
        "the observer on VLAN %d saw nothing from this port" % session.target_vlan,
        frames_sent=FRAME_COUNT,
    )
