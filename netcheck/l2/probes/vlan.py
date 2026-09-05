"""L2A06, double tagging reachability.

Three ICMP echo requests carrying two 802.1Q tags. The outer tag is the native
VLAN of the trunk, which is what makes the first tag get stripped and the frame
appear on the inner VLAN; the payload is a marker and nothing else.

The attack is one way by construction, so no reply is expected and a silent port
proves nothing. Success is only ever reported when a consenting observer on the
target segment confirms the marker arrived. Without one the result is
INDETERMINATE, and no negative is claimed.
"""

from __future__ import annotations

from netcheck.l2 import frames
from netcheck.models import ABSENT, INDETERMINATE, NO_OBSERVER, PREREQUISITE_MISSING, PRESENT, UNTESTED

FRAME_COUNT = 3
DEFAULT_NATIVE_VLAN = 1
OBSERVER_SECONDS = 5
SOURCE_IP = "0.0.0.0"


def native_vlan(capture) -> int:
    """The outer tag, from CDP if it disclosed a native VLAN."""
    if capture is not None:
        for record in capture.discovery:
            if record.native_vlan is not None:
                return record.native_vlan
    return DEFAULT_NATIVE_VLAN


def run(context) -> tuple[str, str, str]:
    """Send three double tagged echo requests toward the target VLAN."""
    target_vlan = getattr(context, "target_vlan", None)
    if target_vlan is None:
        return UNTESTED, "L2A06", "%s: no target VLAN supplied" % PREREQUISITE_MISSING
    if not context.test_ip:
        return (
            UNTESTED,
            "L2A06",
            "%s: --test-ip is required as the address inside the target VLAN"
            % PREREQUISITE_MISSING,
        )

    outer = native_vlan(context.capture)
    if outer == target_vlan:
        return (
            UNTESTED,
            "L2A06",
            "%s: the target VLAN %d is the native VLAN, so a double tagged frame "
            "has nowhere to hop to" % (PREREQUISITE_MISSING, outer),
        )

    marker = frames.new_marker()
    frame = frames.double_tagged_icmp(
        frames.probe_mac(6), "ff:ff:ff:ff:ff:ff", outer, target_vlan,
        SOURCE_IP, context.test_ip, marker,
    )
    context.send_frames([frame] * FRAME_COUNT)

    if not context.observer:
        return (
            INDETERMINATE,
            "L2A06",
            "%s: %d frames tagged %d inside %d were sent. One way delivery cannot "
            "be confirmed from the sending side"
            % (NO_OBSERVER, FRAME_COUNT, target_vlan, outer),
        )

    seen = context.ask_observer(marker, OBSERVER_SECONDS)
    if seen is None:
        return (
            INDETERMINATE,
            "L2A06",
            "the observer at %s did not answer, so delivery is unknown" % context.observer,
        )
    if seen:
        return (
            ABSENT,
            "L2A06",
            "the observer on VLAN %d received a frame sent from this port through "
            "native VLAN %d" % (target_vlan, outer),
        )
    return PRESENT, "L2A06", "the observer on VLAN %d saw nothing" % target_vlan
