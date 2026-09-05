"""L2A01 trunk negotiation and L2A07 discovery protocol injection.

Both ask the switch a question and stop there. L2A01 offers to negotiate a trunk
and reports the answer; it never follows up with tagged traffic, so a port that
would have trunked stays an access port.
"""

from __future__ import annotations

from scapy.contrib.dtp import DTP
from scapy.contrib.lldp import LLDPDU, LLDPDUChassisID

from netcheck.l2 import frames, parse
from netcheck.models import ABSENT, INDETERMINATE, PRESENT

LISTEN_SECONDS = 5
PROBE_NAME = "netcheck"
PROBE_PORT_ID = "netcheck-probe"


def run_dtp(context) -> tuple[str, str, str]:
    """L2A01. Send one DTP desirable frame and report whether the port answers."""
    source = frames.probe_mac(1)
    domain = context.capture.trunking[0].domain if context.capture and context.capture.trunking else ""
    replies, sniffer = context.collect(
        LISTEN_SECONDS, lambda pkt: DTP in pkt and pkt.src != source
    )
    context.send_frames(frames.dtp_desirable(source, domain=domain))
    _wait(context, LISTEN_SECONDS, sniffer)

    if not replies:
        return (
            PRESENT,
            "L2A01",
            "no DTP answer within %d seconds of a desirable offer" % LISTEN_SECONDS,
        )
    record = parse.parse_dtp(replies[0])
    return ABSENT, "L2A01", "the port answered DTP, mode %s" % record.mode


def run_lldp_injection(context) -> tuple[str, str, str]:
    """L2A07. Send one LLDP frame and check whether it comes back to the port."""
    source = frames.probe_mac(7)
    replies, sniffer = context.collect(
        LISTEN_SECONDS,
        lambda pkt: (
            LLDPDU in pkt
            and pkt.src != source
            and LLDPDUChassisID in pkt
            and str(pkt[LLDPDUChassisID].id) == source
        ),
    )
    context.send_frames(frames.lldp_probe(source, PROBE_NAME, PROBE_PORT_ID))
    _wait(context, LISTEN_SECONDS, sniffer)

    if replies:
        return ABSENT, "L2A07", "an injected LLDP identity came back to the port"
    return (
        INDETERMINATE,
        "L2A07",
        "the injected frame was not reflected. The switch may still have accepted "
        "it into its neighbour table, which cannot be seen from this port",
    )


def _wait(context, seconds: float, sniffer) -> None:
    context.sleeper(seconds)
    sniffer.stop()
