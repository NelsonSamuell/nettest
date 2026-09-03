"""L2A01 dynamic trunking negotiation and L2A07 discovery protocol injection.

Both probes ask the switch a question and stop there. L2A01 offers to negotiate
a trunk and reports the answer; it never follows up with tagged traffic, so a
port that would have trunked stays an access port. L2A07 announces a benign
LLDP identity with a short TTL and looks for it coming back.
"""

from __future__ import annotations

from scapy.contrib.dtp import DTP
from scapy.contrib.lldp import LLDPDU, LLDPDUChassisID
from scapy.layers.l2 import Ether

from l2check import frames, parse, posture
from l2check.session import ActiveSession
from l2check.models import Capture
from l2check.posture import ABSENT, INDETERMINATE, PRESENT, ProbeResult
from l2check.probes import listen_after_send

LISTEN_SECONDS = 5
PROBE_CHASSIS = "l2check"
PROBE_PORT_ID = "l2check-probe"


def run_dtp(session: ActiveSession, capture: Capture) -> ProbeResult:
    """L2A01. Send one DTP desirable frame and report whether the port answers."""
    source = frames.probe_mac(1)
    domain = capture.dtp[0].domain if capture.dtp else ""
    replies = listen_after_send(
        session,
        [frames.dtp_desirable(source, domain=domain)],
        seconds=LISTEN_SECONDS,
        match=lambda packet: DTP in packet and packet.src != source,
    )
    if not replies:
        return ProbeResult(
            "L2A01",
            posture.DTP_DISABLED,
            PRESENT,
            "L2A01 active probe",
            "no DTP answer within %d seconds of a desirable offer" % LISTEN_SECONDS,
            frames_sent=1,
        )
    record = parse.parse_dtp(replies[0])
    return ProbeResult(
        "L2A01",
        posture.DTP_DISABLED,
        ABSENT,
        "L2A01 active probe",
        "the port answered DTP, mode %s" % record.mode,
        frames_sent=1,
    )


def run_discovery_injection(session: ActiveSession, capture: Capture) -> ProbeResult:
    """L2A07. Send one LLDP frame and check whether it comes back to the port."""
    source = frames.probe_mac(7)
    frame = frames.lldp_probe(source, PROBE_CHASSIS, PROBE_PORT_ID)
    replies = listen_after_send(
        session,
        [frame],
        seconds=LISTEN_SECONDS,
        match=lambda packet: (
            LLDPDU in packet
            and packet.src != source
            and LLDPDUChassisID in packet
            and str(packet[LLDPDUChassisID].id) == source
        ),
    )
    if replies:
        return ProbeResult(
            "L2A07",
            posture.DISCOVERY_DISABLED,
            ABSENT,
            "L2A07 active probe",
            "an injected LLDP identity came back to the port from %s"
            % Ether(bytes(replies[0])).src,
            frames_sent=1,
        )
    return ProbeResult(
        "L2A07",
        posture.DISCOVERY_DISABLED,
        INDETERMINATE,
        "L2A07 active probe",
        "the injected LLDP frame was not reflected; the switch may still have "
        "accepted it into its neighbour table, which cannot be seen from this port",
        frames_sent=1,
    )
