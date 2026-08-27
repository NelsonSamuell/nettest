"""L2A05 Dynamic ARP Inspection.

One gratuitous ARP for one address the operator has confirmed is unused. The
probe refuses to run unless that address is supplied, does not answer a
liveness check, and did not appear in the passive capture, because announcing
an address that is in use is the one way this could disturb a host.

There is no repetition, no reply handling and no forwarding: the tool announces
once and then asks a consenting observer on the target segment whether the
announcement arrived. Without an observer the result is INDETERMINATE, since
nothing observable happens at the sending port either way.
"""

from __future__ import annotations

from scapy.layers.inet import ICMP, IP
from scapy.layers.l2 import ARP, Ether

from l2check import frames, posture
from l2check.authorisation import ActiveSession
from l2check.models import Capture
from l2check.observe import ask_observer
from l2check.posture import ABSENT, INDETERMINATE, PRESENT, UNTESTED, ProbeResult
from l2check.probes import listen_after_send

LIVENESS_SECONDS = 3
OBSERVER_SECONDS = 5


def _refused(detail: str) -> ProbeResult:
    return ProbeResult("L2A05", posture.ARP_INSPECTION, UNTESTED, "L2A05 refused", detail)


def _address_answers(session: ActiveSession, source: str, address: str) -> bool:
    """Send one ARP request and one echo request and see if anything replies."""
    probe = (
        Ether(dst="ff:ff:ff:ff:ff:ff", src=source)
        / IP(src="0.0.0.0", dst=address)
        / ICMP(type=8)
    )
    replies = listen_after_send(
        session,
        [frames.arp_probe(source, address), bytes(probe)],
        seconds=LIVENESS_SECONDS,
        match=lambda packet: (
            (ARP in packet and packet[ARP].op == 2 and packet[ARP].psrc == address)
            or (IP in packet and packet[IP].src == address)
        ),
    )
    return bool(replies)


def run(session: ActiveSession, capture: Capture) -> ProbeResult:
    """L2A05. Announce one unused address and ask an observer whether it arrived."""
    address = session.test_ip
    if not address:
        return _refused("--test-ip is required and must be an address confirmed unused")
    if address in capture.observed_ips():
        return _refused(
            "%s appeared in the passive capture, so it is not an unused address" % address
        )

    source = frames.probe_mac(5)
    if _address_answers(session, source, address):
        return _refused("%s answered a liveness check, so it is in use" % address)

    session.send(frames.gratuitous_arp(source, address))

    if not session.observer:
        return ProbeResult(
            "L2A05",
            posture.ARP_INSPECTION,
            INDETERMINATE,
            "L2A05, no observer supplied",
            "one announcement for %s was sent; whether it crossed the switch "
            "cannot be seen from the sending port" % address,
            frames_sent=1,
        )

    seen = ask_observer(session.observer, "ARP:" + address, timeout=OBSERVER_SECONDS)
    if seen is None:
        return ProbeResult(
            "L2A05",
            posture.ARP_INSPECTION,
            INDETERMINATE,
            "L2A05, observer unreachable",
            "the observer at %s did not answer, so delivery is unknown" % session.observer,
            frames_sent=1,
        )
    if seen:
        return ProbeResult(
            "L2A05",
            posture.ARP_INSPECTION,
            ABSENT,
            "L2A05 active probe",
            "the observer at %s saw an unsolicited claim for %s"
            % (session.observer, address),
            frames_sent=1,
        )
    return ProbeResult(
        "L2A05",
        posture.ARP_INSPECTION,
        PRESENT,
        "L2A05 active probe",
        "the observer at %s did not see the claim for %s, so it was dropped in transit"
        % (session.observer, address),
        frames_sent=1,
    )
