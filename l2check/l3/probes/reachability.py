"""The checks that need a vantage point somewhere else.

Every one of these tests one-way delivery, so a silent result from the sending
side proves nothing. Without a cooperating observer each reports INDETERMINATE
and says why. That is the single most valuable property this tool has and none
of these checks weakens it: a local timeout does not distinguish a filter from a
dead host, and consumer NAT gives a wrong answer to a hairpin test.

L3A05  inbound IPv4, needs an external observer and --wan
L3A07  egress filtering, needs an external observer
L3A08  inbound IPv6, needs an external observer and a global address on the LAN
L3A09  guest segmentation, run from the guest segment with a LAN observer
L3A10  DNS rebinding, needs an authoritative name server you control
L3A11  resolver scoping, needs a guest or external vantage point
L3A13  anti-spoofing, needs an observer on the far side
L3A14  fragment handling, needs an observer to confirm arrival
L3A15  source routing, needs an observer to confirm arrival

L3A14 and L3A15 own no control. They describe how a filter behaves rather than
whether egress is filtered, which is L3A07's question, and letting them write to
the same control would mean whichever ran last decided the answer.
"""

from __future__ import annotations

import ipaddress

from scapy.layers.inet import GRE, IP, TCP, UDP

from l2check import frames
from l2check.l3.probes import sweep
from l2check.models import HIGH, MEDIUM, Capture, Finding
from l2check.observe import ask_observer, ask_observer_connect
from l2check.posture import (
    ABSENT,
    ANTI_SPOOFING,
    DNS_REBINDING,
    EGRESS_FILTERING,
    GUEST_SEGMENTATION,
    INBOUND_V4,
    INBOUND_V6,
    INDETERMINATE,
    PRESENT,
    RESOLVER_SCOPING,
    UNTESTED,
    ProbeResult,
)
from l2check.session import ActiveSession

INBOUND_PORTS = (22, 23, 80, 443, 445, 3389, 7547, 8080, 8443)
EGRESS_PORTS = (
    21, 22, 23, 25, 53, 80, 110, 123, 143, 443, 445, 465, 587, 993, 995, 1194,
    1723, 3306, 3389, 4500, 5060, 5222, 5432, 5900, 6667, 8080, 8443, 9001,
    9418, 11211, 19132, 25565, 27015, 27017, 31337, 33434, 51413, 51820, 6881,
    8333,
)
CGNAT = ipaddress.ip_network("100.64.0.0/10")
OBSERVER_SECONDS = 6


def _no_observer(check: str, control: str, what: str, frames_sent: int = 0) -> ProbeResult:
    return ProbeResult(
        check,
        control,
        INDETERMINATE,
        "%s, no observer supplied" % check,
        "%s. One way delivery cannot be confirmed from the sending side, so this "
        "is not evidence either way" % what,
        frames_sent=frames_sent,
    )


def _unreachable(check: str, control: str, endpoint: str, frames_sent: int = 0) -> ProbeResult:
    return ProbeResult(
        check,
        control,
        INDETERMINATE,
        "%s, observer unreachable" % check,
        "the observer at %s did not answer, so delivery is unknown" % endpoint,
        frames_sent=frames_sent,
    )


def _refused(check: str, control: str, detail: str) -> ProbeResult:
    return ProbeResult(check, control, UNTESTED, "%s refused" % check, detail)


def run_inbound_v4(session: ActiveSession, capture: Capture) -> ProbeResult:
    """L3A05. Whether the WAN address accepts connections from outside.

    Never substituted with a hairpin test from inside: most consumer NAT answers
    that differently from the outside world, so the answer would be wrong.
    """
    if not session.wan_address:
        return _refused("L3A05", INBOUND_V4, "no WAN address; run with --wan")
    if ipaddress.ip_address(session.wan_address) in CGNAT:
        return ProbeResult(
            "L3A05",
            INBOUND_V4,
            UNTESTED,
            "L3A05 refused, cgnat",
            "the WAN address %s is inside carrier grade NAT, so inbound testing "
            "cannot work and says nothing about your firewall"
            % session.wan_address,
        )
    if not session.external_observer:
        return _no_observer(
            "L3A05", INBOUND_V4, "an external observer is needed to knock on %s"
            % session.wan_address
        )

    reachable = []
    for port in INBOUND_PORTS:
        answer = ask_observer_connect(
            session.external_observer, session.wan_address, port, OBSERVER_SECONDS
        )
        if answer is None:
            return _unreachable("L3A05", INBOUND_V4, session.external_observer)
        if answer == "open":
            reachable.append(port)

    if reachable:
        return ProbeResult(
            "L3A05",
            INBOUND_V4,
            ABSENT,
            "L3A05 active check",
            "the observer reached %s from outside on %s"
            % (session.wan_address, ", ".join(str(p) for p in reachable)),
            segments=("external", "lan"),
            findings=[
                Finding(
                    HIGH,
                    "L3A05",
                    "Inbound from the internet reaches %s on %s"
                    % (session.wan_address, ", ".join(str(p) for p in reachable)),
                )
            ],
        )
    return ProbeResult(
        "L3A05",
        INBOUND_V4,
        PRESENT,
        "L3A05 active check",
        "the observer could not reach %s on any of %d ports from outside"
        % (session.wan_address, len(INBOUND_PORTS)),
        segments=("external", "lan"),
    )


def _target(session: ActiveSession, check: str, control: str):
    """The resolved test host, or a refusal explaining why there is not one."""
    if not session.test_host:
        return None, _refused(check, control, "no external.test_host configured")
    address = session.resolve(session.test_host)
    if not address:
        return None, _refused(
            check, control, "external.test_host %r does not resolve" % session.test_host
        )
    return address, None


def run_egress(session: ActiveSession, capture: Capture) -> ProbeResult:
    """L3A07. Which outbound ports and protocols leave the network."""
    target, refusal = _target(session, "L3A07", EGRESS_FILTERING)
    if refusal is not None:
        return refusal

    marker = frames.new_marker()
    packets = [IP(dst=target) / TCP(dport=port, flags="S") for port in EGRESS_PORTS]
    packets.append(IP(dst=target) / UDP(dport=53) / marker.encode())
    packets.append(IP(dst=target, proto=47) / GRE())
    packets.append(IP(dst=target, proto=50) / marker.encode())
    packets = packets[: session.packets_remaining]
    session.send_ip(packets)

    if not session.external_observer:
        return _no_observer(
            "L3A07",
            EGRESS_FILTERING,
            "%d outbound probes were sent to %s" % (len(packets), target),
            frames_sent=len(packets),
        )

    arrived = ask_observer(session.external_observer, marker, OBSERVER_SECONDS)
    if arrived is None:
        return _unreachable(
            "L3A07", EGRESS_FILTERING, session.external_observer, len(packets)
        )
    if arrived:
        return ProbeResult(
            "L3A07",
            EGRESS_FILTERING,
            ABSENT,
            "L3A07 active check",
            "outbound probes reached the external observer, so egress is not "
            "filtered on the ports tested",
            frames_sent=len(packets),
            segments=("lan", "external"),
            findings=[
                Finding(MEDIUM, "L3A07", "Outbound traffic leaves unfiltered")
            ],
        )
    return ProbeResult(
        "L3A07",
        EGRESS_FILTERING,
        PRESENT,
        "L3A07 active check",
        "the external observer saw none of %d outbound probes" % len(packets),
        frames_sent=len(packets),
        segments=("lan", "external"),
    )


def run_inbound_v6(session: ActiveSession, capture: Capture) -> ProbeResult:
    """L3A08. Whether a globally addressed LAN host is reachable from outside.

    The most likely source of a genuine ABSENT on a home network, because
    consumer firewall rules are frequently v4 only.
    """
    globals_seen = [r for r in capture.ipv6_modes if r.scope == "global"]
    if not globals_seen:
        return _refused(
            "L3A08", INBOUND_V6, "no LAN host holds a global IPv6 address (L3P04)"
        )
    if not session.external_observer:
        return _no_observer(
            "L3A08", INBOUND_V6, "an external observer is needed to knock on %s"
            % globals_seen[0].address
        )

    address = globals_seen[0].address
    reachable = []
    for port in INBOUND_PORTS:
        answer = ask_observer_connect(
            session.external_observer, address, port, OBSERVER_SECONDS
        )
        if answer is None:
            return _unreachable("L3A08", INBOUND_V6, session.external_observer)
        if answer == "open":
            reachable.append(port)

    if reachable:
        return ProbeResult(
            "L3A08",
            INBOUND_V6,
            ABSENT,
            "L3A08 active check",
            "the observer reached the LAN host %s from the internet on %s"
            % (address, ", ".join(str(p) for p in reachable)),
            segments=("external", "lan"),
            findings=[
                Finding(
                    HIGH,
                    "L3A08",
                    "IPv6 inbound reaches a LAN host directly at %s on %s: the "
                    "firewall rules are v4 only"
                    % (address, ", ".join(str(p) for p in reachable)),
                )
            ],
        )
    return ProbeResult(
        "L3A08",
        INBOUND_V6,
        PRESENT,
        "L3A08 active check",
        "the observer could not reach %s from outside on any of %d ports"
        % (address, len(INBOUND_PORTS)),
        segments=("external", "lan"),
    )


def run_guest_segmentation(session: ActiveSession, capture: Capture) -> ProbeResult:
    """L3A09. Three separate questions, because routers commonly isolate one.

    Reaching the LAN subnet, reaching the gateway admin interface, and reaching
    another guest client are different controls and are reported separately.
    """
    if not session.guest_subnet:
        return _refused("L3A09", GUEST_SEGMENTATION, "no guest_subnet configured")
    if not session.observer:
        return _no_observer(
            "L3A09",
            GUEST_SEGMENTATION,
            "run this from the guest segment with an observer on the LAN",
        )

    results = {}
    observer_host = session.observer.rsplit(":", 1)[0]
    answer = ask_observer_connect(session.observer, observer_host, 9001, OBSERVER_SECONDS)
    if answer is None:
        return _unreachable("L3A09", GUEST_SEGMENTATION, session.observer)
    results["LAN host"] = answer

    if session.gateway:
        results["gateway admin"] = session.connect_result(session.gateway, 80)

    reachable = [name for name, state in results.items() if state == "open"]
    detail = ", ".join("%s: %s" % (name, state) for name, state in sorted(results.items()))

    if reachable:
        return ProbeResult(
            "L3A09",
            GUEST_SEGMENTATION,
            ABSENT,
            "L3A09 active check",
            "from the guest segment, %s" % detail,
            segments=("guest", "lan"),
            findings=[
                Finding(
                    HIGH,
                    "L3A09",
                    "Guest segment reaches %s" % ", ".join(reachable),
                )
            ],
        )
    return ProbeResult(
        "L3A09",
        GUEST_SEGMENTATION,
        PRESENT,
        "L3A09 active check",
        "from the guest segment, %s" % detail,
        segments=("guest", "lan"),
    )


def run_dns_rebinding(session: ActiveSession, capture: Capture) -> ProbeResult:
    """L3A10. Whether the local resolver passes through a private answer."""
    if not session.authoritative_ns:
        return _refused(
            "L3A10",
            DNS_REBINDING,
            "needs authoritative_ns configured: a name server you control that "
            "answers with an RFC1918 address",
        )
    if not session.gateway:
        return _refused("L3A10", DNS_REBINDING, "no local resolver to ask")

    from scapy.layers.dns import DNS, DNSQR

    name = "rebind.%s" % session.authoritative_ns
    query = IP(dst=session.gateway) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=name))
    replies = sweep(
        session,
        [query],
        seconds=5,
        match=lambda packet: UDP in packet and packet[UDP].sport == 53 and DNS in packet,
    )

    for packet in replies:
        answer = packet[DNS]
        for index in range(int(answer.ancount or 0)):
            record = answer.an[index]
            if record.type != 1:
                continue
            address = str(record.rdata)
            if ipaddress.ip_address(address).is_private:
                return ProbeResult(
                    "L3A10",
                    DNS_REBINDING,
                    ABSENT,
                    "L3A10 active check",
                    "the local resolver returned the private address %s for %s "
                    "unfiltered" % (address, name),
                    frames_sent=1,
                    findings=[
                        Finding(
                            HIGH,
                            "L3A10",
                            "DNS rebinding protection is off: an external name "
                            "resolved to %s" % address,
                        )
                    ],
                )
    if replies:
        return ProbeResult(
            "L3A10",
            DNS_REBINDING,
            PRESENT,
            "L3A10 active check",
            "the local resolver answered but stripped the private address for %s" % name,
            frames_sent=1,
        )
    return ProbeResult(
        "L3A10",
        DNS_REBINDING,
        INDETERMINATE,
        "L3A10 active check",
        "the local resolver did not answer for %s, so nothing was learned" % name,
        frames_sent=1,
    )


def run_resolver_scoping(session: ActiveSession, capture: Capture) -> ProbeResult:
    """L3A11. Whether the gateway resolver answers from where it should not."""
    if not session.gateway:
        return _refused("L3A11", RESOLVER_SCOPING, "no gateway resolver to test")
    if not session.external_observer and not session.wan_address:
        return _no_observer(
            "L3A11",
            RESOLVER_SCOPING,
            "testing the resolver from the WAN side needs --wan and an external "
            "observer",
        )
    if not session.external_observer:
        return _no_observer("L3A11", RESOLVER_SCOPING, "no external observer configured")

    answer = ask_observer_connect(
        session.external_observer, session.wan_address, 53, OBSERVER_SECONDS
    )
    if answer is None:
        return _unreachable("L3A11", RESOLVER_SCOPING, session.external_observer)
    if answer == "open":
        return ProbeResult(
            "L3A11",
            RESOLVER_SCOPING,
            ABSENT,
            "L3A11 active check",
            "the resolver on %s answers from the WAN side, which makes it usable "
            "for amplification by anyone" % session.wan_address,
            segments=("external", "lan"),
            findings=[
                Finding(
                    HIGH,
                    "L3A11",
                    "The gateway resolver is reachable from the internet",
                )
            ],
        )
    return ProbeResult(
        "L3A11",
        RESOLVER_SCOPING,
        PRESENT,
        "L3A11 active check",
        "the resolver did not answer from the WAN side",
        segments=("external", "lan"),
    )


def run_anti_spoofing(session: ActiveSession, capture: Capture) -> ProbeResult:
    """L3A13. Whether a packet with a forged source leaves, and one arrives."""
    target, refusal = _target(session, "L3A13", ANTI_SPOOFING)
    if refusal is not None:
        return refusal

    marker = frames.new_marker()
    # A source outside the local prefix. If this leaves the network, the ISP or
    # the router is not applying BCP38 on egress.
    forged = IP(src="203.0.113.7", dst=target) / UDP(dport=9001) / marker.encode()
    session.send_ip(forged)

    if not session.external_observer:
        return _no_observer(
            "L3A13",
            ANTI_SPOOFING,
            "one packet with a forged source was sent to %s" % target,
            frames_sent=1,
        )

    arrived = ask_observer(session.external_observer, marker, OBSERVER_SECONDS)
    if arrived is None:
        return _unreachable("L3A13", ANTI_SPOOFING, session.external_observer, 1)
    if arrived:
        return ProbeResult(
            "L3A13",
            ANTI_SPOOFING,
            ABSENT,
            "L3A13 active check",
            "a packet with a source outside this network reached the external "
            "observer, so egress source filtering is not applied",
            frames_sent=1,
            segments=("lan", "external"),
            findings=[
                Finding(
                    HIGH,
                    "L3A13",
                    "Spoofed source addresses leave this network, so it can be "
                    "used in a reflection attack",
                )
            ],
        )
    return ProbeResult(
        "L3A13",
        ANTI_SPOOFING,
        PRESENT,
        "L3A13 active check",
        "the forged source packet did not reach the external observer",
        frames_sent=1,
        segments=("lan", "external"),
    )


def run_fragment_handling(session: ActiveSession, capture: Capture) -> ProbeResult:
    """L3A14. Whether a filter inspects only the first fragment.

    The transport header is split across the fragment boundary, so a filter that
    matches on ports in the first fragment alone sees nothing to match.
    """
    target, refusal = _target(session, "L3A14", None)
    if refusal is not None:
        return refusal

    marker = frames.new_marker()
    payload = marker.encode() + b"\x00" * 32
    whole = IP(dst=target, id=0xBEEF) / UDP(dport=9001) / payload
    raw = bytes(whole[UDP])
    first = IP(dst=target, id=0xBEEF, proto=17, flags="MF", frag=0) / raw[:8]
    second = IP(dst=target, id=0xBEEF, proto=17, frag=1) / raw[8:]
    session.send_ip([first, second])

    if not session.external_observer:
        return _no_observer(
            "L3A14",
            None,
            "a fragmented packet was sent to %s with the transport header split "
            "across the boundary" % target,
            frames_sent=2,
        )

    arrived = ask_observer(session.external_observer, marker, OBSERVER_SECONDS)
    if arrived is None:
        return _unreachable("L3A14", None, session.external_observer, 2)
    if arrived:
        return ProbeResult(
            "L3A14",
            None,
            ABSENT,
            "L3A14 active check",
            "a fragmented packet crossed the filter with its transport header "
            "split, so the filter inspects first fragments only",
            frames_sent=2,
            segments=("lan", "external"),
            findings=[
                Finding(
                    HIGH,
                    "L3A14",
                    "Fragmented traffic bypasses the filter: it inspects the "
                    "first fragment only",
                )
            ],
        )
    return ProbeResult(
        "L3A14",
        EGRESS_FILTERING,
        PRESENT,
        "L3A14 active check",
        "the fragmented packet did not reach the observer",
        frames_sent=2,
        segments=("lan", "external"),
    )


def run_source_routing(session: ActiveSession, capture: Capture) -> ProbeResult:
    """L3A15. Whether loose or strict source routed packets are accepted."""
    target, refusal = _target(session, "L3A15", None)
    if refusal is not None:
        return refusal

    marker = frames.new_marker()
    via = session.gateway or "192.0.2.1"
    # Option 131 is loose source routing, 137 is strict.
    loose = IP(dst=target, options=[_route_option(131, via)]) / UDP(
        dport=9001
    ) / marker.encode()
    strict = IP(dst=target, options=[_route_option(137, via)]) / UDP(
        dport=9001
    ) / marker.encode()
    session.send_ip([loose, strict])

    if not session.external_observer:
        return _no_observer(
            "L3A15",
            None,
            "two source routed packets were sent to %s" % target,
            frames_sent=2,
        )

    arrived = ask_observer(session.external_observer, marker, OBSERVER_SECONDS)
    if arrived is None:
        return _unreachable("L3A15", None, session.external_observer, 2)
    if arrived:
        return ProbeResult(
            "L3A15",
            None,
            ABSENT,
            "L3A15 active check",
            "source routed packets were forwarded, so the path accepts a sender "
            "choosing its own route",
            frames_sent=2,
            segments=("lan", "external"),
            findings=[
                Finding(HIGH, "L3A15", "Source routed packets are accepted")
            ],
        )
    return ProbeResult(
        "L3A15",
        EGRESS_FILTERING,
        PRESENT,
        "L3A15 active check",
        "source routed packets did not reach the observer",
        frames_sent=2,
        segments=("lan", "external"),
    )


def _route_option(kind: int, via: str):
    from scapy.layers.inet import IPOption

    packed = bytes(int(part) for part in via.split("."))
    return IPOption(bytes([kind, 7, 4]) + packed)
