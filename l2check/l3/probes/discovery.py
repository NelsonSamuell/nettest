"""L3A01 host discovery, L3A02 TCP inventory, L3A03 UDP inventory.

These establish what is there and what answers. Nothing is exploited and no
credentials are offered: what a service is, and whether it is reachable, is the
boundary.
"""

from __future__ import annotations

import ipaddress

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.layers.ntp import NTPHeader

from l2check.l3.probes import sweep
from l2check.models import LOW, MEDIUM, Capture, Finding, HostRecord
from l2check.posture import INDETERMINATE, UNTESTED, ProbeResult
from l2check.session import ActiveSession

# Defaults, all overridable. Enough to be useful, small enough to finish.
DEFAULT_TCP_PORTS = (
    21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 135, 139, 143, 443, 445, 465,
    515, 548, 554, 587, 631, 636, 873, 902, 993, 995, 1080, 1433, 1521, 1723,
    1883, 1900, 2000, 2049, 2082, 2181, 3000, 3128, 3306, 3389, 3478, 4443,
    4567, 5000, 5001, 5060, 5222, 5353, 5432, 5555, 5601, 5672, 5900, 6000,
    6379, 6667, 7000, 7547, 8000, 8008, 8009, 8080, 8081, 8088, 8123, 8291,
    8443, 8728, 8888, 9000, 9090, 9100, 9200, 9443, 10000, 11211, 27017, 32400,
    49152, 49153, 51820,
)
DEFAULT_UDP_PORTS = (53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 514, 520,
                     1900, 3702, 4500, 5353, 5355, 7547)

DEFAULT_TCP_HOSTS = 5
DEFAULT_UDP_HOSTS = 3
LISTEN_SECONDS = 6
UDP_RETRIES = 1

SYN = 0x02
SYN_ACK = 0x12
RST = 0x04


def _refused(check: str, detail: str) -> ProbeResult:
    return ProbeResult(check, None, UNTESTED, "%s refused" % check, detail)


def targets_for(session: ActiveSession, capture: Capture, limit: int) -> list[str]:
    """Gateway first, then hosts already seen, then the rest of the prefix."""
    chosen: list[str] = []
    if session.gateway:
        chosen.append(session.gateway)
    for record in capture.hosts:
        if record.family == 4 and record.ip not in chosen:
            chosen.append(record.ip)
    for address in session.sweep_targets or []:
        if address not in chosen:
            chosen.append(address)
    return chosen[:limit]


def run_host_discovery(session: ActiveSession, capture: Capture) -> ProbeResult:
    """L3A01. One ARP request per target address, folded into the inventory."""
    addresses = list(session.sweep_targets or [])
    if not addresses:
        return _refused("L3A01", "no target subnet; set one in the targets file")

    budget = min(len(addresses), session.packets_remaining)
    addresses = addresses[:budget]
    source = session.local_cidr and str(ipaddress.ip_interface(session.local_cidr).ip)
    requests = [
        Ether(dst="ff:ff:ff:ff:ff:ff")
        / ARP(op=1, psrc=source or "0.0.0.0", pdst=address)
        for address in addresses
    ]

    replies = sweep(
        session,
        requests,
        seconds=LISTEN_SECONDS,
        match=lambda packet: ARP in packet and packet[ARP].op == 2,
    )

    found = []
    for packet in replies:
        record = HostRecord(packet[ARP].hwsrc, packet[ARP].psrc, 4, "arp")
        if capture.add("hosts", record):
            found.append(record.ip)

    return ProbeResult(
        "L3A01",
        None,
        INDETERMINATE if not found else UNTESTED,
        "L3A01 active check",
        "asked %d addresses, %d answered" % (len(addresses), len(replies)),
        frames_sent=len(addresses),
        findings=[
            Finding(
                LOW,
                "L3A01",
                "%d hosts answered an ARP request across %d addresses"
                % (len({p[ARP].psrc for p in replies}), len(addresses)),
            )
        ]
        if replies
        else [],
    )


def run_tcp_inventory(session: ActiveSession, capture: Capture) -> ProbeResult:
    """L3A02. SYN sweep. Open, closed and filtered are recorded separately.

    Filtered against closed is the whole point: a closed port means the host
    answered and nothing is listening, a filtered one means something dropped
    the packet. That difference is what says whether the router firewalls its
    own management plane.
    """
    hosts = targets_for(session, capture, session.tcp_hosts)
    if not hosts:
        return _refused("L3A02", "no hosts to sweep")

    ports = list(session.tcp_ports)[: session.tcp_port_limit]
    pairs = [(host, port) for host in hosts for port in ports]
    pairs = pairs[: session.packets_remaining]
    if not pairs:
        return _refused("L3A02", "layer 3 packet budget exhausted")

    packets = [IP(dst=host) / TCP(dport=port, flags="S") for host, port in pairs]
    replies = sweep(
        session,
        packets,
        seconds=LISTEN_SECONDS,
        match=lambda packet: TCP in packet and IP in packet,
    )

    open_ports: dict[str, list[int]] = {}
    closed: dict[str, list[int]] = {}
    for packet in replies:
        host, port = packet[IP].src, int(packet[TCP].sport)
        flags = int(packet[TCP].flags)
        if flags & SYN and flags & 0x10:
            open_ports.setdefault(host, []).append(port)
        elif flags & RST:
            closed.setdefault(host, []).append(port)

    answered = {(h, p) for h in open_ports for p in open_ports[h]}
    answered |= {(h, p) for h in closed for p in closed[h]}
    filtered = [pair for pair in pairs if pair not in answered]

    session.tcp_open = {host: sorted(set(ports)) for host, ports in open_ports.items()}

    findings = []
    for host, ports_found in sorted(session.tcp_open.items()):
        findings.append(
            Finding(
                MEDIUM,
                "L3A02",
                "%s has %d open TCP ports: %s"
                % (host, len(ports_found), ", ".join(str(p) for p in ports_found)),
            )
        )
    return ProbeResult(
        "L3A02",
        None,
        UNTESTED,
        "L3A02 active check",
        "%d pairs swept: %d open, %d closed, %d filtered"
        % (
            len(pairs),
            sum(len(v) for v in open_ports.values()),
            sum(len(v) for v in closed.values()),
            len(filtered),
        ),
        frames_sent=len(pairs),
        findings=findings,
    )


def _udp_payload(port: int):
    """A payload the service on that port will actually answer."""
    if port == 53:
        return DNS(rd=1, qd=DNSQR(qname="example.com"))
    if port == 123:
        return NTPHeader()
    if port in (5353, 5355):
        return DNS(rd=0, qd=DNSQR(qname="_services._dns-sd._udp.local"))
    if port == 1900:
        return (
            b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
            b'MAN: "ssdp:discover"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n'
        )
    if port == 161:
        # A v2c get-next for the system subtree with the default community,
        # which is a read of a public value and nothing more.
        return bytes.fromhex(
            "302902010104067075626c6963a11c02044142434404000201003"
            "00e300c06082b060102010101000500"
        )
    if port == 7547:
        return b"GET / HTTP/1.1\r\nHost: cpe\r\n\r\n"
    return b"\x00"


def run_udp_inventory(session: ActiveSession, capture: Capture) -> ProbeResult:
    """L3A03. UDP sweep with protocol appropriate payloads.

    Silence on UDP is INDETERMINATE and never ABSENT. An unanswered UDP probe is
    indistinguishable from a filtered one, and home routers rate limit responses
    under load, so a quiet result here means nothing was learned.
    """
    hosts = targets_for(session, capture, session.udp_hosts)
    if not hosts:
        return _refused("L3A03", "no hosts to sweep")

    ports = list(session.udp_ports)
    pairs = [(host, port) for host in hosts for port in ports]
    attempts = pairs * (1 + UDP_RETRIES)
    attempts = attempts[: session.packets_remaining]
    if not attempts:
        return _refused("L3A03", "layer 3 packet budget exhausted")

    packets = [
        IP(dst=host) / UDP(dport=port) / _udp_payload(port) for host, port in attempts
    ]
    replies = sweep(
        session,
        packets,
        seconds=LISTEN_SECONDS,
        match=lambda packet: IP in packet and (UDP in packet or ICMP in packet),
    )

    answering: dict[str, set[int]] = {}
    for packet in replies:
        if UDP in packet:
            answering.setdefault(packet[IP].src, set()).add(int(packet[UDP].sport))

    findings = []
    for host, ports_found in sorted(answering.items()):
        findings.append(
            Finding(
                MEDIUM,
                "L3A03",
                "%s answers UDP on %s"
                % (host, ", ".join(str(p) for p in sorted(ports_found))),
            )
        )
    if not answering:
        return ProbeResult(
            "L3A03",
            None,
            INDETERMINATE,
            "L3A03 active check",
            "no UDP answers from %d hosts across %d ports. Silence on UDP is not "
            "evidence of filtering: an unanswered probe and a dropped one look "
            "the same, and home routers rate limit responses"
            % (len(hosts), len(ports)),
            frames_sent=len(attempts),
        )
    return ProbeResult(
        "L3A03",
        None,
        UNTESTED,
        "L3A03 active check",
        "%d hosts answered UDP" % len(answering),
        frames_sent=len(attempts),
        findings=findings,
    )
