"""L3A01 host discovery, L3A02 TCP inventory, L3A03 UDP inventory.

These establish what is there and what answers. Nothing is exploited and no
credentials are offered: what a service is, and whether it is reachable, is the
boundary.
"""

from __future__ import annotations

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP

from netcheck.l3 import packets
from netcheck.l3.parse import Host
from netcheck.models import (
    BUDGET_EXHAUSTED,
    INDETERMINATE,
    LOW,
    MEDIUM,
    PREREQUISITE_MISSING,
    UNTESTED,
    Finding,
)

LISTEN_SECONDS = 6
DEFAULT_TCP_HOSTS = 5
DEFAULT_UDP_HOSTS = 3
UDP_RETRIES = 1
TCP_PORT_LIMIT = 200


def _refused(identifier: str, detail: str):
    return UNTESTED, identifier, "%s: %s" % (PREREQUISITE_MISSING, detail), []


def targets(context, limit: int) -> list[str]:
    """Gateway first, then hosts already seen, then the rest of the prefix."""
    chosen: list[str] = []
    gateway = getattr(context.config, "gateway", "") if context.config else ""
    if gateway:
        chosen.append(gateway)
    if context.capture is not None:
        for record in context.capture.hosts:
            if record.family == 4 and record.ip not in chosen:
                chosen.append(record.ip)
    if context.config is not None:
        for address in context.config.addresses():
            if address not in chosen:
                chosen.append(address)
    return chosen[:limit]


def run_host_discovery(context):
    """L3A01. One ARP request per target address, folded into the inventory."""
    from netcheck.budget import LAYER3

    addresses = context.config.addresses() if context.config else []
    if not addresses:
        return _refused("L3A01", "no target subnet; set one in the targets file")

    source = ""
    from netcheck.platform import interfaces as interfaces_module

    entry = interfaces_module.interface_named(context.interface)
    source = entry.address if entry else ""
    if not source:
        return _refused("L3A01", "this interface has no address to send from")

    budget = min(len(addresses), context.budget.remaining(LAYER3))
    addresses = addresses[:budget]
    replies, sniffer = context.collect(
        LISTEN_SECONDS, lambda pkt: ARP in pkt and pkt[ARP].op == 2
    )
    context.send_packets([packets.arp_request(source, a) for a in addresses])
    context.sleeper(LISTEN_SECONDS)
    sniffer.stop()

    found = set()
    for packet in replies:
        record = Host(packet[ARP].hwsrc, packet[ARP].psrc, 4, "arp")
        if context.capture is not None:
            context.capture.add("hosts", record)
        found.add(record.ip)

    findings = []
    if found:
        findings.append(
            Finding(LOW, "L3A01", "%d hosts answered across %d addresses"
                    % (len(found), len(addresses)), "")
        )
    return UNTESTED, "L3A01", "asked %d addresses, %d answered" % (len(addresses), len(found)), findings


def run_tcp_inventory(context):
    """L3A02. SYN sweep. Open, closed and filtered are recorded separately.

    Filtered against closed is the point: a closed port means the host answered
    and nothing is listening, a filtered one means something dropped the packet.
    That difference says whether the gateway firewalls its own management plane.
    """
    from netcheck.budget import LAYER3

    hosts = targets(context, DEFAULT_TCP_HOSTS)
    if not hosts:
        return _refused("L3A02", "no hosts to sweep")

    ports = list(packets.DEFAULT_TCP_PORTS)[:TCP_PORT_LIMIT]
    pairs = [(host, port) for host in hosts for port in ports]
    pairs = pairs[: context.budget.remaining(LAYER3)]
    if not pairs:
        return UNTESTED, "L3A02", BUDGET_EXHAUSTED, []

    replies, sniffer = context.collect(LISTEN_SECONDS, lambda pkt: TCP in pkt and IP in pkt)
    context.send_packets([packets.tcp_syn(host, port) for host, port in pairs])
    context.sleeper(LISTEN_SECONDS)
    sniffer.stop()

    opened: dict = {}
    closed: dict = {}
    for packet in replies:
        host, port = packet[IP].src, int(packet[TCP].sport)
        flags = int(packet[TCP].flags)
        if flags & packets.SYN and flags & packets.ACK:
            opened.setdefault(host, set()).add(port)
        elif flags & packets.RST:
            closed.setdefault(host, set()).add(port)

    answered = {(h, p) for h, ps in opened.items() for p in ps}
    answered |= {(h, p) for h, ps in closed.items() for p in ps}
    filtered = [pair for pair in pairs if pair not in answered]
    context.tcp_open = {h: sorted(ps) for h, ps in opened.items()}

    findings = []
    for host, found in sorted(context.tcp_open.items()):
        findings.append(
            Finding(MEDIUM, "L3A02", "%s has %d open TCP ports: %s"
                    % (host, len(found), ", ".join(str(p) for p in found)), "")
        )
    detail = "%d pairs swept: %d open, %d closed, %d filtered" % (
        len(pairs),
        sum(len(v) for v in opened.values()),
        sum(len(v) for v in closed.values()),
        len(filtered),
    )
    return UNTESTED, "L3A02", detail, findings


def run_udp_inventory(context):
    """L3A03. UDP sweep with protocol appropriate payloads.

    Silence on UDP is INDETERMINATE and never ABSENT. An unanswered probe is
    indistinguishable from a filtered one, and home routers rate limit responses
    under load, so a quiet result here means nothing was learned.
    """
    from netcheck.budget import LAYER3

    hosts = targets(context, DEFAULT_UDP_HOSTS)
    if not hosts:
        return _refused("L3A03", "no hosts to sweep")

    ports = list(packets.DEFAULT_UDP_PORTS)
    pairs = [(host, port) for host in hosts for port in ports] * (1 + UDP_RETRIES)
    pairs = pairs[: context.budget.remaining(LAYER3)]
    if not pairs:
        return UNTESTED, "L3A03", BUDGET_EXHAUSTED, []

    replies, sniffer = context.collect(
        LISTEN_SECONDS, lambda pkt: IP in pkt and (UDP in pkt or ICMP in pkt)
    )
    context.send_packets([packets.udp_probe(host, port) for host, port in pairs])
    context.sleeper(LISTEN_SECONDS)
    sniffer.stop()

    answering: dict = {}
    for packet in replies:
        if UDP in packet:
            answering.setdefault(packet[IP].src, set()).add(int(packet[UDP].sport))

    if not answering:
        return (
            INDETERMINATE,
            "L3A03",
            "no UDP answers from %d hosts across %d ports. Silence on UDP is not "
            "evidence of filtering: an unanswered probe and a dropped one look the "
            "same, and home routers rate limit responses" % (len(hosts), len(ports)),
            [],
        )

    findings = [
        Finding(MEDIUM, "L3A03", "%s answers UDP on %s"
                % (host, ", ".join(str(p) for p in sorted(found))), "")
        for host, found in sorted(answering.items())
    ]
    return UNTESTED, "L3A03", "%d hosts answered UDP" % len(answering), findings
