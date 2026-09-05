"""Layer 3 passive parsers.

These hook into the same capture loop as the layer 2 parsers rather than opening
a second socket. Protocol metadata only: nothing here returns, copies or retains
the payload of a packet that is not to or from this interface.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.dns import DNS
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import (
    ICMPv6DestUnreach,
    ICMPv6ND_NA,
    ICMPv6ND_NS,
    ICMPv6ND_Redirect,
    IPv6,
    IPv6ExtHdrFragment,
)
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet

from netcheck.models import Capture

DNS_PORT = 53
DOT_PORT = 853

# Hop limits a flat segment produces. Anything else means a router in the path.
FLAT_HOP_LIMITS = (255, 128, 64, 32)

# Scope is decided by prefix, not by ipaddress.is_private, which also treats the
# 2001:db8::/32 documentation range as private.
UNIQUE_LOCAL_V6 = ipaddress.ip_network("fc00::/7")
GLOBAL_V6 = ipaddress.ip_network("2000::/3")

CLEARTEXT_TCP = {21: "FTP", 23: "Telnet", 25: "SMTP", 80: "HTTP", 110: "POP3", 143: "IMAP"}
CLEARTEXT_UDP = {161: "SNMP"}


@dataclass
class Host:
    mac: str
    ip: str
    family: int
    source: str


@dataclass
class Resolver:
    client_mac: str
    resolver_ip: str
    transport: str


@dataclass
class DnsAnswer:
    name: str
    address: str


@dataclass
class IPv6Mode:
    mac: str
    address: str
    scope: str
    mode: str
    privacy: bool


@dataclass
class Icmp:
    kind: str
    source_ip: str
    detail: str


@dataclass
class Outbound:
    source_ip: str
    destination_ip: str
    port: int
    transport: str


@dataclass
class Fragment:
    source_ip: str
    family: int


@dataclass
class HopCount:
    source_ip: str
    hop_limit: int


def _text(value: object) -> str:
    if isinstance(value, bytes):
        return value.rstrip(b"\x00").decode("utf-8", "replace")
    return "" if value is None else str(value)


def is_private(address: str) -> bool:
    """RFC1918, unique local, loopback and link local."""
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return False
    return parsed.is_private or parsed.is_link_local or parsed.is_loopback


def parse_host(pkt: Packet) -> Host | None:
    """L3P01. One address to MAC binding, however it was learned."""
    if Ether not in pkt:
        return None
    mac = pkt[Ether].src
    if ARP in pkt and pkt[ARP].psrc not in ("", "0.0.0.0"):
        return Host(pkt[ARP].hwsrc, pkt[ARP].psrc, 4, "arp")
    if (ICMPv6ND_NA in pkt or ICMPv6ND_NS in pkt) and IPv6 in pkt and pkt[IPv6].src != "::":
        return Host(mac, pkt[IPv6].src, 6, "ndp")
    if BOOTP in pkt and DHCP in pkt and pkt[BOOTP].yiaddr not in ("", "0.0.0.0"):
        return Host(mac, pkt[BOOTP].yiaddr, 4, "dhcp")
    if IP in pkt and pkt[IP].src != "0.0.0.0":
        return Host(mac, pkt[IP].src, 4, "traffic")
    if IPv6 in pkt and pkt[IPv6].src != "::":
        return Host(mac, pkt[IPv6].src, 6, "traffic")
    return None


def parse_resolver(pkt: Packet) -> Resolver | None:
    """L3P03. Which resolver a client uses, and over what transport."""
    if Ether not in pkt:
        return None
    if TCP in pkt and pkt[TCP].dport == DOT_PORT:
        target = pkt[IP].dst if IP in pkt else pkt[IPv6].dst if IPv6 in pkt else ""
        return Resolver(pkt[Ether].src, target, "DoT")
    if UDP not in pkt or pkt[UDP].dport != DNS_PORT or DNS not in pkt:
        return None
    if pkt[DNS].qr != 0:
        return None
    target = pkt[IP].dst if IP in pkt else pkt[IPv6].dst if IPv6 in pkt else ""
    return Resolver(pkt[Ether].src, target, "Do53")


def parse_dns_answer(pkt: Packet) -> DnsAnswer | None:
    """L3P03. An external name answered with a private address.

    That means the resolver is rewriting, which is either a local blocklist or
    the condition a rebinding attack needs.
    """
    if UDP not in pkt or DNS not in pkt or pkt[UDP].sport != DNS_PORT:
        return None
    dns = pkt[DNS]
    if dns.qr != 1 or not dns.ancount:
        return None
    name = _text(dns.qd[0].qname).rstrip(".") if dns.qdcount else ""
    for index in range(int(dns.ancount)):
        answer = dns.an[index]
        if answer.type not in (1, 28):
            continue
        address = _text(answer.rdata)
        if is_private(address) and name and not name.endswith(".local"):
            return DnsAnswer(name, address)
    return None


def parse_ipv6_mode(pkt: Packet) -> IPv6Mode | None:
    """L3P04. How a host got its address, and whether it is globally routable.

    A global address on a LAN host is the precondition for L3A08.
    """
    if IPv6 not in pkt or Ether not in pkt:
        return None
    address = pkt[IPv6].src
    if address == "::":
        return None
    parsed = ipaddress.ip_address(address)
    if parsed.is_multicast:
        return None
    if parsed.is_link_local:
        scope = "link-local"
    elif parsed in UNIQUE_LOCAL_V6:
        scope = "unique-local"
    elif parsed in GLOBAL_V6:
        scope = "global"
    else:
        scope = "other"
    # A SLAAC address derived from the MAC carries ff:fe in the middle of the
    # interface identifier; anything else is privacy extensions or DHCPv6.
    packed = parsed.packed
    eui64 = packed[11] == 0xFF and packed[12] == 0xFE
    return IPv6Mode(
        pkt[Ether].src, address, scope,
        "slaac" if eui64 else "slaac-or-dhcpv6", privacy=not eui64,
    )


def parse_icmp(pkt: Packet) -> Icmp | None:
    """L3P06. Redirects, unreachables and the legacy information requests."""
    if ICMPv6ND_Redirect in pkt:
        return Icmp("redirect", pkt[IPv6].src, "IPv6 redirect")
    if ICMPv6DestUnreach in pkt:
        return Icmp("unreachable", pkt[IPv6].src, "IPv6 unreachable")
    if ICMP not in pkt or IP not in pkt:
        return None
    icmp = pkt[ICMP]
    kinds = {5: "redirect", 3: "unreachable", 14: "timestamp", 18: "netmask"}
    kind = kinds.get(int(icmp.type))
    if kind is None:
        return None
    detail = ""
    if kind == "redirect":
        detail = "gateway offered %s" % icmp.gw
    elif kind == "unreachable":
        detail = "code %d" % int(icmp.code)
    return Icmp(kind, pkt[IP].src, detail)


def parse_cleartext(pkt: Packet) -> tuple[str, str, str, int] | None:
    """L3P02. Protocol, endpoints and port. Merged with L2P11 when reported."""
    if IP not in pkt:
        return None
    source, destination = pkt[IP].src, pkt[IP].dst
    if TCP in pkt:
        for port in (int(pkt[TCP].dport), int(pkt[TCP].sport)):
            if port in CLEARTEXT_TCP:
                return CLEARTEXT_TCP[port], source, destination, port
        return None
    if UDP in pkt:
        for port in (int(pkt[UDP].dport), int(pkt[UDP].sport)):
            if port in CLEARTEXT_UDP:
                return CLEARTEXT_UDP[port], source, destination, port
    return None


def parse_outbound(pkt: Packet, local_network: str = "") -> Outbound | None:
    """L3P07. Where an internal host is talking to on the outside."""
    if IP not in pkt:
        return None
    source, destination = pkt[IP].src, pkt[IP].dst
    if not is_private(source) or is_private(destination):
        return None
    if local_network:
        try:
            if ipaddress.ip_address(source) not in ipaddress.ip_network(local_network):
                return None
        except ValueError:
            pass
    if TCP in pkt:
        return Outbound(source, destination, int(pkt[TCP].dport), "tcp")
    if UDP in pkt:
        return Outbound(source, destination, int(pkt[UDP].dport), "udp")
    return None


def parse_fragment(pkt: Packet) -> Fragment | None:
    """L3P08. Fragmented traffic on a local segment is unusual."""
    if IPv6ExtHdrFragment in pkt:
        return Fragment(pkt[IPv6].src, 6)
    if IP not in pkt:
        return None
    header = pkt[IP]
    # More fragments set, or a non-zero offset: either way it is a fragment.
    if int(header.frag) or (int(header.flags) & 0x01):
        return Fragment(header.src, 4)
    return None


def parse_hop_count(pkt: Packet) -> HopCount | None:
    """L3P10. A hop limit inconsistent with a flat segment means a router."""
    if IP in pkt:
        value, source = int(pkt[IP].ttl), pkt[IP].src
    elif IPv6 in pkt:
        value, source = int(pkt[IPv6].hlim), pkt[IPv6].src
    else:
        return None
    if not is_private(source) or value in FLAT_HOP_LIMITS:
        return None
    return HopCount(source, value)


PARSERS = (
    (parse_host, "hosts"),
    (parse_resolver, "resolvers"),
    (parse_dns_answer, "dns_answers"),
    (parse_ipv6_mode, "ipv6_modes"),
    (parse_icmp, "icmp"),
    (parse_fragment, "fragments"),
    (parse_hop_count, "hop_counts"),
)


def parse_l3(pkt: Packet, capture: Capture) -> None:
    """Dispatch one packet into the layer 3 records. Guarded by the caller."""
    if IP in pkt or IPv6 in pkt:
        capture.packets_seen += 1
    for parser, name in PARSERS:
        record = parser(pkt)
        if record is not None:
            capture.add(name, record)
            if name == "hosts":
                capture.stamp("%s@%s" % (record.ip, record.mac), getattr(pkt, "time", 0.0))
    outbound = parse_outbound(pkt, capture.local_network)
    if outbound is not None:
        capture.add("outbound", outbound)
