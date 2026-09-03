"""Layer 3 passive parsers.

These hook into the existing capture loop rather than opening a second socket.
Same rule as the layer 2 parsers: protocol metadata only. Nothing here returns,
copies or retains the payload of a packet that is not to or from this interface.
"""

from __future__ import annotations

import ipaddress

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

from l2check.models import (
    DnsAnswerRecord,
    FragmentRecord,
    HopCountRecord,
    HostRecord,
    IcmpRecord,
    IPv6ModeRecord,
    OutboundRecord,
    ResolverRecord,
    ServiceAnnouncement,
)

DNS_PORT = 53
DOT_PORT = 853
DOH_PORT = 443
MDNS_PORT = 5353
LLMNR_PORT = 5355
NBNS_PORT = 137
SSDP_PORT = 1900
WSD_PORT = 3702

# Cleartext services worth naming when they appear between two hosts.
CLEARTEXT_TCP = {
    21: "FTP",
    23: "Telnet",
    25: "SMTP",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
}
CLEARTEXT_UDP = {161: "SNMP", 69: "TFTP"}

# Values a flat segment produces. Anything else means a router in the path.
FLAT_HOP_LIMITS = (255, 128, 64, 32)

# Scope is decided by prefix, not by ipaddress.is_private, which also returns
# True for the 2001:db8::/32 documentation range.
UNIQUE_LOCAL_V6 = ipaddress.ip_network("fc00::/7")
GLOBAL_V6 = ipaddress.ip_network("2000::/3")


def _text(value: object) -> str:
    if isinstance(value, bytes):
        return value.rstrip(b"\x00").decode("utf-8", "replace")
    return "" if value is None else str(value)


def is_private(address: str) -> bool:
    """True for RFC1918, unique local, loopback and link local addresses."""
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return False
    return parsed.is_private or parsed.is_link_local or parsed.is_loopback


def parse_host(pkt: Packet) -> HostRecord | None:
    """L3P01. One IP-to-MAC binding from ARP, NDP, DHCP or plain IP traffic."""
    if Ether not in pkt:
        return None
    mac = pkt[Ether].src
    if ARP in pkt and pkt[ARP].psrc not in ("", "0.0.0.0"):
        return HostRecord(pkt[ARP].hwsrc, pkt[ARP].psrc, 4, "arp")
    if ICMPv6ND_NA in pkt or ICMPv6ND_NS in pkt:
        if IPv6 in pkt and pkt[IPv6].src != "::":
            return HostRecord(mac, pkt[IPv6].src, 6, "ndp")
    if BOOTP in pkt and DHCP in pkt and pkt[BOOTP].yiaddr not in ("", "0.0.0.0"):
        return HostRecord(mac, pkt[BOOTP].yiaddr, 4, "dhcp")
    if IP in pkt and pkt[IP].src != "0.0.0.0":
        return HostRecord(mac, pkt[IP].src, 4, "traffic")
    if IPv6 in pkt and pkt[IPv6].src != "::":
        return HostRecord(mac, pkt[IPv6].src, 6, "traffic")
    return None


def parse_resolver(pkt: Packet) -> ResolverRecord | None:
    """L3P03. Which resolver a client is using, and over what transport."""
    if Ether not in pkt:
        return None
    if TCP in pkt and pkt[TCP].dport == DOT_PORT:
        target = pkt[IP].dst if IP in pkt else pkt[IPv6].dst
        return ResolverRecord(pkt[Ether].src, target, "DoT")
    if UDP not in pkt or pkt[UDP].dport != DNS_PORT or DNS not in pkt:
        return None
    if pkt[DNS].qr != 0:
        return None
    target = pkt[IP].dst if IP in pkt else pkt[IPv6].dst if IPv6 in pkt else ""
    return ResolverRecord(pkt[Ether].src, target, "Do53")


def parse_dns_answer(pkt: Packet) -> DnsAnswerRecord | None:
    """L3P03. An answer mapping an external name into private space.

    That means the resolver is rewriting, which is either a local blocklist or
    the condition a rebinding attack needs.
    """
    if UDP not in pkt or DNS not in pkt or pkt[UDP].sport != DNS_PORT:
        return None
    dns = pkt[DNS]
    if dns.qr != 1 or not dns.ancount:
        return None
    name = _text(dns.qd[0].qname).rstrip(".") if dns.qdcount else ""
    for index in range(dns.ancount):
        answer = dns.an[index]
        if answer.type not in (1, 28):
            continue
        address = _text(answer.rdata)
        if is_private(address) and name and not name.endswith(".local"):
            return DnsAnswerRecord(name, address, True)
    return None


def parse_ipv6_mode(pkt: Packet) -> IPv6ModeRecord | None:
    """L3P04. How a host got its IPv6 address, and whether it is globally routable.

    A global address on a LAN host is the precondition for inbound v6 testing.
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

    mac = pkt[Ether].src
    # A SLAAC address derived from the MAC carries ff:fe in the middle of the
    # interface identifier; anything else is either privacy extensions or DHCPv6.
    packed = parsed.packed
    eui64 = packed[11] == 0xFF and packed[12] == 0xFE
    mode = "slaac" if eui64 else "slaac-or-dhcpv6"
    return IPv6ModeRecord(mac, address, scope, mode, privacy=not eui64)


def parse_service(pkt: Packet) -> ServiceAnnouncement | None:
    """L3P05. Which host announces which service type, over which protocol."""
    if UDP not in pkt or Ether not in pkt:
        return None
    mac = pkt[Ether].src
    port = pkt[UDP].dport
    if port == SSDP_PORT:
        payload = bytes(pkt[UDP].payload)
        if not payload.startswith((b"NOTIFY", b"M-SEARCH", b"HTTP/1.1")):
            return None
        service = ""
        for line in payload.split(b"\r\n"):
            if line.upper().startswith((b"NT:", b"ST:")):
                service = _text(line.split(b":", 1)[1].strip())
        return ServiceAnnouncement("SSDP", mac, service or "unnamed")
    if port == WSD_PORT:
        return ServiceAnnouncement("WS-Discovery", mac, "unnamed")
    if port in (MDNS_PORT, LLMNR_PORT) and DNS in pkt and pkt[DNS].qdcount:
        name = _text(pkt[DNS].qd[0].qname).rstrip(".")
        protocol = "mDNS" if port == MDNS_PORT else "LLMNR"
        return ServiceAnnouncement(protocol, mac, name)
    if port == NBNS_PORT:
        return ServiceAnnouncement("NBNS", mac, "unnamed")
    return None


def parse_icmp(pkt: Packet) -> IcmpRecord | None:
    """L3P06. Redirects, unreachables and the legacy information requests."""
    if ICMPv6ND_Redirect in pkt:
        return IcmpRecord("redirect", pkt[IPv6].src, "IPv6 redirect")
    if ICMPv6DestUnreach in pkt:
        return IcmpRecord("unreachable", pkt[IPv6].src, "IPv6 unreachable")
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
    return IcmpRecord(kind, pkt[IP].src, detail)


def parse_outbound(pkt: Packet, local_cidr: str = "") -> OutboundRecord | None:
    """L3P07. Where an internal host is talking to on the outside."""
    if IP not in pkt:
        return None
    source, destination = pkt[IP].src, pkt[IP].dst
    if not is_private(source) or is_private(destination):
        return None
    if local_cidr:
        try:
            network = ipaddress.ip_interface(local_cidr).network
            if ipaddress.ip_address(source) not in network:
                return None
        except ValueError:
            pass
    if TCP in pkt:
        return OutboundRecord(source, destination, int(pkt[TCP].dport), "tcp")
    if UDP in pkt:
        return OutboundRecord(source, destination, int(pkt[UDP].dport), "udp")
    return None


def parse_fragment(pkt: Packet) -> FragmentRecord | None:
    """L3P08. Fragmented traffic on a local segment is unusual. Report the source."""
    if IPv6ExtHdrFragment in pkt:
        return FragmentRecord(pkt[IPv6].src, 6)
    if IP not in pkt:
        return None
    header = pkt[IP]
    # More-fragments set, or a non-zero offset: either way it is a fragment.
    if int(header.frag) or (int(header.flags) & 0x01):
        return FragmentRecord(header.src, 4)
    return None


def parse_hop_count(pkt: Packet) -> HopCountRecord | None:
    """L3P10. A hop limit inconsistent with a flat segment means a router in path."""
    if IP in pkt:
        value, source = int(pkt[IP].ttl), pkt[IP].src
    elif IPv6 in pkt:
        value, source = int(pkt[IPv6].hlim), pkt[IPv6].src
    else:
        return None
    if not is_private(source) or value in FLAT_HOP_LIMITS:
        return None
    return HopCountRecord(source, value)


# Parsers taking only a packet, dispatched like the layer 2 ones.
L3_PARSERS = (
    (parse_host, "hosts"),
    (parse_resolver, "resolvers"),
    (parse_dns_answer, "dns_answers"),
    (parse_ipv6_mode, "ipv6_modes"),
    (parse_service, "services"),
    (parse_icmp, "icmp"),
    (parse_fragment, "fragments"),
    (parse_hop_count, "hop_counts"),
)


def parse_l3(pkt: Packet, capture) -> None:
    """Dispatch one packet into the layer 3 records. Guarded by the caller."""
    for parser, name in L3_PARSERS:
        record = parser(pkt)
        if record is not None:
            capture.add(name, record)
            if name == "hosts":
                capture.stamp("%s@%s" % (record.ip, record.mac), getattr(pkt, "time", 0.0))

    outbound = parse_outbound(pkt, capture.local_cidr)
    if outbound is not None:
        capture.add("outbound", outbound)
