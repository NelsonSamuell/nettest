"""Layer 3 packet builders. Pure functions, no sockets.

Scapy packets rather than bytes, because the kernel does the routing and address
resolution: a layer 3 check should not have to know the next hop's link layer
address to ask a question of a host two subnets away.
"""

from __future__ import annotations

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.ntp import NTPHeader
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet

# A documentation address, routed nowhere, so a cache entry for it cannot
# divert anything real.
REDIRECT_TARGET = "192.0.2.111"

SSDP_GROUP = "239.255.255.250"
SSDP_PORT = 1900
IGD_SEARCH_TARGET = "urn:schemas-upnp-org:device:InternetGatewayDevice:1"

# Enough ports to be useful, few enough to finish inside the runtime cap.
DEFAULT_TCP_PORTS = (
    21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 135, 139, 143, 179, 389, 443, 445,
    465, 514, 515, 548, 554, 587, 631, 636, 873, 902, 993, 995, 1080, 1194, 1433,
    1521, 1723, 1883, 1900, 2000, 2049, 2082, 2181, 2375, 3000, 3128, 3306, 3389,
    3478, 4443, 4567, 5000, 5001, 5060, 5222, 5353, 5432, 5555, 5601, 5672, 5900,
    5985, 6000, 6379, 6667, 7000, 7547, 8000, 8006, 8008, 8009, 8010, 8080, 8081,
    8088, 8123, 8291, 8443, 8728, 8888, 9000, 9090, 9091, 9100, 9200, 9443, 9999,
    10000, 11211, 27017, 32400, 49152, 49153, 51820,
)
DEFAULT_UDP_PORTS = (
    53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 514, 520, 623, 1194, 1701,
    1812, 1900, 3702, 4500, 5060, 5353, 5355, 7547, 11211,
)

SYN = 0x02
ACK = 0x10
RST = 0x04

# Community strings are not credentials to guess: this is the documented
# default read community, sent once to see whether the service answers at all.
SNMP_PUBLIC_GET = bytes.fromhex(
    "302902010104067075626c6963a11c0204414243440400020100300e300c06082b060102010101000500"
)


def arp_request(source_ip: str, target_ip: str) -> Packet:
    """One ARP request, the frame every host sends before talking."""
    return Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, psrc=source_ip, pdst=target_ip)


def tcp_syn(target: str, port: int) -> Packet:
    """One TCP SYN. The reply tells open from closed; silence means filtered."""
    return IP(dst=target) / TCP(dport=port, flags="S")


def udp_payload(port: int):
    """A payload the service on that port will actually answer."""
    if port == 53:
        return DNS(rd=1, qd=DNSQR(qname="example.com"))
    if port == 123:
        return NTPHeader()
    if port in (5353, 5355):
        return DNS(rd=0, qd=DNSQR(qname="_services._dns-sd._udp.local"))
    if port == SSDP_PORT:
        return ssdp_search().encode()
    if port == 161:
        return SNMP_PUBLIC_GET
    if port == 7547:
        return b"GET / HTTP/1.1\r\nHost: cpe\r\n\r\n"
    return b"\x00"


def udp_probe(target: str, port: int) -> Packet:
    """One UDP datagram with a payload appropriate to the port."""
    return IP(dst=target) / UDP(dport=port) / udp_payload(port)


def ssdp_search(target: str = IGD_SEARCH_TARGET, wait: int = 2) -> str:
    """The SSDP search a media player sends when it starts."""
    return (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: %s:%d\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: %d\r\n"
        "ST: %s\r\n\r\n" % (SSDP_GROUP, SSDP_PORT, wait, target)
    )


def ssdp_discover() -> Packet:
    """One multicast SSDP search for an internet gateway."""
    return IP(dst=SSDP_GROUP) / UDP(sport=1901, dport=SSDP_PORT) / ssdp_search().encode()


def icmp_redirect(gateway: str, local_ip: str, target: str = REDIRECT_TARGET) -> Packet:
    """One ICMP redirect for a destination that carries no traffic.

    A redirect is only considered by a host if it appears to come from the
    current gateway and quotes a packet the host plausibly sent, so it carries
    both. The destination is a documentation address routed nowhere, so a route
    installed for it can affect nothing while the check decides.
    """
    quoted = IP(src=local_ip, dst=target) / UDP(sport=53000, dport=53)
    return IP(src=gateway, dst=local_ip) / ICMP(type=5, code=1, gw=gateway) / quoted


# Ports worth knocking on from outside. A short list, because the answer is the
# same whether one or forty are reachable.
INBOUND_PORTS = (22, 23, 80, 443, 445, 3389, 7547, 8080, 8443)

# Forty destination ports for the egress test.
EGRESS_PORTS = (
    21, 22, 23, 25, 53, 80, 110, 123, 143, 443, 445, 465, 587, 993, 995, 1194,
    1723, 3306, 3389, 4500, 5060, 5222, 5432, 5900, 6667, 6881, 8080, 8333,
    8443, 9001, 9418, 11211, 19132, 25565, 27015, 27017, 31337, 33434, 51413,
    51820,
)

GRE_PROTOCOL = 47
ESP_PROTOCOL = 50

# A documentation prefix, so a forged source cannot be mistaken for a real host.
FORGED_SOURCE = "203.0.113.7"

# Option 131 is loose source routing, 137 is strict.
LSRR = 131
SSRR = 137


def egress_probes(target: str, marker: str) -> list:
    """One SYN to each egress port, plus GRE and ESP, plus a direct DNS query."""
    from scapy.layers.inet import IPOption

    probes = [IP(dst=target) / TCP(dport=port, flags="S") for port in EGRESS_PORTS]
    probes.append(IP(dst=target) / UDP(dport=53) / marker.encode())
    probes.append(IP(dst=target, proto=GRE_PROTOCOL) / marker.encode())
    probes.append(IP(dst=target, proto=ESP_PROTOCOL) / marker.encode())
    return probes


def spoofed(target: str, marker: str, source: str = FORGED_SOURCE) -> Packet:
    """One packet whose source is outside the local prefix."""
    return IP(src=source, dst=target) / UDP(dport=9001) / marker.encode()


def fragmented(target: str, marker: str) -> list:
    """Two fragments with the transport header split across the boundary.

    A filter that matches on ports in the first fragment alone sees nothing to
    match, which is what the check is measuring.
    """
    payload = marker.encode() + b"\x00" * 32
    whole = bytes((IP(dst=target) / UDP(dport=9001) / payload)[UDP])
    first = IP(dst=target, id=0xBEEF, proto=17, flags="MF", frag=0) / whole[:8]
    second = IP(dst=target, id=0xBEEF, proto=17, frag=1) / whole[8:]
    return [first, second]


def _route_option(kind: int, via: str):
    from scapy.layers.inet import IPOption

    packed = bytes(int(part) for part in via.split("."))
    return IPOption(bytes([kind, 7, 4]) + packed)


def source_routed(target: str, via: str, marker: str) -> list:
    """One loose and one strict source routed packet."""
    return [
        IP(dst=target, options=[_route_option(kind, via)])
        / UDP(dport=9001)
        / marker.encode()
        for kind in (LSRR, SSRR)
    ]


def dns_query(resolver: str, name: str) -> Packet:
    """One DNS query sent straight at a named resolver."""
    return IP(dst=resolver) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=name))
