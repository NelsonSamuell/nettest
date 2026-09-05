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
