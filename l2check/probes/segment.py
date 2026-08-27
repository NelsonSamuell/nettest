"""L2A08 client isolation and L2A09 UPnP reachability.

Both probes are ordinary requests that any host on a network makes constantly.
L2A08 asks a bounded number of neighbours whether they are there, using the same
ARP request a host sends before any conversation. L2A09 sends the one SSDP
search a media player sends at startup.

Neither changes anything. L2A08 asks at most 25 addresses at five per second,
which is a fraction of what a laptop does when it joins a network, and it never
sends a second frame to an address that answered.
"""

from __future__ import annotations

import ipaddress
import time

from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import ARP, Ether

from l2check import frames, posture
from l2check.authorisation import ActiveSession
from l2check.models import Capture
from l2check.posture import ABSENT, INDETERMINATE, PRESENT, UNTESTED, ProbeResult
from l2check.probes import listen_after_send

DEFAULT_NEIGHBOURS = 25
MAX_NEIGHBOURS = 50
GAP_SECONDS = 0.2
LISTEN_SECONDS = 4
SSDP_GROUP = "239.255.255.250"
SSDP_PORT = 1900
SEARCH_TARGET = "urn:schemas-upnp-org:device:InternetGatewayDevice:1"


def _refused(check: str, control: str, detail: str) -> ProbeResult:
    return ProbeResult(check, control, UNTESTED, "%s refused" % check, detail)


def neighbour_addresses(cidr: str, limit: int) -> list[str]:
    """Return up to limit host addresses from the given network, excluding ours."""
    interface = ipaddress.ip_interface(cidr)
    network = interface.network
    if network.num_addresses > 65536:
        raise ValueError("network is too large to enumerate safely")
    chosen = []
    for host in network.hosts():
        if str(host) == str(interface.ip):
            continue
        chosen.append(str(host))
        if len(chosen) >= limit:
            break
    return chosen


def run_client_isolation(session: ActiveSession, capture: Capture) -> ProbeResult:
    """L2A08. Ask a bounded set of neighbours to answer, and see if any do."""
    if not session.local_cidr:
        return _refused(
            "L2A08",
            posture.CLIENT_ISOLATION,
            "the interface has no IPv4 address, so there are no neighbours to ask",
        )

    limit = min(DEFAULT_NEIGHBOURS, MAX_NEIGHBOURS, session.frames_remaining)
    targets = neighbour_addresses(session.local_cidr, limit)
    if not targets:
        return _refused(
            "L2A08", posture.CLIENT_ISOLATION, "no neighbour addresses to ask"
        )

    source = frames.probe_mac(8)
    answered: list[tuple[str, str]] = []
    sent = 0
    for address in targets:
        replies = listen_after_send(
            session,
            [frames.arp_probe(source, address)],
            seconds=GAP_SECONDS,
            match=lambda packet: ARP in packet and packet[ARP].op == 2,
        )
        sent += 1
        for packet in replies:
            pair = (packet[ARP].psrc, packet[ARP].hwsrc)
            if pair not in answered:
                answered.append(pair)

    if answered:
        listed = ", ".join("%s at %s" % (ip, mac) for ip, mac in answered[:5])
        return ProbeResult(
            "L2A08",
            posture.CLIENT_ISOLATION,
            ABSENT,
            "L2A08 active probe",
            "%d of %d neighbours answered, so stations can reach each other: %s"
            % (len(answered), sent, listed),
            frames_sent=sent,
        )
    return ProbeResult(
        "L2A08",
        posture.CLIENT_ISOLATION,
        PRESENT,
        "L2A08 active probe",
        "none of %d neighbours answered, which is what client isolation looks like"
        % sent,
        frames_sent=sent,
    )


def run_upnp(session: ActiveSession, capture: Capture) -> ProbeResult:
    """L2A09. Send one SSDP search for an internet gateway and count responders."""
    source = frames.probe_mac(9)
    if not session.local_cidr:
        return _refused(
            "L2A09", posture.UPNP_DISABLED, "the interface has no IPv4 address"
        )
    local_ip = str(ipaddress.ip_interface(session.local_cidr).ip)

    body = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: %s:%d\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 2\r\n"
        "ST: %s\r\n\r\n" % (SSDP_GROUP, SSDP_PORT, SEARCH_TARGET)
    )
    search = (
        Ether(dst="01:00:5e:7f:ff:fa", src=source)
        / IP(src=local_ip, dst=SSDP_GROUP)
        / UDP(sport=1901, dport=SSDP_PORT)
        / body.encode()
    )

    replies = listen_after_send(
        session,
        [bytes(search)],
        seconds=LISTEN_SECONDS,
        match=lambda packet: (
            UDP in packet
            and packet[UDP].sport == SSDP_PORT
            and bytes(packet[UDP].payload).startswith(b"HTTP/1.1")
        ),
    )

    responders = []
    for packet in replies:
        if IP in packet and packet[IP].src not in responders:
            responders.append(packet[IP].src)

    if responders:
        return ProbeResult(
            "L2A09",
            posture.UPNP_DISABLED,
            ABSENT,
            "L2A09 active probe",
            "%s answered a UPnP gateway search, so any host on the segment can "
            "ask it to open a port" % ", ".join(responders),
            frames_sent=1,
        )
    return ProbeResult(
        "L2A09",
        posture.UPNP_DISABLED,
        INDETERMINATE,
        "L2A09 active probe",
        "no answer to a UPnP gateway search within %d seconds; the router may "
        "have UPnP off, or may simply not answer this search target"
        % LISTEN_SECONDS,
        frames_sent=1,
    )
