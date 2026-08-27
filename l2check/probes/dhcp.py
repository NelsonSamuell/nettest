"""L2A04 DHCP snooping.

One discover, then five seconds of listening. No request is ever sent and no
lease is ever accepted, so nothing is taken out of the pool: an offer that is
not requested is released by the server when it times out.
"""

from __future__ import annotations

import secrets

from scapy.layers.dhcp import BOOTP

from l2check import frames, parse, posture
from l2check.authorisation import ActiveSession
from l2check.models import Capture
from l2check.posture import ABSENT, INDETERMINATE, PRESENT, ProbeResult
from l2check.probes import listen_after_send

LISTEN_SECONDS = 5


def run(session: ActiveSession, capture: Capture) -> ProbeResult:
    """L2A04. Send one DHCP discover and count the servers that answer."""
    source = frames.probe_mac(4)
    xid = secrets.randbits(32)
    replies = listen_after_send(
        session,
        [frames.dhcp_discover(source, xid)],
        seconds=LISTEN_SECONDS,
        match=lambda packet: BOOTP in packet and packet[BOOTP].xid == xid,
    )

    servers = []
    for packet in replies:
        record = parse.parse_dhcp_server(packet)
        if record is not None and (record.server_mac, record.server_ip) not in servers:
            servers.append((record.server_mac, record.server_ip))

    if len(servers) > 1:
        listed = ", ".join("%s at %s" % (ip, mac) for mac, ip in servers)
        return ProbeResult(
            "L2A04",
            posture.DHCP_SNOOPING,
            ABSENT,
            "L2A04 active probe",
            "%d servers answered one discover: %s" % (len(servers), listed),
            frames_sent=1,
        )
    if len(servers) == 1:
        mac, ip = servers[0]
        return ProbeResult(
            "L2A04",
            posture.DHCP_SNOOPING,
            PRESENT,
            "L2A04 active probe",
            "one server answered, %s at %s, and no second server was reachable "
            "from this port" % (ip, mac),
            frames_sent=1,
        )
    return ProbeResult(
        "L2A04",
        posture.DHCP_SNOOPING,
        INDETERMINATE,
        "L2A04 active probe",
        "no offer within %d seconds; the segment may have no reachable DHCP "
        "server, which says nothing about snooping" % LISTEN_SECONDS,
        frames_sent=1,
    )
