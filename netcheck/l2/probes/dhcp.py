"""L2A04, DHCP snooping.

One discover, then five seconds of listening. No request is ever sent and no
lease is accepted, so nothing leaves the pool: an offer that is not requested is
released by the server when it times out.
"""

from __future__ import annotations

import secrets

from scapy.layers.dhcp import BOOTP

from netcheck.l2 import frames, parse
from netcheck.models import ABSENT, INDETERMINATE, PRESENT

LISTEN_SECONDS = 5


def run(context) -> tuple[str, str, str]:
    """Send one DHCP discover and count the servers that answer."""
    source = frames.probe_mac(4)
    xid = secrets.randbits(32)
    replies, sniffer = context.collect(
        LISTEN_SECONDS, lambda pkt: BOOTP in pkt and pkt[BOOTP].xid == xid
    )
    context.send_frames(frames.dhcp_discover(source, xid))
    context.sleeper(LISTEN_SECONDS)
    sniffer.stop()

    servers = []
    for packet in replies:
        record = parse.parse_dhcp_server(packet)
        if record is not None and (record.server_mac, record.server_ip) not in servers:
            servers.append((record.server_mac, record.server_ip))

    if len(servers) > 1:
        listed = ", ".join("%s at %s" % (ip, mac) for mac, ip in servers)
        return ABSENT, "L2A04", "%d servers answered one discover: %s" % (len(servers), listed)
    if len(servers) == 1:
        mac, ip = servers[0]
        return (
            PRESENT,
            "L2A04",
            "one server answered, %s at %s, and no second server was reachable "
            "from this port" % (ip, mac),
        )
    return (
        INDETERMINATE,
        "L2A04",
        "no offer within %d seconds. The segment may have no reachable server, "
        "which says nothing about snooping" % LISTEN_SECONDS,
    )
