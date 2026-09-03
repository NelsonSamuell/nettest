"""Active layer 3 checks.

Same rule as layer 2: no check transmits directly. Each is handed an
ActiveSession and can only ask it to act, which is where the budgets, the
runtime cap, the send rate and the abort on unexpected state change live.

Bounded on purpose. A check establishes whether a control reacts and then stops,
because a control that dropped your packet and a box that stopped responding
look identical once you have flooded it.
"""

from __future__ import annotations

import time
from typing import Callable

from scapy.sendrecv import AsyncSniffer

from l2check.session import ActiveSession

SNIFFER_WARMUP = 0.3


def sweep(
    session: ActiveSession,
    packets: list,
    seconds: float,
    match: Callable[[object], bool],
) -> list:
    """Send a batch with a listener already running and return matching replies.

    Only matching packets are kept, in memory, for the length of the check.
    Nothing is written to disk.
    """
    replies: list = []
    sniffer = AsyncSniffer(
        iface=session.interface, store=False, lfilter=match, prn=replies.append
    )
    sniffer.start()
    time.sleep(SNIFFER_WARMUP)
    session.send_ip(packets)
    time.sleep(seconds)
    sniffer.stop()
    return replies


def registry_l3() -> dict:
    """Map each layer 3 check identifier to the function that runs it."""
    from l2check.l3.probes import discovery, host, management, reachability

    return {
        "L3A01": discovery.run_host_discovery,
        "L3A02": discovery.run_tcp_inventory,
        "L3A03": discovery.run_udp_inventory,
        "L3A04": management.run_management_plane,
        "L3A05": reachability.run_inbound_v4,
        "L3A06": management.run_upnp_mapping,
        "L3A07": reachability.run_egress,
        "L3A08": reachability.run_inbound_v6,
        "L3A09": reachability.run_guest_segmentation,
        "L3A10": reachability.run_dns_rebinding,
        "L3A11": reachability.run_resolver_scoping,
        "L3A12": host.run_icmp_redirect,
        "L3A13": reachability.run_anti_spoofing,
        "L3A14": reachability.run_fragment_handling,
        "L3A15": reachability.run_source_routing,
    }
