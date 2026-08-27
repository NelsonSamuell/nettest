"""Active probes.

Prove the attack is possible, never perform it. Every probe here is built so
that succeeding cannot cause an outage: the BPDU cannot win an election, MAC
addresses arrive one at a time rather than at flood rate, one DHCP discover is
sent and never a request, and the ARP announcement is for an address the
operator has confirmed is unused.

No probe transmits directly. Each one is handed an
:class:`l2check.authorisation.ActiveSession` and can only ask it to send, which
is where the gate, the total frame cap and the runtime cap are enforced.
"""

from __future__ import annotations

import time
from typing import Callable

from scapy.sendrecv import AsyncSniffer

from l2check.authorisation import ACTIVE_CHECKS, ActiveSession, CapExceeded, LinkStateChanged
from l2check.models import Capture
from l2check.posture import ProbeResult

SNIFFER_WARMUP = 0.3


def listen_after_send(
    session: ActiveSession,
    outgoing: list[bytes],
    seconds: float,
    match: Callable[[object], bool],
) -> list:
    """Send frames with a listener already running and return matching replies.

    Only packets that match are kept, and they are kept in memory for the length
    of the probe. Nothing is written to disk.
    """
    replies: list = []
    sniffer = AsyncSniffer(
        iface=session.interface,
        store=False,
        lfilter=match,
        prn=replies.append,
    )
    sniffer.start()
    time.sleep(SNIFFER_WARMUP)
    session.send(outgoing)
    time.sleep(seconds)
    sniffer.stop()
    return replies


def registry() -> dict[str, Callable[[ActiveSession, Capture], ProbeResult]]:
    """Map each probe identifier to the function that runs it."""
    from l2check.probes import arp, dhcp, port_security, spanning_tree, trunking, vlan_hop

    return {
        "L2A01": trunking.run_dtp,
        "L2A02": spanning_tree.run,
        "L2A03": port_security.run,
        "L2A04": dhcp.run,
        "L2A05": arp.run,
        "L2A06": vlan_hop.run,
        "L2A07": trunking.run_discovery_injection,
    }


def run_selected(
    session: ActiveSession,
    capture: Capture,
    out: Callable[[str], None] = print,
) -> list[ProbeResult]:
    """Run the selected probes in identifier order, stopping at any hard stop."""
    probes = registry()
    results: list[ProbeResult] = []
    for check in sorted(session.tests, key=ACTIVE_CHECKS.index):
        try:
            results.append(probes[check](session, capture))
        except CapExceeded as error:
            out("stopping: %s" % error)
            break
        except LinkStateChanged as error:
            out("stopping: %s" % error)
            break
    return results
