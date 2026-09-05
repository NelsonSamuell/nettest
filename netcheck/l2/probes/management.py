"""L2A08 client isolation and L2A09 switch management plane reachability.

L2A08 is the layer 2 half of what L3A09 measures at layer 3: whether one station
can reach another on the same segment. Confirmation needs the observer running
on that other host, because a silent segment and an isolated one look identical
from here.

L2A09 asks whether the management address a switch disclosed through CDP or LLDP
answers from a user port. Reaching it means the management VLAN is not isolated.
"""

from __future__ import annotations

from scapy.layers.inet import TCP
from scapy.layers.l2 import ARP

from netcheck.l2 import frames
from netcheck.models import (
    ABSENT,
    INDETERMINATE,
    NO_OBSERVER,
    PREREQUISITE_MISSING,
    PRESENT,
    UNTESTED,
)

LISTEN_SECONDS = 5
OBSERVER_SECONDS = 5
MANAGEMENT_PORT = 443


def run_client_isolation(context) -> tuple:
    """L2A08. Two frames to another host, confirmed by an observer on it."""
    if not context.observer:
        return (
            INDETERMINATE,
            "L2A08",
            "%s: reaching another station can only be confirmed by an observer "
            "running on it" % NO_OBSERVER,
        )
    target = context.observer.rsplit(":", 1)[0]
    source_ip = context.address()
    if not source_ip:
        return (
            UNTESTED,
            "L2A08",
            "%s: this interface has no address to send from" % PREREQUISITE_MISSING,
        )

    marker = frames.new_marker()
    source = frames.probe_mac(8)
    context.send_frames(
        [
            frames.arp_request(source, source_ip, target),
            frames.icmp_echo(source, "ff:ff:ff:ff:ff:ff", source_ip, target, marker),
        ]
    )

    seen = context.ask_observer(marker, OBSERVER_SECONDS)
    if seen is None:
        return (
            INDETERMINATE,
            "L2A08",
            "the observer at %s did not answer, so delivery is unknown" % context.observer,
        )
    if seen:
        return ABSENT, "L2A08", "the observer on %s received frames from this port" % target
    return PRESENT, "L2A08", "the observer on %s saw nothing from this port" % target


def run_management_reachable(context) -> tuple:
    """L2A09. Whether the disclosed switch management address answers here."""
    address = context.capture.management_address() if context.capture else ""
    if not address:
        return (
            UNTESTED,
            "L2A09",
            "%s: L2P01 disclosed no switch management address" % PREREQUISITE_MISSING,
        )

    source_ip = context.address()
    if not source_ip:
        return (
            UNTESTED,
            "L2A09",
            "%s: this interface has no address to send from" % PREREQUISITE_MISSING,
        )

    source = frames.probe_mac(9)
    replies, sniffer = context.collect(
        LISTEN_SECONDS,
        lambda pkt: TCP in pkt or (ARP in pkt and pkt[ARP].psrc == address),
    )
    context.send_frames(
        [
            frames.arp_request(source, source_ip, address),
            frames.tcp_syn(source, "ff:ff:ff:ff:ff:ff", source_ip, address, MANAGEMENT_PORT),
        ]
    )
    context.sleeper(LISTEN_SECONDS)
    sniffer.stop()

    answered = [p for p in replies if ARP in p and p[ARP].psrc == address]
    if answered:
        return (
            ABSENT,
            "L2A09",
            "the switch management address %s answers from this access port, so "
            "the management VLAN is not isolated from user ports" % address,
        )
    return (
        INDETERMINATE,
        "L2A09",
        "%s did not answer within %d seconds. It may be isolated, or simply not "
        "answering this port" % (address, LISTEN_SECONDS),
    )
