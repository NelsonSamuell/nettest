"""Frame builders. Pure functions, no sockets.

Every builder returns bytes and is constructed so the frame it returns cannot
change the state of the network it is sent on.
"""

from __future__ import annotations

import secrets

from scapy.contrib.dtp import DTP, DTPDomain, DTPNeighbor, DTPStatus, DTPType
from scapy.contrib.lldp import (
    LLDPDU,
    LLDPDUChassisID,
    LLDPDUEndOfLLDPDU,
    LLDPDUPortID,
    LLDPDUSystemName,
    LLDPDUTimeToLive,
)
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import ICMP, IP, UDP
from scapy.layers.l2 import ARP, LLC, SNAP, STP, Dot1Q, Dot3, Ether

STP_MULTICAST = "01:80:c2:00:00:00"
CISCO_MULTICAST = "01:00:0c:cc:cc:cc"
LLDP_MULTICAST = "01:80:c2:00:00:0e"
BROADCAST = "ff:ff:ff:ff:ff:ff"
UNSPECIFIED = "00:00:00:00:00:00"

# Locally administered, so a probe address can never collide with a real vendor
# assignment on the segment.
PROBE_OUI = (0x02, 0x00, 0x5E)

# 802.1D bridge priority is a four bit field scaled by 4096, so only multiples
# of 4096 up to 61440 are valid.
BRIDGE_PRIORITY_STEP = 4096
MAX_BRIDGE_PRIORITY = 61440

MARKER_PREFIX = "NETCHECK-"


class UnsafeFrameError(ValueError):
    """Raised when a frame cannot be built without risking network impact."""


def probe_mac(index: int) -> str:
    """The index'th deterministic probe address under the local OUI."""
    if not 0 <= index <= 0xFFFFFF:
        raise ValueError("probe address index out of range")
    tail = (index >> 16) & 0xFF, (index >> 8) & 0xFF, index & 0xFF
    return ":".join("%02x" % octet for octet in PROBE_OUI + tail)


def unique_macs(count: int, start: int = 1) -> list[str]:
    if count < 0:
        raise ValueError("count must not be negative")
    return [probe_mac(start + offset) for offset in range(count)]


def new_marker() -> str:
    """A payload marker a cooperating observer can match on."""
    return MARKER_PREFIX + secrets.token_hex(4).upper()


def worse_bridge_priority(observed_root_priority: int | None) -> int:
    """The lowest valid bridge priority strictly worse than the root's.

    Higher is worse in a spanning tree election, and the priority field is
    compared before the bridge address, so a strictly higher priority loses the
    election whatever address the frame carries.
    """
    if observed_root_priority is None:
        raise UnsafeFrameError(
            "no root priority was observed passively, so a losing bridge "
            "priority cannot be chosen"
        )
    if not 0 <= observed_root_priority <= 0xFFFF:
        raise UnsafeFrameError("observed root priority is not a 16 bit value")
    step = (observed_root_priority // BRIDGE_PRIORITY_STEP) * BRIDGE_PRIORITY_STEP
    worse = step + BRIDGE_PRIORITY_STEP
    if worse > MAX_BRIDGE_PRIORITY:
        raise UnsafeFrameError(
            "observed root priority %d is already the worst valid priority, so "
            "no losing priority exists" % observed_root_priority
        )
    return worse


def bpdu_losing_config(
    observed_root_priority: int | None,
    src_mac: str,
    port_id: int = 0x8001,
) -> bytes:
    """One 802.1D configuration BPDU that cannot win the root election.

    The topology change flag is left clear, because a topology change would
    flush address tables across the segment and that is an outage this tool must
    not be able to cause.
    """
    priority = worse_bridge_priority(observed_root_priority)
    frame = (
        Dot3(dst=STP_MULTICAST, src=src_mac)
        / LLC(dsap=0x42, ssap=0x42, ctrl=3)
        / STP(
            proto=0,
            version=0,
            bpdutype=0,
            bpduflags=0,
            rootid=priority,
            rootmac=src_mac,
            pathcost=0,
            bridgeid=priority,
            bridgemac=src_mac,
            portid=port_id,
        )
    )
    return bytes(frame)


def dtp_desirable(src_mac: str, domain: str = "") -> bytes:
    """One DTP frame offering to negotiate a trunk.

    Status 0x03 is desirable and type 0xa5 is negotiated 802.1Q, which is what
    an access port in a dynamic mode answers. The frame asks a question and is
    never followed by tagged traffic.
    """
    frame = (
        Dot3(dst=CISCO_MULTICAST, src=src_mac)
        / LLC(dsap=0xAA, ssap=0xAA, ctrl=3)
        / SNAP(OUI=0x00000C, code=0x2004)
        / DTP(
            ver=1,
            tlvlist=[
                DTPDomain(domain=domain.encode() + b"\x00"),
                DTPStatus(status=b"\x03"),
                DTPType(dtptype=b"\xa5"),
                DTPNeighbor(neighbor=src_mac),
            ],
        )
    )
    return bytes(frame)


def lldp_probe(src_mac: str, name: str, port_id: str, ttl: int = 30) -> bytes:
    """One LLDP frame with a benign identifier and a short time to live.

    The TTL is short so any neighbour entry the switch creates ages out within
    half a minute of the check finishing.
    """
    frame = (
        Ether(dst=LLDP_MULTICAST, src=src_mac, type=0x88CC)
        / LLDPDU()
        / LLDPDUChassisID(subtype=4, id=src_mac)
        / LLDPDUPortID(subtype=7, id=port_id.encode())
        / LLDPDUTimeToLive(ttl=ttl)
        / LLDPDUSystemName(system_name=name.encode())
        / LLDPDUEndOfLLDPDU()
    )
    return bytes(frame)


def dhcp_discover(src_mac: str, xid: int) -> bytes:
    """One DHCP discover.

    A discover asks what is offered. It is never followed by a request, so no
    address is taken out of the pool.
    """
    if not 0 <= xid <= 0xFFFFFFFF:
        raise ValueError("xid is not a 32 bit value")
    frame = (
        Ether(dst=BROADCAST, src=src_mac)
        / IP(src="0.0.0.0", dst="255.255.255.255")
        / UDP(sport=68, dport=67)
        / BOOTP(op=1, chaddr=bytes.fromhex(src_mac.replace(":", "")), xid=xid, flags=0x8000)
        / DHCP(options=[("message-type", "discover"), "end"])
    )
    return bytes(frame)


def gratuitous_arp(src_mac: str, claimed_ip: str) -> bytes:
    """One gratuitous ARP announcing an address confirmed unused.

    One announcement, no repetition, and no reply handling, so nothing can be
    drawn away from a host that already holds an address.
    """
    frame = Ether(dst=BROADCAST, src=src_mac) / ARP(
        op=2, hwsrc=src_mac, psrc=claimed_ip, hwdst=BROADCAST, pdst=claimed_ip
    )
    return bytes(frame)


def arp_request(src_mac: str, src_ip: str, target_ip: str) -> bytes:
    """One ordinary ARP request, the frame every host sends before talking."""
    frame = Ether(dst=BROADCAST, src=src_mac) / ARP(
        op=1, hwsrc=src_mac, psrc=src_ip, hwdst=UNSPECIFIED, pdst=target_ip
    )
    return bytes(frame)


def arp_probe(src_mac: str, target_ip: str) -> bytes:
    """One RFC 5227 ARP probe, used to introduce an address to the switch.

    The sender protocol address is 0.0.0.0, so the frame puts an address in the
    forwarding table without claiming an IP and without creating an ARP entry on
    any host that receives it.
    """
    return arp_request(src_mac, "0.0.0.0", target_ip)


def icmp_echo(src_mac: str, dst_mac: str, src_ip: str, dst_ip: str, marker: str) -> bytes:
    """One ICMP echo request carrying a marker payload."""
    frame = (
        Ether(dst=dst_mac, src=src_mac)
        / IP(src=src_ip, dst=dst_ip)
        / ICMP(type=8)
        / marker.encode()
    )
    return bytes(frame)


def double_tagged_icmp(
    src_mac: str,
    dst_mac: str,
    outer_vlan: int,
    inner_vlan: int,
    src_ip: str,
    dst_ip: str,
    marker: str,
) -> bytes:
    """One double tagged ICMP echo request carrying a marker payload.

    The outer tag must be the native VLAN of the trunk for the first tag to be
    stripped, which is the whole mechanism. The payload is the marker and
    nothing else, so an observer can identify the frame without this tool ever
    reading traffic that is not its own.
    """
    for vlan in (outer_vlan, inner_vlan):
        if not 0 <= vlan <= 4095:
            raise ValueError("VLAN identifier out of range")
    frame = (
        Ether(dst=dst_mac, src=src_mac)
        / Dot1Q(vlan=outer_vlan)
        / Dot1Q(vlan=inner_vlan)
        / IP(src=src_ip, dst=dst_ip)
        / ICMP(type=8)
        / marker.encode()
    )
    return bytes(frame)


def tcp_syn(src_mac: str, dst_mac: str, src_ip: str, dst_ip: str, port: int) -> bytes:
    """One TCP SYN, used to ask whether a management port answers."""
    from scapy.layers.inet import TCP

    frame = (
        Ether(dst=dst_mac, src=src_mac)
        / IP(src=src_ip, dst=dst_ip)
        / TCP(dport=port, flags="S")
    )
    return bytes(frame)
