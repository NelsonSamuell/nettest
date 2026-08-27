"""Observation records and findings.

Every record here holds protocol metadata only. No field in this module ever
holds the payload of a frame that was not sent by or addressed to this tool,
which is the constraint the passive listener is built around.
"""

from __future__ import annotations

from dataclasses import dataclass, field

HIGH = "HIGH"
MEDIUM = "MEDIUM"
LOW = "LOW"


@dataclass
class Finding:
    severity: str
    check: str
    title: str


@dataclass
class DiscoveryRecord:
    protocol: str
    source_mac: str
    device_id: str = ""
    platform: str = ""
    software_version: str = ""
    port_id: str = ""
    native_vlan: int | None = None
    management_address: str = ""
    vtp_domain: str = ""


@dataclass
class DtpRecord:
    source_mac: str
    mode: str
    domain: str = ""


@dataclass
class BpduRecord:
    source_mac: str
    root_priority: int
    root_mac: str
    root_path_cost: int
    bridge_priority: int
    bridge_mac: str

    @property
    def root_priority_is_default(self) -> bool:
        return self.root_priority // 4096 * 4096 == 32768


@dataclass
class VtpRecord:
    source_mac: str
    domain: str
    revision: int


@dataclass
class TaggedFrameRecord:
    source_mac: str
    vlan: int


@dataclass
class DhcpServerRecord:
    server_mac: str
    server_ip: str


@dataclass
class ArpRecord:
    source_mac: str
    claimed_ip: str
    gratuitous: bool


@dataclass
class NameResolutionRecord:
    protocol: str
    source_mac: str
    query_name: str


@dataclass
class FhrpRecord:
    """A first hop redundancy advertisement.

    There is deliberately no field for the authentication value. Whether one is
    present is a finding; the value itself is a credential and is never stored.
    """

    protocol: str
    source_mac: str
    group: int | None
    priority: int | None
    virtual_ip: str
    authenticated: bool


@dataclass
class CleartextRecord:
    protocol: str
    source: str
    destination: str


@dataclass
class Capture:
    interface: str = ""
    duration: int = 0
    frames_seen: int = 0
    discovery: list[DiscoveryRecord] = field(default_factory=list)
    dtp: list[DtpRecord] = field(default_factory=list)
    bpdu: list[BpduRecord] = field(default_factory=list)
    vtp: list[VtpRecord] = field(default_factory=list)
    tagged: list[TaggedFrameRecord] = field(default_factory=list)
    dhcp_servers: list[DhcpServerRecord] = field(default_factory=list)
    arp: list[ArpRecord] = field(default_factory=list)
    name_resolution: list[NameResolutionRecord] = field(default_factory=list)
    fhrp: list[FhrpRecord] = field(default_factory=list)
    cleartext: list[CleartextRecord] = field(default_factory=list)

    def observed_root_priority(self) -> int | None:
        """Return the best root priority seen, or None if no BPDU was observed."""
        if not self.bpdu:
            return None
        return min(record.root_priority for record in self.bpdu)

    def observed_ips(self) -> set[str]:
        """Every IP address the capture saw claimed, used to veto --test-ip."""
        addresses = {record.claimed_ip for record in self.arp}
        addresses |= {record.server_ip for record in self.dhcp_servers}
        addresses |= {record.virtual_ip for record in self.fhrp}
        addresses |= {r.management_address for r in self.discovery}
        return {address for address in addresses if address}
