"""Observation records and findings.

Every record here holds protocol metadata only. No field in this module ever
holds the payload of a frame that was not sent by or addressed to this tool,
which is the constraint the passive listener is built around.
"""

from __future__ import annotations

from dataclasses import astuple, dataclass, field

# A busy segment can produce millions of frames in a capture window. Records are
# deduplicated on their own contents and then capped, because every finding is
# built from the distinct facts observed, never from how many times each
# recurred. Without this a capture on a trunk or a SPAN port exhausts memory.
MAX_RECORDS_PER_CHECK = 2000

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
class RouterAdvertRecord:
    source_mac: str
    source_ip: str
    prefix: str
    managed: bool
    router_lifetime: int


@dataclass
class UpnpRecord:
    source_mac: str
    source_ip: str
    server: str


@dataclass
class PeerTrafficRecord:
    """Traffic between two other stations, seen from this port.

    Only the addresses are kept. Seeing this at all is the finding: it means the
    segment is not isolating stations from each other.
    """

    source_mac: str
    destination_mac: str
    protocol: str


@dataclass
class CleartextRecord:
    protocol: str
    source: str
    destination: str


@dataclass
class HostRecord:
    """One IP-to-MAC binding, however it was learned."""

    mac: str
    ip: str
    family: int
    source: str


@dataclass
class ResolverRecord:
    client_mac: str
    resolver_ip: str
    transport: str


@dataclass
class DnsAnswerRecord:
    name: str
    address: str
    private: bool


@dataclass
class IPv6ModeRecord:
    mac: str
    address: str
    scope: str
    mode: str
    privacy: bool


@dataclass
class ServiceAnnouncement:
    protocol: str
    source_mac: str
    service_type: str


@dataclass
class IcmpRecord:
    kind: str
    source_ip: str
    detail: str


@dataclass
class OutboundRecord:
    source_ip: str
    destination_ip: str
    port: int
    transport: str


@dataclass
class FragmentRecord:
    source_ip: str
    family: int


@dataclass
class HopCountRecord:
    source_ip: str
    hop_limit: int


@dataclass
class Capture:
    interface: str = ""
    duration: int = 0
    frames_seen: int = 0
    packets_seen: int = 0
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
    router_adverts: list[RouterAdvertRecord] = field(default_factory=list)
    upnp: list[UpnpRecord] = field(default_factory=list)
    peer_traffic: list[PeerTrafficRecord] = field(default_factory=list)
    hosts: list[HostRecord] = field(default_factory=list)
    resolvers: list[ResolverRecord] = field(default_factory=list)
    dns_answers: list[DnsAnswerRecord] = field(default_factory=list)
    ipv6_modes: list[IPv6ModeRecord] = field(default_factory=list)
    services: list[ServiceAnnouncement] = field(default_factory=list)
    icmp: list[IcmpRecord] = field(default_factory=list)
    outbound: list[OutboundRecord] = field(default_factory=list)
    fragments: list[FragmentRecord] = field(default_factory=list)
    hop_counts: list[HopCountRecord] = field(default_factory=list)
    wireless: object | None = None
    local_macs: set = field(default_factory=set)

    # Counters that must survive deduplication.
    gratuitous_arps: int = 0
    parse_errors: int = 0
    truncated: set = field(default_factory=set)
    first_seen: dict = field(default_factory=dict)
    last_seen: dict = field(default_factory=dict)
    local_cidr: str = ""
    host_posture: object | None = None
    router_config: object | None = None
    _seen: set = field(default_factory=set, repr=False)

    def stamp(self, key: str, when: float) -> None:
        """Record when a thing was first and last seen, outside the dedup key."""
        if not when:
            return
        self.first_seen.setdefault(key, when)
        self.last_seen[key] = when

    def add(self, name: str, record) -> bool:
        """Store a record unless it duplicates one already held or the cap is hit.

        Returns True when the record was stored. Records are keyed on their own
        field values, so a protocol that repeats every two seconds contributes
        one entry rather than sixty.
        """
        sink = getattr(self, name)
        key = (name,) + astuple(record)
        if key in self._seen:
            return False
        if len(sink) >= MAX_RECORDS_PER_CHECK:
            self.truncated.add(name)
            return False
        self._seen.add(key)
        sink.append(record)
        return True

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
        addresses |= {r.source_ip for r in self.router_adverts}
        addresses |= {r.source_ip for r in self.upnp}
        return {address for address in addresses if address}

    def seen_window(self, key: str) -> tuple[float, float]:
        """First and last sighting of a key, or zeroes if it was never stamped."""
        return self.first_seen.get(key, 0.0), self.last_seen.get(key, 0.0)

    def bindings(self) -> dict[str, set[str]]:
        """IP to the set of MACs that claimed it, across every source."""
        claims: dict[str, set[str]] = {}
        for record in self.hosts:
            claims.setdefault(record.ip, set()).add(record.mac)
        for record in self.arp:
            if record.claimed_ip and record.claimed_ip != "0.0.0.0":
                claims.setdefault(record.claimed_ip, set()).add(record.source_mac)
        return claims

    def router_advert_sources(self) -> set[str]:
        """Distinct routers seen advertising, which is what L2P12 counts."""
        return {record.source_mac for record in self.router_adverts}
