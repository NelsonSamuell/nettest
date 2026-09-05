"""The posture model and the finding record.

Four states, and UNTESTED never collapses toward either PRESENT or ABSENT. A
check that learned nothing says so, and says why.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

PRESENT = "PRESENT"
ABSENT = "ABSENT"
INDETERMINATE = "INDETERMINATE"
UNTESTED = "UNTESTED"
STATES = (PRESENT, ABSENT, INDETERMINATE, UNTESTED)

L2 = "L2"
L3 = "L3"
HOST = "host"
LAYERS = (L2, L3, HOST)

HIGH = "HIGH"
MEDIUM = "MEDIUM"
LOW = "LOW"
SEVERITY_ORDER = {HIGH: 0, MEDIUM: 1, LOW: 2}

# A busy segment produces millions of frames. Records deduplicate on their own
# contents and then cap, because findings are built from the distinct facts
# observed and never from how many times each recurred.
MAX_RECORDS = 2000

# Reasons a check did not produce a state. These are contract strings: they
# appear in the JSON output and a reader keys off them.
BUDGET_EXHAUSTED = "budget_exhausted"
NOT_SELECTED = "not_selected"
UNSUPPORTED_PLATFORM = "unsupported_platform"
INSUFFICIENT_PRIVILEGE = "insufficient_privilege"
NO_OBSERVER = "no_observer"
PREREQUISITE_MISSING = "prerequisite_missing"

# The port security walk default, kept with the model so the CLI and the
# budget module agree on it without importing each other.
MAX_MACS_DEFAULT = 50


@dataclass
class Capture:
    interface: str = ""
    duration: int = 0
    frames_seen: int = 0
    parse_errors: int = 0
    gratuitous_arps: int = 0
    truncated: set = field(default_factory=set)
    discovery: list = field(default_factory=list)
    trunking: list = field(default_factory=list)
    bpdu: list = field(default_factory=list)
    vtp: list = field(default_factory=list)
    tagged: list = field(default_factory=list)
    dhcp_servers: list = field(default_factory=list)
    arp: list = field(default_factory=list)
    names: list = field(default_factory=list)
    fhrp: list = field(default_factory=list)
    cleartext: list = field(default_factory=list)
    router_adverts: list = field(default_factory=list)
    services: list = field(default_factory=list)
    hosts: list = field(default_factory=list)
    resolvers: list = field(default_factory=list)
    dns_answers: list = field(default_factory=list)
    ipv6_modes: list = field(default_factory=list)
    icmp: list = field(default_factory=list)
    outbound: list = field(default_factory=list)
    fragments: list = field(default_factory=list)
    hop_counts: list = field(default_factory=list)
    packets_seen: int = 0
    local_network: str = ""
    host_posture: object = None
    router_config: object = None
    first_seen: dict = field(default_factory=dict)
    last_seen: dict = field(default_factory=dict)
    _seen: set = field(default_factory=set, repr=False)

    def stamp(self, key: str, when: float) -> None:
        """When a thing was first and last seen, kept outside the dedup key."""
        if not when:
            return
        self.first_seen.setdefault(key, when)
        self.last_seen[key] = when

    def seen_window(self, key: str) -> tuple[float, float]:
        return self.first_seen.get(key, 0.0), self.last_seen.get(key, 0.0)

    def bindings(self) -> dict:
        """Address to the set of MACs that claimed it, across every source."""
        claims: dict = {}
        for record in self.hosts:
            claims.setdefault(record.ip, set()).add(record.mac)
        for record in self.arp:
            if record.claimed_ip and record.claimed_ip != "0.0.0.0":
                claims.setdefault(record.claimed_ip, set()).add(record.source_mac)
        return claims

    def add(self, name: str, record) -> bool:
        """Store a record unless it duplicates one held or the cap is reached."""
        from dataclasses import astuple

        sink = getattr(self, name)
        key = (name,) + astuple(record)
        if key in self._seen:
            return False
        if len(sink) >= MAX_RECORDS:
            self.truncated.add(name)
            return False
        self._seen.add(key)
        sink.append(record)
        return True

    def observed_root_priority(self) -> int | None:
        """The best root priority seen. L2A02 refuses to run without this."""
        if not self.bpdu:
            return None
        return min(record.root_priority for record in self.bpdu)

    def management_address(self) -> str:
        """A switch management address disclosed by L2P01, if any."""
        for record in self.discovery:
            if record.management_address:
                return record.management_address
        return ""

    def observed_ips(self) -> set[str]:
        found = {r.claimed_ip for r in self.arp}
        found |= {r.server_ip for r in self.dhcp_servers}
        found |= {r.virtual_ip for r in self.fhrp}
        found |= {r.management_address for r in self.discovery}
        return {address for address in found if address}

    def as_dict(self) -> dict:
        return {
            "interface": self.interface,
            "duration": self.duration,
            "frames_seen": self.frames_seen,
            "packets_seen": self.packets_seen,
            "parse_errors": self.parse_errors,
            "gratuitous_arps": self.gratuitous_arps,
            "truncated": sorted(self.truncated),
            "host": self.host_posture.as_dict() if self.host_posture else None,
            "router_config": self.router_config.as_dict() if self.router_config else None,
            "records": {
                name: len(getattr(self, name))
                for name in (
                    "discovery", "trunking", "bpdu", "vtp", "tagged", "dhcp_servers",
                    "arp", "names", "fhrp", "cleartext", "router_adverts", "services",
                    "hosts", "resolvers", "dns_answers", "ipv6_modes", "icmp",
                    "outbound", "fragments", "hop_counts",
                )
            },
        }


@dataclass
class Control:
    name: str
    layer: str
    state: str
    basis: str
    detail: str = ""


@dataclass
class Finding:
    severity: str
    check: str
    title: str
    remedy: str = ""


# Every control, the layer it belongs to, and the checks that can establish it.
CONTROL_TABLE: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("BPDU Guard", L2, ("L2A02",)),
    ("Root Guard", L2, ("L2P03", "L2A02")),
    ("DTP disabled on access ports", L2, ("L2P02", "L2A01")),
    ("DHCP Snooping", L2, ("L2P07", "L2A04")),
    ("Dynamic ARP Inspection", L2, ("L2A05",)),
    ("Port Security", L2, ("L2A03",)),
    ("Native VLAN not default", L2, ("L2P05",)),
    ("Discovery protocol disclosure disabled", L2, ("L2P01", "L2A07")),
    ("VLAN isolation", L2, ("L2A06",)),
    ("Client isolation", L2, ("L2A08",)),
    ("Switch management plane isolation", L2, ("L2A09",)),
    ("First-hop redundancy authentication", L2, ("L2P10",)),
    ("Inbound filtering, IPv4", L3, ("L3A05",)),
    ("Inbound filtering, IPv6", L3, ("L3A08",)),
    ("Egress filtering", L3, ("L3A07",)),
    ("Anti-spoofing", L3, ("L3A13",)),
    ("Gateway management plane isolation", L3, ("L3A04",)),
    ("UPnP mapping restraint", L3, ("L3A06",)),
    ("DNS rebinding protection", L3, ("L3A10",)),
    ("Resolver scoping", L3, ("L3A11",)),
    ("Guest segmentation", L3, ("L3A09",)),
    ("Fragment inspection", L3, ("L3A14",)),
    ("Source routing rejected", L3, ("L3A15",)),
    ("ICMP redirect handling", HOST, ("L3A12",)),
)

CONTROL_NAMES = tuple(name for name, _, _ in CONTROL_TABLE)
CONTROL_LAYER = {name: layer for name, layer, _ in CONTROL_TABLE}
CONTROL_CHECKS = {name: checks for name, _, checks in CONTROL_TABLE}


@dataclass
class Posture:
    controls: dict[str, Control] = field(default_factory=dict)

    @classmethod
    def new(cls) -> "Posture":
        """Every control UNTESTED, with the reason being that nothing ran yet."""
        posture = cls()
        for name, layer, checks in CONTROL_TABLE:
            posture.controls[name] = Control(
                name, layer, UNTESTED, ", ".join(checks), NOT_SELECTED
            )
        return posture

    def set(self, name: str, state: str, basis: str, detail: str = "") -> None:
        if name not in CONTROL_LAYER:
            raise KeyError("unknown control: %s" % name)
        if state not in STATES:
            raise ValueError("unknown state: %s" % state)
        self.controls[name] = Control(name, CONTROL_LAYER[name], state, basis, detail)

    def by_layer(self, layer: str) -> list[Control]:
        return [c for c in self.controls.values() if c.layer == layer]

    def counts(self) -> dict[str, int]:
        tally = Counter(c.state for c in self.controls.values())
        return {state: tally.get(state, 0) for state in STATES}

    def exit_code(self) -> int:
        return 1 if self.counts()[ABSENT] else 0

    def as_dict(self) -> dict:
        return {
            name: {
                "layer": c.layer,
                "state": c.state,
                "basis": c.basis,
                "detail": c.detail,
            }
            for name, c in self.controls.items()
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Posture":
        posture = cls.new()
        for name, values in data.items():
            if name in CONTROL_LAYER:
                posture.set(name, values["state"], values["basis"], values.get("detail", ""))
        return posture
