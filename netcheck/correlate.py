"""The correlation layer.

A distinct stage after all checks and before the report. It joins what layer 2
learned about MAC addresses with what layer 3 learned about IP addresses, so the
report talks about devices rather than observations.

The findings here exist only because both layers are in one tool: a control
enforced at layer 2 whose layer 3 equivalent is not, a device on two segments, an
address on two MACs attributed to the layer that explains it.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from netcheck.models import ABSENT, HIGH, LOW, MEDIUM, PRESENT, Finding

LAN = "lan"
GUEST = "guest"
EXTERNAL = "external"
UNKNOWN = "unknown"

TESTED = "tested"
REACHABLE = "reachable"
FILTERED = "filtered"
UNTESTED_CELL = "untested"

# Layer 2 controls and the layer 3 control that ought to agree with them.
LAYER_PAIRS = (
    ("Client isolation", "Guest segmentation"),
    ("Switch management plane isolation", "Gateway management plane isolation"),
    ("VLAN isolation", "Inbound filtering, IPv4"),
)


@dataclass
class Device:
    macs: list = field(default_factory=list)
    ipv4: list = field(default_factory=list)
    ipv6: list = field(default_factory=list)
    oui_vendor: str = ""
    segment: str = UNKNOWN
    first_seen: str = ""
    last_seen: str = ""
    services_announced: list = field(default_factory=list)
    protocols_spoken: list = field(default_factory=list)
    findings: list = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "macs": self.macs,
            "ipv4": self.ipv4,
            "ipv6": self.ipv6,
            "oui_vendor": self.oui_vendor,
            "segment": self.segment,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "services_announced": self.services_announced,
            "protocols_spoken": self.protocols_spoken,
            "findings": self.findings,
        }


def is_locally_administered(mac: str) -> bool:
    """True when the address is locally assigned, which usually means randomised."""
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except (ValueError, IndexError):
        return False


def vendor_for(mac: str) -> str:
    """What can be said about an address without a vendor table.

    Whether it is a real vendor assignment or a randomised one is computed from
    the address itself and is always correct, which a shipped prefix list would
    not be.
    """
    return "locally assigned or randomised" if is_locally_administered(mac) else ""


def segment_of(address: str, config=None) -> str:
    """Which segment an address belongs to, from the targets file."""
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return UNKNOWN
    if config is not None:
        guest = getattr(config, "guest_subnet", "")
        if guest and parsed in ipaddress.ip_network(guest, strict=False):
            return GUEST
        for subnet in getattr(config, "subnets", []):
            network = ipaddress.ip_network(subnet, strict=False)
            if parsed.version == network.version and parsed in network:
                return LAN
    if parsed.is_link_local or parsed.is_loopback or parsed.is_multicast:
        return UNKNOWN
    return LAN if parsed.is_private else EXTERNAL


def _timestamp(value: float) -> str:
    if not value:
        return ""
    import datetime

    return datetime.datetime.fromtimestamp(
        value, datetime.timezone.utc
    ).isoformat(timespec="seconds")


def correlate(capture, config=None) -> list[Device]:
    """Build the device inventory by joining the two layers."""
    by_mac: dict[str, Device] = {}

    def device(mac: str) -> Device:
        if mac not in by_mac:
            by_mac[mac] = Device(macs=[mac], oui_vendor=vendor_for(mac))
        return by_mac[mac]

    windows: dict[str, tuple[float, float]] = {}
    for record in capture.hosts:
        entry = device(record.mac)
        bucket = entry.ipv4 if record.family == 4 else entry.ipv6
        if record.ip not in bucket:
            bucket.append(record.ip)
        if record.source not in entry.protocols_spoken:
            entry.protocols_spoken.append(record.source)
        first, last = capture.seen_window("%s@%s" % (record.ip, record.mac))
        seen_first, seen_last = windows.get(record.mac, (0.0, 0.0))
        windows[record.mac] = (
            first if not seen_first or (first and first < seen_first) else seen_first,
            max(last, seen_last),
        )

    for record in capture.arp:
        if record.claimed_ip and record.claimed_ip != "0.0.0.0":
            entry = device(record.source_mac)
            if record.claimed_ip not in entry.ipv4:
                entry.ipv4.append(record.claimed_ip)

    for record in capture.services:
        entry = device(record.source_mac)
        label = "%s %s" % (record.protocol, record.service_type)
        if label not in entry.services_announced:
            entry.services_announced.append(label)

    for record in capture.discovery:
        entry = device(record.source_mac)
        if record.protocol not in entry.protocols_spoken:
            entry.protocols_spoken.append(record.protocol)

    for mac, entry in by_mac.items():
        first, last = windows.get(mac, (0.0, 0.0))
        entry.first_seen = _timestamp(first)
        entry.last_seen = _timestamp(last)
        segments = {segment_of(a, config) for a in entry.ipv4 + entry.ipv6}
        segments.discard(UNKNOWN)
        if len(segments) == 1:
            entry.segment = segments.pop()
        elif segments:
            entry.segment = "+".join(sorted(segments))

    return sorted(by_mac.values(), key=lambda d: (d.segment, d.macs[0]))


def reachability(capture, results=None, config=None) -> dict:
    """The segment reachability matrix.

    Cells nothing established read untested. That is the point: a blank cell is
    not a filtered one.
    """
    devices = correlate(capture, config)
    segments = {d.segment for d in devices if d.segment != UNKNOWN and "+" not in d.segment}
    segments |= {LAN, GUEST}
    ordered = sorted(segments)

    matrix = {}
    for source in ordered:
        for destination in ordered:
            matrix[(source, destination)] = UNTESTED_CELL

    for result in results or []:
        pair = getattr(result, "segments", None)
        if not pair:
            continue
        state = getattr(result, "state", "")
        if state == ABSENT:
            matrix[pair] = REACHABLE
        elif state == PRESENT:
            matrix[pair] = FILTERED
        else:
            matrix[pair] = UNTESTED_CELL
    return matrix


def findings(devices: list[Device], posture=None, capture=None) -> list[Finding]:
    """Findings that only exist once the two layers are joined."""
    results: list[Finding] = []

    for entry in devices:
        subnets = {ip.rsplit(".", 1)[0] for ip in entry.ipv4}
        if len(subnets) > 1:
            results.append(
                Finding(MEDIUM, "COR01",
                        "%s holds addresses in %d subnets (%s). Which of a router, "
                        "a bridge, or a segmentation failure that is cannot be told "
                        "from here" % (entry.macs[0], len(subnets), ", ".join(sorted(subnets))),
                        "")
            )
        if "+" in entry.segment:
            results.append(
                Finding(HIGH, "COR02",
                        "%s appears on more than one segment (%s), so the segments "
                        "are not separated for that device"
                        % (entry.macs[0], entry.segment.replace("+", " and ")), "")
            )

    if posture is not None:
        for l2_name, l3_name in LAYER_PAIRS:
            l2_control = posture.controls.get(l2_name)
            l3_control = posture.controls.get(l3_name)
            if l2_control is None or l3_control is None:
                continue
            if l2_control.state == PRESENT and l3_control.state == ABSENT:
                results.append(
                    Finding(HIGH, "COR03",
                            "%s is enforced but %s is not, so the control holds at "
                            "layer 2 and is bypassed at layer 3" % (l2_name, l3_name), "")
                )

    announcing = [d for d in devices if d.services_announced]
    if announcing:
        results.append(
            Finding(LOW, "COR04",
                    "%d device%s services by name, which is how they are found "
                    "without any scanning"
                    % (len(announcing), " announces" if len(announcing) == 1 else "s announce"),
                    "")
        )
    return results
