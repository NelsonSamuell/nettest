"""The correlation layer.

Runs after every check and before the report. Joins what layer 2 learned about
MAC addresses with what layer 3 learned about IP addresses, so the report talks
about devices rather than about observations.

The interesting findings live here rather than in any single check: one MAC in
two subnets, one address on two MACs, a device on the guest segment that also
appears in the LAN inventory, and a control enforced at layer 2 whose layer 3
equivalent is not.
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field
from pathlib import Path

from l2check.models import HIGH, LOW, MEDIUM, Capture, Finding

OUI_FILE = Path(__file__).resolve().parent.parent / "data" / "oui.json"

LAN = "lan"
GUEST = "guest"
EXTERNAL = "external"
UNKNOWN = "unknown"

TESTED = "tested"
REACHABLE = "reachable"
FILTERED = "filtered"
UNTESTED_CELL = "untested"

# Layer 2 controls and the layer 3 control that ought to agree with them. A
# control enforced at one layer and absent at the other is the finding.
LAYER_PAIRS = (
    ("Client isolation", "Guest segmentation"),
    ("UPnP IGD disabled", "UPnP mapping restraint"),
    ("Gateway management encrypted", "Management plane isolation"),
)


@dataclass
class Device:
    macs: list[str] = field(default_factory=list)
    ipv4: list[str] = field(default_factory=list)
    ipv6: list[str] = field(default_factory=list)
    oui_vendor: str = ""
    segment: str = UNKNOWN
    first_seen: float = 0.0
    last_seen: float = 0.0
    services_announced: list[str] = field(default_factory=list)
    protocols_spoken: list[str] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)

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
    """True when the MAC is locally assigned, which usually means randomised."""
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except (ValueError, IndexError):
        return False


def load_oui(path: Path = OUI_FILE) -> dict:
    """Read the optional OUI prefix table. Absent or empty is fine."""
    if not path.is_file():
        return {}
    data = json.loads(path.read_text())
    return {str(k).lower(): str(v) for k, v in (data.get("prefixes") or {}).items()}


def vendor_for(mac: str, prefixes: dict | None = None) -> str:
    """Vendor for a MAC, or a computed description when the table has no entry.

    The prefix table ships empty, so the useful answer most of the time is
    whether the address is a real vendor assignment or a randomised one.
    """
    if is_locally_administered(mac):
        return "locally assigned or randomised"
    table = load_oui() if prefixes is None else prefixes
    return table.get(mac.lower()[:8], "")


def segment_of(address: str, targets=None) -> str:
    """Which segment an address belongs to, from the targets file."""
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return UNKNOWN
    if targets is not None:
        guest = getattr(targets, "guest_subnet", "")
        if guest and parsed in ipaddress.ip_network(guest, strict=False):
            return GUEST
        for subnet in getattr(targets, "subnets", []):
            if parsed in ipaddress.ip_network(subnet, strict=False):
                return LAN
    if parsed.is_link_local or parsed.is_loopback:
        return UNKNOWN
    return LAN if parsed.is_private else EXTERNAL


def correlate(capture: Capture, targets=None) -> list[Device]:
    """Build the device inventory by joining the layer 2 and layer 3 records."""
    prefixes = load_oui()
    by_mac: dict[str, Device] = {}

    def device(mac: str) -> Device:
        if mac not in by_mac:
            by_mac[mac] = Device(macs=[mac], oui_vendor=vendor_for(mac, prefixes))
        return by_mac[mac]

    for record in capture.hosts:
        entry = device(record.mac)
        bucket = entry.ipv4 if record.family == 4 else entry.ipv6
        if record.ip not in bucket:
            bucket.append(record.ip)
        if record.source not in entry.protocols_spoken:
            entry.protocols_spoken.append(record.source)
        first, last = capture.seen_window("%s@%s" % (record.ip, record.mac))
        if first and (not entry.first_seen or first < entry.first_seen):
            entry.first_seen = first
        if last > entry.last_seen:
            entry.last_seen = last

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

    for entry in by_mac.values():
        addresses = entry.ipv4 + entry.ipv6
        segments = {segment_of(address, targets) for address in addresses}
        segments.discard(UNKNOWN)
        if len(segments) == 1:
            entry.segment = segments.pop()
        elif segments:
            entry.segment = "+".join(sorted(segments))

    return sorted(by_mac.values(), key=lambda d: (d.segment, d.macs[0]))


def reachability(capture: Capture, results=None, targets=None) -> dict:
    """Build the segment reachability matrix from whatever has been tested.

    Cells nothing established stay untested. That is the whole point: a blank
    cell is not a filtered one.
    """
    devices = correlate(capture, targets)
    segments = sorted({d.segment for d in devices if d.segment != UNKNOWN})
    for extra in (LAN, GUEST):
        if extra not in segments:
            segments.append(extra)
    segments = sorted(set(segments))

    matrix = {}
    for source in segments:
        for destination in segments:
            matrix[(source, destination)] = UNTESTED_CELL

    for result in results or []:
        pair = getattr(result, "segments", None)
        if not pair:
            continue
        state = REACHABLE if result.state == "ABSENT" else FILTERED
        if result.state in ("UNTESTED", "INDETERMINATE"):
            state = UNTESTED_CELL
        matrix[pair] = state
    return matrix


def correlation_findings(
    devices: list[Device], posture=None, capture: Capture | None = None
) -> list[Finding]:
    """Findings that only exist once the two layers are joined."""
    results: list[Finding] = []

    for entry in devices:
        subnets = {ip.rsplit(".", 1)[0] for ip in entry.ipv4}
        if len(subnets) > 1:
            results.append(
                Finding(
                    MEDIUM,
                    "COR01",
                    "%s holds addresses in %d subnets (%s): a router, a bridge, "
                    "or a segmentation failure"
                    % (entry.macs[0], len(subnets), ", ".join(sorted(subnets))),
                )
            )
        if "+" in entry.segment:
            results.append(
                Finding(
                    HIGH,
                    "COR02",
                    "%s appears on more than one segment (%s), so the segments "
                    "are not separated for that device"
                    % (entry.macs[0], entry.segment.replace("+", " and ")),
                )
            )

    if capture is not None:
        conflicts = {ip: macs for ip, macs in capture.bindings().items() if len(macs) > 1}
        churn = {r.server_ip for r in capture.dhcp_servers}
        for ip, macs in sorted(conflicts.items()):
            gratuitous = any(r.claimed_ip == ip and r.gratuitous for r in capture.arp)
            cause = (
                "an ARP anomaly, cross referenced with L2P08"
                if gratuitous
                else "DHCP churn" if ip in churn else "cause unclear"
            )
            results.append(
                Finding(
                    HIGH,
                    "COR03",
                    "%s claimed by %s: %s"
                    % (ip, " and ".join(sorted(macs)), cause),
                )
            )

    if posture is not None:
        for l2_name, l3_name in LAYER_PAIRS:
            l2_control = posture.controls.get(l2_name)
            l3_control = posture.controls.get(l3_name)
            if l2_control is None or l3_control is None:
                continue
            if l2_control.state == "PRESENT" and l3_control.state == "ABSENT":
                results.append(
                    Finding(
                        HIGH,
                        "COR04",
                        "%s is enforced but %s is not, so the control holds at "
                        "layer 2 and is bypassed at layer 3" % (l2_name, l3_name),
                    )
                )

    announcing = [d for d in devices if d.services_announced]
    if announcing:
        results.append(
            Finding(
                LOW,
                "COR05",
                "%d device%s services by name, which is how they are found "
                "without any scanning"
                % (len(announcing), " announces" if len(announcing) == 1 else "s announce"),
            )
        )

    order = {HIGH: 0, MEDIUM: 1, LOW: 2}
    return sorted(results, key=lambda f: (order.get(f.severity, 3), f.check))
