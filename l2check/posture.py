"""The posture model.

Four states, and UNTESTED is never collapsed into ABSENT. A control is only
ABSENT when something was observed or sent that shows it is not enforcing.
A control nothing was learned about stays UNTESTED, because a quiet port is
not a protected port.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from l2check.models import HIGH, MEDIUM, Capture, Finding

PRESENT = "PRESENT"
ABSENT = "ABSENT"
INDETERMINATE = "INDETERMINATE"
UNTESTED = "UNTESTED"

STATES = (PRESENT, ABSENT, INDETERMINATE, UNTESTED)

BPDU_GUARD = "BPDU Guard"
ROOT_GUARD = "Root Guard"
DTP_DISABLED = "DTP disabled on access ports"
DHCP_SNOOPING = "DHCP Snooping"
ARP_INSPECTION = "Dynamic ARP Inspection"
PORT_SECURITY = "Port Security"
NATIVE_VLAN = "Native VLAN not default"
DISCOVERY_DISABLED = "Discovery protocol disclosure disabled"
VLAN_PRUNING = "Unused VLAN pruning"
FHRP_AUTH = "First-hop redundancy authentication"

CONTROL_NAMES = (
    BPDU_GUARD,
    ROOT_GUARD,
    DTP_DISABLED,
    DHCP_SNOOPING,
    ARP_INSPECTION,
    PORT_SECURITY,
    NATIVE_VLAN,
    DISCOVERY_DISABLED,
    VLAN_PRUNING,
    FHRP_AUTH,
)

# Root Guard cannot be tested without sending a BPDU superior to the current
# root, which is the one thing this tool will never do.
ROOT_GUARD_REASON = "not testable without claiming the root role"


@dataclass
class Control:
    name: str
    state: str
    basis: str
    detail: str


@dataclass
class ProbeResult:
    """What one active probe concluded, and how many frames it cost."""

    check: str
    control: str
    state: str
    basis: str
    detail: str
    frames_sent: int = 0


@dataclass
class Posture:
    controls: dict[str, Control] = field(default_factory=dict)

    @classmethod
    def new(cls) -> "Posture":
        """Return a posture with every control UNTESTED."""
        posture = cls()
        for name in CONTROL_NAMES:
            reason = ROOT_GUARD_REASON if name == ROOT_GUARD else "probe not selected"
            posture.controls[name] = Control(name, UNTESTED, reason, "")
        return posture

    def set(self, name: str, state: str, basis: str, detail: str = "") -> None:
        """Record a state for one control."""
        if name not in self.controls:
            raise KeyError("unknown control: %s" % name)
        if state not in STATES:
            raise ValueError("unknown state: %s" % state)
        self.controls[name] = Control(name, state, basis, detail)

    def apply(self, result: ProbeResult) -> None:
        """Record the outcome of one active probe."""
        self.set(result.control, result.state, result.basis, result.detail)

    def counts(self) -> dict[str, int]:
        tally = Counter(control.state for control in self.controls.values())
        return {state: tally.get(state, 0) for state in STATES}

    def exit_code(self) -> int:
        return 1 if self.counts()[ABSENT] else 0

    def to_dict(self) -> dict:
        return {
            name: {
                "state": control.state,
                "basis": control.basis,
                "detail": control.detail,
            }
            for name, control in self.controls.items()
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Posture":
        posture = cls.new()
        for name, values in data.items():
            posture.set(name, values["state"], values["basis"], values.get("detail", ""))
        return posture


def _distinct(values) -> list:
    seen = []
    for value in values:
        if value not in seen:
            seen.append(value)
    return seen


def _arp_conflicts(capture: Capture) -> dict[str, list[str]]:
    claims: dict[str, list[str]] = {}
    for record in capture.arp:
        if record.claimed_ip == "0.0.0.0":
            continue
        macs = claims.setdefault(record.claimed_ip, [])
        if record.source_mac not in macs:
            macs.append(record.source_mac)
    return {ip: macs for ip, macs in claims.items() if len(macs) > 1}


def apply_passive(posture: Posture, capture: Capture) -> None:
    """Fold the passive capture into the posture.

    Passive evidence can only move a control to ABSENT or INDETERMINATE. It can
    never make one PRESENT: seeing no BPDUs does not mean BPDU Guard is on, it
    means no BPDUs arrived during the window.
    """
    if capture.discovery:
        protocols = ", ".join(_distinct(r.protocol for r in capture.discovery))
        posture.set(
            DISCOVERY_DISABLED,
            ABSENT,
            "L2P01 passive",
            "%s frames observed on the port" % protocols,
        )

    if capture.dtp:
        posture.set(
            DTP_DISABLED,
            ABSENT,
            "L2P02 passive",
            "DTP offered, mode %s" % capture.dtp[0].mode,
        )

    if capture.bpdu:
        priorities = _distinct(str(r.root_priority) for r in capture.bpdu)
        posture.set(
            BPDU_GUARD,
            ABSENT,
            "L2P03 passive",
            "BPDUs reached the port, root priority %s" % ", ".join(priorities),
        )

    native_vlans = [r.native_vlan for r in capture.discovery if r.native_vlan is not None]
    if 1 in native_vlans:
        posture.set(NATIVE_VLAN, ABSENT, "L2P05 passive", "native VLAN is 1")
    elif native_vlans:
        posture.set(
            NATIVE_VLAN,
            PRESENT,
            "L2P05 passive",
            "native VLAN is %d" % native_vlans[0],
        )

    if capture.tagged:
        vlans = _distinct(str(r.vlan) for r in capture.tagged)
        posture.set(
            VLAN_PRUNING,
            ABSENT,
            "L2P06 passive",
            "tagged frames on an access port, VLAN %s" % ", ".join(vlans),
        )

    servers = _distinct((r.server_mac, r.server_ip) for r in capture.dhcp_servers)
    if len(servers) > 1:
        listed = ", ".join("%s at %s" % (ip, mac) for mac, ip in servers)
        posture.set(
            DHCP_SNOOPING,
            ABSENT,
            "L2P07 passive",
            "%d DHCP servers answering: %s" % (len(servers), listed),
        )

    conflicts = _arp_conflicts(capture)
    if conflicts:
        listed = ", ".join(
            "%s claimed by %s" % (ip, " and ".join(macs)) for ip, macs in conflicts.items()
        )
        posture.set(
            ARP_INSPECTION,
            INDETERMINATE,
            "L2P08 passive",
            "%s; a legitimate failover looks the same from one port" % listed,
        )

    unauthenticated = [r for r in capture.fhrp if not r.authenticated]
    if unauthenticated:
        record = unauthenticated[0]
        posture.set(
            FHRP_AUTH,
            ABSENT,
            "L2P10 passive",
            "%s group %s advertised without authentication" % (record.protocol, record.group),
        )
    elif capture.fhrp:
        posture.set(
            FHRP_AUTH,
            PRESENT,
            "L2P10 passive",
            "%s advertisements carry authentication" % capture.fhrp[0].protocol,
        )


def findings(capture: Capture) -> list[Finding]:
    """Return the passive findings, most severe first."""
    results: list[Finding] = []

    for record in _distinct(
        (r.protocol, r.device_id, r.platform, r.software_version) for r in capture.discovery
    ):
        protocol, device_id, platform, software = record
        described = ", ".join(part for part in (device_id, platform, software) if part)
        results.append(
            Finding(MEDIUM, "L2P01", "%s discloses %s" % (protocol, described or "device details"))
        )

    for mode in _distinct(r.mode for r in capture.dtp):
        results.append(
            Finding(HIGH, "L2P02", "Port negotiates trunking, mode %s" % mode)
        )

    for record in _distinct((r.root_priority, r.root_mac, r.root_path_cost) for r in capture.bpdu):
        priority, root_mac, cost = record
        default = " (default priority)" if priority // 4096 * 4096 == 32768 else ""
        results.append(
            Finding(
                HIGH,
                "L2P03",
                "BPDUs received on the port: root %s priority %d%s, path cost %d"
                % (root_mac, priority, default, cost),
            )
        )

    for domain, revision in _distinct((r.domain, r.revision) for r in capture.vtp):
        results.append(
            Finding(MEDIUM, "L2P04", "VTP domain %s at revision %d" % (domain, revision))
        )

    if any(r.native_vlan == 1 for r in capture.discovery):
        results.append(
            Finding(MEDIUM, "L2P05", "Native VLAN is 1, which is what makes double tagging work")
        )

    tagged_vlans = _distinct(r.vlan for r in capture.tagged)
    if tagged_vlans:
        results.append(
            Finding(
                HIGH,
                "L2P06",
                "802.1Q tagged frames on an access port, VLAN %s"
                % ", ".join(str(vlan) for vlan in tagged_vlans),
            )
        )

    servers = _distinct((r.server_mac, r.server_ip) for r in capture.dhcp_servers)
    if len(servers) > 1:
        results.append(
            Finding(
                HIGH,
                "L2P07",
                "%d DHCP servers observed: %s"
                % (len(servers), ", ".join("%s at %s" % (ip, mac) for mac, ip in servers)),
            )
        )

    gratuitous = [r for r in capture.arp if r.gratuitous]
    conflicts = _arp_conflicts(capture)
    if conflicts:
        results.append(
            Finding(
                MEDIUM,
                "L2P08",
                "Address claimed by more than one MAC: "
                + ", ".join(
                    "%s by %s" % (ip, " and ".join(macs)) for ip, macs in conflicts.items()
                ),
            )
        )
    elif gratuitous:
        results.append(
            Finding(MEDIUM, "L2P08", "%d gratuitous ARPs observed" % len(gratuitous))
        )

    by_protocol: dict[str, set[str]] = {}
    for record in capture.name_resolution:
        by_protocol.setdefault(record.protocol, set()).add(record.source_mac)
    for protocol, hosts in by_protocol.items():
        results.append(
            Finding(
                HIGH,
                "L2P09",
                "Name resolution poisoning surface: %s from %d host%s"
                % (protocol, len(hosts), "" if len(hosts) == 1 else "s"),
            )
        )

    for record in [r for r in capture.fhrp if not r.authenticated]:
        results.append(
            Finding(
                HIGH,
                "L2P10",
                "%s group %s for %s advertised without authentication, priority %s"
                % (record.protocol, record.group, record.virtual_ip or "unknown", record.priority),
            )
        )

    for protocol, source, destination in _distinct(
        (r.protocol, r.source, r.destination) for r in capture.cleartext
    ):
        results.append(
            Finding(
                MEDIUM,
                "L2P11",
                "Cleartext %s between %s and %s" % (protocol, source, destination),
            )
        )

    order = {HIGH: 0, MEDIUM: 1}
    return sorted(results, key=lambda finding: (order.get(finding.severity, 2), finding.check))


def from_capture(capture: Capture) -> tuple[Posture, list[Finding]]:
    """Build the posture and findings a passive capture supports."""
    posture = Posture.new()
    apply_passive(posture, capture)
    return posture, findings(capture)
