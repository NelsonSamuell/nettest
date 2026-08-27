"""The posture model.

Four states, and UNTESTED is never collapsed into ABSENT. A control is only
ABSENT when something was observed or sent that shows it is not enforcing.
A control nothing was learned about stays UNTESTED, because a quiet port is
not a protected port.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from l2check import wireless
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

NAME_RESOLUTION = "Name resolution poisoning protection"
MGMT_ENCRYPTION = "Management plane encryption"
RA_GUARD = "IPv6 RA Guard"
CLIENT_ISOLATION = "Client isolation"
UPNP_DISABLED = "UPnP IGD disabled"
GATEWAY_ADMIN = "Gateway management encrypted"

LINK_ENCRYPTION = "Link encryption"
PMF = "Protected Management Frames"
WPS_DISABLED = "WPS disabled"

WIRED = "wired"
WIRELESS = "wireless"

# Controls that mean something on any segment, wired or wireless.
COMMON_CONTROLS = (
    DHCP_SNOOPING,
    ARP_INSPECTION,
    NAME_RESOLUTION,
    MGMT_ENCRYPTION,
    RA_GUARD,
    CLIENT_ISOLATION,
    UPNP_DISABLED,
    GATEWAY_ADMIN,
)

# Controls that only exist on a switch port.
WIRED_CONTROLS = (
    BPDU_GUARD,
    ROOT_GUARD,
    DTP_DISABLED,
    PORT_SECURITY,
    NATIVE_VLAN,
    DISCOVERY_DISABLED,
    VLAN_PRUNING,
    FHRP_AUTH,
)

# Controls that only exist on a radio link.
WIRELESS_CONTROLS = (
    LINK_ENCRYPTION,
    PMF,
    WPS_DISABLED,
)

PROFILES = {
    WIRED: WIRED_CONTROLS + COMMON_CONTROLS,
    WIRELESS: WIRELESS_CONTROLS + COMMON_CONTROLS,
}

CONTROL_NAMES = WIRED_CONTROLS + WIRELESS_CONTROLS + COMMON_CONTROLS

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
    profile: str = WIRED

    @classmethod
    def new(cls, profile: str = WIRED) -> "Posture":
        """Return a posture with every control in the profile UNTESTED."""
        if profile not in PROFILES:
            raise ValueError("unknown profile: %s" % profile)
        posture = cls(profile=profile)
        for name in PROFILES[profile]:
            reason = ROOT_GUARD_REASON if name == ROOT_GUARD else "probe not selected"
            posture.controls[name] = Control(name, UNTESTED, reason, "")
        return posture

    def set(self, name: str, state: str, basis: str, detail: str = "") -> None:
        """Record a state for one control.

        A control outside the profile is added rather than refused, so a probe
        aimed at the other medium still reports what it found.
        """
        if name not in self.controls and name not in CONTROL_NAMES:
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
    def from_dict(cls, data: dict, profile: str = WIRED) -> "Posture":
        posture = cls.new(profile)
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

    hosts = {record.source_mac for record in capture.name_resolution}
    if hosts:
        protocols = ", ".join(_distinct(r.protocol for r in capture.name_resolution))
        posture.set(
            NAME_RESOLUTION,
            ABSENT,
            "L2P09 passive",
            "%s queries from %d host%s, any of which can be answered by anyone "
            "on the segment" % (protocols, len(hosts), "" if len(hosts) == 1 else "s"),
        )

    if capture.cleartext:
        protocols = ", ".join(_distinct(r.protocol for r in capture.cleartext))
        posture.set(
            MGMT_ENCRYPTION,
            ABSENT,
            "L2P11 passive",
            "%s observed in cleartext between other hosts" % protocols,
        )

    routers = capture.router_advert_sources()
    if len(routers) > 1:
        posture.set(
            RA_GUARD,
            ABSENT,
            "L2P12 passive",
            "%d sources advertising IPv6 routes: %s"
            % (len(routers), ", ".join(sorted(routers))),
        )
    elif routers:
        posture.set(
            RA_GUARD,
            UNTESTED,
            "L2P12 passive, one router only",
            "one router advertising; proving RA Guard absent would mean sending "
            "a router advertisement, which would reconfigure every host that "
            "believed it, so this tool does not",
        )

    if capture.peer_traffic:
        pairs = _distinct((r.source_mac, r.destination_mac) for r in capture.peer_traffic)
        posture.set(
            CLIENT_ISOLATION,
            ABSENT,
            "L2P14 passive",
            "unicast traffic between %d pair%s of other stations reached this "
            "port" % (len(pairs), "" if len(pairs) == 1 else "s"),
        )

    if capture.upnp:
        servers = _distinct(r.server for r in capture.upnp if r.server)
        posture.set(
            UPNP_DISABLED,
            ABSENT,
            "L2P13 passive",
            "UPnP announced on the segment%s"
            % (": " + ", ".join(servers) if servers else ""),
        )


def apply_wireless(posture: Posture, link) -> None:
    """Fold the read-only wireless link facts into the posture.

    These come from the kernel's cached scan results. Nothing was transmitted to
    learn them, so unlike the passive frame checks they can report PRESENT.
    """
    if link is None:
        return

    weak = link.weak_cipher
    if not link.encrypted:
        posture.set(
            LINK_ENCRYPTION,
            ABSENT,
            "L2P15 wireless link",
            "the link is %s, so every frame is readable by anyone in range"
            % link.security,
        )
    elif weak or link.security == wireless.WPA:
        posture.set(
            LINK_ENCRYPTION,
            ABSENT,
            "L2P15 wireless link",
            "%s with %s, which is broken" % (link.security, weak or "a legacy cipher"),
        )
    else:
        posture.set(
            LINK_ENCRYPTION,
            PRESENT,
            "L2P15 wireless link",
            "%s with %s" % (link.security, link.group_cipher or "a modern cipher"),
        )

    if link.pmf_required:
        posture.set(PMF, PRESENT, "L2P16 wireless link", "management frames are protected")
    elif link.pmf_capable:
        posture.set(
            PMF,
            INDETERMINATE,
            "L2P16 wireless link",
            "the access point offers protected management frames but does not "
            "require them, so a client that does not ask for them can still be "
            "deauthenticated",
        )
    else:
        posture.set(
            PMF,
            ABSENT,
            "L2P16 wireless link",
            "802.11w is not offered, so any device in range can deauthenticate "
            "any station on this network",
        )

    if link.wps:
        posture.set(
            WPS_DISABLED,
            ABSENT,
            "L2P17 wireless link",
            "WPS is advertised by the access point",
        )
    else:
        posture.set(
            WPS_DISABLED, PRESENT, "L2P17 wireless link", "WPS is not advertised"
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
    elif capture.gratuitous_arps:
        results.append(
            Finding(
                MEDIUM,
                "L2P08",
                "%d gratuitous ARPs observed" % capture.gratuitous_arps,
            )
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

    routers = capture.router_advert_sources()
    if len(routers) > 1:
        results.append(
            Finding(
                HIGH,
                "L2P12",
                "%d sources advertising IPv6 routes, so a rogue advertisement "
                "is already reaching this port: %s"
                % (len(routers), ", ".join(sorted(routers))),
            )
        )
    elif routers:
        prefixes = _distinct(r.prefix for r in capture.router_adverts if r.prefix)
        results.append(
            Finding(
                MEDIUM,
                "L2P12",
                "IPv6 router advertisements for %s; hosts autoconfigure from "
                "whatever advertises, so this is the rogue router surface"
                % (", ".join(prefixes) or "an unnamed prefix"),
            )
        )

    for server in _distinct(r.server or "an unnamed device" for r in capture.upnp):
        results.append(
            Finding(
                MEDIUM,
                "L2P13",
                "UPnP announced by %s, which lets any host on the segment open "
                "ports on the router" % server,
            )
        )

    pairs = _distinct((r.source_mac, r.destination_mac) for r in capture.peer_traffic)
    if pairs:
        results.append(
            Finding(
                HIGH,
                "L2P14",
                "Traffic between other stations is visible from this port, %d "
                "pair%s seen; clients are not isolated from each other"
                % (len(pairs), "" if len(pairs) == 1 else "s"),
            )
        )

    results.extend(wireless_findings(capture.wireless))

    order = {HIGH: 0, MEDIUM: 1}

    order = {HIGH: 0, MEDIUM: 1}
    return sorted(results, key=lambda finding: (order.get(finding.severity, 2), finding.check))


def wireless_findings(link) -> list[Finding]:
    """Return the findings the read-only wireless link facts support."""
    if link is None:
        return []
    results: list[Finding] = []

    if not link.encrypted:
        results.append(
            Finding(
                HIGH,
                "L2P15",
                "Wireless link is %s, so every frame is readable by anyone in range"
                % link.security,
            )
        )
    elif link.weak_cipher or link.security == wireless.WPA:
        results.append(
            Finding(
                HIGH,
                "L2P15",
                "Wireless link uses %s with %s, which is broken"
                % (link.security, link.weak_cipher or "a legacy cipher"),
            )
        )

    if not link.pmf_capable:
        results.append(
            Finding(
                HIGH,
                "L2P16",
                "No protected management frames, so any device in range can "
                "deauthenticate any station on this network",
            )
        )
    elif not link.pmf_required:
        results.append(
            Finding(
                MEDIUM,
                "L2P16",
                "Protected management frames are offered but not required, so a "
                "client that does not ask for them can still be deauthenticated",
            )
        )

    if link.wps:
        results.append(
            Finding(HIGH, "L2P17", "WPS is advertised by the access point")
        )
    return results


def profile_for(capture: Capture) -> str:
    """Pick the control set that matches the medium the capture came from."""
    if capture.wireless is not None or wireless.is_wireless(capture.interface):
        return WIRELESS
    return WIRED


def from_capture(capture: Capture, profile: str | None = None) -> tuple[Posture, list[Finding]]:
    """Build the posture and findings a passive capture supports."""
    posture = Posture.new(profile or profile_for(capture))
    apply_passive(posture, capture)
    apply_wireless(posture, capture.wireless)
    return posture, findings(capture)
