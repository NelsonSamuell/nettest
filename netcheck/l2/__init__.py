"""Layer 2 checks: what the switch port itself enforces.

This module registers every layer 2 check and turns a passive capture into
control states and findings. Passive evidence can move a control to ABSENT or
INDETERMINATE and never to PRESENT: not seeing something is not evidence that
something is being enforced.
"""

from __future__ import annotations

from netcheck.models import (
    ABSENT,
    HIGH,
    INDETERMINATE,
    LOW,
    MEDIUM,
    PRESENT,
    Finding,
    Posture,
)
from netcheck.platform.detect import RAW_L2_CAPTURE, RAW_L2_SEND
from netcheck.registry import Check, Registry

CAPTURE = frozenset({RAW_L2_CAPTURE})
SEND = frozenset({RAW_L2_SEND, RAW_L2_CAPTURE})

PASSIVE = (
    ("L2P01", "Discovery protocol disclosure", ("Discovery protocol disclosure disabled",)),
    ("L2P02", "Dynamic trunking negotiation offered", ("DTP disabled on access ports",)),
    ("L2P03", "Spanning tree BPDUs on an access port", ("Root Guard",)),
    ("L2P04", "VTP frames observed", ()),
    ("L2P05", "Native VLAN is the default", ("Native VLAN not default",)),
    ("L2P06", "802.1Q tagged frames on an access port", ()),
    ("L2P07", "Multiple DHCP servers observed", ("DHCP Snooping",)),
    ("L2P08", "Gratuitous ARP anomalies", ()),
    ("L2P09", "Name resolution poisoning surface", ()),
    ("L2P10", "First-hop redundancy without authentication",
     ("First-hop redundancy authentication",)),
    ("L2P11", "Cleartext management protocols", ()),
    ("L2P12", "Router advertisements observed", ()),
    ("L2P13", "Service announcement surface", ()),
)


def register(registry: Registry) -> Registry:
    """Add every layer 2 check. Probes import lazily to avoid a cycle."""
    from netcheck.l2.probes import (
        arp,
        dhcp,
        management,
        port_security,
        spanning_tree,
        trunking,
        vlan,
    )

    active = (
        ("L2A01", "DTP trunk negotiation", ("DTP disabled on access ports",),
         trunking.run_dtp, ("L2P02",)),
        ("L2A02", "BPDU Guard verification", ("BPDU Guard",),
         spanning_tree.run, ("L2P03",)),
        ("L2A03", "Port security threshold", ("Port Security",),
         port_security.run, ()),
        ("L2A04", "DHCP snooping", ("DHCP Snooping",), dhcp.run, ("L2P07",)),
        ("L2A05", "Dynamic ARP Inspection", ("Dynamic ARP Inspection",),
         arp.run, ("L2P08",)),
        ("L2A06", "Double tagging reachability", ("VLAN isolation",),
         vlan.run, ("L2P05", "L2P06")),
        ("L2A07", "Discovery protocol injection",
         ("Discovery protocol disclosure disabled",), trunking.run_lldp_injection, ("L2P01",)),
        ("L2A08", "Client isolation", ("Client isolation",),
         management.run_client_isolation, ()),
        ("L2A09", "Switch management plane reachable",
         ("Switch management plane isolation",), management.run_management_reachable, ("L2P01",)),
    )

    for identifier, title, controls in PASSIVE:
        registry.register(Check(identifier, title, controls, requires=CAPTURE))
    for identifier, title, controls, run, depends in active:
        registry.register(
            Check(identifier, title, controls, requires=SEND, depends_on=depends, run=run)
        )
    return registry


def _distinct(values) -> list:
    seen = []
    for value in values:
        if value not in seen:
            seen.append(value)
    return seen


def apply_passive(posture: Posture, capture) -> None:
    """Fold the capture into the posture.

    Only ABSENT and INDETERMINATE are reachable from here. Seeing no BPDUs does
    not mean BPDU Guard is on, it means no BPDUs arrived during the window.
    """
    if capture.discovery:
        protocols = ", ".join(_distinct(r.protocol for r in capture.discovery))
        posture.set(
            "Discovery protocol disclosure disabled", ABSENT, "L2P01 passive",
            "%s frames observed on the port" % protocols,
        )

    if capture.trunking:
        posture.set(
            "DTP disabled on access ports", ABSENT, "L2P02 passive",
            "DTP offered, mode %s" % capture.trunking[0].mode,
        )

    if capture.bpdu:
        priorities = _distinct(str(r.root_priority) for r in capture.bpdu)
        posture.set(
            "Root Guard", INDETERMINATE, "L2P03 passive",
            "BPDUs reached the port, root priority %s. Whether Root Guard is "
            "configured cannot be told without claiming the root role, which "
            "this tool never does" % ", ".join(priorities),
        )

    native = [r.native_vlan for r in capture.discovery if r.native_vlan is not None]
    if 1 in native:
        posture.set("Native VLAN not default", ABSENT, "L2P05 passive", "native VLAN is 1")
    elif native:
        posture.set(
            "Native VLAN not default", PRESENT, "L2P05 passive",
            "native VLAN is %d" % native[0],
        )

    servers = _distinct((r.server_mac, r.server_ip) for r in capture.dhcp_servers)
    if len(servers) > 1:
        listed = ", ".join("%s at %s" % (ip, mac) for mac, ip in servers)
        posture.set(
            "DHCP Snooping", ABSENT, "L2P07 passive",
            "%d DHCP servers answering: %s" % (len(servers), listed),
        )

    unauthenticated = [r for r in capture.fhrp if not r.authenticated]
    if unauthenticated:
        record = unauthenticated[0]
        posture.set(
            "First-hop redundancy authentication", ABSENT, "L2P10 passive",
            "%s group %s advertised without authentication"
            % (record.protocol, record.group),
        )
    elif capture.fhrp:
        posture.set(
            "First-hop redundancy authentication", PRESENT, "L2P10 passive",
            "%s advertisements carry authentication" % capture.fhrp[0].protocol,
        )


def _arp_conflicts(capture) -> dict:
    claims: dict = {}
    for record in capture.arp:
        if record.claimed_ip and record.claimed_ip != "0.0.0.0":
            claims.setdefault(record.claimed_ip, [])
            if record.source_mac not in claims[record.claimed_ip]:
                claims[record.claimed_ip].append(record.source_mac)
    return {ip: macs for ip, macs in claims.items() if len(macs) > 1}


def findings(capture) -> list[Finding]:
    """The layer 2 passive findings."""
    results: list[Finding] = []

    for protocol, device, platform, software in _distinct(
        (r.protocol, r.device_id, r.platform, r.software) for r in capture.discovery
    ):
        described = ", ".join(part for part in (device, platform, software) if part)
        results.append(
            Finding(MEDIUM, "L2P01", "%s discloses %s" % (protocol, described or "device details"),
                    "disabling discovery on user ports")
        )

    for mode in _distinct(r.mode for r in capture.trunking):
        results.append(
            Finding(HIGH, "L2P02", "Port negotiates trunking, mode %s" % mode,
                    "setting the port to access mode with negotiation off")
        )

    for priority, root, cost in _distinct(
        (r.root_priority, r.root_mac, r.root_path_cost) for r in capture.bpdu
    ):
        default = " (default priority)" if priority // 4096 * 4096 == 32768 else ""
        results.append(
            Finding(HIGH, "L2P03",
                    "BPDUs received on the port: root %s priority %d%s, path cost %d"
                    % (root, priority, default, cost),
                    "enabling BPDU Guard on access ports")
        )

    for domain, revision in _distinct((r.domain, r.revision) for r in capture.vtp):
        results.append(
            Finding(MEDIUM, "L2P04", "VTP domain %s at revision %d" % (domain, revision), "")
        )

    if any(r.native_vlan == 1 for r in capture.discovery):
        results.append(
            Finding(MEDIUM, "L2P05", "Native VLAN is 1, which is what makes double tagging work",
                    "changing the native VLAN to an unused one")
        )

    vlans = _distinct(r.vlan for r in capture.tagged)
    if vlans:
        results.append(
            Finding(HIGH, "L2P06",
                    "802.1Q tagged frames on an access port, VLAN %s"
                    % ", ".join(str(v) for v in vlans),
                    "pruning unused VLANs from the port")
        )

    servers = _distinct((r.server_mac, r.server_ip) for r in capture.dhcp_servers)
    if len(servers) > 1:
        results.append(
            Finding(HIGH, "L2P07",
                    "%d DHCP servers observed: %s"
                    % (len(servers), ", ".join("%s at %s" % (ip, mac) for mac, ip in servers)),
                    "enabling DHCP snooping and trusting only the server port")
        )

    conflicts = _arp_conflicts(capture)
    if conflicts:
        results.append(
            Finding(MEDIUM, "L2P08",
                    "Address claimed by more than one MAC: "
                    + ", ".join("%s by %s" % (ip, " and ".join(m)) for ip, m in conflicts.items()),
                    "enabling Dynamic ARP Inspection")
        )
    elif capture.gratuitous_arps:
        results.append(
            Finding(MEDIUM, "L2P08", "%d gratuitous ARPs observed" % capture.gratuitous_arps, "")
        )

    by_protocol: dict = {}
    for record in capture.names:
        by_protocol.setdefault(record.protocol, set()).add(record.source_mac)
    for protocol, hosts in sorted(by_protocol.items()):
        results.append(
            Finding(HIGH, "L2P09",
                    "Name resolution poisoning surface: %s from %d host%s"
                    % (protocol, len(hosts), "" if len(hosts) == 1 else "s"),
                    "disabling %s on the clients that use it" % protocol)
        )

    for record in [r for r in capture.fhrp if not r.authenticated]:
        results.append(
            Finding(HIGH, "L2P10",
                    "%s group %s for %s advertised without authentication, priority %s"
                    % (record.protocol, record.group, record.virtual_ip or "unknown",
                       record.priority),
                    "configuring authentication on the redundancy group")
        )

    for protocol, source, destination in _distinct(
        (r.protocol, r.source, r.destination) for r in capture.cleartext
    ):
        results.append(
            Finding(MEDIUM, "L2P11", "Cleartext %s between %s and %s"
                    % (protocol, source, destination), "moving management to an encrypted transport")
        )

    routers = _distinct(r.source_mac for r in capture.router_adverts)
    if len(routers) > 1:
        results.append(
            Finding(HIGH, "L2P12",
                    "%d sources advertising IPv6 routes: %s. Whether that is a rogue "
                    "advertisement or a redundancy design cannot be told from here"
                    % (len(routers), ", ".join(sorted(routers))),
                    "enabling RA Guard on access ports")
        )
    elif routers:
        prefixes = _distinct(r.prefix for r in capture.router_adverts if r.prefix)
        results.append(
            Finding(MEDIUM, "L2P12",
                    "IPv6 router advertisements for %s. Hosts autoconfigure from "
                    "whatever advertises" % (", ".join(prefixes) or "an unnamed prefix"),
                    "enabling RA Guard on access ports")
        )

    announcing: dict = {}
    for record in capture.services:
        announcing.setdefault(record.protocol, set()).add(record.source_mac)
    for protocol, hosts in sorted(announcing.items()):
        types = _distinct(r.service_type for r in capture.services if r.protocol == protocol)[:4]
        results.append(
            Finding(MEDIUM, "L2P13",
                    "%s announced by %d host%s: %s"
                    % (protocol, len(hosts), "" if len(hosts) == 1 else "s",
                       ", ".join(types) or "unnamed"), "")
        )

    if capture.frames_seen:
        results.append(
            Finding(LOW, "L2P01", "%d frames seen in %d seconds"
                    % (capture.frames_seen, capture.duration), "")
        )
    return results
