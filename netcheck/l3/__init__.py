"""Layer 3 checks: what the network enforces, and what is reachable from where.

Registers the layer 3 and offline checks, and turns a passive capture into
control states and findings. Passive evidence reaches ABSENT and INDETERMINATE
only; the offline host checks are the exception, because reading a sysctl is a
direct observation of configuration rather than an inference from silence.
"""

from __future__ import annotations

from netcheck.models import (
    ABSENT,
    HIGH,
    LOW,
    MEDIUM,
    PRESENT,
    Finding,
    Posture,
)
from netcheck.platform.detect import (
    RAW_L2_CAPTURE,
    RAW_L3_SEND,
    SOCKET_L4,
    SYSCTL_READ,
)
from netcheck.registry import Check, Registry

CAPTURE = frozenset({RAW_L2_CAPTURE})
OFFLINE = frozenset()
SEND = frozenset({RAW_L3_SEND})
# L3A04 talks to services over ordinary TCP, which needs no privilege anywhere.
TRANSPORT = frozenset({SOCKET_L4})

PASSIVE = (
    ("L3P01", "Host and address inventory", ()),
    ("L3P02", "Cleartext transport metadata", ()),
    ("L3P03", "Resolver behaviour", ()),
    ("L3P04", "IPv6 addressing mode", ()),
    ("L3P05", "Local discovery surface", ()),
    ("L3P06", "ICMP anomalies", ()),
    ("L3P07", "Outbound destination profile", ()),
    ("L3P08", "Fragmentation observed", ()),
    ("L3P09", "Duplicate address correlation", ()),
    ("L3P10", "Hop count anomaly", ()),
)

OFFLINE_CHECKS = (
    ("CFG01", "Router config parse", (), OFFLINE),
    ("CFG02", "Local host posture", ("ICMP redirect handling",),
     frozenset({SYSCTL_READ})),
    ("CFG03", "Firmware version", (), OFFLINE),
)


def register(registry: Registry) -> Registry:
    """Add every layer 3 and offline check. Probes import lazily to avoid a cycle."""
    from netcheck.l3.probes import (
        discovery,
        dns,
        filtering,
        segmentation,
        services,
        spoofing,
        upnp,
    )

    active = (
        ("L3A01", "Host discovery", (), SEND, discovery.run_host_discovery, ("L3P01",)),
        ("L3A02", "TCP service inventory", (), SEND, discovery.run_tcp_inventory, ("L3A01",)),
        ("L3A03", "UDP service inventory", (), SEND, discovery.run_udp_inventory, ("L3A01",)),
        ("L3A04", "Gateway management plane exposure",
         ("Gateway management plane isolation",), TRANSPORT, services.run, ("L3A02",)),
        ("L3A06", "UPnP and NAT-PMP mapping", ("UPnP mapping restraint",),
         SEND, upnp.run, ("L2P13",)),
        ("L3A12", "ICMP redirect acceptance", ("ICMP redirect handling",),
         SEND, filtering.run, ()),
        ("L3A05", "Inbound reachability, IPv4", ("Inbound filtering, IPv4",),
         TRANSPORT, filtering.run_inbound_v4, ()),
        ("L3A07", "Egress filtering", ("Egress filtering",),
         SEND, filtering.run_egress, ()),
        ("L3A08", "Inbound reachability, IPv6", ("Inbound filtering, IPv6",),
         TRANSPORT, filtering.run_inbound_v6, ("L3P04",)),
        ("L3A09", "Guest segmentation", ("Guest segmentation",),
         TRANSPORT, segmentation.run, ()),
        ("L3A10", "DNS rebinding protection", ("DNS rebinding protection",),
         SEND, dns.run_rebinding, ()),
        ("L3A11", "Resolver scoping", ("Resolver scoping",),
         TRANSPORT, dns.run_resolver_scoping, ()),
        ("L3A13", "Anti-spoofing", ("Anti-spoofing",),
         SEND, spoofing.run, ()),
        ("L3A14", "Fragment handling", ("Fragment inspection",),
         SEND, filtering.run_fragment_handling, ("L3A02",)),
        ("L3A15", "Source routing", ("Source routing rejected",),
         SEND, filtering.run_source_routing, ()),
    )

    for identifier, title, controls in PASSIVE:
        registry.register(Check(identifier, title, controls, requires=CAPTURE))
    for identifier, title, controls, requires in OFFLINE_CHECKS:
        registry.register(Check(identifier, title, controls, requires=requires))
    for identifier, title, controls, requires, run, depends in active:
        registry.register(
            Check(identifier, title, controls, requires=requires, depends_on=depends, run=run)
        )
    return registry


def _distinct(values) -> list:
    seen = []
    for value in values:
        if value not in seen:
            seen.append(value)
    return seen


def apply_passive(posture: Posture, capture) -> None:
    """Fold the layer 3 and offline records into the posture."""
    if capture.dns_answers:
        record = capture.dns_answers[0]
        posture.set(
            "DNS rebinding protection", ABSENT, "L3P03 passive",
            "the local resolver answered %s with %s, a private address"
            % (record.name, record.address),
        )

    host = capture.host_posture
    if host is not None:
        v4 = host.sysctls.get("net.ipv4.conf.all.accept_redirects") == "1"
        v6 = host.sysctls.get("net.ipv6.conf.all.accept_redirects") == "1"
        if v4 or v6:
            posture.set(
                "ICMP redirect handling", ABSENT, "CFG02 offline",
                "this machine accepts ICMP redirects, so a host on the segment "
                "can install a route into it. This describes the machine running "
                "the tool, not the network",
            )
        elif host.sysctls:
            posture.set(
                "ICMP redirect handling", PRESENT, "CFG02 offline",
                "this machine ignores ICMP redirects. This describes the machine "
                "running the tool, not the network",
            )


def findings(capture) -> list[Finding]:
    """The layer 3 passive and offline findings."""
    from netcheck.cfg.firmware import NO_DATA, knows, match
    from netcheck.cfg.host_posture import SYSCTLS

    results: list[Finding] = []

    conflicts = {ip: macs for ip, macs in capture.bindings().items() if len(macs) > 1}
    if conflicts:
        # L3P09 joins with L2P08: the same event seen from two layers, and the
        # report should say which it was.
        for ip, macs in sorted(conflicts.items()):
            gratuitous = any(r.claimed_ip == ip and r.gratuitous for r in capture.arp)
            leased = any(r.server_ip == ip for r in capture.dhcp_servers)
            cause = (
                "an ARP anomaly, cross referenced with L2P08" if gratuitous
                else "DHCP churn" if leased else "cause unclear"
            )
            results.append(
                Finding(HIGH, "L3P09", "%s claimed by %s: %s"
                        % (ip, " and ".join(sorted(macs)), cause),
                        "enabling Dynamic ARP Inspection")
            )

    if capture.hosts:
        results.append(
            Finding(LOW, "L3P01", "%d addresses across %d hosts seen without sending anything"
                    % (len({r.ip for r in capture.hosts}), len({r.mac for r in capture.hosts})), "")
        )

    resolvers = _distinct(r.resolver_ip for r in capture.resolvers if r.resolver_ip)
    if len(resolvers) > 1:
        results.append(
            Finding(MEDIUM, "L3P03",
                    "Clients use %d different resolvers, so at least one bypasses "
                    "the one DHCP hands out: %s" % (len(resolvers), ", ".join(resolvers)),
                    "forcing DNS to the local resolver at the gateway")
        )
    encrypted = _distinct(r.transport for r in capture.resolvers if r.transport != "Do53")
    if encrypted:
        results.append(
            Finding(LOW, "L3P03", "Encrypted DNS in use (%s), which the local "
                    "resolver cannot see into" % ", ".join(encrypted), "")
        )
    for record in capture.dns_answers:
        results.append(
            Finding(HIGH, "L3P03",
                    "External name %s resolved to the private address %s, which is "
                    "either a local blocklist or a rebinding answer"
                    % (record.name, record.address),
                    "enabling DNS rebinding protection on the resolver")
        )

    globals_seen = [r for r in capture.ipv6_modes if r.scope == "global"]
    if globals_seen:
        count = len({r.mac for r in globals_seen})
        results.append(
            Finding(HIGH, "L3P04",
                    "%d host%s a globally routable IPv6 address, reachable from the "
                    "internet unless the router filters v6 inbound"
                    % (count, " holds" if count == 1 else "s hold"),
                    "confirming the IPv6 firewall matches the IPv4 one")
        )

    redirects = [r for r in capture.icmp if r.kind == "redirect"]
    if redirects:
        results.append(
            Finding(HIGH, "L3P06", "ICMP redirects seen from %s, which can reroute a "
                    "host's traffic" % ", ".join(_distinct(r.source_ip for r in redirects)),
                    "ignoring redirects on hosts and not sending them on the gateway")
        )
    legacy = [r for r in capture.icmp if r.kind in ("timestamp", "netmask")]
    if legacy:
        results.append(
            Finding(LOW, "L3P06", "Legacy ICMP information replies (%s) leak host "
                    "configuration" % ", ".join(_distinct(r.kind for r in legacy)), "")
        )

    talkers: dict = {}
    for record in capture.outbound:
        talkers.setdefault(record.source_ip, set()).add(record.destination_ip)
    if talkers:
        busiest = sorted(talkers.items(), key=lambda item: -len(item[1]))[0]
        results.append(
            Finding(LOW, "L3P07",
                    "%d internal host%s contacted external addresses; the widest "
                    "profile is %s with %d destination%s"
                    % (len(talkers), "" if len(talkers) == 1 else "s", busiest[0],
                       len(busiest[1]), "" if len(busiest[1]) == 1 else "s"), "")
        )

    if capture.fragments:
        results.append(
            Finding(MEDIUM, "L3P08",
                    "Fragmented traffic on a local segment from %s, which is unusual "
                    "and is how a filter inspecting only first fragments is evaded"
                    % ", ".join(_distinct(r.source_ip for r in capture.fragments)), "")
        )

    if capture.hop_counts:
        results.append(
            Finding(MEDIUM, "L3P10",
                    "Hop limits inconsistent with a flat segment from %s, meaning a "
                    "router or bridge not in the expected topology"
                    % ", ".join(_distinct(r.source_ip for r in capture.hop_counts)), "")
        )

    config = capture.router_config
    if config is not None:
        if not config.readable:
            results.append(Finding(LOW, "CFG01", "Router config not parsed: %s" % config.note, ""))
        else:
            for setting in config.settings:
                if setting.enabled is True:
                    results.append(
                        Finding(MEDIUM, "CFG01", "Router config enables %s (%s)"
                                % (setting.meaning, setting.key), "")
                    )

    host = capture.host_posture
    if host is not None:
        if not host.firewall:
            results.append(
                Finding(MEDIUM, "CFG02", "No host firewall detected on this machine",
                        "enabling the host firewall")
            )
        for name, acceptable, severity, description in SYSCTLS:
            value = host.sysctls.get(name, "")
            if not value or severity is None or value in acceptable:
                continue
            results.append(
                Finding(severity, "CFG02", "This machine %s (%s=%s)" % (description, name, value),
                        "setting %s to %s" % (name, acceptable[0]))
            )
        if host.listening:
            results.append(
                Finding(LOW, "CFG02", "This machine listens on %d ports: %s"
                        % (len(host.listening),
                           ", ".join("%s/%d" % p for p in host.listening[:8])), "")
            )

    if config is not None and config.model:
        for entry in match(config.model, config.firmware):
            results.append(
                Finding(entry.get("severity", MEDIUM), "CFG03",
                        "%s: %s" % (entry.get("identifier"), entry.get("summary")),
                        entry.get("fixed_in", ""))
            )
        if not knows(config.model):
            results.append(
                Finding(LOW, "CFG03",
                        "%s for %s. That is not a clean bill of health, it means the "
                        "shipped file has nothing on this model" % (NO_DATA, config.model), "")
            )
    return results
