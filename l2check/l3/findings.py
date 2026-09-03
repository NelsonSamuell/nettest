"""Findings and control derivation for the layer 3 passive and offline checks.

L3P02 records cleartext transport metadata but emits no finding of its own: the
same fact is already reported by L2P11, and the two overlap by design. The layer
3 contribution is the endpoint detail carried in the records, not a second row
in the findings table. For the same reason "one MAC in several subnets" is
reported once, by the correlation layer as COR01, rather than here as well.

Passive evidence can move a control to ABSENT or INDETERMINATE and never to
PRESENT, for the same reason it cannot at layer 2: not seeing something is not
evidence that something is being enforced. The offline host checks are the
exception, because reading a sysctl is a direct observation of configuration
rather than an inference from silence.
"""

from __future__ import annotations

from l2check.models import HIGH, LOW, MEDIUM, Capture, Finding
from l2check.posture import (
    ABSENT,
    DNS_REBINDING,
    ICMP_REDIRECTS,
    PRESENT,
    Posture,
)


def _distinct(values) -> list:
    seen = []
    for value in values:
        if value not in seen:
            seen.append(value)
    return seen


def apply_passive_l3(posture: Posture, capture: Capture) -> None:
    """Fold the layer 3 passive records into the posture."""
    if capture.dns_answers:
        record = capture.dns_answers[0]
        posture.set(
            DNS_REBINDING,
            ABSENT,
            "L3P03 passive",
            "the local resolver answered %s with %s, a private address"
            % (record.name, record.address),
        )

    host = capture.host_posture
    if host is not None:
        accepts = host.sysctls.get("net.ipv4.conf.all.accept_redirects") == "1"
        accepts_v6 = host.sysctls.get("net.ipv6.conf.all.accept_redirects") == "1"
        if accepts or accepts_v6:
            posture.set(
                ICMP_REDIRECTS,
                ABSENT,
                "CFG02 local host",
                "this machine accepts ICMP redirects, so a host on the segment "
                "can install a route into it. This describes the machine running "
                "the tool, not the network",
            )
        else:
            posture.set(
                ICMP_REDIRECTS,
                PRESENT,
                "CFG02 local host",
                "this machine ignores ICMP redirects. This describes the machine "
                "running the tool, not the network",
            )


def findings_l3(capture: Capture) -> list[Finding]:
    """Return the layer 3 passive and offline findings, most severe first."""
    results: list[Finding] = []

    conflicts = {ip: macs for ip, macs in capture.bindings().items() if len(macs) > 1}
    if conflicts:
        results.append(
            Finding(
                HIGH,
                "L3P09",
                "Address held by more than one MAC: "
                + ", ".join(
                    "%s by %s" % (ip, " and ".join(sorted(macs)))
                    for ip, macs in sorted(conflicts.items())
                ),
            )
        )

    if capture.hosts:
        addresses = len({r.ip for r in capture.hosts})
        macs = len({r.mac for r in capture.hosts})
        results.append(
            Finding(
                LOW,
                "L3P01",
                "%d addresses across %d hosts seen without sending anything"
                % (addresses, macs),
            )
        )

    resolvers = _distinct(r.resolver_ip for r in capture.resolvers if r.resolver_ip)
    if len(resolvers) > 1:
        results.append(
            Finding(
                MEDIUM,
                "L3P03",
                "Clients use %d different resolvers, so at least one bypasses the "
                "one DHCP hands out: %s" % (len(resolvers), ", ".join(resolvers)),
            )
        )
    encrypted = _distinct(r.transport for r in capture.resolvers if r.transport != "Do53")
    if encrypted:
        results.append(
            Finding(
                LOW,
                "L3P03",
                "Encrypted DNS in use (%s), which your local resolver cannot see "
                "into" % ", ".join(encrypted),
            )
        )
    for record in capture.dns_answers:
        results.append(
            Finding(
                HIGH,
                "L3P03",
                "External name %s resolved to the private address %s, which is "
                "either a local blocklist or a rebinding answer"
                % (record.name, record.address),
            )
        )

    globals_seen = [r for r in capture.ipv6_modes if r.scope == "global"]
    if globals_seen:
        count = len({r.mac for r in globals_seen})
        results.append(
            Finding(
                HIGH,
                "L3P04",
                "%d host%s a globally routable IPv6 address, which is reachable "
                "from the internet unless the router filters v6 inbound"
                % (count, " holds" if count == 1 else "s hold"),
            )
        )

    by_protocol: dict[str, set[str]] = {}
    for record in capture.services:
        by_protocol.setdefault(record.protocol, set()).add(record.source_mac)
    for protocol, hosts in sorted(by_protocol.items()):
        types = _distinct(
            r.service_type for r in capture.services if r.protocol == protocol
        )[:4]
        results.append(
            Finding(
                MEDIUM,
                "L3P05",
                "%s announced by %d host%s: %s"
                % (
                    protocol,
                    len(hosts),
                    "" if len(hosts) == 1 else "s",
                    ", ".join(types) or "unnamed",
                ),
            )
        )

    redirects = [r for r in capture.icmp if r.kind == "redirect"]
    if redirects:
        results.append(
            Finding(
                HIGH,
                "L3P06",
                "ICMP redirects seen from %s, which can reroute a host's traffic"
                % ", ".join(_distinct(r.source_ip for r in redirects)),
            )
        )
    legacy = [r for r in capture.icmp if r.kind in ("timestamp", "netmask")]
    if legacy:
        results.append(
            Finding(
                LOW,
                "L3P06",
                "Legacy ICMP information replies (%s) leak host configuration"
                % ", ".join(_distinct(r.kind for r in legacy)),
            )
        )

    talkers: dict[str, set[str]] = {}
    for record in capture.outbound:
        talkers.setdefault(record.source_ip, set()).add(record.destination_ip)
    if talkers:
        busiest = sorted(talkers.items(), key=lambda item: -len(item[1]))[0]
        results.append(
            Finding(
                LOW,
                "L3P07",
                "%d internal host%s contacted external addresses; the widest "
                "profile is %s with %d destination%s"
                % (
                    len(talkers),
                    "" if len(talkers) == 1 else "s",
                    busiest[0],
                    len(busiest[1]),
                    "" if len(busiest[1]) == 1 else "s",
                ),
            )
        )

    if capture.fragments:
        results.append(
            Finding(
                MEDIUM,
                "L3P08",
                "Fragmented traffic on a local segment from %s, which is unusual "
                "and is how a filter that inspects only first fragments is evaded"
                % ", ".join(_distinct(r.source_ip for r in capture.fragments)),
            )
        )

    if capture.hop_counts:
        results.append(
            Finding(
                MEDIUM,
                "L3P10",
                "Hop limits inconsistent with a flat segment from %s, meaning a "
                "router or bridge that is not in the expected topology"
                % ", ".join(_distinct(r.source_ip for r in capture.hop_counts)),
            )
        )

    results.extend(findings_cfg(capture))
    order = {HIGH: 0, MEDIUM: 1, LOW: 2}
    return sorted(results, key=lambda f: (order.get(f.severity, 3), f.check))


def findings_cfg(capture: Capture) -> list[Finding]:
    """Findings from the offline audit checks."""
    from l2check.l3.config_audit import SYSCTLS, knows_model, match_advisories

    results: list[Finding] = []

    config = capture.router_config
    if config is not None:
        if not config.readable:
            results.append(Finding(LOW, "CFG01", "Router config not parsed: %s" % config.note))
        else:
            for setting in config.settings:
                if setting.enabled is not True:
                    continue
                results.append(
                    Finding(
                        MEDIUM,
                        "CFG01",
                        "Router config enables %s (%s)" % (setting.meaning, setting.key),
                    )
                )

    host = capture.host_posture
    if host is not None:
        if not host.firewall:
            results.append(
                Finding(MEDIUM, "CFG02", "No host firewall detected on this machine")
            )
        for name, acceptable, severity, description in SYSCTLS:
            value = host.sysctls.get(name, "")
            if not value or severity is None or value in acceptable:
                continue
            results.append(
                Finding(severity, "CFG02", "This machine %s (%s=%s)" % (description, name, value))
            )
        if host.listening:
            results.append(
                Finding(
                    LOW,
                    "CFG02",
                    "This machine listens on %d ports: %s"
                    % (
                        len(host.listening),
                        ", ".join("%s/%d" % pair for pair in host.listening[:8]),
                    ),
                )
            )

    if config is not None and config.model:
        hits = match_advisories(config.model, config.firmware)
        for entry in hits:
            results.append(
                Finding(
                    entry.get("severity", MEDIUM),
                    "CFG03",
                    "%s: %s" % (entry.get("identifier"), entry.get("summary")),
                )
            )
        if not hits and not knows_model(config.model):
            results.append(
                Finding(
                    LOW,
                    "CFG03",
                    "No advisory data for %s. That is not a clean bill of health, "
                    "it means the shipped file has nothing on this model"
                    % config.model,
                )
            )
    return results
