"""The filtering checks.

L3A05 and L3A08 ask whether anything reaches in from outside. L3A07 asks what
leaves. L3A14 asks whether a filter inspects only first fragments, and L3A15
whether it forwards source routed packets. Every one of them measures one way
delivery, so without a cooperating observer they return INDETERMINATE: a local
timeout does not distinguish a filter from a dead host, and a hairpin test from
inside gives a different answer from most consumer NAT than the outside world
does.

L3A12 also lives here. It measures what the host accepts rather than what it
sends, and it tests the machine the tool is running on, not the network, which
is why its control is labelled `host` in the posture table.
"""

from __future__ import annotations

import subprocess

from netcheck.l2.frames import new_marker
from netcheck.l3 import packets
from netcheck.models import (
    ABSENT,
    HIGH,
    INDETERMINATE,
    NO_OBSERVER,
    PREREQUISITE_MISSING,
    PRESENT,
    UNTESTED,
    Finding,
)

CONTROL = "ICMP redirect handling"
SETTLE_SECONDS = 2
OBSERVER_SECONDS = 6
CGNAT_REASON = "cgnat"


def _external_target(context, identifier: str):
    """The resolved test host, or a refusal explaining why there is not one."""
    config = context.config
    name = config.external.get("test_host", "") if config else ""
    if not name:
        return None, (
            UNTESTED, identifier,
            "%s: no external.test_host configured" % PREREQUISITE_MISSING, [],
        )
    address = context.resolve(name)
    if not address:
        return None, (
            UNTESTED, identifier,
            "%s: external.test_host %r does not resolve" % (PREREQUISITE_MISSING, name),
            [],
        )
    return address, None


def _unreachable(identifier: str, endpoint: str):
    return (
        INDETERMINATE, identifier,
        "the observer at %s did not answer, so delivery is unknown" % endpoint, [],
    )


def run_inbound_v4(context):
    """L3A05. Whether the WAN address accepts connections from outside.

    Never substituted with a hairpin test from inside: most consumer NAT answers
    that differently from the outside world, so the answer would be wrong.
    """
    config = context.config
    if not config or not config.wan_address:
        return UNTESTED, "L3A05", "%s: no WAN address; run with --wan" % PREREQUISITE_MISSING, []
    if config.is_cgnat():
        return (
            UNTESTED, "L3A05",
            "%s: the WAN address %s is inside carrier grade NAT, so inbound "
            "testing cannot work and says nothing about the firewall"
            % (CGNAT_REASON, config.wan_address),
            [],
        )
    observer = config.external_observer
    if not observer:
        return (
            INDETERMINATE, "L3A05",
            "%s: an external observer is needed to knock on %s from outside"
            % (NO_OBSERVER, config.wan_address),
            [],
        )
    return _knock(context, "L3A05", observer, config.wan_address, "the WAN address")


def run_inbound_v6(context):
    """L3A08. Whether a globally addressed LAN host is reachable from outside.

    The most likely source of a genuine ABSENT on a home network, because
    consumer firewall rules are frequently v4 only.
    """
    capture = context.capture
    globals_seen = [r for r in (capture.ipv6_modes if capture else []) if r.scope == "global"]
    if not globals_seen:
        return (
            UNTESTED, "L3A08",
            "%s: L3P04 found no LAN host holding a global IPv6 address"
            % PREREQUISITE_MISSING,
            [],
        )
    observer = context.config.external_observer if context.config else ""
    if not observer:
        return (
            INDETERMINATE, "L3A08",
            "%s: an external observer is needed to knock on %s"
            % (NO_OBSERVER, globals_seen[0].address),
            [],
        )
    return _knock(context, "L3A08", observer, globals_seen[0].address, "a LAN host")


def _knock(context, identifier: str, observer: str, address: str, described: str):
    reachable = []
    for port in packets.INBOUND_PORTS:
        answer = context.ask_observer_connect(observer, address, port, OBSERVER_SECONDS)
        if answer is None:
            return _unreachable(identifier, observer)
        if answer == "open":
            reachable.append(port)

    if reachable:
        listed = ", ".join(str(p) for p in reachable)
        return (
            ABSENT, identifier,
            "the observer reached %s (%s) from the internet on %s"
            % (described, address, listed),
            [
                Finding(HIGH, identifier,
                        "Inbound from the internet reaches %s on %s" % (address, listed),
                        "closing the forward or firewall rule that allows it")
            ],
            ("external", "lan"),
        )
    return (
        PRESENT, identifier,
        "the observer could not reach %s on any of %d ports from outside"
        % (address, len(packets.INBOUND_PORTS)),
        [],
        ("external", "lan"),
    )


def run_egress(context):
    """L3A07. Which outbound ports and protocols leave the network."""
    target, refusal = _external_target(context, "L3A07")
    if refusal is not None:
        return refusal

    marker = new_marker()
    probes = packets.egress_probes(target, marker)
    probes = probes[: context.budget.remaining(3)]
    context.send_packets(probes)

    observer = context.config.external_observer if context.config else ""
    if not observer:
        return (
            INDETERMINATE, "L3A07",
            "%s: %d outbound probes were sent to %s. A local timeout does not "
            "distinguish a filter from a dead host" % (NO_OBSERVER, len(probes), target),
            [],
        )

    arrived = context.ask_observer(marker, OBSERVER_SECONDS, observer)
    if arrived is None:
        return _unreachable("L3A07", observer)
    if arrived:
        return (
            ABSENT, "L3A07",
            "outbound probes reached the external observer, so egress is not "
            "filtered on the ports tested",
            [Finding(HIGH, "L3A07", "Outbound traffic leaves unfiltered on %d ports"
                     % len(packets.EGRESS_PORTS), "applying an egress policy")],
            ("lan", "external"),
        )
    return (
        PRESENT, "L3A07",
        "the external observer saw none of %d outbound probes" % len(probes),
        [],
        ("lan", "external"),
    )


def run_fragment_handling(context):
    """L3A14. Whether a filter inspects only the first fragment."""
    target, refusal = _external_target(context, "L3A14")
    if refusal is not None:
        return refusal

    marker = new_marker()
    context.send_packets(packets.fragmented(target, marker))

    observer = context.config.external_observer if context.config else ""
    if not observer:
        return (
            INDETERMINATE, "L3A14",
            "%s: a fragmented packet was sent to %s with its transport header "
            "split across the boundary" % (NO_OBSERVER, target),
            [],
        )

    arrived = context.ask_observer(marker, OBSERVER_SECONDS, observer)
    if arrived is None:
        return _unreachable("L3A14", observer)
    if arrived:
        return (
            ABSENT, "L3A14",
            "a fragmented packet crossed the filter with its transport header "
            "split, so the filter inspects first fragments only",
            [Finding(HIGH, "L3A14",
                     "Fragmented traffic bypasses the filter: it inspects the first "
                     "fragment only", "enabling fragment reassembly on the firewall")],
        )
    return PRESENT, "L3A14", "the fragmented packet did not reach the observer", []


def run_source_routing(context):
    """L3A15. Whether loose or strict source routed packets are forwarded."""
    target, refusal = _external_target(context, "L3A15")
    if refusal is not None:
        return refusal

    marker = new_marker()
    via = (context.config.gateway if context.config else "") or "192.0.2.1"
    context.send_packets(packets.source_routed(target, via, marker))

    observer = context.config.external_observer if context.config else ""
    if not observer:
        return (
            INDETERMINATE, "L3A15",
            "%s: two source routed packets were sent to %s" % (NO_OBSERVER, target),
            [],
        )

    arrived = context.ask_observer(marker, OBSERVER_SECONDS, observer)
    if arrived is None:
        return _unreachable("L3A15", observer)
    if arrived:
        return (
            ABSENT, "L3A15",
            "source routed packets were forwarded, so the path accepts a sender "
            "choosing its own route",
            [Finding(HIGH, "L3A15", "Source routed packets are accepted",
                     "dropping packets carrying LSRR or SSRR options")],
        )
    return PRESENT, "L3A15", "source routed packets did not reach the observer", []


def _route_to(destination: str) -> str:
    """What the kernel would do with a packet for this destination, right now."""
    try:
        result = subprocess.run(
            ["ip", "route", "get", destination],
            capture_output=True, text=True, timeout=5, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return result.stdout.strip() if result.returncode == 0 else ""


def _flush(destination: str) -> None:
    try:
        subprocess.run(
            ["ip", "route", "flush", "cache", destination],
            capture_output=True, text=True, timeout=5, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        pass


def run(context):
    """Whether this host installs a route from one ICMP redirect."""
    gateway = getattr(context.config, "gateway", "") if context.config else ""
    local_ip = context.address()
    if not gateway or not local_ip:
        return (
            UNTESTED,
            "L3A12",
            "%s: a gateway and a local address are needed to construct a "
            "plausible redirect" % PREREQUISITE_MISSING,
            [],
        )

    before = _route_to(packets.REDIRECT_TARGET)
    context.send_packets(packets.icmp_redirect(gateway, local_ip))
    context.sleeper(SETTLE_SECONDS)
    after = _route_to(packets.REDIRECT_TARGET)
    installed = after != before and gateway in after and "cache" in after
    _flush(packets.REDIRECT_TARGET)

    if installed:
        return (
            ABSENT,
            "L3A12",
            "this machine installed a route from one ICMP redirect. The route to "
            "%s was removed afterwards. This describes the machine running the "
            "tool, not the network" % packets.REDIRECT_TARGET,
            [
                Finding(HIGH, "L3A12",
                        "This machine accepts ICMP redirects in practice, so any "
                        "host on the segment can reroute its traffic",
                        "setting net.ipv4.conf.all.accept_redirects to 0")
            ],
        )
    return (
        PRESENT,
        "L3A12",
        "this machine ignored an ICMP redirect. This describes the machine "
        "running the tool, not the network",
        [],
    )
