"""L3A12, ICMP redirect acceptance.

This lives with the filtering checks because it measures what the host accepts
rather than what it sends. It tests the machine the tool is running on, not the
network, and the posture table labels the control `host` for that reason.

A redirect is sent for a documentation address that carries no traffic, the
routing table is read to see whether the kernel installed it, and the route is
removed either way.
"""

from __future__ import annotations

import subprocess

from netcheck.l3 import packets
from netcheck.models import (
    ABSENT,
    HIGH,
    PREREQUISITE_MISSING,
    PRESENT,
    UNTESTED,
    Finding,
)
from netcheck.platform import interfaces as interfaces_module

CONTROL = "ICMP redirect handling"
SETTLE_SECONDS = 2


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
    entry = interfaces_module.interface_named(context.interface)
    local_ip = entry.address if entry else ""
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
