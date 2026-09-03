"""L3A12 ICMP redirect acceptance.

This tests the machine the tool is running on, not the network, and the report
says so. A redirect is sent to this host for a route to an address the operator
controls; the routing table is then read to see whether the kernel installed it,
and the route is removed either way.

The destination is a documentation-range address that carries no traffic, so a
route installed for it can affect nothing while the check is deciding.
"""

from __future__ import annotations

import subprocess

from scapy.layers.inet import ICMP, IP, UDP

from l2check.models import HIGH, Capture, Finding
from l2check.posture import ABSENT, ICMP_REDIRECTS, PRESENT, UNTESTED, ProbeResult
from l2check.session import ActiveSession

# TEST-NET-1. Reserved for documentation, routed nowhere, so a cache entry for
# it cannot divert anything real.
REDIRECT_TARGET = "192.0.2.111"
SETTLE_SECONDS = 2


def _cached_route(destination: str) -> str:
    """What the kernel would do with a packet for this destination, right now."""
    try:
        result = subprocess.run(
            ["ip", "route", "get", destination],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return result.stdout.strip()


def _flush_cache(destination: str) -> None:
    subprocess.run(
        ["ip", "route", "flush", "cache", destination],
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )


def run_icmp_redirect(session: ActiveSession, capture: Capture) -> ProbeResult:
    """L3A12. Whether this host installs a route from an ICMP redirect."""
    import time

    if not session.gateway or not session.local_cidr:
        return ProbeResult(
            "L3A12",
            ICMP_REDIRECTS,
            UNTESTED,
            "L3A12 refused",
            "needs a gateway and a local address to construct a plausible redirect",
        )

    import ipaddress

    local_ip = str(ipaddress.ip_interface(session.local_cidr).ip)
    before = _cached_route(REDIRECT_TARGET)

    # A redirect is only considered if it appears to come from the current
    # gateway and quotes a packet the host plausibly sent.
    quoted = IP(src=local_ip, dst=REDIRECT_TARGET) / UDP(sport=53000, dport=53)
    redirect = (
        IP(src=session.gateway, dst=local_ip)
        / ICMP(type=5, code=1, gw=session.gateway)
        / quoted
    )
    session.send_ip(redirect)
    time.sleep(SETTLE_SECONDS)

    after = _cached_route(REDIRECT_TARGET)
    installed = after != before and session.gateway in after and "cache" in after
    _flush_cache(REDIRECT_TARGET)

    if installed:
        return ProbeResult(
            "L3A12",
            ICMP_REDIRECTS,
            ABSENT,
            "L3A12 active check",
            "this machine installed a route from one ICMP redirect. The route to "
            "%s was removed afterwards. This describes the machine running the "
            "tool, not the network" % REDIRECT_TARGET,
            frames_sent=1,
            findings=[
                Finding(
                    HIGH,
                    "L3A12",
                    "This machine accepts ICMP redirects in practice, so any host "
                    "on the segment can reroute its traffic",
                )
            ],
        )
    return ProbeResult(
        "L3A12",
        ICMP_REDIRECTS,
        PRESENT,
        "L3A12 active check",
        "this machine ignored an ICMP redirect. This describes the machine "
        "running the tool, not the network",
        frames_sent=1,
    )
