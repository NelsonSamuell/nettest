"""CFG02, local host posture.

This describes the machine the tool is running on, not the network, and the
report keeps it in its own section saying so. A reader skimming a network
posture report will otherwise attribute a missing host firewall to the router.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from netcheck.models import LOW, MEDIUM
from netcheck.platform.system import firewall_rules, listening_sockets, read_sysctls

# (name, values that are fine, severity, description). A severity of None means
# the value is recorded as context and never raised as a finding: accept_ra is
# how an IPv6 client is supposed to work, and reporting it as a problem would be
# a confident wrong answer.
SYSCTLS = (
    (
        "net.ipv4.conf.all.accept_redirects", ("0",), MEDIUM,
        "accepts ICMP redirects, so a host on the segment can install a route into it",
    ),
    ("net.ipv4.conf.all.accept_source_route", ("0",), MEDIUM,
     "accepts source routed IPv4 packets"),
    (
        "net.ipv4.conf.all.rp_filter", ("1", "2"), LOW,
        "has reverse path filtering off on all interfaces, so it accepts packets "
        "with spoofed source addresses",
    ),
    ("net.ipv6.conf.all.accept_redirects", ("0",), MEDIUM, "accepts ICMPv6 redirects"),
    # Negative disables routing headers outright; 0 is the kernel default and
    # accepts only type 2, which is mobile IPv6 rather than the deprecated RH0.
    ("net.ipv6.conf.all.accept_source_route", ("-1", "0"), MEDIUM,
     "accepts IPv6 routing headers beyond type 2"),
    ("net.ipv6.conf.all.accept_ra", None, None, "accepts router advertisements"),
)

SYSCTL_NAMES = [name for name, _, _, _ in SYSCTLS]


@dataclass
class HostPosture:
    firewall: str = ""
    firewall_rules: int = 0
    sysctls: dict = field(default_factory=dict)
    listening: list = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "firewall": self.firewall or "none detected",
            "firewall_rules": self.firewall_rules,
            "listening": ["%s/%d" % pair for pair in self.listening],
            **{name: value for name, value in sorted(self.sysctls.items()) if value},
        }


def read() -> HostPosture:
    """Read this machine's firewall, sysctls and listening ports."""
    name, rules = firewall_rules()
    return HostPosture(
        firewall=name,
        firewall_rules=rules,
        sysctls=read_sysctls(SYSCTL_NAMES),
        listening=listening_sockets(),
    )
