"""Capability detection.

A capability is resolved by attempting the operation and recording what
happened, never by inferring it from the platform name. The difference between
a mechanism that does not exist here and one that exists but was refused is
carried through to the report, because only the second is worth acting on.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from netcheck.platform import interfaces as interfaces_module
from netcheck.platform import sockets
from netcheck.platform.system import LINUX, MACOS, WINDOWS, system

RAW_L2_SEND = "raw_l2_send"
RAW_L2_CAPTURE = "raw_l2_capture"
RAW_L3_SEND = "raw_l3_send"
SOCKET_L4 = "socket_l4"
ROUTING_READ = "routing_read"
FIREWALL_READ = "firewall_read"
SYSCTL_READ = "sysctl_read"

CAPABILITIES = frozenset(
    {
        RAW_L2_SEND,
        RAW_L2_CAPTURE,
        RAW_L3_SEND,
        SOCKET_L4,
        ROUTING_READ,
        FIREWALL_READ,
        SYSCTL_READ,
    }
)

REASON_UNSUPPORTED = "unsupported_platform"
REASON_PRIVILEGE = "insufficient_privilege"


@dataclass
class Capability:
    name: str
    available: bool
    how: str
    reason: str = ""
    detail: str = ""


@dataclass
class CapabilitySet:
    capabilities: dict[str, Capability] = field(default_factory=dict)

    def __contains__(self, name: str) -> bool:
        entry = self.capabilities.get(name)
        return bool(entry and entry.available)

    def available(self) -> set[str]:
        return {n for n, c in self.capabilities.items() if c.available}

    def missing(self, required) -> list[Capability]:
        """The required capabilities this host does not have."""
        return [
            self.capabilities[name]
            for name in sorted(required)
            if name in self.capabilities and not self.capabilities[name].available
        ]

    def reason_for(self, required) -> str:
        """Why a check needing these cannot run: privilege beats platform.

        A missing privilege is actionable and a missing platform mechanism is
        not, so when both apply the operator is told the one they can fix.
        """
        reasons = {c.reason for c in self.missing(required)}
        if REASON_PRIVILEGE in reasons:
            return REASON_PRIVILEGE
        if REASON_UNSUPPORTED in reasons:
            return REASON_UNSUPPORTED
        return ""

    def as_dict(self) -> dict:
        return {
            name: {
                "available": c.available,
                "how": c.how,
                "reason": c.reason,
                "detail": c.detail,
            }
            for name, c in sorted(self.capabilities.items())
        }


def _from_probe(name: str, probe) -> Capability:
    if probe.ok:
        return Capability(name, True, probe.how)
    reason = REASON_PRIVILEGE if probe.privileged_failure else REASON_UNSUPPORTED
    return Capability(name, False, probe.how, reason, probe.detail)


def _probe_routing() -> Capability:
    how = interfaces_module.routing_probe_description()
    try:
        found = interfaces_module.list_interfaces()
    except Exception as error:
        return Capability(ROUTING_READ, False, how, REASON_UNSUPPORTED, str(error))
    if not found:
        return Capability(
            ROUTING_READ, False, how, REASON_UNSUPPORTED, "no interfaces returned"
        )
    return Capability(ROUTING_READ, True, how)


def _probe_sysctl() -> Capability:
    kind = system()
    if kind == LINUX:
        how = "read /proc/sys/net"
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "r", encoding="utf-8") as handle:
                handle.read()
        except OSError as error:
            return Capability(SYSCTL_READ, False, how, REASON_UNSUPPORTED, str(error))
        return Capability(SYSCTL_READ, True, how)
    if kind == MACOS:
        how = "sysctl -n net.inet.ip.forwarding"
        ok = _command_works(["sysctl", "-n", "net.inet.ip.forwarding"])
        return (
            Capability(SYSCTL_READ, True, how)
            if ok
            else Capability(SYSCTL_READ, False, how, REASON_UNSUPPORTED, "sysctl failed")
        )
    if kind == WINDOWS:
        how = "Get-NetIPInterface"
        ok = _command_works(
            ["powershell", "-NoProfile", "-Command", "Get-NetIPInterface | Out-Null"]
        )
        return (
            Capability(SYSCTL_READ, True, how)
            if ok
            else Capability(SYSCTL_READ, False, how, REASON_UNSUPPORTED, "cmdlet failed")
        )
    return Capability(SYSCTL_READ, False, "unsupported", REASON_UNSUPPORTED)


FIREWALL_COMMANDS = {
    LINUX: (
        ("nftables", ["nft", "list", "ruleset"]),
        ("iptables", ["iptables", "-S"]),
        ("ufw", ["ufw", "status"]),
        ("firewalld", ["firewall-cmd", "--list-all"]),
    ),
    MACOS: (("pf", ["pfctl", "-s", "rules"]),),
    WINDOWS: (
        (
            "Windows Firewall",
            ["powershell", "-NoProfile", "-Command", "Get-NetFirewallRule | Out-Null"],
        ),
    ),
}


def _command_works(command: list[str]) -> bool:
    import shutil
    import subprocess

    if not shutil.which(command[0]):
        return False
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=15, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0


def _probe_firewall() -> Capability:
    for label, command in FIREWALL_COMMANDS.get(system(), ()):
        if _command_works(command):
            return Capability(FIREWALL_READ, True, "%s via %s" % (label, command[0]))
    tried = ", ".join(label for label, _ in FIREWALL_COMMANDS.get(system(), ()))
    return Capability(
        FIREWALL_READ,
        False,
        "try %s" % (tried or "nothing known"),
        REASON_PRIVILEGE,
        "no firewall tool answered; reading rules usually needs privilege",
    )


def detect() -> CapabilitySet:
    """Resolve the capability set for this host by probing each one."""
    l2 = sockets.probe_raw_l2()
    found = {
        RAW_L2_CAPTURE: _from_probe(RAW_L2_CAPTURE, l2),
        RAW_L2_SEND: _from_probe(RAW_L2_SEND, l2),
        RAW_L3_SEND: _from_probe(RAW_L3_SEND, sockets.probe_raw_l3()),
        SOCKET_L4: _from_probe(SOCKET_L4, sockets.probe_socket_l4()),
        ROUTING_READ: _probe_routing(),
        FIREWALL_READ: _probe_firewall(),
        SYSCTL_READ: _probe_sysctl(),
    }
    return CapabilitySet(found)
