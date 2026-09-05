"""The environment check.

The first thing to run and the first thing to attach to a bug report. It answers
what this host can do, what privilege it holds, what to run to gain what it
lacks, and which checks are therefore runnable.
"""

from __future__ import annotations

import ipaddress
import sys
from dataclasses import dataclass, field

from netcheck import config as config_module

from netcheck.platform.detect import CapabilitySet, detect
from netcheck.platform import interfaces as interfaces_module
from netcheck.platform import privilege
from netcheck.platform.system import in_container, machine, system
from netcheck.registry import REGISTRY, Registry

CGNAT_REASON = "cgnat"

CONTAINER_WARNING = (
    "a container was detected. On macOS and Windows a container runs inside a "
    "virtual machine, so a host network attaches to the VM's network and not the "
    "real one. Every result would then describe a network that does not exist."
)

@dataclass
class Diagnosis:
    profile_name: str = "self"
    python: str = ""
    platform_name: str = ""
    capabilities: CapabilitySet = field(default_factory=CapabilitySet)
    elevated: bool = False
    elevation_command: str = ""
    interfaces: list = field(default_factory=list)
    default_interface: str = ""
    gateway: str = ""
    wan_address: str = ""
    cgnat: bool = False
    containerised: bool = False
    container_detail: str = ""
    vm_network: bool = False
    config_source: str = ""
    observers: dict = field(default_factory=dict)
    runnable: list = field(default_factory=list)
    skipped: list = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "python": self.python,
            "platform": self.platform_name,
            "capabilities": self.capabilities.as_dict(),
            "privilege": {
                "elevated": self.elevated,
                "command_to_gain": self.elevation_command,
            },
            "interfaces": [
                {
                    "name": i.name,
                    "kind": i.kind,
                    "up": i.up,
                    "address": i.cidr,
                    "default_route": i.is_default,
                }
                for i in self.interfaces
            ],
            "default_interface": self.default_interface,
            "gateway": self.gateway,
            "wan_address": self.wan_address,
            "cgnat": self.cgnat,
            "container": {
                "detected": self.containerised,
                "detail": self.container_detail,
                "network_is_virtual": self.vm_network,
            },
            "config": self.config_source,
            "observers": self.observers,
            "checks": {
                "runnable": self.runnable,
                "skipped": [
                    {"check": s.identifier, "reason": s.reason, "detail": s.detail}
                    for s in self.skipped
                ],
            },
        }

def diagnose(
    explicit_config: str | None = None,
    registry: Registry | None = None,
) -> Diagnosis:
    """Probe everything the operator needs to know before a first run."""
    registry = registry or REGISTRY
    capabilities = detect()
    found = interfaces_module.list_interfaces()
    default = interfaces_module.default_interface()
    containerised, detail = in_container()

    configuration = config_module.load(explicit_config, default)
    runnable, skipped = registry.resolve(registry.identifiers(), capabilities)

    diagnosis = Diagnosis(
        python="%d.%d.%d" % sys.version_info[:3],
        platform_name="%s %s" % (system(), machine()),
        capabilities=capabilities,
        elevated=privilege.is_elevated() or privilege.has_file_capability(),
        elevation_command=privilege.elevation_command(),
        interfaces=found,
        default_interface=default,
        gateway=configuration.gateway,
        wan_address=configuration.wan_address,
        cgnat=configuration.is_cgnat(),
        containerised=containerised,
        container_detail=detail,
        vm_network=bool(default and interfaces_module.looks_like_vm_adapter(default)),
        config_source=configuration.source,
        observers=dict(configuration.observers),
        runnable=runnable,
        skipped=skipped,
    )
    return diagnosis

def render(diagnosis: Diagnosis, prog: str = "netcheck") -> str:
    """The human form. Only the command for this platform is printed."""
    lines = ["%s environment check" % prog, ""]
    lines.append("  %-14s %s" % ("python", diagnosis.python))
    lines.append("  %-14s %s" % ("platform", diagnosis.platform_name))
    lines.append(
        "  %-14s %s" % ("privilege", "elevated" if diagnosis.elevated else "unprivileged")
    )
    lines.append("  %-14s %s" % ("config", diagnosis.config_source))

    lines += ["", "Capabilities"]
    for name, capability in sorted(diagnosis.capabilities.capabilities.items()):
        status = "yes" if capability.available else "no"
        lines.append("  %-16s %-4s probed by %s" % (name, status, capability.how))
        if not capability.available:
            note = capability.reason
            if capability.detail:
                note += ": " + capability.detail
            lines.append("  %-16s      %s" % ("", note))

    if not diagnosis.elevated and diagnosis.elevation_command:
        lines += ["", "To gain raw socket access on this host:", "  " + diagnosis.elevation_command]

    lines += ["", "Interfaces", "  %-14s %-10s %-6s %s" % ("NAME", "TYPE", "STATE", "ADDRESS")]
    for entry in diagnosis.interfaces:
        marker = "   default route" if entry.is_default else ""
        lines.append(
            "  %-14s %-10s %-6s %s%s"
            % (entry.name, entry.kind, "up" if entry.up else "down",
               entry.cidr or "-", marker)
        )
    if not diagnosis.interfaces:
        lines.append("  none found")

    lines += ["", "Network"]
    lines.append("  %-14s %s" % ("gateway", diagnosis.gateway or "not detected"))
    if diagnosis.wan_address:
        note = " (CGNAT: inbound testing cannot work)" if diagnosis.cgnat else ""
        lines.append("  %-14s %s%s" % ("wan address", diagnosis.wan_address, note))
    for name, endpoint in sorted(diagnosis.observers.items()):
        lines.append("  %-14s %s" % ("observer " + name, endpoint))
    if not diagnosis.observers:
        lines.append("  %-14s none configured" % "observers")

    if diagnosis.containerised:
        lines += ["", "Container", "  detected: " + diagnosis.container_detail, "  " + CONTAINER_WARNING]
        if diagnosis.vm_network:
            lines.append("  the default route is a virtual adapter, so active checks are refused")

    lines += ["", "Checks"]
    lines.append("  %-14s %d" % ("runnable", len(diagnosis.runnable)))
    if diagnosis.runnable:
        lines.append("  %-14s %s" % ("", ", ".join(diagnosis.runnable)))
    for entry in diagnosis.skipped:
        lines.append("  %-14s %s: %s" % (entry.identifier, entry.reason, entry.detail))
    if not diagnosis.runnable and not diagnosis.skipped:
        lines.append("  none registered yet")

    return "\n".join(lines)

def refuses_active(diagnosis: Diagnosis) -> str:
    """Why active checks must not run here, or an empty string."""
    if diagnosis.containerised and diagnosis.vm_network:
        return (
            "the default route is a virtual adapter inside a container, so any "
            "result would describe the container's network rather than the real one"
        )
    return ""

def cgnat_reason(address: str) -> str:
    """Reason string when the WAN address makes inbound testing meaningless."""
    if not address:
        return ""
    try:
        inside = ipaddress.ip_address(address) in config_module.CGNAT
    except ValueError:
        return ""
    return CGNAT_REASON if inside else ""
