"""Interface and routing facts, per platform.

Never assume an interface name. Everything that needs one asks for the interface
holding the default route.
"""

from __future__ import annotations

import ipaddress
import re
import shutil
import socket
import subprocess
from dataclasses import dataclass
from pathlib import Path

from netcheck.platform.system import LINUX, MACOS, WINDOWS, system

LOOPBACK = "loopback"
WIRED = "wired"
WIRELESS = "wireless"

VM_ADAPTER_HINTS = ("vmnet", "vboxnet", "vethernet", "docker", "br-", "utun", "hyper-v")


@dataclass
class Interface:
    name: str
    kind: str
    up: bool
    address: str
    prefix_length: int
    is_default: bool = False

    @property
    def cidr(self) -> str:
        if not self.address:
            return ""
        return "%s/%d" % (self.address, self.prefix_length)


def routing_probe_description() -> str:
    """How routing information is read on this platform."""
    return {
        LINUX: "read /sys/class/net and /proc/net/route",
        MACOS: "route -n get default, ifconfig",
        WINDOWS: "Get-NetRoute, Get-NetIPAddress",
    }.get(system(), "unsupported")


def _run(command: list[str], timeout: int = 15) -> str:
    if not shutil.which(command[0]):
        return ""
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=timeout, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return result.stdout if result.returncode == 0 else ""


def _linux_interfaces() -> list[Interface]:
    root = Path("/sys/class/net")
    if not root.is_dir():
        return []
    default = default_interface()
    found = []
    for path in sorted(root.iterdir()):
        name = path.name
        if name == "lo":
            kind = LOOPBACK
        elif (path / "wireless").exists() or (path / "phy80211").exists():
            kind = WIRELESS
        else:
            kind = WIRED
        state = (path / "operstate")
        up = state.read_text().strip() == "up" if state.exists() else False
        address, length = _linux_address(name)
        found.append(Interface(name, kind, up, address, length, name == default))
    return found


def _linux_address(name: str) -> tuple[str, int]:
    text = _run(["ip", "-o", "-4", "addr", "show", "dev", name])
    found = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", text)
    if found:
        return found.group(1), int(found.group(2))
    return "", 0


def _macos_interfaces() -> list[Interface]:
    default = default_interface()
    names = _run(["ifconfig", "-l"]).split()
    found = []
    for name in names:
        text = _run(["ifconfig", name])
        up = "status: active" in text or ("UP," in text and "LOOPBACK" in text)
        kind = LOOPBACK if name.startswith("lo") else WIRED
        if re.search(r"^\s*media:.*(802\.11|Wi-Fi)", text, re.MULTILINE | re.IGNORECASE):
            kind = WIRELESS
        address, length = "", 0
        inet = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)\s+netmask\s+0x([0-9a-f]{8})", text)
        if inet:
            address = inet.group(1)
            length = bin(int(inet.group(2), 16)).count("1")
        found.append(Interface(name, kind, up, address, length, name == default))
    return found


def _windows_interfaces() -> list[Interface]:
    script = (
        "Get-NetIPAddress -AddressFamily IPv4 | "
        "Select-Object -Property InterfaceAlias,IPAddress,PrefixLength | "
        "ForEach-Object { \"$($_.InterfaceAlias)`t$($_.IPAddress)`t$($_.PrefixLength)\" }"
    )
    text = _run(["powershell", "-NoProfile", "-Command", script])
    default = default_interface()
    found = []
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) != 3:
            continue
        name, address, length = parts[0].strip(), parts[1].strip(), parts[2].strip()
        kind = LOOPBACK if address.startswith("127.") else WIRED
        if "wi-fi" in name.lower() or "wireless" in name.lower():
            kind = WIRELESS
        found.append(
            Interface(name, kind, True, address, int(length) if length.isdigit() else 0,
                      name == default)
        )
    return found


def list_interfaces() -> list[Interface]:
    """Every interface this host has, with the default-route one marked."""
    kind = system()
    if kind == LINUX:
        found = _linux_interfaces()
    elif kind == MACOS:
        found = _macos_interfaces()
    elif kind == WINDOWS:
        found = _windows_interfaces()
    else:
        found = []
    found.sort(key=lambda i: (not i.is_default, i.kind == LOOPBACK, not i.up, i.name))
    return found


def default_interface() -> str:
    """The interface holding the default route, or an empty string."""
    kind = system()
    if kind == LINUX:
        route = Path("/proc/net/route")
        if route.exists():
            for line in route.read_text().splitlines()[1:]:
                fields = line.split()
                if len(fields) >= 2 and fields[1] == "00000000":
                    return fields[0]
        found = re.search(r"default via \S+ dev (\S+)", _run(["ip", "route", "show", "default"]))
        return found.group(1) if found else ""
    if kind == MACOS:
        found = re.search(r"interface:\s*(\S+)", _run(["route", "-n", "get", "default"]))
        return found.group(1) if found else ""
    if kind == WINDOWS:
        script = (
            "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | "
            "Sort-Object RouteMetric | Select-Object -First 1).InterfaceAlias"
        )
        return _run(["powershell", "-NoProfile", "-Command", script]).strip()
    return ""


def default_gateway() -> str:
    """The default gateway address, or an empty string."""
    kind = system()
    if kind == LINUX:
        route = Path("/proc/net/route")
        if route.exists():
            for line in route.read_text().splitlines()[1:]:
                fields = line.split()
                if len(fields) >= 3 and fields[1] == "00000000":
                    packed = int(fields[2], 16).to_bytes(4, "little")
                    return ".".join(str(octet) for octet in packed)
        found = re.search(r"default via (\S+)", _run(["ip", "route", "show", "default"]))
        return found.group(1) if found else ""
    if kind == MACOS:
        found = re.search(r"gateway:\s*(\S+)", _run(["route", "-n", "get", "default"]))
        return found.group(1) if found else ""
    if kind == WINDOWS:
        script = (
            "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | "
            "Sort-Object RouteMetric | Select-Object -First 1).NextHop"
        )
        return _run(["powershell", "-NoProfile", "-Command", script]).strip()
    return ""


def gateway_mac(address: str) -> str:
    """The gateway's link layer address from the neighbour table, if known."""
    if not address:
        return ""
    kind = system()
    if kind == LINUX:
        table = Path("/proc/net/arp")
        if table.exists():
            for line in table.read_text().splitlines()[1:]:
                fields = line.split()
                if fields and fields[0] == address and len(fields) >= 4:
                    return fields[3].lower()
        text = _run(["ip", "neigh", "show", address])
    elif kind == MACOS:
        text = _run(["arp", "-n", address])
    elif kind == WINDOWS:
        text = _run(["powershell", "-NoProfile", "-Command",
                     "Get-NetNeighbor -IPAddress %s | Select-Object -ExpandProperty LinkLayerAddress"
                     % address])
        return text.strip().lower().replace("-", ":")
    else:
        return ""
    found = re.search(r"([0-9a-f]{2}(?::[0-9a-f]{2}){5})", text, re.IGNORECASE)
    return found.group(1).lower() if found else ""


def interface_named(name: str) -> Interface | None:
    for entry in list_interfaces():
        if entry.name == name:
            return entry
    return None


def local_network(name: str) -> str:
    """The interface's IPv4 network in CIDR form, or an empty string."""
    entry = interface_named(name)
    if entry is None or not entry.cidr:
        return ""
    return str(ipaddress.ip_interface(entry.cidr).network)


def looks_like_vm_adapter(name: str) -> bool:
    """Whether an interface belongs to a hypervisor rather than the real network."""
    lowered = name.lower()
    return any(hint in lowered for hint in VM_ADAPTER_HINTS)


def resolves_dns(name: str = "localhost") -> bool:
    """Whether name resolution is working, used by the abort watcher."""
    try:
        socket.getaddrinfo(name, None)
    except OSError:
        return False
    return True
