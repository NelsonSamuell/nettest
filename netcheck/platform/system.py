"""The single place the operating system is named.

Everything else in the tool asks a question about capability, never about
platform. Keeping the branch here means adding a fourth platform touches this
package and nothing else.
"""

from __future__ import annotations

import os
import platform
import sys
from pathlib import Path

LINUX = "linux"
MACOS = "macos"
WINDOWS = "windows"
OTHER = "other"


def system() -> str:
    """Which operating system family this is."""
    if sys.platform.startswith("linux"):
        return LINUX
    if sys.platform == "darwin":
        return MACOS
    if os.name == "nt" or sys.platform.startswith("win"):
        return WINDOWS
    return OTHER


def machine() -> str:
    """The processor architecture, for the doctor line."""
    return platform.machine()


def config_home() -> Path:
    """The per-user configuration directory for this platform."""
    if system() == WINDOWS:
        base = os.environ.get("APPDATA")
        return Path(base) / "netcheck" if base else Path.home() / "netcheck"
    base = os.environ.get("XDG_CONFIG_HOME")
    return (Path(base) if base else Path.home() / ".config") / "netcheck"


def state_home() -> Path:
    """Where the tool may write state, when it is not told otherwise."""
    if system() == WINDOWS:
        base = os.environ.get("LOCALAPPDATA")
        return Path(base) / "netcheck" if base else Path.home() / "netcheck"
    base = os.environ.get("XDG_STATE_HOME")
    return (Path(base) if base else Path.home() / ".local" / "state") / "netcheck"


def in_container() -> tuple[bool, str]:
    """Whether this looks like a container, and what gave it away.

    It matters because on macOS and Windows a container runs inside a virtual
    machine, so a host network attaches to the VM's network rather than the real
    one and every result describes a network that does not exist.
    """
    if Path("/.dockerenv").exists():
        return True, "/.dockerenv exists"
    if os.environ.get("KUBERNETES_SERVICE_HOST"):
        return True, "KUBERNETES_SERVICE_HOST is set"
    cgroup = Path("/proc/1/cgroup")
    if cgroup.exists():
        text = cgroup.read_text(errors="replace")
        for marker in ("docker", "containerd", "podman", "lxc"):
            if marker in text:
                return True, "%s appears in /proc/1/cgroup" % marker
    return False, ""


def read_sysctls(names: list[str]) -> dict[str, str]:
    """Read network sysctls, however this platform exposes them."""
    kind = system()
    found: dict[str, str] = {}
    if kind == LINUX:
        for name in names:
            path = Path("/proc/sys") / name.replace(".", "/")
            try:
                found[name] = path.read_text().strip() if path.exists() else ""
            except OSError:
                found[name] = ""
        return found
    if kind == MACOS:
        import subprocess

        for name in names:
            try:
                result = subprocess.run(
                    ["sysctl", "-n", name], capture_output=True, text=True,
                    timeout=10, check=False,
                )
            except (OSError, subprocess.SubprocessError):
                found[name] = ""
                continue
            found[name] = result.stdout.strip() if result.returncode == 0 else ""
        return found
    return {name: "" for name in names}


def listening_sockets() -> list[tuple[str, int]]:
    """Ports this host is listening on."""
    kind = system()
    if kind == LINUX:
        return _linux_listening()
    if kind == MACOS:
        return _command_listening(
            ["netstat", "-an", "-p", "tcp"], ["netstat", "-an", "-p", "udp"]
        )
    if kind == WINDOWS:
        return _windows_listening()
    return []


def _linux_listening() -> list[tuple[str, int]]:
    found: set[tuple[str, int]] = set()
    for name, protocol, state in (
        ("tcp", "tcp", "0A"), ("tcp6", "tcp6", "0A"),
        ("udp", "udp", "07"), ("udp6", "udp6", "07"),
    ):
        path = Path("/proc/net") / name
        if not path.exists():
            continue
        try:
            lines = path.read_text().splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            fields = line.split()
            if len(fields) < 4 or fields[3].upper() != state:
                continue
            local = fields[1].rsplit(":", 1)
            if len(local) == 2:
                found.add((protocol, int(local[1], 16)))
    return sorted(found)


def _command_listening(*commands) -> list[tuple[str, int]]:
    import re
    import subprocess

    found: set[tuple[str, int]] = set()
    for command in commands:
        try:
            result = subprocess.run(
                command, capture_output=True, text=True, timeout=15, check=False
            )
        except (OSError, subprocess.SubprocessError):
            continue
        protocol = command[-1]
        for line in result.stdout.splitlines():
            if protocol == "tcp" and "LISTEN" not in line:
                continue
            match = re.search(r"[.:](\d+)\s", line)
            if match:
                found.add((protocol, int(match.group(1))))
    return sorted(found)


def _windows_listening() -> list[tuple[str, int]]:
    import subprocess

    script = (
        "Get-NetTCPConnection -State Listen | "
        "ForEach-Object { \"tcp`t$($_.LocalPort)\" }; "
        "Get-NetUDPEndpoint | ForEach-Object { \"udp`t$($_.LocalPort)\" }"
    )
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", script],
            capture_output=True, text=True, timeout=20, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    found: set[tuple[str, int]] = set()
    for line in result.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) == 2 and parts[1].strip().isdigit():
            found.add((parts[0].strip(), int(parts[1].strip())))
    return sorted(found)


def firewall_rules() -> tuple[str, int]:
    """Which firewall answered and how many rules it holds."""
    import shutil
    import subprocess

    from netcheck.platform.detect import FIREWALL_COMMANDS

    for label, command in FIREWALL_COMMANDS.get(system(), ()):
        if not shutil.which(command[0]):
            continue
        try:
            result = subprocess.run(
                command, capture_output=True, text=True, timeout=15, check=False
            )
        except (OSError, subprocess.SubprocessError):
            continue
        if result.returncode != 0:
            continue
        return label, len([line for line in result.stdout.splitlines() if line.strip()])
    return "", 0
