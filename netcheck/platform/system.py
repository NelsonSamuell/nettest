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
