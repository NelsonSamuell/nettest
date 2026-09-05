"""What privilege the process holds, and how to gain what it lacks."""

from __future__ import annotations

import os
import shutil
import sys
from netcheck.platform.system import LINUX, MACOS, WINDOWS, system


def is_elevated() -> bool:
    """True when the process can already open privileged sockets."""
    if system() == WINDOWS:
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except (AttributeError, OSError):
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


def has_file_capability() -> bool:
    """Whether this interpreter carries CAP_NET_RAW as a file capability."""
    if system() != LINUX:
        return False
    marker = "/proc/self/status"
    try:
        with open(marker, "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                if line.startswith("CapEff:"):
                    # Bit 13 is CAP_NET_RAW.
                    return bool(int(line.split()[1], 16) & (1 << 13))
    except OSError:
        return False
    return False


def interpreter_is_shared() -> bool:
    """Whether this interpreter is a system one other programs also use.

    A file capability attaches to the binary, so granting it to a shared
    interpreter gives raw socket access to every program that runs under it.
    An environment built with ``--copies`` has its own binary and does not.
    """
    resolved = os.path.realpath(sys.executable)
    prefix = os.path.realpath(sys.prefix)
    return not resolved.startswith(prefix)


def elevation_command() -> str:
    """The exact command to gain raw socket access on this host.

    Resolved for the platform running it. Printing all three would leave the
    reader to work out which applies to them.
    """
    kind = system()
    if kind == LINUX:
        target = os.path.realpath(sys.executable)
        command = "sudo setcap cap_net_raw,cap_net_admin+eip %s" % target
        if not shutil.which("setcap"):
            command = "install libcap tools, then: " + command
        if interpreter_is_shared():
            command += (
                "\n  That interpreter is shared, so this grants raw socket access "
                "to every program using it.\n  For one project only, build an "
                "environment with its own binary:\n"
                "    python3 -m venv --copies .venv && "
                "sudo setcap cap_net_raw,cap_net_admin+eip .venv/bin/python3"
            )
        return command
    if kind == MACOS:
        return "sudo chmod g+r /dev/bpf*   (or run the command under sudo)"
    if kind == WINDOWS:
        return (
            "install Npcap with WinPcap compatibility, then run the shell as "
            "Administrator"
        )
    return "raw socket access is not available on this platform"
