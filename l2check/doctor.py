"""Environment check.

Answers the question a beginner actually has when nothing works: is the tool
installed, does it have permission to read frames, and which interface should I
point it at. It opens and closes one raw socket to test permission and touches
nothing else.
"""

from __future__ import annotations

import shutil
import socket
import sys
from dataclasses import dataclass
from pathlib import Path

from l2check import wireless

NET = Path("/sys/class/net")
ROUTE = Path("/proc/net/route")


@dataclass
class Interface:
    name: str
    kind: str
    state: str
    address: str
    is_default: bool


def can_open_raw_socket() -> bool:
    """True when the process may read frames, which is what CAP_NET_RAW grants."""
    try:
        probe = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0)
    except PermissionError:
        return False
    except OSError:
        return False
    probe.close()
    return True


def default_interface() -> str:
    """Return the interface holding the default route, or an empty string."""
    if not ROUTE.exists():
        return ""
    for line in ROUTE.read_text().splitlines()[1:]:
        fields = line.split()
        if len(fields) >= 2 and fields[1] == "00000000":
            return fields[0]
    return ""


def _ipv4(name: str) -> str:
    from l2check.listen import interface_cidr

    return interface_cidr(name)


def interfaces() -> list[Interface]:
    """List the machine's interfaces, most useful first."""
    if not NET.is_dir():
        return []
    default = default_interface()
    found = []
    for path in sorted(NET.iterdir()):
        name = path.name
        if name == "lo":
            kind = "loopback"
        elif wireless.is_wireless(name):
            kind = "wireless"
        else:
            kind = "wired"
        state_file = path / "operstate"
        state = state_file.read_text().strip() if state_file.exists() else "unknown"
        found.append(Interface(name, kind, state, _ipv4(name), name == default))
    # The interface carrying the default route is the one to suggest.
    found.sort(key=lambda i: (not i.is_default, i.kind == "loopback", i.state != "up"))
    return found


def suggested_interface() -> str:
    """The interface a first run should use."""
    for candidate in interfaces():
        if candidate.kind != "loopback" and candidate.state == "up":
            return candidate.name
    return ""


def _module_version(name: str) -> str:
    try:
        module = __import__(name)
    except ImportError:
        return ""
    return getattr(module, "__version__", "present")


def report(prog: str = "netcheck") -> str:
    """Render the environment check as plain text.

    The command name is passed in rather than hardcoded, so running this through
    the l2check alias does not tell you to type netcheck, or the reverse.
    """
    lines = ["%s environment check" % prog, ""]

    raw = can_open_raw_socket()
    checks = [
        ("python", "%d.%d.%d" % sys.version_info[:3], True, ""),
        ("scapy", _module_version("scapy") or "missing", bool(_module_version("scapy")),
         "install it with: pip install scapy"),
        ("pyyaml", _module_version("yaml") or "missing", bool(_module_version("yaml")),
         "install it with: pip install pyyaml"),
        ("iw", "present" if shutil.which("iw") else "missing", bool(shutil.which("iw")),
         "only needed for the wireless checks: apt install iw"),
        ("frame access", "available" if raw else "not permitted", raw,
         "run ./setup.sh once to grant it to this project only"),
    ]
    for name, value, ok, hint in checks:
        lines.append("  %-14s %-12s %s" % (name, value, "ok" if ok else "PROBLEM"))
        if not ok and hint:
            lines.append("  %-14s %s" % ("", hint))

    lines += ["", "Interfaces", "  %-9s %-10s %-8s %s" % ("NAME", "TYPE", "STATE", "ADDRESS")]
    found = interfaces()
    for item in found:
        note = "   default route" if item.is_default else ""
        lines.append(
            "  %-9s %-10s %-8s %s%s"
            % (item.name, item.kind, item.state, item.address or "-", note)
        )
    if not found:
        lines.append("  none found")

    lines.append("")
    suggested = suggested_interface()
    if not raw:
        lines.append("Next step: run ./setup.sh, then try this check again.")
    elif suggested:
        lines.append(
            "Next step: %s listen --interface %s --duration 60" % (prog, suggested)
        )
        lines.append(
            "Or just: %s listen   (it picks %s on its own)" % (prog, suggested)
        )
    else:
        lines.append("Next step: connect an interface, then run this check again.")
    return "\n".join(lines)
