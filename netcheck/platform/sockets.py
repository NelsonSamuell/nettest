"""Socket construction, and the probes that decide whether it is possible.

Each opener attempts the real thing and closes it. A capability is present
because the socket opened, never because the platform name suggested it would.
"""

from __future__ import annotations

import errno
import socket
from pathlib import Path

from netcheck.platform.system import LINUX, MACOS, WINDOWS, system

ETH_P_ALL = 0x0003


class ProbeResult:
    """Whether a mechanism worked, and if not, whether privilege was the reason."""

    def __init__(self, ok: bool, how: str, privileged_failure: bool = False,
                 detail: str = "") -> None:
        self.ok = ok
        self.how = how
        self.privileged_failure = privileged_failure
        self.detail = detail


def _privilege_error(error: OSError) -> bool:
    return error.errno in (errno.EPERM, errno.EACCES)


def probe_raw_l2() -> ProbeResult:
    """Try to open a link layer socket the way a capture would."""
    kind = system()
    if kind == LINUX:
        how = "socket(AF_PACKET, SOCK_RAW)"
        try:
            handle = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        except AttributeError:
            return ProbeResult(False, how, detail="AF_PACKET is not available")
        except OSError as error:
            return ProbeResult(False, how, _privilege_error(error), str(error))
        handle.close()
        return ProbeResult(True, how)
    if kind == MACOS:
        how = "open /dev/bpf*"
        found = sorted(Path("/dev").glob("bpf*"))
        if not found:
            return ProbeResult(False, how, detail="no bpf device nodes")
        try:
            handle = open(found[0], "rb")
        except OSError as error:
            return ProbeResult(False, how, _privilege_error(error), str(error))
        handle.close()
        return ProbeResult(True, how)
    if kind == WINDOWS:
        how = "load the Npcap driver"
        ok, detail = _npcap_present()
        return ProbeResult(ok, how, detail=detail)
    return ProbeResult(False, "unsupported", detail="no link layer mechanism")


def _npcap_present() -> tuple[bool, str]:
    """Whether a packet capture driver is installed on Windows."""
    import ctypes

    for library in ("wpcap.dll", "Packet.dll"):
        try:
            ctypes.CDLL(library)
        except OSError:
            return False, "%s not found: install Npcap" % library
    return True, ""


def probe_raw_l3() -> ProbeResult:
    """Try to open a raw IP socket the way header crafting would."""
    if system() == WINDOWS:
        how = "raw IPv4 socket via the capture driver"
        ok, detail = _npcap_present()
        return ProbeResult(ok, how, detail=detail)
    how = "socket(AF_INET, SOCK_RAW, IPPROTO_RAW)"
    try:
        handle = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    except OSError as error:
        return ProbeResult(False, how, _privilege_error(error), str(error))
    handle.close()
    return ProbeResult(True, how)


def probe_socket_l4() -> ProbeResult:
    """Ordinary TCP. Needs no privilege anywhere, so this should always pass."""
    how = "socket(AF_INET, SOCK_STREAM)"
    try:
        handle = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except OSError as error:
        return ProbeResult(False, how, _privilege_error(error), str(error))
    handle.close()
    return ProbeResult(True, how)
