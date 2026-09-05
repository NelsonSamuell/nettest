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


def send_frame(interface: str, frame: bytes) -> None:
    """Put one Ethernet frame on the wire. The capture library handles the
    platform difference between AF_PACKET, BPF and Npcap."""
    from scapy.sendrecv import sendp

    sendp(frame, iface=interface, verbose=False)


def capture_frames(interface: str, seconds: float, handler, match=None) -> None:
    """Capture for a fixed time, handing each frame to the handler.

    store is False, so a frame is dissected and discarded. Nothing accumulates
    and nothing is written.
    """
    from scapy.sendrecv import sniff

    sniff(
        iface=interface,
        timeout=seconds,
        store=False,
        prn=handler,
        lfilter=match,
    )


def collect_frames(interface: str, seconds: float, match) -> list:
    """Capture matching frames in the background and return them.

    Only frames the check asked for are kept, in memory, for the length of the
    check. Nothing is written to disk.
    """
    from scapy.sendrecv import AsyncSniffer

    collected: list = []
    sniffer = AsyncSniffer(
        iface=interface, store=False, lfilter=match, prn=collected.append
    )
    sniffer.start()
    return collected, sniffer


def send_packet(interface: str, packet) -> None:
    """Send one IP packet, letting the kernel route and resolve it."""
    from scapy.sendrecv import send

    send(packet, iface=interface, verbose=False)


def classify_connect(address: str, port: int, timeout: float) -> str:
    """Open, closed or filtered, from the errno the connect returned.

    Refused and timed out are different findings. Refused means the host
    answered and nothing is listening; timed out means something dropped the
    packet. Collapsing them loses the thing the check exists to measure.
    """
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    connection = socket.socket(family, socket.SOCK_STREAM)
    connection.settimeout(timeout)
    try:
        code = connection.connect_ex((address, port))
    except OSError:
        return "filtered"
    finally:
        connection.close()
    if code == 0:
        return "open"
    # Refused means the packet reached the host and it answered with a reset.
    # No route means it never got there. Those are different findings and a
    # check that conflates them cannot tell reachability from isolation.
    if code in (errno.ECONNREFUSED, errno.ECONNRESET):
        return "closed"
    return "filtered"


def read_banner(address: str, port: int, timeout: float) -> str:
    """Whatever a service volunteers on connect. Nothing is requested."""
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    connection = socket.socket(family, socket.SOCK_STREAM)
    connection.settimeout(timeout)
    try:
        connection.connect((address, port))
        return connection.recv(256).decode("utf-8", "replace").strip()
    except OSError:
        return ""
    finally:
        connection.close()


def read_tls(address: str, port: int, timeout: float) -> dict:
    """Negotiate TLS and report the version and certificate, nothing more."""
    import ssl

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # Verification is off on purpose: a self signed certificate on a home router
    # is the normal case and is itself worth reporting, not an error.
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    raw = socket.socket(family, socket.SOCK_STREAM)
    raw.settimeout(timeout)
    try:
        raw.connect((address, port))
        with context.wrap_socket(raw) as wrapped:
            certificate = wrapped.getpeercert(binary_form=False) or {}
            return {
                "version": wrapped.version() or "",
                "cipher": (wrapped.cipher() or ("",))[0],
                "subject": str(certificate.get("subject", "")),
                "issuer": str(certificate.get("issuer", "")),
                "self_signed": certificate.get("subject") == certificate.get("issuer"),
            }
    except OSError as error:
        return {"error": str(error)}
    finally:
        raw.close()


def http_request(url: str, timeout: float, data=None, headers=None) -> tuple[int, str, str]:
    """One HTTP request. Returns the status, the body and the final URL."""
    import urllib.error
    import urllib.request

    request = urllib.request.Request(url, data=data, headers=headers or {})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, response.read(65536).decode("utf-8", "replace"), response.url
    except urllib.error.HTTPError as error:
        return error.code, error.read(65536).decode("utf-8", "replace"), url
    except (OSError, ValueError) as error:
        return 0, str(error), url
