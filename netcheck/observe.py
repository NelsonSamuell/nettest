"""The cooperating listener.

Run by the operator at a vantage point the tool cannot reach on its own. It
records only the marker tokens the checks emit, never frame payloads, and
answers a one line query about them.

Without one, every check measuring one way delivery returns INDETERMINATE. That
is the point: a local timeout does not distinguish a filter from a dead host.
"""

from __future__ import annotations

import re
import socket
import threading

MARKER_PATTERN = re.compile(rb"NETCHECK-[0-9A-F]{8}")

INTERNAL = "internal"
EXTERNAL = "external"
SIDES = (INTERNAL, EXTERNAL)

USAGE = "ERROR expected: SEEN <token> | SIDE"


class Observer:
    """Records probe markers seen on an interface and answers queries about them."""

    def __init__(self, interface: str, port: int, side: str = INTERNAL) -> None:
        self.interface = interface
        self.port = port
        self.side = side
        self.seen: set[str] = set()
        self._lock = threading.Lock()

    def record(self, packet) -> None:
        """Note any marker in a frame. Nothing else about it is kept."""
        from scapy.layers.l2 import ARP

        tokens = {match.decode() for match in MARKER_PATTERN.findall(bytes(packet))}
        if ARP in packet and packet[ARP].op == 2:
            tokens.add("ARP:" + packet[ARP].psrc)
        if tokens:
            with self._lock:
                self.seen |= tokens

    def answer(self, line: str) -> str:
        """Handle one query. An unknown verb is refused rather than guessed at."""
        parts = line.strip().split()
        if not parts:
            return USAGE
        verb = parts[0].upper()
        if verb == "SIDE":
            return "SIDE " + self.side
        if verb == "SEEN" and len(parts) == 2:
            with self._lock:
                return ("YES " if parts[1] in self.seen else "NO ") + parts[1]
        return USAGE

    def serve(self) -> None:
        """Capture markers and serve queries until interrupted."""
        from scapy.sendrecv import AsyncSniffer

        sniffer = AsyncSniffer(iface=self.interface, store=False, prn=self.record)
        sniffer.start()
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("", self.port))
        listener.listen(4)
        print(
            "observing %s on the %s side, answering on port %d"
            % (self.interface, self.side, listener.getsockname()[1])
        )
        try:
            while True:
                connection, _ = listener.accept()
                with connection:
                    line = connection.makefile("r").readline()
                    connection.sendall((self.answer(line) + "\n").encode())
        except KeyboardInterrupt:
            pass
        finally:
            listener.close()
            sniffer.stop()


def query(endpoint: str, line: str, timeout: float = 5.0) -> str | None:
    """One request to an observer. None means it could not be reached."""
    host, _, port = endpoint.rpartition(":")
    if not host or not port.isdigit():
        raise ValueError("observer must be given as HOST:PORT")
    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connection.settimeout(timeout)
    try:
        connection.connect((host, int(port)))
        connection.sendall((line + "\n").encode())
        return connection.makefile("r").readline().strip()
    except OSError:
        return None
    finally:
        connection.close()


def ask_seen(endpoint: str, token: str, timeout: float = 5.0) -> bool | None:
    """Whether an observer saw a token. None means it could not be reached.

    None is never read as a negative: an observer that did not answer is not an
    observer that saw nothing.
    """
    reply = query(endpoint, "SEEN %s" % token, timeout)
    return None if reply is None else reply.startswith("YES ")


def ask_side(endpoint: str, timeout: float = 5.0) -> str | None:
    """Which side of the boundary an observer says it is on."""
    reply = query(endpoint, "SIDE", timeout)
    if reply is None or not reply.startswith("SIDE "):
        return None
    return reply.split()[1]
