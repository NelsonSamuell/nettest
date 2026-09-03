"""The cooperating listener.

Run by the operator at a vantage point the tool cannot reach on its own. An
internal observer sits on the target segment; an external one sits outside the
NAT boundary, on a cheap VPS, and is what makes the inbound and egress checks
able to answer at all.

It records only the marker tokens the checks emit, never frame payloads, and
answers a one line TCP query about them. An external observer will additionally
attempt a connection on request, which is the only way to ask whether something
is reachable from outside without guessing.
"""

import re
import socket
import threading

from scapy.layers.l2 import ARP
from scapy.sendrecv import AsyncSniffer

MARKER_PATTERN = re.compile(rb"L2CHECK-[0-9A-F]{8}")

INTERNAL = "internal"
EXTERNAL = "external"

OPEN = "open"
CLOSED = "closed"
FILTERED = "filtered"

CONNECT_TIMEOUT = 4.0


class Observer:
    """Records probe markers seen on an interface and answers queries about them."""

    def __init__(self, interface: str, port: int, side: str = INTERNAL) -> None:
        self.interface = interface
        self.port = port
        self.side = side
        self.seen: set[str] = set()
        self._lock = threading.Lock()

    def record(self, packet) -> None:
        """Note any probe marker in a frame. Nothing else about it is kept."""
        tokens = {match.decode() for match in MARKER_PATTERN.findall(bytes(packet))}
        if ARP in packet and packet[ARP].op == 2:
            tokens.add("ARP:" + packet[ARP].psrc)
        if tokens:
            with self._lock:
                self.seen |= tokens

    def _connect(self, host: str, port: int) -> str:
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        connection = socket.socket(family, socket.SOCK_STREAM)
        connection.settimeout(CONNECT_TIMEOUT)
        try:
            code = connection.connect_ex((host, port))
        except OSError:
            return FILTERED
        finally:
            connection.close()
        if code == 0:
            return OPEN
        return CLOSED if code in (111, 104, 113, 101) else FILTERED

    def answer(self, line: str) -> str:
        """Handle one query. Unknown verbs are refused rather than guessed at."""
        parts = line.strip().split()
        if not parts:
            return "ERROR expected: SEEN <token> | CONNECT <host> <port> | SIDE"
        verb = parts[0].upper()

        if verb == "SIDE":
            return "SIDE " + self.side
        if verb == "SEEN" and len(parts) == 2:
            with self._lock:
                return ("YES " if parts[1] in self.seen else "NO ") + parts[1]
        if verb == "CONNECT" and len(parts) == 3:
            if self.side != EXTERNAL:
                return "ERROR CONNECT needs an observer started with --side external"
            if not parts[2].isdigit():
                return "ERROR port must be a number"
            return "%s %s %s" % (self._connect(parts[1], int(parts[2])), parts[1], parts[2])
        return "ERROR expected: SEEN <token> | CONNECT <host> <port> | SIDE"

    def serve(self) -> None:
        """Sniff for markers and serve queries until interrupted."""
        sniffer = AsyncSniffer(iface=self.interface, store=False, prn=self.record)
        sniffer.start()
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("", self.port))
        listener.listen(4)
        print(
            "observing %s on the %s side, answering queries on port %d"
            % (self.interface, self.side, self.port)
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


def _query(endpoint: str, line: str, timeout: float) -> str | None:
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


def ask_observer(endpoint: str, token: str, timeout: float = 5.0) -> bool | None:
    """Ask an observer whether it saw a token. None means it could not be reached."""
    reply = _query(endpoint, "SEEN %s" % token, timeout)
    return None if reply is None else reply.startswith("YES ")


def ask_observer_connect(
    endpoint: str, host: str, port: int, timeout: float = 5.0
) -> str | None:
    """Ask an external observer to attempt a connection and report what happened.

    Returns open, closed or filtered, or None when the observer could not be
    reached or refused the request. None is never read as a negative result.
    """
    reply = _query(endpoint, "CONNECT %s %d" % (host, port), timeout)
    if reply is None or reply.startswith("ERROR"):
        return None
    return reply.split()[0]


def ask_observer_side(endpoint: str, timeout: float = 5.0) -> str | None:
    """Which side of the NAT boundary an observer says it is on."""
    reply = _query(endpoint, "SIDE", timeout)
    if reply is None or not reply.startswith("SIDE "):
        return None
    return reply.split()[1]
