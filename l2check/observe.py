"""The cooperating listener for L2A05 and L2A06.

Run by the operator on the target segment. It records only the marker tokens the
probes emit, never frame payloads, and answers a one line TCP query about them.
"""

import re
import socket
import threading

from scapy.layers.l2 import ARP
from scapy.sendrecv import AsyncSniffer

MARKER_PATTERN = re.compile(rb"L2CHECK-[0-9A-F]{8}")


class Observer:
    """Records probe markers seen on an interface and answers queries about them."""

    def __init__(self, interface: str, port: int) -> None:
        self.interface = interface
        self.port = port
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

    def answer(self, line: str) -> str:
        verb, _, token = line.strip().partition(" ")
        if verb.upper() != "SEEN" or not token:
            return "ERROR expected: SEEN <token>"
        with self._lock:
            return ("YES " if token in self.seen else "NO ") + token

    def serve(self) -> None:
        """Sniff for markers and serve queries until interrupted."""
        sniffer = AsyncSniffer(iface=self.interface, store=False, prn=self.record)
        sniffer.start()
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("", self.port))
        listener.listen(4)
        print("observing %s, answering queries on port %d" % (self.interface, self.port))
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


def ask_observer(endpoint: str, token: str, timeout: float = 5.0) -> bool | None:
    """Ask an observer whether it saw a token. None means it could not be reached."""
    host, _, port = endpoint.rpartition(":")
    if not host or not port.isdigit():
        raise ValueError("observer must be given as HOST:PORT")
    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connection.settimeout(timeout)
    try:
        connection.connect((host, int(port)))
        connection.sendall(("SEEN %s\n" % token).encode())
        reply = connection.makefile("r").readline().strip()
    except OSError:
        return None
    finally:
        connection.close()
    return reply.startswith("YES ")
