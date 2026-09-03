"""The active session and the run limits.

There is no permission gate. This tool runs on a network its operator owns, so
the authorisation file, its date window and the retyped segment prompt are gone.
What remains is the measurement discipline: the session is still the only route
to the network, and it still counts everything that leaves.

The limits here are defaults rather than ceilings, and every one of them has a
flag that raises it, with a single exception. The send rate is capped in code
because above roughly a thousand packets per second consumer gateways start
dropping responses selectively, and every silence in the report becomes
ambiguous. That is an accuracy constraint, not a policy one.
"""

from __future__ import annotations

import errno
import socket
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable

from scapy.sendrecv import send, sendp

L2_ACTIVE_CHECKS = (
    "L2A01",
    "L2A02",
    "L2A03",
    "L2A04",
    "L2A05",
    "L2A06",
    "L2A07",
    "L2A08",
    "L2A09",
    "L2A10",
)

L3_ACTIVE_CHECKS = (
    "L3A01",
    "L3A02",
    "L3A03",
    "L3A04",
    "L3A05",
    "L3A06",
    "L3A07",
    "L3A08",
    "L3A09",
    "L3A10",
    "L3A11",
    "L3A12",
    "L3A13",
    "L3A14",
    "L3A15",
)

CFG_CHECKS = ("CFG01", "CFG02", "CFG03")

ACTIVE_CHECKS = L2_ACTIVE_CHECKS + L3_ACTIVE_CHECKS

# Defaults for one run. Each has a flag that raises it, except RATE_HARD_CAP.
FRAME_BUDGET = 600
PACKET_BUDGET = 5000
RUNTIME_SECONDS = 15 * 60
DEFAULT_RATE_PPS = 200
RATE_HARD_CAP = 1000

DEFAULT_MAX_MACS = 50
MAX_MACS_DEFAULT_CEILING = 500

# One TCP connect and close is a SYN, an ACK and a RST on the wire.
CONNECT_FRAME_COST = 3

LAYER2 = 2
LAYER3 = 3

BUDGET_EXHAUSTED = "budget_exhausted"


class ConfigError(Exception):
    """An input or configuration problem. The CLI turns this into exit 2."""


class CapExceeded(Exception):
    """A budget, runtime or rate limit was reached."""


class StateChanged(Exception):
    """Something changed mid-run that makes further measurement untrustworthy."""


class SessionNotStarted(Exception):
    """A send was attempted before the session was started."""


def parse_tests(value: str | None, known: Iterable[str] = ACTIVE_CHECKS) -> list[str]:
    """Turn --tests into a validated list of check identifiers."""
    known = tuple(known)
    if value is None or not value.strip():
        raise ConfigError(
            "--tests is required in active mode unless --all is given. "
            "Known checks: %s" % ", ".join(known)
        )
    requested = [item.strip().upper() for item in value.split(",") if item.strip()]
    if not requested:
        raise ConfigError("--tests is empty")
    unknown = [item for item in requested if item not in known]
    if unknown:
        raise ConfigError(
            "unknown check identifier: %s. Known checks: %s"
            % (", ".join(unknown), ", ".join(known))
        )
    ordered = []
    for item in requested:
        if item not in ordered:
            ordered.append(item)
    return ordered


def validate_rate(value: int) -> int:
    """Clamp check for the send rate. This is the one limit a flag cannot raise."""
    if value < 1:
        raise ConfigError("send rate must be at least 1 packet per second")
    if value > RATE_HARD_CAP:
        raise ConfigError(
            "send rate may not exceed %d packets per second: above that, consumer "
            "gateways drop responses selectively and every silence in the report "
            "becomes ambiguous. Use nmap if you need a faster sweep."
            % RATE_HARD_CAP
        )
    return value


def validate_max_macs(value: int) -> int:
    """Bounds check for --max-macs."""
    if value < 1:
        raise ConfigError("--max-macs must be at least 1")
    return value


def link_state(interface: str) -> str:
    """Return the kernel's operstate for the interface, or 'unknown'."""
    path = Path("/sys/class/net") / interface / "operstate"
    if not path.exists():
        return "unknown"
    return path.read_text().strip()


def _send_frame(interface: str, frame: bytes) -> None:
    sendp(frame, iface=interface, verbose=False)


def _send_packet(interface: str, packet) -> None:
    """Send one IP packet, letting the kernel route and resolve it."""
    send(packet, iface=interface, verbose=False)


OPEN = "open"
CLOSED = "closed"
FILTERED = "filtered"


def _tcp_connect(address: str, port: int, timeout: float) -> bool:
    """Open and immediately close one TCP connection. True when it was accepted."""
    return _classify_connect(address, port, timeout) == OPEN


def _classify_connect(address: str, port: int, timeout: float) -> str:
    """Open, closed or filtered, from the errno the connect returned."""
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    connection = socket.socket(family, socket.SOCK_STREAM)
    connection.settimeout(timeout)
    try:
        code = connection.connect_ex((address, port))
    except OSError:
        return FILTERED
    finally:
        connection.close()
    if code == 0:
        return OPEN
    # ECONNREFUSED means the host answered with a reset; a timeout means
    # something in the path swallowed it.
    if code in (errno.ECONNREFUSED, errno.ECONNRESET):
        return CLOSED
    if code in (errno.EHOSTUNREACH, errno.ENETUNREACH):
        return CLOSED
    return FILTERED


def _resolve(name: str) -> str:
    """Resolve a name to one address, or an empty string."""
    try:
        info = socket.getaddrinfo(name, None)
    except OSError:
        return ""
    return info[0][4][0] if info else ""


def _read_banner(address: str, port: int, timeout: float) -> str:
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


def _read_tls(address: str, port: int, timeout: float) -> dict:
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
                "not_after": certificate.get("notAfter", ""),
                "self_signed": certificate.get("subject") == certificate.get("issuer"),
            }
    except OSError as error:
        return {"error": str(error)}
    finally:
        raw.close()


def _http_request(url: str, timeout: float, data, headers: dict) -> tuple[int, str]:
    import urllib.error
    import urllib.request

    request = urllib.request.Request(url, data=data, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, response.read(65536).decode("utf-8", "replace")
    except urllib.error.HTTPError as error:
        return error.code, error.read(65536).decode("utf-8", "replace")
    except (OSError, ValueError) as error:
        return 0, str(error)


@dataclass
class Budget:
    """One run's allowances. Layer 2 and layer 3 decrement independently."""

    frames: int = FRAME_BUDGET
    packets: int = PACKET_BUDGET
    frames_sent: int = 0
    packets_sent: int = 0

    def remaining(self, layer: int) -> int:
        if layer == LAYER2:
            return self.frames - self.frames_sent
        return self.packets - self.packets_sent

    def spend(self, layer: int, count: int) -> None:
        if count > self.remaining(layer):
            raise CapExceeded(
                "layer %d budget of %d reached after %d"
                % (
                    layer,
                    self.frames if layer == LAYER2 else self.packets,
                    self.frames_sent if layer == LAYER2 else self.packets_sent,
                )
            )
        if layer == LAYER2:
            self.frames_sent += count
        else:
            self.packets_sent += count

    def as_dict(self) -> dict:
        return {
            "frame_budget": self.frames,
            "frames_sent": self.frames_sent,
            "frames_remaining": self.remaining(LAYER2),
            "packet_budget": self.packets,
            "packets_sent": self.packets_sent,
            "packets_remaining": self.remaining(LAYER3),
        }


@dataclass
class ActiveSession:
    """The only route from a check to the network.

    A check holds one of these and asks it to send. It has no other way to
    transmit, so the budgets, the runtime cap, the rate limit and the abort on
    unexpected state change cannot be bypassed by a check getting it wrong.
    """

    interface: str
    tests: list[str] = field(default_factory=list)
    budget: Budget = field(default_factory=Budget)
    runtime_cap: int = RUNTIME_SECONDS
    rate_pps: int = DEFAULT_RATE_PPS
    max_macs: int = DEFAULT_MAX_MACS
    test_ip: str | None = None
    target_vlan: int | None = None
    local_cidr: str | None = None
    gateway: str | None = None
    observer: str | None = None
    external_observer: str | None = None
    sweep_targets: list = field(default_factory=list)
    guest_subnet: str = ""
    test_host: str = ""
    authoritative_ns: str = ""
    wan_address: str = ""
    tcp_ports: tuple = ()
    udp_ports: tuple = ()
    tcp_port_limit: int = 200
    tcp_hosts: int = 5
    udp_hosts: int = 3
    tcp_open: dict = field(default_factory=dict)
    upnp_control_url: str = ""
    management_services: list = field(default_factory=list)
    cleanup_required: str = ""
    sender: Callable[[str, bytes], None] = _send_frame
    ip_sender: Callable[[str, object], None] = _send_packet
    connector: Callable[[str, int, float], bool] = _tcp_connect
    classifier: Callable[[str, int, float], str] = None
    banner_reader: Callable[[str, int, float], str] = None
    tls_reader: Callable[[str, int, float], dict] = None
    http_client: Callable = None
    resolver: Callable[[str], str] = None
    clock: Callable[[], float] = time.monotonic
    sleeper: Callable[[float], None] = time.sleep
    started: bool = False
    link_change_expected: bool = False
    aborted_during: str | None = None
    current_check: str | None = None
    _started_at: float | None = None
    _baseline_link: str = ""
    _baseline_gateway_mac: str = ""
    _last_send: float | None = None

    def start(self, tests: Iterable[str]) -> None:
        """Arm the session. Called once, before the first check runs."""
        selected = list(tests)
        if not selected:
            raise ConfigError("no checks selected")
        validate_rate(self.rate_pps)
        if self.classifier is None:
            self.classifier = _classify_connect
        if self.banner_reader is None:
            self.banner_reader = _read_banner
        if self.tls_reader is None:
            self.tls_reader = _read_tls
        if self.http_client is None:
            self.http_client = _http_request
        if self.resolver is None:
            self.resolver = _resolve
        self.tests = selected
        self.started = True
        self._started_at = self.clock()
        self._baseline_link = link_state(self.interface)
        self._baseline_gateway_mac = self.gateway_mac()

    # Backwards compatible name for the L2 budget, which several probes read.
    @property
    def frames_sent(self) -> int:
        return self.budget.frames_sent

    @frames_sent.setter
    def frames_sent(self, value: int) -> None:
        self.budget.frames_sent = value

    @property
    def frame_cap(self) -> int:
        return self.budget.frames

    @frame_cap.setter
    def frame_cap(self, value: int) -> None:
        self.budget.frames = value

    @property
    def frames_remaining(self) -> int:
        return self.budget.remaining(LAYER2)

    @property
    def packets_remaining(self) -> int:
        return self.budget.remaining(LAYER3)

    @property
    def elapsed(self) -> float:
        if self._started_at is None:
            return 0.0
        return self.clock() - self._started_at

    def gateway_mac(self) -> str:
        """The gateway's MAC from the kernel neighbour table, or an empty string."""
        if not self.gateway:
            return ""
        table = Path("/proc/net/arp")
        if not table.exists():
            return ""
        for line in table.read_text().splitlines()[1:]:
            fields = line.split()
            if fields and fields[0] == self.gateway and len(fields) >= 4:
                return fields[3].lower()
        return ""

    def check_runtime(self) -> None:
        if self.elapsed > self.runtime_cap:
            raise CapExceeded("runtime cap of %d seconds reached" % self.runtime_cap)

    def check_state(self) -> None:
        """Abort when something changed that makes further measurement untrustworthy.

        The link going down, the gateway being swapped, or the default route
        moving all mean the thing being measured is no longer the thing that was
        measured a minute ago.
        """
        if not self.link_change_expected:
            current = link_state(self.interface)
            if current != self._baseline_link:
                self.aborted_during = self.current_check
                raise StateChanged(
                    "interface %s went from %s to %s"
                    % (self.interface, self._baseline_link, current)
                )
        if self._baseline_gateway_mac:
            current_mac = self.gateway_mac()
            if current_mac and current_mac != self._baseline_gateway_mac:
                self.aborted_during = self.current_check
                raise StateChanged(
                    "gateway %s changed MAC from %s to %s"
                    % (self.gateway, self._baseline_gateway_mac, current_mac)
                )

    def _pace(self, count: int) -> None:
        """Hold the configured send rate. The rate limit is not overridable."""
        if self.rate_pps <= 0:
            return
        interval = count / float(self.rate_pps)
        # A monotonic clock can legitimately read 0.0, so the first send is
        # identified by the sentinel rather than by a falsy timestamp.
        if self._last_send is not None:
            elapsed = self.clock() - self._last_send
            if elapsed < interval:
                self.sleeper(interval - elapsed)
        self._last_send = self.clock()

    def _permit(self, count: int, layer: int) -> None:
        if not self.started:
            raise SessionNotStarted(
                "the session has not been started, so nothing may be sent"
            )
        self.check_runtime()
        self.check_state()
        self.budget.spend(layer, count)
        self._pace(count)

    def send(self, frames: bytes | Iterable[bytes], layer: int = LAYER2) -> int:
        """Transmit one or more frames, counted against the layer's budget."""
        batch = [frames] if isinstance(frames, (bytes, bytearray)) else list(frames)
        self._permit(len(batch), layer)
        for frame in batch:
            self.sender(self.interface, bytes(frame))
        return len(batch)

    def send_ip(self, packets) -> int:
        """Send IP packets, counted against the layer 3 budget.

        Scapy packets rather than bytes, because the kernel does the routing and
        address resolution: a layer 3 check should not have to know the next
        hop's MAC address to ask a question of a host two subnets away.
        """
        batch = packets if isinstance(packets, (list, tuple)) else [packets]
        batch = list(batch)
        self._permit(len(batch), LAYER3)
        for packet in batch:
            self.ip_sender(self.interface, packet)
        return len(batch)

    def resolve(self, name: str) -> str:
        """Resolve a configured name to an address, or an empty string.

        Not counted against a budget: it goes through the system resolver like
        any other name lookup, and it is not a probe of the target.
        """
        if not name:
            return ""
        try:
            import ipaddress as _ip

            _ip.ip_address(name)
            return name
        except ValueError:
            return (self.resolver or _resolve)(name)

    def grab_banner(self, address: str, port: int, timeout: float = 3.0) -> str:
        """Read whatever a service says on connect. Never sends a request.

        The banner is data the service volunteered to a connection this tool
        opened, so it is addressed to us. Nothing is requested, and no
        credentials are offered: version detection is the boundary.
        """
        self._permit(CONNECT_FRAME_COST, LAYER3)
        return self.banner_reader(address, port, timeout)

    def tls_details(self, address: str, port: int, timeout: float = 4.0) -> dict:
        """Negotiate TLS and report the version and certificate, nothing more."""
        self._permit(CONNECT_FRAME_COST, LAYER3)
        return self.tls_reader(address, port, timeout)

    def http(self, url: str, timeout: float = 4.0, data: bytes | None = None,
             headers: dict | None = None) -> tuple[int, str]:
        """One HTTP request, counted. Returns the status and the body."""
        self._permit(CONNECT_FRAME_COST, LAYER3)
        return self.http_client(url, timeout, data, headers or {})

    def connect_result(self, address: str, port: int, timeout: float = 2.0) -> str:
        """Classify one TCP connection as open, closed or filtered.

        A refused connection and a timed out one are different findings: refused
        means the host answered and nothing is listening, timed out means
        something dropped the packet. Collapsing them loses the thing the check
        exists to measure.
        """
        self._permit(CONNECT_FRAME_COST, LAYER3)
        return self.classifier(address, port, timeout)

    def connect(self, address: str, port: int, timeout: float = 2.0) -> bool:
        """Open and close one TCP connection, counted against the caps."""
        self._permit(CONNECT_FRAME_COST, LAYER2)
        return self.connector(address, port, timeout)
