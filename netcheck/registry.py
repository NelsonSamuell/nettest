"""The check registry.

Every check declares the capabilities it needs. A check whose requirements are
unmet is skipped before it runs, and the reason distinguishes a platform that
cannot do it from a privilege that has not been granted: the first cannot be
fixed, the second tells the operator what command to run.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable

from netcheck.models import (
    BUDGET_EXHAUSTED,
    NOT_SELECTED,
    UNTESTED,
)
from netcheck.platform.detect import CAPABILITIES, CapabilitySet

L2P = "L2P"
L2A = "L2A"
L3P = "L3P"
L3A = "L3A"
CFG = "CFG"
PREFIXES = (L2P, L2A, L3P, L3A, CFG)

PASSIVE_PREFIXES = (L2P, L3P, CFG)


@dataclass
class Check:
    """One check, what it needs, and what it can establish."""

    identifier: str
    title: str
    controls: tuple[str, ...] = ()
    requires: frozenset[str] = frozenset()
    depends_on: tuple[str, ...] = ()
    run: Callable | None = None

    @property
    def prefix(self) -> str:
        return self.identifier[:3]

    @property
    def is_passive(self) -> bool:
        return self.prefix in PASSIVE_PREFIXES


@dataclass
class Skipped:
    identifier: str
    reason: str
    detail: str = ""


@dataclass
class Registry:
    checks: dict[str, Check] = field(default_factory=dict)

    def register(self, check: Check) -> Check:
        if check.prefix not in PREFIXES:
            raise ValueError("unknown check prefix: %s" % check.identifier)
        unknown = set(check.requires) - set(CAPABILITIES)
        if unknown:
            raise ValueError(
                "%s declares unknown capabilities: %s"
                % (check.identifier, ", ".join(sorted(unknown)))
            )
        if check.identifier in self.checks:
            raise ValueError("%s is already registered" % check.identifier)
        self.checks[check.identifier] = check
        return check

    def identifiers(self) -> list[str]:
        """Every registered check, in dependency order.

        Passive completes before active, and a check that reads another's output
        runs after it. Sorting by identifier alone would run L3A08 before L3P04.
        """
        return sorted(self.checks, key=self._order)

    def _order(self, identifier: str) -> tuple:
        check = self.checks[identifier]
        return (0 if check.is_passive else 1, len(check.depends_on), identifier)

    def resolve(
        self,
        selected: list[str],
        capabilities: CapabilitySet,
        budget=None,
    ) -> tuple[list[str], list[Skipped]]:
        """Split the selection into what can run and what cannot, with reasons."""
        runnable: list[str] = []
        skipped: list[Skipped] = []
        for identifier in sorted(selected, key=self._order):
            check = self.checks.get(identifier)
            if check is None:
                skipped.append(Skipped(identifier, NOT_SELECTED, "not registered"))
                continue
            reason = capabilities.reason_for(check.requires)
            if reason:
                missing = capabilities.missing(check.requires)
                skipped.append(
                    Skipped(
                        identifier,
                        reason,
                        "needs %s" % ", ".join(c.name for c in missing),
                    )
                )
                continue
            if budget is not None and not check.is_passive:
                from netcheck.budget import LAYER2, LAYER3

                layer = LAYER2 if check.prefix == L2A else LAYER3
                if budget.exhausted(layer):
                    skipped.append(Skipped(identifier, BUDGET_EXHAUSTED, ""))
                    continue
            runnable.append(identifier)
        return runnable, skipped


@dataclass
class Context:
    """What a check is given, and the only route it has to the network.

    A check can ask this to send. It has no other way, so the budgets, the send
    rate and the abort watcher cannot be bypassed by a check getting it wrong.
    """

    interface: str = ""
    config: object = None
    budget: object = None
    abort: object = None
    capabilities: CapabilitySet = field(default_factory=CapabilitySet)
    profile: object = None
    capture: object = None
    test_ip: str = ""
    observer: str = ""
    max_macs: int = 50
    started: bool = False
    sender: Callable[[str, bytes], None] | None = None
    collector: Callable | None = None
    observer_query: Callable | None = None
    observer_connect: Callable | None = None
    resolver: Callable | None = None
    packet_sender: Callable | None = None
    classifier: Callable | None = None
    banner_reader: Callable | None = None
    tls_reader: Callable | None = None
    http_client: Callable | None = None
    cleanup: list = field(default_factory=list)
    tcp_open: dict = field(default_factory=dict)
    management_services: list = field(default_factory=list)

    def run_cleanup(self) -> None:
        """Undo anything a check wrote to another device.

        Called on a normal finish and on an abort. Checks that write state also
        register with atexit and the interrupt handlers, so nothing survives a
        run that ends unexpectedly.
        """
        for handler in self.cleanup:
            handler()
    clock: Callable[[], float] = time.monotonic
    sleeper: Callable[[float], None] = time.sleep
    expect_link_change: bool = False
    _last_send: float | None = None

    def start(self) -> None:
        """Open the route to the network. Called once, after every gate passed."""
        self.started = True

    def _pace(self, count: int) -> None:
        """Hold the configured send rate. This limit is never overridable."""
        rate = getattr(self.budget, "rate_pps", 0) or 0
        if rate <= 0:
            return
        interval = count / float(rate)
        # A monotonic clock can legitimately read 0.0, so the first send is
        # identified by the sentinel rather than by a falsy timestamp.
        if self._last_send is not None:
            elapsed = self.clock() - self._last_send
            if elapsed < interval:
                self.sleeper(interval - elapsed)
        self._last_send = self.clock()

    def send_frames(self, frames) -> int:
        """Transmit frames, counted against the layer 2 budget."""
        from netcheck.budget import LAYER2

        if not self.started:
            raise NotStarted("nothing may be sent before the context is started")
        batch = [frames] if isinstance(frames, (bytes, bytearray)) else list(frames)
        if self.abort is not None:
            self.abort.expect_link_change = self.expect_link_change
            self.abort.check()
        self.budget.spend(LAYER2, len(batch))
        self._pace(len(batch))
        sender = self.sender or _default_sender
        for frame in batch:
            sender(self.interface, bytes(frame))
        return len(batch)

    def send_packets(self, packets) -> int:
        """Send IP packets, counted against the layer 3 budget.

        Separate from send_frames because the two budgets decrement
        independently: one ceiling covering both would let a sweep starve the
        checks that need a handful of frames.
        """
        from netcheck.budget import LAYER3

        if not self.started:
            raise NotStarted("nothing may be sent before the context is started")
        batch = packets if isinstance(packets, (list, tuple)) else [packets]
        batch = list(batch)
        if self.abort is not None:
            self.abort.expect_link_change = self.expect_link_change
            self.abort.check()
        self.budget.spend(LAYER3, len(batch))
        self._pace(len(batch))
        sender = self.packet_sender or _default_packet_sender
        for packet in batch:
            sender(self.interface, packet)
        return len(batch)

    def connect_result(self, address: str, port: int, timeout: float = 2.0) -> str:
        """Whether a port is open, closed or filtered. Costs one layer 3 packet."""
        from netcheck.budget import LAYER3

        self.budget.spend(LAYER3, 1)
        return (self.classifier or _default_classifier)(address, port, timeout)

    def banner(self, address: str, port: int, timeout: float = 3.0) -> str:
        """What a service says on connect. Version detection is the boundary."""
        from netcheck.budget import LAYER3

        self.budget.spend(LAYER3, 1)
        return (self.banner_reader or _default_banner)(address, port, timeout)

    def tls(self, address: str, port: int, timeout: float = 4.0) -> dict:
        """The TLS version and certificate, and nothing else."""
        from netcheck.budget import LAYER3

        self.budget.spend(LAYER3, 1)
        return (self.tls_reader or _default_tls)(address, port, timeout)

    def http(self, url: str, timeout: float = 4.0, data=None, headers=None):
        """One HTTP request, counted."""
        from netcheck.budget import LAYER3

        self.budget.spend(LAYER3, 1)
        return (self.http_client or _default_http)(url, timeout, data, headers)

    def ask_observer_connect(self, endpoint: str, host: str, port: int,
                             timeout: float = 5.0):
        """Ask an external observer to attempt a connection from its side."""
        asker = self.observer_connect or _default_observer_connect
        return asker(endpoint, host, port, timeout)

    def collect(self, seconds: float, match):
        """Listen for matching replies while a check is sending."""
        collector = self.collector or _default_collector
        return collector(self.interface, seconds, match)

    def ask_observer(self, token: str, timeout: float = 5.0, endpoint: str = ""):
        """Whether an observer saw a token, or None if it could not be reached.

        Routed through the context for the same reason sending is: it is the one
        place a check reaches anything outside itself, and it keeps the query out
        of the checks so they stay testable without a socket.
        """
        target = endpoint or self.observer
        if not target:
            return None
        asker = self.observer_query or _default_observer_query
        return asker(target, token, timeout)

    def resolve(self, name: str) -> str:
        """A configured name as an address, or an empty string.

        Not counted: it goes through the system resolver like any other lookup
        and is not a probe of the target. A name that does not resolve makes the
        check refuse rather than raise mid run.
        """
        if not name:
            return ""
        import ipaddress

        try:
            ipaddress.ip_address(name)
            return name
        except ValueError:
            pass
        return (self.resolver or _default_resolver)(name)


class NotStarted(Exception):
    """A send was attempted before the context was started."""


def _default_sender(interface: str, frame: bytes) -> None:
    from netcheck.platform.sockets import send_frame

    send_frame(interface, frame)


def _default_resolver(name: str) -> str:
    import socket

    try:
        info = socket.getaddrinfo(name, None)
    except OSError:
        return ""
    return info[0][4][0] if info else ""


def _default_observer_connect(endpoint: str, host: str, port: int, timeout: float):
    from netcheck.observe import ask_connect

    return ask_connect(endpoint, host, port, timeout)


def _default_packet_sender(interface: str, packet) -> None:
    from netcheck.platform.sockets import send_packet

    send_packet(interface, packet)


def _default_classifier(address: str, port: int, timeout: float) -> str:
    from netcheck.platform.sockets import classify_connect

    return classify_connect(address, port, timeout)


def _default_banner(address: str, port: int, timeout: float) -> str:
    from netcheck.platform.sockets import read_banner

    return read_banner(address, port, timeout)


def _default_tls(address: str, port: int, timeout: float) -> dict:
    from netcheck.platform.sockets import read_tls

    return read_tls(address, port, timeout)


def _default_http(url: str, timeout: float, data, headers):
    from netcheck.platform.sockets import http_request

    return http_request(url, timeout, data, headers)


def _default_observer_query(endpoint: str, token: str, timeout: float):
    from netcheck.observe import ask_seen

    return ask_seen(endpoint, token, timeout)


def _default_collector(interface: str, seconds: float, match):
    from netcheck.platform.sockets import collect_frames

    return collect_frames(interface, seconds, match)


REGISTRY = Registry()


def skipped_controls(skipped: list[Skipped], registry: Registry, posture) -> None:
    """Record why a control was not established, never as ABSENT."""
    for entry in skipped:
        check = registry.checks.get(entry.identifier)
        if check is None:
            continue
        for control in check.controls:
            posture.set(
                control,
                UNTESTED,
                entry.identifier,
                entry.detail or entry.reason,
            )
