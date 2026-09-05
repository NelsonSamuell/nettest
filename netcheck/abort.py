"""The abort watcher.

Stops the run when something changes that makes further measurement
untrustworthy: the link going down, the default route moving, the gateway
changing MAC or going quiet, or name resolution failing. Which check was in
flight is recorded, because a gateway that stopped answering during a UDP sweep
is a finding about the gateway, not an interruption.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable

from netcheck.platform import interfaces as interfaces_module

LINK_CHANGED = "link_state_changed"
ROUTE_CHANGED = "default_route_changed"
GATEWAY_MAC_CHANGED = "gateway_mac_changed"
GATEWAY_UNRESPONSIVE = "gateway_unresponsive"
DNS_LOST = "dns_resolution_lost"


class StateChanged(Exception):
    """Something changed mid-run. Carries the reason and the check in flight."""

    def __init__(self, reason: str, detail: str, during: str | None) -> None:
        super().__init__(detail)
        self.reason = reason
        self.detail = detail
        self.during = during


@dataclass
class Baseline:
    interface: str = ""
    link_up: bool = False
    default_interface: str = ""
    gateway: str = ""
    gateway_mac: str = ""


@dataclass
class AbortWatcher:
    interface: str = ""
    gateway: str = ""
    baseline: Baseline = field(default_factory=Baseline)
    current_check: str | None = None
    aborted_during: str | None = None
    reason: str = ""
    expect_link_change: bool = False
    gateway_probe: Callable[[str], bool] | None = None
    resolver_probe: Callable[[], bool] = interfaces_module.resolves_dns
    clock: Callable[[], float] = time.monotonic
    started_at: float = 0.0

    def start(self) -> None:
        """Record what the world looked like before anything was sent."""
        entry = interfaces_module.interface_named(self.interface)
        self.baseline = Baseline(
            interface=self.interface,
            link_up=bool(entry and entry.up),
            default_interface=interfaces_module.default_interface(),
            gateway=self.gateway or interfaces_module.default_gateway(),
            gateway_mac=interfaces_module.gateway_mac(
                self.gateway or interfaces_module.default_gateway()
            ),
        )
        self.started_at = self.clock()

    def _raise(self, reason: str, detail: str) -> None:
        self.aborted_during = self.current_check
        self.reason = reason
        raise StateChanged(reason, detail, self.current_check)

    def check(self) -> None:
        """Look for anything that invalidates measurements taken from here on."""
        if not self.expect_link_change:
            entry = interfaces_module.interface_named(self.interface)
            up = bool(entry and entry.up)
            if self.baseline.link_up and not up:
                self._raise(
                    LINK_CHANGED,
                    "interface %s went down" % self.interface,
                )

        current_default = interfaces_module.default_interface()
        if self.baseline.default_interface and current_default != self.baseline.default_interface:
            self._raise(
                ROUTE_CHANGED,
                "the default route moved from %s to %s"
                % (self.baseline.default_interface, current_default or "nothing"),
            )

        if self.baseline.gateway_mac:
            current_mac = interfaces_module.gateway_mac(self.baseline.gateway)
            if current_mac and current_mac != self.baseline.gateway_mac:
                self._raise(
                    GATEWAY_MAC_CHANGED,
                    "gateway %s changed link layer address"
                    % self.baseline.gateway,
                )

        if self.gateway_probe is not None and self.baseline.gateway:
            if not self.gateway_probe(self.baseline.gateway):
                self._raise(
                    GATEWAY_UNRESPONSIVE,
                    "gateway %s stopped answering. A box that stopped responding "
                    "and a control that dropped the packet look identical from "
                    "here, so the run stops rather than guess"
                    % self.baseline.gateway,
                )

        if not self.resolver_probe():
            self._raise(DNS_LOST, "name resolution stopped working")

    def as_dict(self) -> dict:
        return {
            "aborted": bool(self.reason),
            "reason": self.reason,
            "during": self.aborted_during,
            "baseline_interface": self.baseline.interface,
            "baseline_gateway": self.baseline.gateway,
        }
