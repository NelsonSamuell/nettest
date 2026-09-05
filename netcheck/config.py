"""The targets file, and where it is found.

Input, not a permission slip. Every field defaults from the routing table, so a
plain LAN run needs no file at all.
"""

from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from netcheck.budget import (
    FRAME_BUDGET,
    PACKET_BUDGET,
    RATE_PPS,
    RUNTIME_MINUTES,
    validate_rate,
)
from netcheck.platform import interfaces as interfaces_module
from netcheck.platform.system import config_home
from netcheck.profile import ConfigError

CONFIG_ENV = "NETCHECK_CONFIG"
CONFIG_NAME = "netcheck.yaml"

# Anything wider than this prints an estimate and needs --yes.
WIDE_PREFIX_V4 = 24

CGNAT = ipaddress.ip_network("100.64.0.0/10")


@dataclass
class Limits:
    rate_pps: int = RATE_PPS
    frame_budget: int = FRAME_BUDGET
    packet_budget: int = PACKET_BUDGET
    runtime_minutes: int = RUNTIME_MINUTES


@dataclass
class Config:
    subnets: list[str] = field(default_factory=list)
    gateway: str = ""
    guest_subnet: str = ""
    exclude: list[str] = field(default_factory=list)
    observers: dict[str, str] = field(default_factory=dict)
    external: dict[str, str] = field(default_factory=dict)
    limits: Limits = field(default_factory=Limits)
    source: str = "defaults"
    wan_address: str = ""

    @property
    def internal_observer(self) -> str:
        return self.observers.get("internal", "")

    @property
    def external_observer(self) -> str:
        return self.observers.get("external", "")

    def excluded(self) -> set[str]:
        blocked: set[str] = set()
        for entry in self.exclude:
            blocked |= {str(host) for host in _hosts_of(entry)}
        if self.wan_address:
            blocked.add(self.wan_address)
        return blocked

    def addresses(self, include_wan: bool = False) -> list[str]:
        """Target addresses with exclusions applied. Exclude always wins."""
        blocked = self.excluded()
        if include_wan and self.wan_address:
            blocked.discard(self.wan_address)
        chosen: list[str] = []
        for subnet in self.subnets:
            network = ipaddress.ip_network(subnet, strict=False)
            if network.version != 4:
                continue
            for host in network.hosts():
                text = str(host)
                if text not in blocked and text not in chosen:
                    chosen.append(text)
        return chosen

    def wide_prefixes(self) -> list[tuple[str, int]]:
        wide = []
        for subnet in self.subnets:
            network = ipaddress.ip_network(subnet, strict=False)
            if network.version == 4 and network.prefixlen < WIDE_PREFIX_V4:
                wide.append((subnet, max(network.num_addresses - 2, 0)))
        return wide

    def is_cgnat(self) -> bool:
        """Carrier grade NAT makes inbound testing impossible, not clean."""
        if not self.wan_address:
            return False
        try:
            return ipaddress.ip_address(self.wan_address) in CGNAT
        except ValueError:
            return False

    def as_dict(self) -> dict:
        return {
            "source": self.source,
            "subnets": self.subnets,
            "gateway": self.gateway,
            "guest_subnet": self.guest_subnet,
            "exclude": self.exclude,
            "observers": self.observers,
            "wan_address": self.wan_address,
        }


def _hosts_of(entry: str):
    text = str(entry).strip()
    if "/" in text:
        network = ipaddress.ip_network(text, strict=False)
        if network.num_addresses <= 2:
            return [network.network_address]
        return network.hosts()
    return [ipaddress.ip_address(text)]


def candidate_paths(explicit: str | None = None) -> list[Path]:
    """Where a config may live, in the order they are tried."""
    found: list[Path] = []
    if explicit:
        found.append(Path(explicit))
    from_env = os.environ.get(CONFIG_ENV)
    if from_env:
        found.append(Path(from_env))
    found.append(Path.cwd() / CONFIG_NAME)
    found.append(config_home() / "config.yaml")
    return found


def discover(explicit: str | None = None) -> Path | None:
    """The first config that exists, or None. First hit wins."""
    for path in candidate_paths(explicit):
        if path.is_file():
            return path
    return None


def load(explicit: str | None = None, interface: str = "") -> Config:
    """Read the targets file if there is one, then fill gaps from the system."""
    path = discover(explicit)
    if explicit and path is None:
        raise ConfigError("config file not found: %s" % explicit)

    document: dict = {}
    if path is not None:
        loaded = yaml.safe_load(path.read_text())
        if loaded is not None and not isinstance(loaded, dict):
            raise ConfigError("config file is not a YAML mapping: %s" % path)
        document = loaded or {}

    config = _validated(document, str(path) if path else "defaults")
    return fill_from_system(config, interface)


def _validated(document: dict, source: str) -> Config:
    targets = document.get("targets") or {}
    limits_in = document.get("limits") or {}
    limits = Limits(
        rate_pps=int(limits_in.get("rate_pps", RATE_PPS)),
        frame_budget=int(limits_in.get("frame_budget", FRAME_BUDGET)),
        packet_budget=int(limits_in.get("packet_budget", PACKET_BUDGET)),
        runtime_minutes=int(limits_in.get("runtime_minutes", RUNTIME_MINUTES)),
    )
    validate_rate(limits.rate_pps)

    subnets = [str(item) for item in (targets.get("subnets") or [])]
    for subnet in subnets:
        try:
            ipaddress.ip_network(subnet, strict=False)
        except ValueError as error:
            raise ConfigError("bad subnet %r in %s: %s" % (subnet, source, error))

    exclude = [str(item) for item in (document.get("exclude") or [])]
    for entry in exclude:
        try:
            _hosts_of(entry)
        except ValueError as error:
            raise ConfigError("bad exclude entry %r in %s: %s" % (entry, source, error))

    observers = {str(k): str(v) for k, v in (document.get("observers") or {}).items()}
    for name, endpoint in observers.items():
        if not re.match(r"^.+:\d+$", endpoint):
            raise ConfigError("observer %r must be given as HOST:PORT" % name)

    return Config(
        subnets=subnets,
        gateway=str(targets.get("gateway") or ""),
        guest_subnet=str(targets.get("guest_subnet") or ""),
        exclude=exclude,
        observers=observers,
        external={str(k): str(v) for k, v in (document.get("external") or {}).items()},
        limits=limits,
        source=source,
    )


def fill_from_system(config: Config, interface: str = "") -> Config:
    """Fill anything the file left out from the routing table."""
    chosen = interface or interfaces_module.default_interface()
    if not chosen:
        return config
    if not config.gateway:
        config.gateway = interfaces_module.default_gateway()
    if not config.subnets:
        network = interfaces_module.local_network(chosen)
        if network:
            config.subnets = [network]
    return config
