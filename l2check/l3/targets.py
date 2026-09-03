"""The targets file.

Input, not a permission slip. It tells the tool which subnets to sweep, where the
gateway is and where the observers are. Every field has a default derived from
the routing table, so a plain LAN run needs no file at all.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from l2check.session import (
    DEFAULT_RATE_PPS,
    FRAME_BUDGET,
    PACKET_BUDGET,
    RUNTIME_SECONDS,
    ConfigError,
    validate_rate,
)

DEFAULT_CONFIG = "netcheck.yaml"

# A sweep wider than this needs --yes, because the operator should see the
# estimated packet count before starting something that runs for an hour.
WIDE_PREFIX_V4 = 24

CGNAT = ipaddress.ip_network("100.64.0.0/10")


@dataclass
class Limits:
    rate_pps: int = DEFAULT_RATE_PPS
    packet_budget: int = PACKET_BUDGET
    frame_budget: int = FRAME_BUDGET
    runtime_minutes: int = RUNTIME_SECONDS // 60


@dataclass
class Targets:
    subnets: list[str] = field(default_factory=list)
    gateway: str = ""
    guest_subnet: str = ""
    exclude: list[str] = field(default_factory=list)
    observers: dict[str, str] = field(default_factory=dict)
    external: dict[str, str] = field(default_factory=dict)
    limits: Limits = field(default_factory=Limits)
    path: str = ""
    wan_address: str = ""

    @property
    def internal_observer(self) -> str:
        return self.observers.get("internal", "")

    @property
    def external_observer(self) -> str:
        return self.observers.get("external", "")

    def excluded(self) -> set[str]:
        """Addresses that must never be touched, including the WAN address."""
        blocked = set()
        for entry in self.exclude:
            blocked |= {str(host) for host in _hosts_of(entry)}
        if self.wan_address:
            blocked.add(self.wan_address)
        return blocked

    def addresses(self, include_wan: bool = False) -> list[str]:
        """Every target address, with exclusions applied. Exclude wins over targets."""
        blocked = self.excluded()
        if include_wan and self.wan_address:
            blocked.discard(self.wan_address)
        chosen: list[str] = []
        for subnet in self.subnets:
            for host in _hosts_of(subnet):
                text = str(host)
                if text not in blocked and text not in chosen:
                    chosen.append(text)
        return chosen

    def wide_prefixes(self) -> list[tuple[str, int]]:
        """Subnets wider than a /24, with the address count each would sweep."""
        wide = []
        for subnet in self.subnets:
            network = ipaddress.ip_network(subnet, strict=False)
            if network.version == 4 and network.prefixlen < WIDE_PREFIX_V4:
                wide.append((subnet, network.num_addresses - 2))
        return wide

    def is_cgnat(self) -> bool:
        """True when the WAN address is inside CGNAT space, where inbound cannot work."""
        if not self.wan_address:
            return False
        return ipaddress.ip_address(self.wan_address) in CGNAT


def _hosts_of(entry: str):
    """Yield the addresses an entry covers, whether it is a host or a prefix."""
    text = entry.strip()
    if "/" in text:
        network = ipaddress.ip_network(text, strict=False)
        if network.num_addresses <= 2:
            return [network.network_address]
        return network.hosts()
    return [ipaddress.ip_address(text)]


def _validated(document: dict, path: str) -> Targets:
    targets = document.get("targets") or {}
    limits_in = document.get("limits") or {}
    limits = Limits(
        rate_pps=int(limits_in.get("rate_pps", DEFAULT_RATE_PPS)),
        packet_budget=int(limits_in.get("packet_budget", PACKET_BUDGET)),
        frame_budget=int(limits_in.get("frame_budget", FRAME_BUDGET)),
        runtime_minutes=int(limits_in.get("runtime_minutes", RUNTIME_SECONDS // 60)),
    )
    validate_rate(limits.rate_pps)

    subnets = [str(item) for item in (targets.get("subnets") or [])]
    for subnet in subnets:
        try:
            ipaddress.ip_network(subnet, strict=False)
        except ValueError as error:
            raise ConfigError("bad subnet %r in %s: %s" % (subnet, path, error))

    exclude = [str(item) for item in (document.get("exclude") or [])]
    for entry in exclude:
        try:
            _hosts_of(entry)
        except ValueError as error:
            raise ConfigError("bad exclude entry %r in %s: %s" % (entry, path, error))

    observers = {str(k): str(v) for k, v in (document.get("observers") or {}).items()}
    for name, endpoint in observers.items():
        if ":" not in endpoint:
            raise ConfigError("observer %r must be given as HOST:PORT" % name)

    return Targets(
        subnets=subnets,
        gateway=str(targets.get("gateway") or ""),
        guest_subnet=str(targets.get("guest_subnet") or ""),
        exclude=exclude,
        observers=observers,
        external={str(k): str(v) for k, v in (document.get("external") or {}).items()},
        limits=limits,
        path=path,
    )


def load(path: str | Path | None = None, interface: str = "") -> Targets:
    """Read the targets file, filling anything absent from the routing table.

    A missing file is not an error. The passive default has to run with no
    configuration at all, so an absent file yields defaults derived from the
    machine itself.
    """
    location = Path(path or DEFAULT_CONFIG)
    if path is not None and not location.is_file():
        raise ConfigError("config file not found: %s" % location)

    document: dict = {}
    if location.is_file():
        loaded = yaml.safe_load(location.read_text())
        if loaded is not None and not isinstance(loaded, dict):
            raise ConfigError("config file is not a YAML mapping: %s" % location)
        document = loaded or {}

    targets = _validated(document, str(location) if location.is_file() else "defaults")
    return fill_from_system(targets, interface)


def discover_wan(targets: Targets, fetcher=None) -> str:
    """Find the WAN address from the configured echo service.

    Only runs when an echo service is configured, and the address it returns is
    excluded from every sweep unless --wan is given.
    """
    service = targets.external.get("echo_service", "")
    if not service:
        return ""
    if fetcher is None:
        import urllib.request

        def fetcher(url):
            with urllib.request.urlopen(url, timeout=8) as response:
                return response.read(128).decode("utf-8", "replace")

    try:
        text = fetcher(service)
    except Exception:
        return ""
    found = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", text or "")
    if not found:
        return ""
    try:
        ipaddress.ip_address(found.group(1))
    except ValueError:
        return ""
    return found.group(1)


def fill_from_system(targets: Targets, interface: str = "") -> Targets:
    """Derive anything the file left out from the routing table."""
    from l2check.listen import default_gateway, interface_cidr

    if not interface:
        from l2check.doctor import default_interface

        interface = default_interface()
    if not interface:
        return targets

    if not targets.gateway:
        targets.gateway = default_gateway(interface)
    if not targets.subnets:
        cidr = interface_cidr(interface)
        if cidr:
            network = ipaddress.ip_interface(cidr).network
            targets.subnets = [str(network)]
    return targets
