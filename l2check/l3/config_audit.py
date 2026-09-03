"""Offline audit checks. These send nothing and need no targets file.

CFG01 parses an exported router configuration, CFG02 reads this machine's own
firewall and sysctl posture, and CFG03 compares a detected firmware version
against a curated advisory file shipped in the repository. Nothing here fetches
anything at runtime, so a run is offline and reproducible.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

ADVISORIES = Path(__file__).resolve().parent.parent / "data" / "advisories.json"

UCI = "openwrt-uci"
NVRAM = "ddwrt-nvram"
KEYVALUE = "key-value"
PLAINTEXT = "plain-text"
OPAQUE = "opaque"

# The settings worth naming in an exported config, and what a hit means. Keys
# are matched case insensitively against the whole setting name.
SETTINGS = (
    ("telnet", "Telnet service configured"),
    ("remote_management", "remote administration from the WAN"),
    ("remote_admin", "remote administration from the WAN"),
    ("wan_access", "administration reachable from the WAN"),
    ("upnp", "UPnP IGD"),
    ("wps", "WPS"),
    ("dmz", "a DMZ host, which forwards everything to one machine"),
    ("port_forward", "a port forward"),
    ("redirect", "a port forward"),
    ("snmp", "SNMP"),
    ("tr069", "TR-069 remote management by the ISP"),
    ("cwmp", "TR-069 remote management by the ISP"),
    ("guest", "a guest network"),
    ("isolate", "client isolation"),
    ("rebind_protection", "DNS rebinding protection"),
    ("dnssec", "DNSSEC validation"),
    ("firewall", "firewall configuration"),
    ("syslog", "remote logging"),
    ("wan_ping", "WAN ping response"),
    ("macfilter", "MAC filtering"),
    ("encryption", "wireless encryption mode"),
)

# Values that mean a setting is switched on, whatever the format used.
TRUTHY = {"1", "on", "yes", "true", "enable", "enabled"}
FALSY = {"0", "off", "no", "false", "disable", "disabled"}

# (name, values that are fine, severity, description). A severity of None means
# the value is recorded as context and never raised as a finding: accept_ra=1 is
# how an IPv6 client is supposed to work, and reporting it as a problem would be
# a confident wrong answer.
SYSCTLS = (
    (
        "net.ipv4.conf.all.accept_redirects",
        ("0",),
        "MEDIUM",
        "accepts ICMP redirects, so a host on the segment can install a route into it",
    ),
    (
        "net.ipv4.conf.all.accept_source_route",
        ("0",),
        "MEDIUM",
        "accepts source routed IPv4 packets",
    ),
    (
        "net.ipv4.conf.all.rp_filter",
        ("1", "2"),
        "LOW",
        "has reverse path filtering off on all interfaces, so it accepts packets "
        "with spoofed source addresses",
    ),
    (
        "net.ipv6.conf.all.accept_redirects",
        ("0",),
        "MEDIUM",
        "accepts ICMPv6 redirects",
    ),
    # Negative disables routing headers outright; 0 is the kernel default and
    # accepts only type 2, which is mobile IPv6 rather than the deprecated RH0.
    (
        "net.ipv6.conf.all.accept_source_route",
        ("-1", "0"),
        "MEDIUM",
        "accepts IPv6 routing headers beyond type 2",
    ),
    ("net.ipv6.conf.all.accept_ra", None, None, "accepts router advertisements"),
)

FIREWALLS = (
    ("nftables", ["nft", "list", "ruleset"]),
    ("iptables", ["iptables", "-S"]),
    ("ufw", ["ufw", "status"]),
    ("firewalld", ["firewall-cmd", "--list-all"]),
)


@dataclass
class Setting:
    key: str
    value: str
    meaning: str

    @property
    def enabled(self) -> bool | None:
        lowered = self.value.strip().strip("'\"").lower()
        if lowered in TRUTHY:
            return True
        if lowered in FALSY:
            return False
        return None


@dataclass
class RouterConfig:
    format: str = PLAINTEXT
    settings: list[Setting] = field(default_factory=list)
    model: str = ""
    firmware: str = ""
    path: str = ""
    readable: bool = True
    note: str = ""


@dataclass
class HostPosture:
    firewall: str = ""
    firewall_rules: int = 0
    sysctls: dict[str, str] = field(default_factory=dict)
    listening: list[tuple[str, int]] = field(default_factory=list)


def _looks_opaque(raw: bytes) -> bool:
    """True when the export is an encrypted or packed blob rather than text.

    Many ISP routers export exactly that, and saying so is more useful than
    failing to parse it.
    """
    if not raw:
        return True
    if b"\x00" in raw[:512]:
        return True
    printable = sum(1 for byte in raw[:512] if 9 <= byte <= 13 or 32 <= byte <= 126)
    return printable / float(min(len(raw), 512)) < 0.85


def detect_format(text: str) -> str:
    """Identify the export format from its shape."""
    if re.search(r"^\s*config\s+[\w-]+", text, re.MULTILINE) and "option" in text:
        return UCI
    lines = [line for line in text.splitlines() if line.strip()]
    if not lines:
        return PLAINTEXT
    equals = sum(1 for line in lines if re.match(r"^[\w./:-]+=", line.strip()))
    if equals / float(len(lines)) > 0.6:
        return NVRAM if any("nvram" in line.lower() for line in lines[:5]) else KEYVALUE
    return PLAINTEXT


def _pairs(text: str, style: str):
    """Yield (key, value) for whichever export format this is."""
    if style == UCI:
        section = ""
        for line in text.splitlines():
            stripped = line.strip()
            found = re.match(r"config\s+([\w-]+)(?:\s+'?([\w.-]+)'?)?", stripped)
            if found:
                # Keep the section type as well as its name: "config upnpd
                # 'config'" is about UPnP, and the name alone loses that.
                kind, name = found.group(1), found.group(2)
                section = "%s.%s" % (kind, name) if name and name != kind else kind
                continue
            found = re.match(r"(?:option|list)\s+([\w.-]+)\s+(.*)", stripped)
            if found:
                yield ("%s.%s" % (section, found.group(1)) if section else found.group(1),
                       found.group(2).strip())
        return
    if style in (NVRAM, KEYVALUE):
        for line in text.splitlines():
            found = re.match(r"^\s*([\w./:-]+)\s*=\s*(.*)$", line)
            if found:
                yield found.group(1), found.group(2).strip()
        return
    for line in text.splitlines():
        # Plain text exports use human labels, so the key may contain spaces.
        found = re.match(r"^\s*([\w][\w ./:-]*?)\s*[:=]\s*(.+)$", line)
        if found:
            yield found.group(1).strip().lower().replace(" ", "_"), found.group(2).strip()


def parse_router_config(path: str | Path) -> RouterConfig:
    """CFG01. Parse an exported router configuration."""
    location = Path(path)
    if not location.is_file():
        return RouterConfig(path=str(location), readable=False, note="file not found")

    raw = location.read_bytes()
    if _looks_opaque(raw):
        return RouterConfig(
            format=OPAQUE,
            path=str(location),
            readable=False,
            note="the export is encrypted or packed, not text. Many ISP routers "
            "do this; there is nothing to parse without the vendor's tooling",
        )

    text = raw.decode("utf-8", "replace")
    style = detect_format(text)
    config = RouterConfig(format=style, path=str(location))

    for key, value in _pairs(text, style):
        lowered = key.lower()
        for needle, meaning in SETTINGS:
            if needle in lowered:
                config.settings.append(Setting(key, value, meaning))
                break
        if not config.model and lowered.endswith(("model", "boardname", "device_model")):
            config.model = value.strip("'\"")
        if not config.firmware and any(
            lowered.endswith(tail) for tail in ("firmware", "fwver", "version", "os_version")
        ):
            config.firmware = value.strip("'\"")
    return config


def _read_sysctl(name: str) -> str:
    path = Path("/proc/sys") / name.replace(".", "/")
    if not path.exists():
        return ""
    try:
        return path.read_text().strip()
    except OSError:
        return ""


def _listening_sockets() -> list[tuple[str, int]]:
    """Ports this machine is listening on, read straight from /proc."""
    found: set[tuple[str, int]] = set()
    for name, protocol, state in (
        ("tcp", "tcp", "0A"),
        ("tcp6", "tcp6", "0A"),
        ("udp", "udp", "07"),
        ("udp6", "udp6", "07"),
    ):
        path = Path("/proc/net") / name
        if not path.exists():
            continue
        for line in path.read_text().splitlines()[1:]:
            fields = line.split()
            if len(fields) < 4 or fields[3].upper() != state:
                continue
            local = fields[1].rsplit(":", 1)
            if len(local) == 2:
                found.add((protocol, int(local[1], 16)))
    return sorted(found)


def _firewall() -> tuple[str, int]:
    for name, command in FIREWALLS:
        if not shutil.which(command[0]):
            continue
        try:
            result = subprocess.run(
                command, capture_output=True, text=True, timeout=10, check=False
            )
        except (OSError, subprocess.SubprocessError):
            continue
        if result.returncode != 0:
            continue
        rules = [line for line in result.stdout.splitlines() if line.strip()]
        return name, len(rules)
    return "", 0


def read_host_posture() -> HostPosture:
    """CFG02. This machine's own firewall, sysctls and listening ports.

    This describes the machine the tool is running on, not the network, and the
    report labels it that way.
    """
    name, rules = _firewall()
    return HostPosture(
        firewall=name,
        firewall_rules=rules,
        sysctls={key: _read_sysctl(key) for key, _, _, _ in SYSCTLS},
        listening=_listening_sockets(),
    )


def load_advisories(path: Path = ADVISORIES) -> dict:
    """Read the curated advisory file shipped with the tool."""
    if not path.is_file():
        return {"entries": []}
    return json.loads(path.read_text())


def match_advisories(model: str, firmware: str, advisories: dict | None = None) -> list[dict]:
    """CFG03. Advisories matching a detected model and firmware, if any.

    An empty list with no matching model means the shipped file has nothing on
    this device, which is UNTESTED rather than a clean bill of health.
    """
    data = advisories if advisories is not None else load_advisories()
    if not model:
        return []
    hits = []
    for entry in data.get("entries", []):
        if entry.get("model", "").lower() not in model.lower():
            continue
        affected = entry.get("affected_firmware", [])
        if not affected or any(str(v).lower() in firmware.lower() for v in affected):
            hits.append(entry)
    return hits


def knows_model(model: str, advisories: dict | None = None) -> bool:
    """Whether the shipped advisory file has any entry for this model at all."""
    data = advisories if advisories is not None else load_advisories()
    if not model:
        return False
    return any(e.get("model", "").lower() in model.lower() for e in data.get("entries", []))
