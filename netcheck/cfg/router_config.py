"""CFG01, router configuration parse.

Formats are tried in order: OpenWrt UCI, DD-WRT nvram, generic key-value, then a
plain text fallback grepping for the highest value settings. Many ISP routers
export an obfuscated or encrypted blob, and saying so is more useful than
failing to parse it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

UCI = "openwrt-uci"
NVRAM = "ddwrt-nvram"
KEYVALUE = "key-value"
PLAINTEXT = "plain-text"
OPAQUE = "opaque"

# The settings worth naming in an export, and what a hit means. Matched case
# insensitively against the whole setting name.
SETTINGS = (
    ("telnet", "Telnet service"),
    ("remote_management", "remote administration from the WAN"),
    ("remote_admin", "remote administration from the WAN"),
    ("wan_access", "administration reachable from the WAN"),
    ("upnp", "UPnP"),
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
)

TRUTHY = {"1", "on", "yes", "true", "enable", "enabled"}
FALSY = {"0", "off", "no", "false", "disable", "disabled"}


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
    settings: list = field(default_factory=list)
    model: str = ""
    firmware: str = ""
    path: str = ""
    readable: bool = True
    note: str = ""

    def as_dict(self) -> dict:
        return {
            "format": self.format,
            "readable": self.readable,
            "model": self.model,
            "firmware": self.firmware,
            "note": self.note,
            "settings": [
                {"key": s.key, "value": s.value, "enabled": s.enabled} for s in self.settings
            ],
        }


def _looks_opaque(raw: bytes) -> bool:
    """Whether the export is encrypted or packed rather than text."""
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
    """Yield key and value for whichever export format this is."""
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
                key = "%s.%s" % (section, found.group(1)) if section else found.group(1)
                yield key, found.group(2).strip()
        return
    if style in (NVRAM, KEYVALUE):
        for line in text.splitlines():
            found = re.match(r"^\s*([\w./:-]+)\s*=\s*(.*)$", line)
            if found:
                yield found.group(1), found.group(2).strip()
        return
    for line in text.splitlines():
        # Plain text exports use human labels, so a key may contain spaces.
        found = re.match(r"^\s*([\w][\w ./:-]*?)\s*[:=]\s*(.+)$", line)
        if found:
            yield found.group(1).strip().lower().replace(" ", "_"), found.group(2).strip()


def parse(path: str | Path) -> RouterConfig:
    """Parse an exported router configuration."""
    location = Path(path)
    if not location.is_file():
        return RouterConfig(path=str(location), readable=False, note="file not found")

    raw = location.read_bytes()
    if _looks_opaque(raw):
        return RouterConfig(
            format=OPAQUE, path=str(location), readable=False,
            note="the export is encrypted or packed, not text. Many ISP routers "
                 "do this, and there is nothing to parse without vendor tooling",
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
