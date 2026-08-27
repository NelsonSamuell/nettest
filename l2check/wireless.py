"""Read-only facts about a wireless link.

Nothing here transmits, changes interface state, or triggers a scan. The
information comes from the kernel's cached scan results through ``iw``, which is
readable by an ordinary user, so this runs with no privileges and no effect on
the association.

Monitor mode is deliberately not used. Putting the adapter into monitor mode
would drop the connection, which is exactly the kind of outage the tool refuses
to be able to cause.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

# 802.11w management frame protection bits in the RSN capabilities field.
MFP_REQUIRED = 0x0040
MFP_CAPABLE = 0x0080

WEAK_CIPHERS = ("TKIP", "WEP")

OPEN = "Open"
WEP = "WEP"
WPA = "WPA"
WPA2 = "WPA2"
WPA3 = "WPA3"
WPA2_WPA3 = "WPA2/WPA3"


@dataclass
class WirelessLink:
    interface: str
    ssid: str = ""
    bssid: str = ""
    security: str = OPEN
    auth_suites: list[str] = field(default_factory=list)
    pairwise_ciphers: list[str] = field(default_factory=list)
    group_cipher: str = ""
    pmf_capable: bool = False
    pmf_required: bool = False
    wps: bool = False
    privacy: bool = False

    @property
    def encrypted(self) -> bool:
        return self.security not in (OPEN, WEP)

    @property
    def weak_cipher(self) -> str:
        for cipher in self.pairwise_ciphers + [self.group_cipher]:
            for weak in WEAK_CIPHERS:
                if weak in cipher.upper():
                    return cipher
        return ""


def is_wireless(interface: str) -> bool:
    """True when the kernel reports the interface as a wireless device."""
    return (Path("/sys/class/net") / interface / "wireless").exists()


def _suites(line: str) -> list[str]:
    return [item for item in re.split(r"[,\s]+", line.split(":", 1)[1].strip()) if item]


def parse_scan_dump(text: str, interface: str) -> WirelessLink | None:
    """Parse the associated BSS out of ``iw scan dump`` output.

    Returns None when the interface is not associated with anything.
    """
    blocks = re.split(r"^BSS ", text, flags=re.MULTILINE)
    associated = [
        block
        for block in blocks
        if block.splitlines() and "-- associated" in block.splitlines()[0]
    ]
    if not associated:
        return None

    block = associated[0]
    link = WirelessLink(interface=interface)
    link.bssid = block.split("(")[0].strip()

    has_rsn = False
    has_wpa = False
    section = ""
    for raw in block.splitlines():
        line = raw.strip()
        if line.startswith("capability:"):
            link.privacy = "Privacy" in line
        elif line.startswith("SSID:"):
            link.ssid = line.split(":", 1)[1].strip()
        elif line.startswith("RSN:"):
            has_rsn = True
            section = "RSN"
        elif line.startswith("WPA:"):
            has_wpa = True
            section = "WPA"
        elif line.startswith("WPS:"):
            link.wps = True
            section = "WPS"
        elif line and not line.startswith("*") and ":" in line and not raw.startswith("\t\t"):
            section = ""

        if not line.startswith("*"):
            continue
        body = line.lstrip("* ").strip()
        if body.startswith("Group cipher:"):
            link.group_cipher = body.split(":", 1)[1].strip()
        elif body.startswith("Pairwise ciphers:"):
            link.pairwise_ciphers = _suites(body)
        elif body.startswith("Authentication suites:"):
            link.auth_suites = _suites(body)
        elif body.startswith("Capabilities:") and section == "RSN":
            found = re.search(r"\(0x([0-9a-fA-F]+)\)", body)
            if found:
                capabilities = int(found.group(1), 16)
                link.pmf_required = bool(capabilities & MFP_REQUIRED)
                link.pmf_capable = bool(capabilities & MFP_CAPABLE)

    suites = [suite.upper() for suite in link.auth_suites]
    if has_rsn and "SAE" in suites and any(s.startswith("PSK") for s in suites):
        link.security = WPA2_WPA3
    elif has_rsn and "SAE" in suites:
        link.security = WPA3
    elif has_rsn:
        link.security = WPA2
    elif has_wpa:
        link.security = WPA
    elif link.privacy:
        link.security = WEP
    else:
        link.security = OPEN
    return link


def _run_iw(interface: str) -> str:
    result = subprocess.run(
        ["iw", "dev", interface, "scan", "dump"],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    return result.stdout


def read_link(
    interface: str,
    runner: Callable[[str], str] = _run_iw,
) -> WirelessLink | None:
    """Return the wireless link facts, or None if unavailable or not associated."""
    if not is_wireless(interface):
        return None
    try:
        text = runner(interface)
    except (OSError, subprocess.SubprocessError):
        return None
    if not text.strip():
        return None
    return parse_scan_dump(text, interface)
