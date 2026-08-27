"""Report rendering.

Two sections: the posture table first, then the findings. The JSON form carries
the same information plus the detail strings and the authorisation hash, and is
what ``l2check posture --from`` reads back.
"""

from __future__ import annotations

import json
from typing import Iterable

from l2check.authorisation import Authorisation
from l2check.models import Capture, Finding
from l2check.posture import ABSENT, INDETERMINATE, PRESENT, UNTESTED, Posture

MIN_CONTROL_WIDTH = 37
STATE_WIDTH = 15
SEVERITY_WIDTH = 10
CHECK_WIDTH = 8


def posture_table(posture: Posture) -> str:
    """Render the control table."""
    width = max([MIN_CONTROL_WIDTH] + [len(name) + 2 for name in posture.controls])
    lines = ["CONTROL".ljust(width) + "STATE".ljust(STATE_WIDTH) + "BASIS"]
    for control in posture.controls.values():
        lines.append(
            control.name.ljust(width) + control.state.ljust(STATE_WIDTH) + control.basis
        )
    return "\n".join(lines)


def findings_table(findings: Iterable[Finding]) -> str:
    """Render the findings table."""
    findings = list(findings)
    lines = [
        "SEVERITY".ljust(SEVERITY_WIDTH) + "CHECK".ljust(CHECK_WIDTH) + "FINDING"
    ]
    for finding in findings:
        lines.append(
            finding.severity.ljust(SEVERITY_WIDTH)
            + finding.check.ljust(CHECK_WIDTH)
            + finding.title
        )
    if not findings:
        lines.append("none".ljust(SEVERITY_WIDTH + CHECK_WIDTH) + "nothing observed")
    return "\n".join(lines)


def summary_line(posture: Posture) -> str:
    """Render the counts line that closes the report."""
    counts = posture.counts()
    return "%d controls: %d absent, %d present, %d indeterminate, %d untested" % (
        len(posture.controls),
        counts[ABSENT],
        counts[PRESENT],
        counts[INDETERMINATE],
        counts[UNTESTED],
    )


def render(posture: Posture, findings: Iterable[Finding]) -> str:
    """Render the full text report."""
    return "\n\n".join(
        [posture_table(posture), findings_table(findings), summary_line(posture)]
    )


def to_dict(
    posture: Posture,
    findings: Iterable[Finding],
    capture: Capture | None = None,
    authorisation: Authorisation | None = None,
    frames_sent: int = 0,
) -> dict:
    """Build the JSON form of a run."""
    document: dict = {
        "profile": posture.profile,
        "controls": posture.to_dict(),
        "findings": [
            {"severity": f.severity, "check": f.check, "title": f.title} for f in findings
        ],
        "summary": posture.counts(),
        "frames_sent": frames_sent,
    }
    if capture is not None:
        document["capture"] = {
            "interface": capture.interface,
            "duration": capture.duration,
            "frames_seen": capture.frames_seen,
            "parse_errors": capture.parse_errors,
            "truncated": sorted(capture.truncated),
            "gratuitous_arps": capture.gratuitous_arps,
            "records": {
                "discovery": len(capture.discovery),
                "dtp": len(capture.dtp),
                "bpdu": len(capture.bpdu),
                "vtp": len(capture.vtp),
                "tagged": len(capture.tagged),
                "dhcp_servers": len(capture.dhcp_servers),
                "arp": len(capture.arp),
                "name_resolution": len(capture.name_resolution),
                "fhrp": len(capture.fhrp),
                "cleartext": len(capture.cleartext),
                "router_adverts": len(capture.router_adverts),
                "upnp": len(capture.upnp),
                "peer_traffic": len(capture.peer_traffic),
            },
        }
        if capture.wireless is not None:
            link = capture.wireless
            document["wireless"] = {
                "ssid": link.ssid,
                "bssid": link.bssid,
                "security": link.security,
                "group_cipher": link.group_cipher,
                "pairwise_ciphers": link.pairwise_ciphers,
                "auth_suites": link.auth_suites,
                "pmf_capable": link.pmf_capable,
                "pmf_required": link.pmf_required,
                "wps": link.wps,
            }
    if authorisation is not None:
        document["authorisation"] = {
            "file": authorisation.path,
            "sha256": authorisation.sha256,
            "client": authorisation.client,
            "engagement": authorisation.engagement,
            "authorised_by": authorisation.authorised_by,
            "segment": authorisation.segment,
            "window": authorisation.window(),
        }
    return document


def to_json(document: dict) -> str:
    return json.dumps(document, indent=2, sort_keys=False)


def from_dict(document: dict) -> tuple[Posture, list[Finding]]:
    """Rebuild a posture and its findings from a saved JSON report."""
    posture = Posture.from_dict(document["controls"], document.get("profile", "wired"))
    findings = [
        Finding(item["severity"], item["check"], item["title"])
        for item in document.get("findings", [])
    ]
    return posture, findings
