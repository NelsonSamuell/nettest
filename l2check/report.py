"""Report rendering.

Two sections: the posture table first, then the findings. The JSON form carries
the same information plus the detail strings and the run metadata, and is what
``netcheck posture --from`` reads back.
"""

from __future__ import annotations

import json
from typing import Iterable

from l2check.models import Capture, Finding
from l2check.posture import ABSENT, INDETERMINATE, PRESENT, UNTESTED, Posture

MIN_CONTROL_WIDTH = 37
STATE_WIDTH = 15
SEVERITY_WIDTH = 10
CHECK_WIDTH = 8


def _layer_of(control) -> str:
    """Which layer a control belongs to.

    Membership decides this, not the basis text: an untested layer 3 control has
    a basis of "probe not selected" and would otherwise be filed under layer 2.
    """
    from l2check.posture import L3_CONTROLS

    return "l3" if control.name in L3_CONTROLS else "l2"


def posture_table(posture: Posture, layers: str = "both") -> str:
    """Render the control table, layer 2 and layer 3 grouped separately."""
    shown = [
        control
        for control in posture.controls.values()
        if layers == "both" or _layer_of(control) == layers
    ]
    if not shown:
        return "CONTROL".ljust(MIN_CONTROL_WIDTH) + "STATE".ljust(STATE_WIDTH) + "BASIS"
    width = max([MIN_CONTROL_WIDTH] + [len(c.name) + 2 for c in shown])
    lines = ["CONTROL".ljust(width) + "STATE".ljust(STATE_WIDTH) + "BASIS"]
    for group in ("l2", "l3"):
        rows = [c for c in shown if _layer_of(c) == group]
        if not rows:
            continue
        if layers == "both" and any(_layer_of(c) != group for c in shown):
            lines.append("%s:" % ("layer 2" if group == "l2" else "layer 3"))
        for control in rows:
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


def reachability_matrix(matrix: dict | None) -> str:
    """Render the segment reachability matrix. Empty until the L3 checks exist."""
    if not matrix:
        return "REACHABILITY\n  no segment pairs tested"
    segments = sorted({name for pair in matrix for name in pair})
    width = max(len(name) for name in segments) + 2
    header = "".ljust(width) + "".join(name.ljust(width) for name in segments)
    lines = ["REACHABILITY", header]
    for source in segments:
        row = source.ljust(width)
        for destination in segments:
            row += str(matrix.get((source, destination), "untested")).ljust(width)
        lines.append(row)
    return "\n".join(lines)


def device_table(devices: Iterable[dict] | None) -> str:
    """Render the correlated device inventory. Empty until the L3 checks exist."""
    devices = list(devices or [])
    if not devices:
        return "DEVICES\n  none correlated"
    lines = ["DEVICES", "  %-18s %-16s %s" % ("MAC", "ADDRESSES", "VENDOR")]
    for device in devices:
        addresses = ", ".join(device.get("ipv4", []) + device.get("ipv6", []))
        lines.append(
            "  %-18s %-16s %s"
            % (
                (device.get("macs") or [""])[0],
                addresses or "-",
                device.get("oui_vendor", "") or "-",
            )
        )
    return "\n".join(lines)


def host_posture_section(host) -> str:
    """Render CFG02, which describes this machine and not the network.

    Kept in its own section and labelled, because a reader skimming a network
    posture report will otherwise attribute these to the router.
    """
    if host is None:
        return ""
    lines = ["THIS MACHINE (not the network)"]
    lines.append("  firewall      %s" % (host.firewall or "none detected"))
    if host.firewall:
        lines.append("  rules         %d" % host.firewall_rules)
    for name, value in sorted(host.sysctls.items()):
        if value:
            lines.append("  %-38s %s" % (name, value))
    if host.listening:
        shown = ", ".join("%s/%d" % pair for pair in host.listening[:10])
        more = "" if len(host.listening) <= 10 else " and %d more" % (len(host.listening) - 10)
        lines.append("  listening     %s%s" % (shown, more))
    return "\n".join(lines)


def render(
    posture: Posture,
    findings: Iterable[Finding],
    layers: str = "both",
    matrix: dict | None = None,
    devices: Iterable[dict] | None = None,
    host: object | None = None,
) -> str:
    """Render the full text report."""
    sections = []
    if matrix or devices:
        sections.append(reachability_matrix(matrix))
        sections.append(device_table(devices))
    sections.append(posture_table(posture, layers))
    sections.append(findings_table(findings))
    if host is not None:
        sections.append(host_posture_section(host))
    sections.append(summary_line(posture))
    return "\n\n".join(section for section in sections if section)


def to_markdown(document: dict, posture: Posture, findings: Iterable[Finding]) -> str:
    """Render the same report as Markdown, for pasting into notes."""
    lines = ["# netcheck report", ""]
    run = document.get("run") or {}
    capture = document.get("capture") or {}
    if run or capture:
        lines += ["## Run", ""]
        for label, value in (
            ("Config", run.get("config")),
            ("Gateway", run.get("gateway")),
            ("Subnets", ", ".join(run.get("subnets", []))),
            ("Interface", capture.get("interface")),
            ("Frames seen", capture.get("frames_seen")),
            ("Packets seen", capture.get("packets_seen")),
        ):
            if value not in (None, "", []):
                lines.append("- %s: %s" % (label, value))
        lines.append("")

    lines += ["## Posture", "", "| Control | State | Basis |", "| --- | --- | --- |"]
    for control in posture.controls.values():
        lines.append("| %s | %s | %s |" % (control.name, control.state, control.basis))

    host = document.get("host")
    if host:
        lines += ["", "## This machine (not the network)", ""]
        lines.append("- Firewall: %s" % (host.get("firewall") or "none detected"))
        for name, value in sorted((host.get("sysctls") or {}).items()):
            if value:
                lines.append("- %s: %s" % (name, value))
        if host.get("listening"):
            lines.append("- Listening: %s" % ", ".join(host["listening"]))

    lines += ["", "## Findings", ""]
    findings = list(findings)
    if findings:
        lines += ["| Severity | Check | Finding |", "| --- | --- | --- |"]
        for finding in findings:
            lines.append(
                "| %s | %s | %s |" % (finding.severity, finding.check, finding.title)
            )
    else:
        lines.append("Nothing observed.")

    budget = document.get("budget")
    if budget:
        lines += ["", "## Budget", ""]
        for key, value in budget.items():
            lines.append("- %s: %s" % (key.replace("_", " "), value))
    lines += ["", summary_line(posture), ""]
    return "\n".join(lines)


def diff(previous: dict, current: dict) -> str:
    """Compare two saved runs and report what changed.

    On a network you own and test repeatedly, the change is the signal: a port
    that opened, a control that stopped enforcing after a firmware update.
    """
    before = previous.get("controls", {})
    after = current.get("controls", {})
    lines = ["CHANGES SINCE PREVIOUS RUN"]

    for name in sorted(set(before) | set(after)):
        old = before.get(name, {}).get("state")
        new = after.get(name, {}).get("state")
        if old is None:
            lines.append("  + %-38s %s (new control)" % (name, new))
        elif new is None:
            lines.append("  - %-38s was %s (no longer reported)" % (name, old))
        elif old != new:
            lines.append("  ~ %-38s %s -> %s" % (name, old, new))

    old_findings = {(f["check"], f["title"]) for f in previous.get("findings", [])}
    new_findings = {(f["check"], f["title"]) for f in current.get("findings", [])}
    for check, title in sorted(new_findings - old_findings):
        lines.append("  + %-7s %s" % (check, title))
    for check, title in sorted(old_findings - new_findings):
        lines.append("  - %-7s %s (gone)" % (check, title))

    if len(lines) == 1:
        lines.append("  nothing changed")
    return "\n".join(lines)


def to_dict(
    posture: Posture,
    findings: Iterable[Finding],
    capture: Capture | None = None,
    targets=None,
    budget=None,
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
    if budget is not None:
        document["budget"] = budget.as_dict()
    if capture is not None:
        document["capture"] = {
            "interface": capture.interface,
            "duration": capture.duration,
            "frames_seen": capture.frames_seen,
            "packets_seen": capture.packets_seen,
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
        if capture.host_posture is not None:
            host = capture.host_posture
            document["host"] = {
                "firewall": host.firewall,
                "firewall_rules": host.firewall_rules,
                "sysctls": host.sysctls,
                "listening": ["%s/%d" % pair for pair in host.listening],
            }
        if capture.router_config is not None:
            config = capture.router_config
            document["router_config"] = {
                "format": config.format,
                "readable": config.readable,
                "model": config.model,
                "firmware": config.firmware,
                "note": config.note,
                "settings": [
                    {"key": s.key, "value": s.value, "enabled": s.enabled}
                    for s in config.settings
                ],
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
    if targets is not None:
        document["run"] = {
            "config": targets.path,
            "gateway": targets.gateway,
            "subnets": targets.subnets,
            "observers": targets.observers,
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
