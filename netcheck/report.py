"""Report rendering.

Plain aligned text, no colour and no box drawing. The JSON keys are the machine
contract: once written, a key does not change meaning.
"""

from __future__ import annotations

import json
from typing import Iterable

from netcheck.models import (
    ABSENT,
    HOST,
    INDETERMINATE,
    L2,
    L3,
    PRESENT,
    SEVERITY_ORDER,
    UNTESTED,
    Control,
    Finding,
    Posture,
)

STATE_WIDTH = 15
SEVERITY_WIDTH = 10
CHECK_WIDTH = 8
MIN_CONTROL_WIDTH = 38

LAYER_TITLES = ((L2, "layer 2"), (L3, "layer 3"), (HOST, "this host"))

REACHABILITY_STATES = ("tested", "reachable", "filtered", "untested")


def run_header(profile, config=None, authorisation=None) -> str:
    lines = [profile.header()]
    if config is not None:
        lines.append("config: %s" % config.source)
    if authorisation is not None:
        lines.append("authorisation: %s (sha256 %s)" % (authorisation.path, authorisation.sha256))
    return "\n".join(lines)


def reachability_matrix(matrix: dict | None) -> str:
    """Segments on both axes. A blank cell is untested, not filtered."""
    if not matrix:
        return "REACHABILITY\n  no segment pairs tested"
    segments = sorted({name for pair in matrix for name in pair})
    width = max([len(n) for n in segments] + [len(str(v)) for v in matrix.values()]) + 2
    lines = ["REACHABILITY", "".ljust(width) + "".join(n.ljust(width) for n in segments)]
    for source in segments:
        row = source.ljust(width)
        for destination in segments:
            row += str(matrix.get((source, destination), "untested")).ljust(width)
        lines.append(row)
    return "\n".join(lines)


def device_table(devices: Iterable[dict] | None) -> str:
    devices = list(devices or [])
    if not devices:
        return "DEVICES\n  none correlated"
    lines = ["DEVICES", "  %-18s %-24s %s" % ("MAC", "ADDRESSES", "SEGMENT")]
    for device in devices:
        addresses = ", ".join(device.get("ipv4", []) + device.get("ipv6", []))
        lines.append(
            "  %-18s %-24s %s"
            % (
                (device.get("macs") or [""])[0],
                addresses or "-",
                device.get("segment", "") or "-",
            )
        )
    return "\n".join(lines)


def posture_table(posture: Posture, layers: str = "both") -> str:
    """Controls grouped by layer, in the order L2, L3, host."""
    wanted = {
        "both": (L2, L3, HOST),
        "l2": (L2,),
        "l3": (L3, HOST),
    }[layers]
    shown: list[Control] = [c for c in posture.controls.values() if c.layer in wanted]
    width = max([MIN_CONTROL_WIDTH] + [len(c.name) + 2 for c in shown])
    lines = ["CONTROL".ljust(width) + "STATE".ljust(STATE_WIDTH) + "BASIS"]
    for layer, title in LAYER_TITLES:
        rows = [c for c in shown if c.layer == layer]
        if not rows:
            continue
        if len(wanted) > 1:
            lines.append("%s:" % title)
        for control in rows:
            lines.append(
                control.name.ljust(width) + control.state.ljust(STATE_WIDTH) + control.basis
            )
    return "\n".join(lines)


def findings_table(findings: Iterable[Finding]) -> str:
    findings = list(findings)
    lines = ["SEVERITY".ljust(SEVERITY_WIDTH) + "CHECK".ljust(CHECK_WIDTH) + "FINDING"]
    if not findings:
        lines.append("none".ljust(SEVERITY_WIDTH + CHECK_WIDTH) + "nothing observed")
        return "\n".join(lines)
    for finding in findings:
        lines.append(
            finding.severity.ljust(SEVERITY_WIDTH)
            + finding.check.ljust(CHECK_WIDTH)
            + finding.title
        )
        if finding.remedy:
            lines.append(" " * (SEVERITY_WIDTH + CHECK_WIDTH) + "would change: " + finding.remedy)
    return "\n".join(lines)


def host_section(host: dict | None) -> str:
    """CFG02, kept separate because it describes this machine, not the network."""
    if not host:
        return ""
    lines = ["THIS MACHINE (not the network)"]
    for key in sorted(host):
        value = host[key]
        if isinstance(value, list):
            value = ", ".join(str(item) for item in value) or "-"
        lines.append("  %-34s %s" % (key, value))
    return "\n".join(lines)


def metadata_section(document: dict) -> str:
    lines = ["RUN"]
    for label, key in (
        ("started", "started"),
        ("finished", "finished"),
        ("interface", "interface"),
        ("version", "version"),
        ("commit", "commit"),
    ):
        value = document.get(key)
        if value:
            lines.append("  %-12s %s" % (label, value))
    budget = document.get("budget")
    if budget:
        lines.append(
            "  %-12s frames %d/%d, packets %d/%d"
            % (
                "budget",
                budget["frames_sent"],
                budget["frame_budget"],
                budget["packets_sent"],
                budget["packet_budget"],
            )
        )
    abort = document.get("abort")
    if abort and abort.get("aborted"):
        lines.append(
            "  %-12s %s during %s" % ("aborted", abort["reason"], abort.get("during") or "setup")
        )
    return "\n".join(lines)


def summary_line(posture: Posture) -> str:
    counts = posture.counts()
    return "%d controls: %d absent, %d present, %d indeterminate, %d untested" % (
        len(posture.controls),
        counts[ABSENT],
        counts[PRESENT],
        counts[INDETERMINATE],
        counts[UNTESTED],
    )


def render(
    posture: Posture,
    findings: Iterable[Finding],
    profile,
    config=None,
    authorisation=None,
    layers: str = "both",
    matrix: dict | None = None,
    devices: Iterable[dict] | None = None,
    host: dict | None = None,
    metadata: dict | None = None,
) -> str:
    """The full text report, in the documented order."""
    sections = [
        run_header(profile, config, authorisation),
        reachability_matrix(matrix),
        device_table(devices),
        posture_table(posture, layers),
        findings_table(findings),
    ]
    body = host_section(host)
    if body:
        sections.append(body)
    if metadata:
        sections.append(metadata_section(metadata))
    sections.append(summary_line(posture))
    return "\n\n".join(section for section in sections if section)


def to_dict(
    posture: Posture,
    findings: Iterable[Finding],
    profile,
    config=None,
    authorisation=None,
    budget=None,
    matrix: dict | None = None,
    devices: Iterable[dict] | None = None,
    host: dict | None = None,
    abort: dict | None = None,
    capture: dict | None = None,
    metadata: dict | None = None,
) -> dict:
    """The machine form. Keys here are a contract."""
    document: dict = {
        "profile": profile.name,
        "controls": posture.as_dict(),
        "findings": [
            {"severity": f.severity, "check": f.check, "title": f.title, "remedy": f.remedy}
            for f in findings
        ],
        "summary": posture.counts(),
    }
    if config is not None:
        document["config"] = config.as_dict()
    if authorisation is not None:
        document["authorisation"] = authorisation.as_dict()
    if budget is not None:
        document["budget"] = budget.as_dict()
    if matrix is not None:
        document["reachability"] = {"%s>%s" % pair: state for pair, state in sorted(matrix.items())}
    if devices is not None:
        document["devices"] = list(devices)
    if host is not None:
        document["host"] = host
    if abort is not None:
        document["abort"] = abort
    if capture is not None:
        document["capture"] = capture
    if metadata:
        document.update(metadata)
    return document


def to_json(document: dict) -> str:
    return json.dumps(document, indent=2, sort_keys=False, default=str)


def from_dict(document: dict) -> tuple[Posture, list[Finding]]:
    posture = Posture.from_dict(document.get("controls", {}))
    findings = [
        Finding(f["severity"], f["check"], f["title"], f.get("remedy", ""))
        for f in document.get("findings", [])
    ]
    return posture, findings


def diff(previous: dict, current: dict) -> str:
    """What changed between two runs. On a network tested repeatedly this is the signal."""
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


def sort_findings(findings: Iterable[Finding]) -> list[Finding]:
    return sorted(
        findings, key=lambda f: (SEVERITY_ORDER.get(f.severity, 3), f.check, f.title)
    )
