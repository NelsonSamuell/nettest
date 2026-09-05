"""L3A04, gateway management plane exposure.

Reports what a management service is and how it is protected: scheme, TLS
version, certificate, whether HTTP redirects to HTTPS, and the banner. It offers
no credentials and guesses no passwords. Version and banner detection is the
boundary, deliberately: the moment a posture checker starts guessing passwords,
PRESENT and ABSENT stop describing the same kind of thing.
"""

from __future__ import annotations

from netcheck.models import (
    ABSENT,
    HIGH,
    INDETERMINATE,
    LOW,
    MEDIUM,
    PREREQUISITE_MISSING,
    PRESENT,
    UNTESTED,
    Finding,
)

CONTROL = "Gateway management plane isolation"

MANAGEMENT_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    80: "HTTP",
    81: "HTTP",
    443: "HTTPS",
    7547: "TR-069",
    8080: "HTTP",
    8443: "HTTPS",
}
CLEARTEXT = ("FTP", "Telnet", "HTTP", "TR-069")
TLS_PORTS = (443, 8443)
HTTP_PORTS = (80, 81, 8080)
OBSOLETE_TLS = ("SSLv3", "TLSv1", "TLSv1.1")


def run(context):
    """What the gateway's management services are, and how protected."""
    gateway = getattr(context.config, "gateway", "") if context.config else ""
    if not gateway:
        return UNTESTED, "L3A04", "%s: no gateway to examine" % PREREQUISITE_MISSING, []

    found = getattr(context, "tcp_open", {}).get(gateway)
    if found is None:
        # L3A02 was not selected, so ask directly about the management ports.
        found = [
            port
            for port in sorted(MANAGEMENT_PORTS)
            if context.budget.remaining(3) > 1
            and context.connect_result(gateway, port) == "open"
        ]

    services = []
    findings: list[Finding] = []
    cleartext = []

    for port in found:
        name = MANAGEMENT_PORTS.get(port)
        if name is None:
            continue
        entry = {"port": port, "service": name}

        if port in TLS_PORTS:
            details = context.tls(gateway, port)
            entry.update(details)
            if details.get("self_signed"):
                findings.append(
                    Finding(LOW, "L3A04",
                            "%s:%d presents a self signed certificate, so a client "
                            "cannot tell it from an interceptor" % (gateway, port), "")
                )
            version = details.get("version", "")
            if version in OBSOLETE_TLS:
                findings.append(
                    Finding(MEDIUM, "L3A04", "%s:%d negotiates %s, which is obsolete"
                            % (gateway, port, version), "moving the interface to TLS 1.2 or later")
                )
        elif port in HTTP_PORTS:
            status, _, final = context.http("http://%s:%d/" % (gateway, port))
            entry["status"] = status
            entry["redirects_to_https"] = str(final).startswith("https://")
            if status and not entry["redirects_to_https"]:
                findings.append(
                    Finding(MEDIUM, "L3A04",
                            "%s:%d serves management over HTTP and does not redirect "
                            "to HTTPS" % (gateway, port), "redirecting to HTTPS")
                )
        else:
            banner = context.banner(gateway, port)
            if banner:
                entry["banner"] = banner.splitlines()[0][:120]

        if name in CLEARTEXT:
            cleartext.append("%s/%d" % (name, port))
        services.append(entry)

    context.management_services = services

    if not services:
        return (
            INDETERMINATE,
            "L3A04",
            "no management service answered on %s. It may be on another port, or "
            "restricted to another network" % gateway,
            findings,
        )

    described = ", ".join("%s/%d" % (e["service"], e["port"]) for e in services)
    if cleartext:
        findings.append(
            Finding(HIGH, "L3A04", "Gateway management reachable in cleartext on %s"
                    % ", ".join(cleartext), "disabling cleartext management")
        )
        return (
            ABSENT,
            "L3A04",
            "the gateway serves management over %s from this segment" % described,
            findings,
        )
    return (
        PRESENT,
        "L3A04",
        "management on %s is encrypted, though still reachable from this segment"
        % described,
        findings,
    )
