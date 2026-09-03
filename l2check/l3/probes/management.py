"""L3A04 management plane exposure and L3A06 UPnP mapping.

L3A04 reports what a management service is and how it is protected: scheme, TLS
version, certificate, banner. It offers no credentials and guesses no passwords.
Version detection is the boundary, deliberately: the moment a posture checker
starts guessing passwords, PRESENT and ABSENT stop describing the same kind of
thing.

L3A06 creates one port mapping, confirms it, deletes it and confirms the
deletion. A mapping left behind is a hole punched in your own firewall, so a
failed cleanup halts the run and prints how to remove it by hand.
"""

from __future__ import annotations

import re

from l2check.l3.probes import sweep
from l2check.models import HIGH, LOW, MEDIUM, Capture, Finding
from l2check.posture import (
    ABSENT,
    INDETERMINATE,
    MANAGEMENT_ISOLATION,
    PRESENT,
    UNTESTED,
    UPNP_RESTRAINT,
    ProbeResult,
)
from l2check.session import ActiveSession

MANAGEMENT_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    80: "HTTP",
    81: "HTTP",
    443: "HTTPS",
    8080: "HTTP",
    8443: "HTTPS",
    7547: "TR-069",
    8291: "Winbox",
}
CLEARTEXT_SCHEMES = ("FTP", "Telnet", "HTTP", "TR-069")
TLS_PORTS = (443, 8443)

# A port well outside anything a home network assigns, so a mapping made here
# cannot collide with a real service.
TEST_MAPPING_PORT = 54892
SOAP_ACTION = "urn:schemas-upnp-org:service:WANIPConnection:1#%s"


def _refused(check: str, control, detail: str) -> ProbeResult:
    return ProbeResult(check, control, UNTESTED, "%s refused" % check, detail)


def run_management_plane(session: ActiveSession, capture: Capture) -> ProbeResult:
    """L3A04. What the gateway's management services are, and how protected."""
    gateway = session.gateway
    if not gateway:
        return _refused("L3A04", MANAGEMENT_ISOLATION, "no gateway to examine")

    found = session.tcp_open.get(gateway)
    if found is None:
        # L3A02 was not selected, so ask directly about the management ports.
        found = []
        for port in sorted(MANAGEMENT_PORTS):
            if session.packets_remaining < 4:
                break
            if session.connect_result(gateway, port) == "open":
                found.append(port)

    services = []
    findings = []
    cleartext = []
    for port in found:
        name = MANAGEMENT_PORTS.get(port)
        if name is None:
            continue
        entry = {"port": port, "service": name}
        if port in TLS_PORTS:
            details = session.tls_details(gateway, port)
            entry.update(details)
            if details.get("self_signed"):
                findings.append(
                    Finding(
                        LOW,
                        "L3A04",
                        "%s:%d presents a self signed certificate, so a client "
                        "cannot tell it from an interceptor" % (gateway, port),
                    )
                )
            version = details.get("version", "")
            if version and version < "TLSv1.2":
                findings.append(
                    Finding(
                        MEDIUM,
                        "L3A04",
                        "%s:%d negotiates %s, which is obsolete"
                        % (gateway, port, version),
                    )
                )
        else:
            banner = session.grab_banner(gateway, port)
            if banner:
                entry["banner"] = banner.splitlines()[0][:120]
        if name in CLEARTEXT_SCHEMES:
            cleartext.append("%s/%d" % (name, port))
        services.append(entry)

    session.management_services = services

    if not services:
        return ProbeResult(
            "L3A04",
            MANAGEMENT_ISOLATION,
            INDETERMINATE,
            "L3A04 active check",
            "no management service answered on %s. It may be on another port, or "
            "restricted to another network" % gateway,
            frames_sent=0,
            findings=findings,
        )

    described = ", ".join(
        "%s/%d" % (entry["service"], entry["port"]) for entry in services
    )
    if cleartext:
        findings.append(
            Finding(
                HIGH,
                "L3A04",
                "Gateway management reachable in cleartext on %s"
                % ", ".join(cleartext),
            )
        )
        return ProbeResult(
            "L3A04",
            MANAGEMENT_ISOLATION,
            ABSENT,
            "L3A04 active check",
            "the gateway serves management over %s from this segment" % described,
            findings=findings,
        )
    return ProbeResult(
        "L3A04",
        MANAGEMENT_ISOLATION,
        PRESENT,
        "L3A04 active check",
        "management on %s is encrypted, though still reachable from this segment"
        % described,
        findings=findings,
    )


def _discover_igd(session: ActiveSession) -> str:
    """Find the IGD description URL by asking, then read the control URL from it."""
    if session.upnp_control_url:
        return session.upnp_control_url

    from scapy.layers.inet import IP, UDP

    search = (
        "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
        'MAN: "ssdp:discover"\r\nMX: 2\r\n'
        "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n"
    )
    replies = sweep(
        session,
        [IP(dst="239.255.255.250") / UDP(sport=1901, dport=1900) / search.encode()],
        seconds=4,
        match=lambda packet: UDP in packet and packet[UDP].sport == 1900,
    )
    for packet in replies:
        payload = bytes(packet[UDP].payload)
        found = re.search(rb"LOCATION:\s*(\S+)", payload, re.IGNORECASE)
        if found:
            return found.group(1).decode("ascii", "replace")
    return ""


def _control_url(session: ActiveSession, description_url: str) -> str:
    status, body = session.http(description_url)
    if status != 200:
        return ""
    found = re.search(r"<controlURL>([^<]+)</controlURL>", body, re.IGNORECASE)
    if not found:
        return ""
    path = found.group(1)
    if path.startswith("http"):
        return path
    base = re.match(r"(https?://[^/]+)", description_url)
    return (base.group(1) + path) if base else ""


def _soap(session: ActiveSession, url: str, action: str, body: str):
    envelope = (
        '<?xml version="1.0"?>'
        '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
        's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
        "<s:Body>%s</s:Body></s:Envelope>" % body
    )
    return session.http(
        url,
        data=envelope.encode(),
        headers={
            "Content-Type": 'text/xml; charset="utf-8"',
            "SOAPAction": '"%s"' % (SOAP_ACTION % action),
        },
    )


def run_upnp_mapping(session: ActiveSession, capture: Capture) -> ProbeResult:
    """L3A06. Create one mapping, confirm it, delete it, confirm the deletion."""
    description_url = _discover_igd(session)
    if not description_url:
        return ProbeResult(
            "L3A06",
            UPNP_RESTRAINT,
            INDETERMINATE,
            "L3A06 active check",
            "no UPnP gateway answered a search. The router may have UPnP off, or "
            "may not answer this search target",
            frames_sent=1,
        )

    control = _control_url(session, description_url)
    if not control:
        return ProbeResult(
            "L3A06",
            UPNP_RESTRAINT,
            INDETERMINATE,
            "L3A06 active check",
            "found a UPnP device at %s but no control URL to ask" % description_url,
            frames_sent=1,
        )

    local_ip = ""
    if session.local_cidr:
        import ipaddress

        local_ip = str(ipaddress.ip_interface(session.local_cidr).ip)

    add_body = (
        '<u:AddPortMapping xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">'
        "<NewRemoteHost></NewRemoteHost>"
        "<NewExternalPort>%d</NewExternalPort>"
        "<NewProtocol>TCP</NewProtocol>"
        "<NewInternalPort>%d</NewInternalPort>"
        "<NewInternalClient>%s</NewInternalClient>"
        "<NewEnabled>1</NewEnabled>"
        "<NewPortMappingDescription>netcheck L3A06</NewPortMappingDescription>"
        "<NewLeaseDuration>60</NewLeaseDuration>"
        "</u:AddPortMapping>" % (TEST_MAPPING_PORT, TEST_MAPPING_PORT, local_ip)
    )
    status, _ = _soap(session, control, "AddPortMapping", add_body)
    if status != 200:
        return ProbeResult(
            "L3A06",
            UPNP_RESTRAINT,
            PRESENT,
            "L3A06 active check",
            "the gateway refused an unauthenticated port mapping request "
            "(HTTP %s), so UPnP does not hand out holes on request" % status,
            frames_sent=2,
        )

    delete_body = (
        '<u:DeletePortMapping xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">'
        "<NewRemoteHost></NewRemoteHost>"
        "<NewExternalPort>%d</NewExternalPort>"
        "<NewProtocol>TCP</NewProtocol>"
        "</u:DeletePortMapping>" % TEST_MAPPING_PORT
    )
    deleted, _ = _soap(session, control, "DeletePortMapping", delete_body)

    if deleted != 200:
        session.cleanup_required = (
            "netcheck created a UPnP port mapping on %s for external port %d and "
            "could not delete it (HTTP %s). Remove it by hand: open the router's "
            "UPnP or port forwarding page and delete the entry described "
            "'netcheck L3A06'. It carries a 60 second lease, so it may also "
            "expire on its own." % (control, TEST_MAPPING_PORT, deleted)
        )
        raise RuntimeError(session.cleanup_required)

    return ProbeResult(
        "L3A06",
        UPNP_RESTRAINT,
        ABSENT,
        "L3A06 active check",
        "any host on this segment can open a port on the router: a mapping for "
        "external port %d was created and deleted without authentication"
        % TEST_MAPPING_PORT,
        frames_sent=3,
        findings=[
            Finding(
                HIGH,
                "L3A06",
                "UPnP accepts unauthenticated port mappings, so any device or "
                "any page a browser loads can open a port through the firewall",
            )
        ],
    )
