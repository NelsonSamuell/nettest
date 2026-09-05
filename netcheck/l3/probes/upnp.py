"""L3A06, UPnP and NAT-PMP mapping.

This is the only check that writes state to another device. It creates one
mapping to an unused high port, confirms it appears, deletes it, and confirms
the deletion. A forgotten mapping is a hole punched in your own firewall, so the
cleanup is registered before the mapping is made and runs on abort and on
interrupt, not only on a normal exit. If deletion cannot be confirmed the run
halts and prints how to remove it by hand.
"""

from __future__ import annotations

import atexit
import re
import signal

from scapy.layers.inet import UDP

from netcheck.l3 import packets
from netcheck.models import (
    ABSENT,
    HIGH,
    INDETERMINATE,
    PREREQUISITE_MISSING,
    PRESENT,
    UNTESTED,
    Finding,
)

CONTROL = "UPnP mapping restraint"

# Well outside anything a home network assigns, so a mapping made here cannot
# collide with a real service.
TEST_PORT = 54892
LEASE_SECONDS = 60
LISTEN_SECONDS = 4
SOAP_ACTION = "urn:schemas-upnp-org:service:WANIPConnection:1#%s"

MANUAL_REMOVAL = (
    "netcheck created a UPnP port mapping for external port %d on %s and could "
    "not delete it. Remove it by hand: open the router's UPnP or port forwarding "
    "page and delete the entry described 'netcheck L3A06'. It carries a %d second "
    "lease, so it may also expire on its own."
)


class CleanupFailed(RuntimeError):
    """A mapping was created and could not be removed. The run halts."""


def _discover(context) -> str:
    """Find the IGD description URL by asking."""
    replies, sniffer = context.collect(
        LISTEN_SECONDS, lambda pkt: UDP in pkt and pkt[UDP].sport == packets.SSDP_PORT
    )
    context.send_packets(packets.ssdp_discover())
    context.sleeper(LISTEN_SECONDS)
    sniffer.stop()
    for packet in replies:
        found = re.search(rb"LOCATION:\s*(\S+)", bytes(packet[UDP].payload), re.IGNORECASE)
        if found:
            return found.group(1).decode("ascii", "replace")
    return ""


def _control_url(context, description_url: str) -> str:
    status, body, _ = context.http(description_url)
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


def _soap(context, url: str, action: str, body: str):
    envelope = (
        '<?xml version="1.0"?>'
        '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
        's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
        "<s:Body>%s</s:Body></s:Envelope>" % body
    )
    return context.http(
        url,
        data=envelope.encode(),
        headers={
            "Content-Type": 'text/xml; charset="utf-8"',
            "SOAPAction": '"%s"' % (SOAP_ACTION % action),
        },
    )


def _delete_body() -> str:
    return (
        '<u:DeletePortMapping xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">'
        "<NewRemoteHost></NewRemoteHost>"
        "<NewExternalPort>%d</NewExternalPort>"
        "<NewProtocol>TCP</NewProtocol>"
        "</u:DeletePortMapping>" % TEST_PORT
    )


def _register_cleanup(context, control: str) -> None:
    """Arm removal before the mapping exists, so nothing can outlive the run."""
    state = {"done": False}

    def remove(*_args):
        if state["done"]:
            return
        state["done"] = True
        _soap(context, control, "DeletePortMapping", _delete_body())

    context.cleanup.append(remove)
    atexit.register(remove)
    for number in (signal.SIGINT, signal.SIGTERM):
        try:
            previous = signal.getsignal(number)

            def handler(signum, frame, previous=previous):
                remove()
                if callable(previous):
                    previous(signum, frame)
                raise KeyboardInterrupt

            signal.signal(number, handler)
        except (ValueError, OSError):
            # Not the main thread, or the platform has no such signal.
            pass
    return remove


def run(context):
    """Create one mapping, confirm it, delete it, confirm the deletion."""
    description_url = _discover(context)
    if not description_url:
        return (
            INDETERMINATE,
            "L3A06",
            "no UPnP gateway answered a search. The router may have UPnP off, or "
            "may not answer this search target",
            [],
        )

    control = _control_url(context, description_url)
    if not control:
        return (
            INDETERMINATE,
            "L3A06",
            "found a UPnP device at %s but no control URL to ask" % description_url,
            [],
        )

    local_ip = context.address()
    if not local_ip:
        return UNTESTED, "L3A06", "%s: no local address" % PREREQUISITE_MISSING, []

    remove = _register_cleanup(context, control)

    add_body = (
        '<u:AddPortMapping xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">'
        "<NewRemoteHost></NewRemoteHost>"
        "<NewExternalPort>%d</NewExternalPort>"
        "<NewProtocol>TCP</NewProtocol>"
        "<NewInternalPort>%d</NewInternalPort>"
        "<NewInternalClient>%s</NewInternalClient>"
        "<NewEnabled>1</NewEnabled>"
        "<NewPortMappingDescription>netcheck L3A06</NewPortMappingDescription>"
        "<NewLeaseDuration>%d</NewLeaseDuration>"
        "</u:AddPortMapping>" % (TEST_PORT, TEST_PORT, local_ip, LEASE_SECONDS)
    )
    status, _, _ = _soap(context, control, "AddPortMapping", add_body)
    if status != 200:
        return (
            PRESENT,
            "L3A06",
            "the gateway refused an unauthenticated mapping request (HTTP %s), so "
            "UPnP does not hand out holes on request" % status,
            [],
        )

    deleted, _, _ = _soap(context, control, "DeletePortMapping", _delete_body())
    if deleted == 200:
        remove()  # marks the cleanup done so the exit handler is a no-op
    else:
        raise CleanupFailed(MANUAL_REMOVAL % (TEST_PORT, control, LEASE_SECONDS))

    return (
        ABSENT,
        "L3A06",
        "any host on this segment can open a port on the router: a mapping for "
        "external port %d was created and deleted without authentication" % TEST_PORT,
        [
            Finding(HIGH, "L3A06",
                    "UPnP accepts unauthenticated port mappings, so any device, or "
                    "any page a browser loads, can open a port through the firewall",
                    "turning UPnP off on the router")
        ],
    )
