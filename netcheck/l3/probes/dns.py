"""L3A10 DNS rebinding protection and L3A11 resolver scoping.

L3A10 asks the local resolver for a name under a domain the operator controls
that answers with an RFC1918 address. An unfiltered answer means protection is
absent. It needs `authoritative_ns`, otherwise there is nothing to ask about.

L3A11 asks whether the gateway resolver answers from where it should not: the
WAN side, which makes it usable for amplification by anyone.
"""

from __future__ import annotations

import ipaddress

from scapy.layers.dns import DNS
from scapy.layers.inet import UDP

from netcheck.l3 import packets
from netcheck.models import (
    ABSENT,
    HIGH,
    INDETERMINATE,
    NO_OBSERVER,
    PREREQUISITE_MISSING,
    PRESENT,
    UNTESTED,
    Finding,
)

LISTEN_SECONDS = 5
OBSERVER_SECONDS = 6
DNS_PORT = 53
REBIND_LABEL = "rebind"


def run_rebinding(context):
    """L3A10. Whether the local resolver passes a private answer through."""
    config = context.config
    authoritative = config.external.get("authoritative_ns", "") if config else ""
    if not authoritative:
        return (
            UNTESTED, "L3A10",
            "%s: needs external.authoritative_ns, a name server you control that "
            "answers with an RFC1918 address" % PREREQUISITE_MISSING,
            [],
        )
    if not config.gateway:
        return UNTESTED, "L3A10", "%s: no local resolver to ask" % PREREQUISITE_MISSING, []

    name = "%s.%s" % (REBIND_LABEL, authoritative)
    replies, sniffer = context.collect(
        LISTEN_SECONDS,
        lambda pkt: UDP in pkt and pkt[UDP].sport == DNS_PORT and DNS in pkt,
    )
    context.send_packets(packets.dns_query(config.gateway, name))
    context.sleeper(LISTEN_SECONDS)
    sniffer.stop()

    answered = False
    for packet in replies:
        dns = packet[DNS]
        answered = answered or bool(dns.ancount)
        for index in range(int(dns.ancount or 0)):
            record = dns.an[index]
            if record.type != 1:
                continue
            address = str(record.rdata)
            try:
                private = ipaddress.ip_address(address).is_private
            except ValueError:
                continue
            if private:
                return (
                    ABSENT, "L3A10",
                    "the local resolver returned the private address %s for %s "
                    "unfiltered" % (address, name),
                    [
                        Finding(HIGH, "L3A10",
                                "DNS rebinding protection is off: an external name "
                                "resolved to %s" % address,
                                "enabling rebind protection on the resolver")
                    ],
                )
    if answered:
        return (
            PRESENT, "L3A10",
            "the local resolver answered for %s but stripped the private address" % name,
            [],
        )
    return (
        INDETERMINATE, "L3A10",
        "the local resolver did not answer for %s, so nothing was learned" % name,
        [],
    )


def run_resolver_scoping(context):
    """L3A11. Whether the gateway resolver answers from the WAN side."""
    config = context.config
    if not config or not config.gateway:
        return UNTESTED, "L3A11", "%s: no gateway resolver" % PREREQUISITE_MISSING, []

    observer = config.external_observer
    if not observer or not config.wan_address:
        return (
            INDETERMINATE, "L3A11",
            "%s: testing the resolver from outside needs --wan and an external "
            "observer" % NO_OBSERVER,
            [],
        )

    answer = context.ask_observer_connect(
        observer, config.wan_address, DNS_PORT, OBSERVER_SECONDS
    )
    if answer is None:
        return (
            INDETERMINATE, "L3A11",
            "the observer at %s did not answer, so nothing was learned" % observer,
            [],
        )
    if answer == "open":
        return (
            ABSENT, "L3A11",
            "the resolver on %s answers from the WAN side, which makes it usable "
            "for amplification by anyone" % config.wan_address,
            [
                Finding(HIGH, "L3A11",
                        "The gateway resolver is reachable from the internet",
                        "restricting the resolver to the LAN interface")
            ],
        )
    return (
        PRESENT, "L3A11",
        "the resolver did not answer from the WAN side (%s)" % answer,
        [],
    )
