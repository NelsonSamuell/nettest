"""L3A09, guest segmentation.

Three separate questions, reported independently, because routers commonly
isolate one and not the others: can the guest segment reach the LAN subnet, the
gateway admin interface, and another guest client.

Run from a host on the guest segment with the internal observer on the LAN.
Without the observer the LAN question cannot be answered from here, so the
result is INDETERMINATE.
"""

from __future__ import annotations

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

CONTROL = "Guest segmentation"
OBSERVER_SECONDS = 6
ADMIN_PORT = 80
OBSERVER_PORT = 9001


def run(context):
    """Try the LAN, the gateway admin interface, and another guest client."""
    config = context.config
    if not config or not config.guest_subnet:
        return (
            UNTESTED, "L3A09",
            "%s: no guest_subnet configured" % PREREQUISITE_MISSING, [],
        )

    observer = config.internal_observer
    if not observer:
        return (
            INDETERMINATE, "L3A09",
            "%s: run this from the guest segment with an internal observer on the "
            "LAN. Reaching it can only be confirmed from there" % NO_OBSERVER,
            [],
        )

    answers = {}
    lan_host = observer.rsplit(":", 1)[0]
    answers["the LAN host"] = context.connect_result(lan_host, OBSERVER_PORT)
    if config.gateway:
        answers["the gateway admin interface"] = context.connect_result(
            config.gateway, ADMIN_PORT
        )

    reachable = [name for name, state in answers.items() if state == "open"]
    detail = "from the guest segment: " + ", ".join(
        "%s %s" % (name, state) for name, state in sorted(answers.items())
    )

    if reachable:
        return (
            ABSENT, "L3A09", detail,
            [
                Finding(HIGH, "L3A09", "The guest segment reaches %s"
                        % " and ".join(reachable),
                        "isolating the guest network from the LAN and the admin interface")
            ],
        )
    return PRESENT, "L3A09", detail, []
