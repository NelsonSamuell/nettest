"""Active layer 3 checks.

The state tests come first: an absent prerequisite must yield UNTESTED and UDP
silence must yield INDETERMINATE, never ABSENT.
"""

import pytest

from netcheck.budget import LAYER3, Budget
from netcheck.config import Config
from netcheck.l3 import packets
from netcheck.l3.probes import discovery, filtering, services, upnp
from netcheck.models import ABSENT, INDETERMINATE, PRESENT, UNTESTED, Capture
from netcheck.registry import Context, NotStarted


class Sniffer:
    def stop(self):
        return None


def context(**kwargs):
    replies = kwargs.pop("replies", [])
    sent = kwargs.pop("sent", [])
    ports = kwargs.pop("ports", {})
    # The address is injected, so no test depends on an interface existing under
    # a particular name. Interface names differ on every platform.
    defaults = dict(interface="probe0", budget=Budget(), capture=Capture(),
                    local_address="10.20.0.9",
                    config=Config(gateway="10.20.0.1", subnets=["10.20.0.0/24"]))
    defaults.update(kwargs)
    made = Context(**defaults)
    made.sender = lambda i, f: sent.append(f)
    made.packet_sender = lambda i, p: sent.append(p)
    made.collector = lambda i, s, m: (replies, Sniffer())
    made.sleeper = lambda s: None
    made.classifier = lambda a, p, t: ports.get(p, "closed")
    made.banner_reader = lambda a, p, t: "Example SSH 1.0"
    made.tls_reader = lambda a, p, t: {"version": "TLSv1.3", "self_signed": False}
    made.http_client = lambda u, t, d, h: (200, "<root/>", u)
    made.start()
    made.sent = sent
    return made


# State tests.

def test_host_discovery_without_targets_is_untested():
    made = context(config=Config())
    state, _, detail, _ = discovery.run_host_discovery(made)
    assert state == UNTESTED
    assert state != ABSENT
    assert "target subnet" in detail


def test_tcp_inventory_without_hosts_is_untested():
    made = context(config=Config())
    state, _, _, _ = discovery.run_tcp_inventory(made)
    assert state == UNTESTED


def test_udp_silence_is_indeterminate_never_absent():
    state, _, detail, _ = discovery.run_udp_inventory(context())
    assert state == INDETERMINATE
    assert state != ABSENT
    assert "not evidence of filtering" in detail


def test_management_plane_without_a_gateway_is_untested():
    state, _, detail, _ = services.run(context(config=Config()))
    assert state == UNTESTED
    assert "no gateway" in detail


def test_no_management_service_is_indeterminate_not_present():
    state, _, detail, _ = services.run(context())
    assert state == INDETERMINATE
    assert state != PRESENT
    assert "may be on another port" in detail


def test_cleartext_management_is_absent():
    made = context(ports={80: "open"})
    state, _, _, findings = services.run(made)
    assert state == ABSENT
    assert any(f.check == "L3A04" for f in findings)


def test_encrypted_only_management_is_present():
    state, _, _, _ = services.run(context(ports={443: "open"}))
    assert state == PRESENT


def test_an_obsolete_tls_version_is_reported():
    made = context(ports={443: "open"})
    made.tls_reader = lambda a, p, t: {"version": "TLSv1", "self_signed": True}
    _, _, _, findings = services.run(made)
    titles = " ".join(f.title for f in findings)
    assert "obsolete" in titles and "self signed" in titles


def test_upnp_with_no_gateway_answer_is_indeterminate():
    state, _, detail, _ = upnp.run(context())
    assert state == INDETERMINATE
    assert state != ABSENT
    assert "no UPnP gateway answered" in detail


def test_icmp_redirect_needs_a_gateway_and_an_address():
    state, _, detail, _ = filtering.run(context(config=Config()))
    assert state == UNTESTED
    assert "plausible redirect" in detail


def test_icmp_redirect_says_it_describes_this_machine(monkeypatch):
    monkeypatch.setattr(filtering, "_route_to", lambda d: "unchanged")
    monkeypatch.setattr(filtering, "_flush", lambda d: None)
    made = context()
    state, _, detail, _ = filtering.run(made)
    assert state == PRESENT
    assert "not the network" in detail


def test_icmp_redirect_detects_an_installed_route(monkeypatch):
    routes = iter(["before", "192.0.2.111 via 10.20.0.1 dev x cache"])
    monkeypatch.setattr(filtering, "_route_to", lambda d: next(routes, "x"))
    flushed = []
    monkeypatch.setattr(filtering, "_flush", flushed.append)
    made = context()
    state, _, _, findings = filtering.run(made)
    assert state == ABSENT
    assert flushed, "the route must be removed whatever the answer"
    assert findings


# Budget tests.

def test_host_discovery_respects_the_packet_budget():
    sent = []
    made = context(sent=sent, budget=Budget(packets=10),
                   config=Config(subnets=["10.20.0.0/24"], gateway="10.20.0.1"))
    discovery.run_host_discovery(made)
    assert len(sent) == 10
    assert made.budget.remaining(LAYER3) == 0


def test_tcp_inventory_is_bounded_by_ports_and_hosts():
    sent = []
    made = context(sent=sent, config=Config(subnets=["10.20.0.0/24"], gateway="10.20.0.1"))
    discovery.run_tcp_inventory(made)
    expected = discovery.DEFAULT_TCP_HOSTS * min(
        len(packets.DEFAULT_TCP_PORTS), discovery.TCP_PORT_LIMIT
    )
    assert len(sent) == expected


def test_tcp_inventory_stops_at_the_budget():
    sent = []
    made = context(sent=sent, budget=Budget(packets=7))
    _, _, detail, _ = discovery.run_tcp_inventory(made)
    assert len(sent) == 7


def test_udp_inventory_applies_one_retry():
    sent = []
    made = context(sent=sent, config=Config(gateway="10.20.0.1"))
    discovery.run_udp_inventory(made)
    assert len(sent) == len(packets.DEFAULT_UDP_PORTS) * (1 + discovery.UDP_RETRIES)


def test_the_redirect_check_sends_exactly_one_packet(monkeypatch):
    monkeypatch.setattr(filtering, "_route_to", lambda d: "unchanged")
    monkeypatch.setattr(filtering, "_flush", lambda d: None)
    sent = []
    made = context(sent=sent)
    filtering.run(made)
    assert len(sent) == 1


def test_the_two_budgets_stay_independent():
    made = context()
    made.send_frames(b"\x00" * 60)
    made.send_packets(packets.tcp_syn("10.20.0.1", 80))
    assert made.budget.frames_sent == 1
    assert made.budget.packets_sent == 1


def test_nothing_sends_before_the_context_is_started():
    made = Context(interface="probe0", budget=Budget(), local_address="10.20.0.9")
    made.packet_sender = lambda i, p: pytest.fail("must not send")
    with pytest.raises(NotStarted):
        made.send_packets(packets.tcp_syn("10.20.0.1", 80))


# The mapping L3A06 writes must not outlive the run.

def test_a_mapping_that_cannot_be_deleted_halts_the_run(monkeypatch):
    monkeypatch.setattr(upnp, "_discover", lambda c: "http://10.20.0.1:5000/desc.xml")
    monkeypatch.setattr(upnp, "_control_url", lambda c, u: "http://10.20.0.1:5000/ctl")
    calls = []

    def soap(context_, url, action, body):
        calls.append(action)
        return (200, "", url) if action == "AddPortMapping" else (500, "", url)

    monkeypatch.setattr(upnp, "_soap", soap)
    made = context()
    with pytest.raises(upnp.CleanupFailed) as excinfo:
        upnp.run(made)
    assert "Remove it by hand" in str(excinfo.value)
    assert calls == ["AddPortMapping", "DeletePortMapping"]


def test_cleanup_is_registered_before_the_mapping_is_made(monkeypatch):
    """Arming removal first is what stops an interrupt leaving a hole behind."""
    monkeypatch.setattr(upnp, "_discover", lambda c: "http://10.20.0.1:5000/desc.xml")
    monkeypatch.setattr(upnp, "_control_url", lambda c, u: "http://10.20.0.1:5000/ctl")
    order = []

    def soap(context_, url, action, body):
        order.append(("soap", action))
        return 200, "", url

    made = context()
    original = upnp._register_cleanup

    def spy(context_, control):
        order.append(("register", control))
        return original(context_, control)

    monkeypatch.setattr(upnp, "_register_cleanup", spy)
    monkeypatch.setattr(upnp, "_soap", soap)
    upnp.run(made)
    assert order[0][0] == "register"
    assert made.cleanup, "a cleanup handler must be left on the context"


def test_a_successful_delete_makes_the_exit_handler_a_no_op(monkeypatch):
    monkeypatch.setattr(upnp, "_discover", lambda c: "http://10.20.0.1:5000/desc.xml")
    monkeypatch.setattr(upnp, "_control_url", lambda c, u: "http://10.20.0.1:5000/ctl")
    calls = []
    monkeypatch.setattr(upnp, "_soap",
                        lambda c, u, a, b: (calls.append(a), (200, "", u))[1])
    made = context()
    state, _, _, _ = upnp.run(made)
    assert state == ABSENT
    before = len(calls)
    made.run_cleanup()
    assert len(calls) == before, "the mapping was already removed"


def test_a_refused_mapping_is_present():
    import netcheck.l3.probes.upnp as module

    made = context()
    original_discover, original_url, original_soap = (
        module._discover, module._control_url, module._soap
    )
    module._discover = lambda c: "http://10.20.0.1:5000/desc.xml"
    module._control_url = lambda c, u: "http://10.20.0.1:5000/ctl"
    module._soap = lambda c, u, a, b: (401, "", u)
    try:
        state, _, detail, _ = module.run(made)
    finally:
        module._discover, module._control_url, module._soap = (
            original_discover, original_url, original_soap
        )
    assert state == PRESENT
    assert "refused" in detail


# The observer dependent checks. The state test comes first for each: without an
# observer the answer is INDETERMINATE, never ABSENT and never PRESENT.

from netcheck.l3.probes import dns, segmentation, spoofing  # noqa: E402


def observer_context(**kwargs):
    saw = kwargs.pop("saw", None)
    connect = kwargs.pop("connect", None)
    made = context(**kwargs)
    made.observer_query = lambda endpoint, token, timeout: saw
    made.observer_connect = lambda endpoint, host, port, timeout: connect
    made.resolver = lambda name: "198.51.100.9"
    return made


def config_with(**kwargs):
    external = kwargs.pop("external", {})
    observers = kwargs.pop("observers", {})
    return Config(gateway="10.20.0.1", subnets=["10.20.0.0/24"],
                  external=external, observers=observers, **kwargs)


@pytest.mark.parametrize(
    "identifier,runner,config",
    [
        ("L3A07", filtering.run_egress, config_with(external={"test_host": "h.example"})),
        ("L3A13", spoofing.run, config_with(external={"test_host": "h.example"})),
        ("L3A14", filtering.run_fragment_handling,
         config_with(external={"test_host": "h.example"})),
        ("L3A15", filtering.run_source_routing,
         config_with(external={"test_host": "h.example"})),
        ("L3A09", segmentation.run, config_with(guest_subnet="10.40.0.0/24")),
    ],
)
def test_without_an_observer_the_answer_is_indeterminate(identifier, runner, config):
    state, _, detail, *_ = runner(observer_context(config=config))
    assert state == INDETERMINATE
    assert state not in (ABSENT, PRESENT)
    assert "no_observer" in detail


def test_inbound_v4_without_a_wan_address_is_untested():
    state, _, detail, *_ = filtering.run_inbound_v4(observer_context())
    assert state == UNTESTED
    assert "--wan" in detail


def test_cgnat_is_untested_and_never_present():
    config = config_with(observers={"external": "o:9001"})
    config.wan_address = "100.64.1.1"
    state, _, detail, *_ = filtering.run_inbound_v4(observer_context(config=config))
    assert state == UNTESTED
    assert state != PRESENT
    assert "cgnat" in detail


def test_inbound_v6_needs_a_global_address_first():
    config = config_with(observers={"external": "o:9001"})
    state, _, detail, *_ = filtering.run_inbound_v6(observer_context(config=config))
    assert state == UNTESTED
    assert "L3P04" in detail


def test_inbound_reports_absent_when_the_observer_gets_in():
    config = config_with(observers={"external": "o:9001"})
    config.wan_address = "198.51.100.9"
    made = observer_context(config=config, connect="open")
    state, _, _, findings, segments = filtering.run_inbound_v4(made)
    assert state == ABSENT
    assert segments == ("external", "lan")
    assert findings


def test_inbound_reports_present_when_the_observer_cannot():
    config = config_with(observers={"external": "o:9001"})
    config.wan_address = "198.51.100.9"
    made = observer_context(config=config, connect="filtered")
    state, _, _, _, _ = filtering.run_inbound_v4(made)
    assert state == PRESENT


def test_an_unreachable_observer_is_indeterminate_not_a_negative():
    config = config_with(observers={"external": "o:9001"})
    config.wan_address = "198.51.100.9"
    made = observer_context(config=config, connect=None)
    state, _, detail, *_ = filtering.run_inbound_v4(made)
    assert state == INDETERMINATE
    assert state != PRESENT
    assert "did not answer" in detail


def test_egress_absent_when_the_marker_arrives():
    config = config_with(external={"test_host": "h.example"},
                         observers={"external": "o:9001"})
    state, _, _, findings, segments = filtering.run_egress(
        observer_context(config=config, saw=True)
    )
    assert state == ABSENT
    assert segments == ("lan", "external")


def test_a_test_host_that_does_not_resolve_is_refused_not_crashed():
    config = config_with(external={"test_host": "nonexistent.invalid"})
    made = observer_context(config=config)
    made.resolver = lambda name: ""
    for runner in (filtering.run_egress, filtering.run_fragment_handling,
                   filtering.run_source_routing, spoofing.run):
        state, _, detail, *_ = runner(made)
        assert state == UNTESTED
        assert "does not resolve" in detail


def test_rebinding_without_an_authoritative_server_is_untested():
    state, _, detail, *_ = dns.run_rebinding(observer_context())
    assert state == UNTESTED
    assert "authoritative_ns" in detail


def test_rebinding_with_no_answer_is_indeterminate():
    config = config_with(external={"authoritative_ns": "ns.example"})
    state, _, detail, *_ = dns.run_rebinding(observer_context(config=config))
    assert state == INDETERMINATE
    assert state != ABSENT


def test_resolver_scoping_without_an_external_observer_is_indeterminate():
    state, _, detail, *_ = dns.run_resolver_scoping(observer_context())
    assert state == INDETERMINATE
    assert "no_observer" in detail


def test_resolver_scoping_absent_when_the_wan_side_answers():
    config = config_with(observers={"external": "o:9001"})
    config.wan_address = "198.51.100.9"
    state, _, _, findings = dns.run_resolver_scoping(
        observer_context(config=config, connect="open")
    )
    assert state == ABSENT
    assert findings


def test_guest_segmentation_reports_each_question_separately():
    config = config_with(guest_subnet="10.40.0.0/24",
                         observers={"internal": "10.20.0.20:9001"})
    made = observer_context(config=config, ports={9001: "open", 80: "closed"})
    state, _, detail, findings = segmentation.run(made)
    assert state == ABSENT
    assert "the LAN host" in detail and "the gateway admin interface" in detail


def test_guest_segmentation_present_when_nothing_is_reachable():
    """Nothing reachable means filtered. Closed would mean the packet arrived."""
    config = config_with(guest_subnet="10.40.0.0/24",
                         observers={"internal": "10.20.0.20:9001"})
    made = observer_context(config=config)
    made.classifier = lambda a, p, t: "filtered"
    state, _, _, _ = segmentation.run(made)
    assert state == PRESENT


def test_every_control_can_reach_a_non_untested_state():
    """The whole table is establishable given a complete setup."""
    from netcheck.cli import registry
    from netcheck.models import CONTROL_TABLE

    owners = {}
    for identifier, check in registry().checks.items():
        for control in check.controls:
            owners.setdefault(control, []).append(identifier)
    missing = [name for name, _, _ in CONTROL_TABLE if name not in owners]
    assert missing == [], "no check can establish: %s" % missing


def test_a_refused_connection_counts_as_having_reached_the_lan():
    """A reset means the packet arrived. Reading that as isolation is a false PRESENT."""
    config = config_with(guest_subnet="10.40.0.0/24",
                         observers={"internal": "10.20.0.20:9001"})
    made = observer_context(config=config)
    made.classifier = lambda a, p, t: "closed"
    state, _, _, _ = segmentation.run(made)
    assert state == ABSENT

    made.classifier = lambda a, p, t: "filtered"
    assert segmentation.run(made)[0] == PRESENT


def test_no_route_is_filtered_not_closed():
    """Closed must mean reached and refused, or L3A02 cannot tell them apart."""
    import errno
    from unittest import mock

    from netcheck.platform import sockets

    for code, expected in (
        (0, "open"),
        (errno.ECONNREFUSED, "closed"),
        (errno.ECONNRESET, "closed"),
        (errno.EHOSTUNREACH, "filtered"),
        (errno.ENETUNREACH, "filtered"),
        (errno.ETIMEDOUT, "filtered"),
    ):
        with mock.patch("socket.socket") as made:
            made.return_value.connect_ex.return_value = code
            assert sockets.classify_connect("192.0.2.1", 80, 0.1) == expected, code
