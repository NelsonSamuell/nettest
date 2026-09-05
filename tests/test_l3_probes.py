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
    defaults = dict(interface="lo", budget=Budget(), capture=Capture(),
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
    made.interface = _an_interface_with_an_address()
    state, _, detail, _ = filtering.run(made)
    assert state == PRESENT
    assert "not the network" in detail


def test_icmp_redirect_detects_an_installed_route(monkeypatch):
    routes = iter(["before", "192.0.2.111 via 10.20.0.1 dev x cache"])
    monkeypatch.setattr(filtering, "_route_to", lambda d: next(routes, "x"))
    flushed = []
    monkeypatch.setattr(filtering, "_flush", flushed.append)
    made = context()
    made.interface = _an_interface_with_an_address()
    state, _, _, findings = filtering.run(made)
    assert state == ABSENT
    assert flushed, "the route must be removed whatever the answer"
    assert findings


def _an_interface_with_an_address() -> str:
    from netcheck.platform import interfaces as interfaces_module

    for entry in interfaces_module.list_interfaces():
        if entry.address:
            return entry.name
    return "lo"


# Budget tests.

def test_host_discovery_respects_the_packet_budget():
    sent = []
    made = context(sent=sent, budget=Budget(packets=10),
                   config=Config(subnets=["10.20.0.0/24"], gateway="10.20.0.1"))
    made.interface = _an_interface_with_an_address()
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
    made.interface = _an_interface_with_an_address()
    filtering.run(made)
    assert len(sent) == 1


def test_the_two_budgets_stay_independent():
    made = context()
    made.send_frames(b"\x00" * 60)
    made.send_packets(packets.tcp_syn("10.20.0.1", 80))
    assert made.budget.frames_sent == 1
    assert made.budget.packets_sent == 1


def test_nothing_sends_before_the_context_is_started():
    made = Context(interface="lo", budget=Budget())
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
    made.interface = _an_interface_with_an_address()
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
    made.interface = _an_interface_with_an_address()
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
    made.interface = _an_interface_with_an_address()
    state, _, _, _ = upnp.run(made)
    assert state == ABSENT
    before = len(calls)
    made.run_cleanup()
    assert len(calls) == before, "the mapping was already removed"


def test_a_refused_mapping_is_present():
    import netcheck.l3.probes.upnp as module

    made = context()
    made.interface = _an_interface_with_an_address()
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
