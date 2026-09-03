"""The state tests come first: no observer must mean INDETERMINATE, never ABSENT."""

import pytest

from l2check.l3.probes import discovery, host, management, reachability, registry_l3
from l2check.models import Capture, IPv6ModeRecord
from l2check.posture import ABSENT, INDETERMINATE, PRESENT, UNTESTED
from l2check.session import ActiveSession, Budget


def session(**kwargs):
    defaults = dict(
        interface="lo",
        sender=lambda i, f: None,
        ip_sender=lambda i, p: None,
        connector=lambda a, p, t: False,
        classifier=lambda a, p, t: "filtered",
        banner_reader=lambda a, p, t: "",
        tls_reader=lambda a, p, t: {},
        http_client=lambda u, t, d, h: (0, ""),
        resolver=lambda name: "",
        budget=Budget(),
    )
    defaults.update(kwargs)
    made = ActiveSession(**defaults)
    made.start(["L3A01"])
    return made


# Every check that tests one way delivery must refuse to claim a negative.

@pytest.mark.parametrize(
    "check,runner,kwargs",
    [
        ("L3A05", reachability.run_inbound_v4, {"wan_address": "81.2.3.4"}),
        ("L3A07", reachability.run_egress, {"test_host": "198.51.100.9"}),
        ("L3A09", reachability.run_guest_segmentation, {"guest_subnet": "192.168.2.0/24"}),
        ("L3A13", reachability.run_anti_spoofing, {"test_host": "198.51.100.9"}),
        ("L3A14", reachability.run_fragment_handling, {"test_host": "198.51.100.9"}),
        ("L3A15", reachability.run_source_routing, {"test_host": "198.51.100.9"}),
    ],
)
def test_no_observer_means_indeterminate_never_absent(check, runner, kwargs):
    result = runner(session(**kwargs), Capture())
    assert result.state == INDETERMINATE
    assert result.state != ABSENT
    assert "no observer supplied" in result.basis


def test_inbound_v6_without_an_observer_is_indeterminate():
    capture = Capture(
        ipv6_modes=[IPv6ModeRecord("aa:bb:cc:dd:ee:01", "2400::1", "global", "slaac", False)]
    )
    result = reachability.run_inbound_v6(session(), capture)
    assert result.state == INDETERMINATE


def test_an_unreachable_observer_is_indeterminate_not_a_negative(monkeypatch):
    monkeypatch.setattr(reachability, "ask_observer", lambda *a, **k: None)
    result = reachability.run_egress(
        session(test_host="198.51.100.9", external_observer="vps:9001"), Capture()
    )
    assert result.state == INDETERMINATE
    assert "unreachable" in result.basis


def test_an_observer_that_saw_nothing_gives_present(monkeypatch):
    monkeypatch.setattr(reachability, "ask_observer", lambda *a, **k: False)
    result = reachability.run_egress(
        session(test_host="198.51.100.9", external_observer="vps:9001"), Capture()
    )
    assert result.state == PRESENT


def test_an_observer_that_saw_the_marker_gives_absent(monkeypatch):
    monkeypatch.setattr(reachability, "ask_observer", lambda *a, **k: True)
    result = reachability.run_egress(
        session(test_host="198.51.100.9", external_observer="vps:9001"), Capture()
    )
    assert result.state == ABSENT
    assert result.segments == ("lan", "external")


def test_cgnat_is_untested_not_a_pass():
    result = reachability.run_inbound_v4(
        session(wan_address="100.64.1.1", external_observer="vps:9001"), Capture()
    )
    assert result.state == UNTESTED
    assert "cgnat" in result.basis
    assert result.state != PRESENT


def test_inbound_v4_without_a_wan_address_is_untested():
    assert reachability.run_inbound_v4(session(), Capture()).state == UNTESTED


def test_inbound_v6_needs_a_global_address_first():
    result = reachability.run_inbound_v6(session(external_observer="vps:9001"), Capture())
    assert result.state == UNTESTED
    assert "L3P04" in result.detail


def test_rebinding_without_an_authoritative_server_is_untested():
    assert reachability.run_dns_rebinding(session(), Capture()).state == UNTESTED


# Budgets.

def test_host_discovery_respects_the_packet_budget(monkeypatch):
    monkeypatch.setattr(discovery, "sweep", lambda s, p, seconds, match: s.send_ip(p) and [])
    made = session(sweep_targets=["192.168.1.%d" % n for n in range(1, 60)])
    made.budget.packets = 10
    result = discovery.run_host_discovery(made, Capture())
    assert result.frames_sent == 10
    assert made.budget.packets_sent == 10


def test_host_discovery_without_targets_is_refused():
    assert discovery.run_host_discovery(session(), Capture()).state == UNTESTED


def test_tcp_inventory_is_bounded_by_ports_hosts_and_budget(monkeypatch):
    sent = []

    def fake_sweep(s, packets, seconds, match):
        sent.extend(packets)
        s.send_ip(packets)
        return []

    monkeypatch.setattr(discovery, "sweep", fake_sweep)
    made = session(
        gateway="192.168.1.1",
        sweep_targets=["192.168.1.%d" % n for n in range(2, 40)],
        tcp_ports=tuple(range(1, 400)),
        tcp_port_limit=200,
        tcp_hosts=5,
    )
    discovery.run_tcp_inventory(made, Capture())
    assert len(sent) == 5 * 200


def test_tcp_inventory_stops_at_the_budget(monkeypatch):
    monkeypatch.setattr(discovery, "sweep", lambda s, p, seconds, match: s.send_ip(p) and [])
    made = session(gateway="192.168.1.1", tcp_ports=(80, 443, 8080), tcp_hosts=1)
    made.budget.packets = 2
    result = discovery.run_tcp_inventory(made, Capture())
    assert result.frames_sent == 2


def test_udp_silence_is_indeterminate_never_absent(monkeypatch):
    monkeypatch.setattr(discovery, "sweep", lambda s, p, seconds, match: [])
    result = discovery.run_udp_inventory(
        session(gateway="192.168.1.1", udp_ports=(53, 161)), Capture()
    )
    assert result.state == INDETERMINATE
    assert result.state != ABSENT
    assert "not evidence of filtering" in result.detail


def test_udp_payloads_are_protocol_appropriate():
    assert b"M-SEARCH" in bytes(discovery._udp_payload(1900))
    assert discovery._udp_payload(53) is not None
    assert discovery._udp_payload(9999) == b"\x00"


# Management plane and UPnP.

def test_management_plane_without_a_gateway_is_refused():
    assert management.run_management_plane(session(), Capture()).state == UNTESTED


def test_cleartext_management_is_absent():
    made = session(gateway="192.168.1.1", classifier=lambda a, p, t: "open" if p == 80 else "closed")
    result = management.run_management_plane(made, Capture())
    assert result.state == ABSENT
    assert any(f.check == "L3A04" for f in result.findings)


def test_encrypted_only_management_is_present():
    made = session(
        gateway="192.168.1.1",
        classifier=lambda a, p, t: "open" if p == 443 else "closed",
        tls_reader=lambda a, p, t: {"version": "TLSv1.3", "self_signed": False},
    )
    assert management.run_management_plane(made, Capture()).state == PRESENT


def test_no_management_service_is_indeterminate():
    made = session(gateway="192.168.1.1", classifier=lambda a, p, t: "closed")
    assert management.run_management_plane(made, Capture()).state == INDETERMINATE


def test_upnp_without_a_gateway_answer_is_indeterminate(monkeypatch):
    monkeypatch.setattr(management, "_discover_igd", lambda s: "")
    result = management.run_upnp_mapping(session(), Capture())
    assert result.state == INDETERMINATE


def test_upnp_refusing_a_mapping_is_present(monkeypatch):
    monkeypatch.setattr(management, "_discover_igd", lambda s: "http://192.168.1.1:5000/x.xml")
    monkeypatch.setattr(management, "_control_url", lambda s, u: "http://192.168.1.1:5000/ctl")
    monkeypatch.setattr(management, "_soap", lambda s, u, a, b: (401, ""))
    result = management.run_upnp_mapping(session(local_cidr="192.168.1.9/24"), Capture())
    assert result.state == PRESENT


def test_upnp_accepting_a_mapping_is_absent(monkeypatch):
    monkeypatch.setattr(management, "_discover_igd", lambda s: "http://192.168.1.1:5000/x.xml")
    monkeypatch.setattr(management, "_control_url", lambda s, u: "http://192.168.1.1:5000/ctl")
    monkeypatch.setattr(management, "_soap", lambda s, u, a, b: (200, ""))
    result = management.run_upnp_mapping(session(local_cidr="192.168.1.9/24"), Capture())
    assert result.state == ABSENT


def test_a_mapping_that_cannot_be_deleted_halts_the_run(monkeypatch):
    monkeypatch.setattr(management, "_discover_igd", lambda s: "http://192.168.1.1:5000/x.xml")
    monkeypatch.setattr(management, "_control_url", lambda s, u: "http://192.168.1.1:5000/ctl")
    calls = []

    def soap(s, url, action, body):
        calls.append(action)
        return (200, "") if action == "AddPortMapping" else (500, "")

    monkeypatch.setattr(management, "_soap", soap)
    made = session(local_cidr="192.168.1.9/24")
    with pytest.raises(RuntimeError) as excinfo:
        management.run_upnp_mapping(made, Capture())
    assert "Remove it by hand" in str(excinfo.value)
    assert made.cleanup_required
    assert calls == ["AddPortMapping", "DeletePortMapping"]


# The local host check.

def test_icmp_redirect_needs_a_gateway_and_an_address():
    assert host.run_icmp_redirect(session(), Capture()).state == UNTESTED


def test_icmp_redirect_reports_it_describes_this_machine(monkeypatch):
    monkeypatch.setattr(host, "_cached_route", lambda d: "unchanged")
    monkeypatch.setattr(host, "_flush_cache", lambda d: None)
    result = host.run_icmp_redirect(
        session(gateway="192.168.1.1", local_cidr="192.168.1.9/24"), Capture()
    )
    assert result.state == PRESENT
    assert "not the network" in result.detail


def test_icmp_redirect_detects_an_installed_route(monkeypatch):
    routes = iter(["before", "192.0.2.111 via 192.168.1.1 dev wlan0 cache"])
    monkeypatch.setattr(host, "_cached_route", lambda d: next(routes, "x"))
    flushed = []
    monkeypatch.setattr(host, "_flush_cache", flushed.append)
    result = host.run_icmp_redirect(
        session(gateway="192.168.1.1", local_cidr="192.168.1.9/24"), Capture()
    )
    assert result.state == ABSENT
    assert flushed, "the route must be removed whatever the answer"


def test_every_layer_three_check_is_registered():
    from l2check.session import L3_ACTIVE_CHECKS

    assert sorted(registry_l3()) == sorted(L3_ACTIVE_CHECKS)


def test_a_test_host_that_does_not_resolve_is_refused_not_crashed():
    """A bad name in the config must report, not raise, mid run."""
    made = session(test_host="nonexistent.invalid", resolver=lambda name: "")
    for runner in (
        reachability.run_egress,
        reachability.run_anti_spoofing,
        reachability.run_fragment_handling,
        reachability.run_source_routing,
    ):
        result = runner(made, Capture())
        assert result.state == UNTESTED
        assert "does not resolve" in result.detail


def test_a_resolvable_name_is_used():
    made = session(test_host="vps.example.net", resolver=lambda name: "198.51.100.9")
    assert made.resolve("vps.example.net") == "198.51.100.9"
    assert made.resolve("198.51.100.9") == "198.51.100.9"
    assert made.resolve("") == ""


def test_only_l3a07_owns_the_egress_control():
    """Three checks touch egress. If they shared a control the last would win."""
    made = session(test_host="198.51.100.9", resolver=lambda n: "198.51.100.9")
    assert reachability.run_egress(made, Capture()).control is not None
    assert reachability.run_fragment_handling(made, Capture()).control is None
    assert reachability.run_source_routing(made, Capture()).control is None


def test_a_result_without_a_control_leaves_the_table_alone():
    from l2check.posture import Posture, ProbeResult, UNTESTED as U

    board = Posture.new()
    before = board.counts()
    board.apply(ProbeResult("L3A14", None, ABSENT, "L3A14", "detail"))
    assert board.counts() == before
