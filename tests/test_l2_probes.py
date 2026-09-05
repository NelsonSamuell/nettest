"""Layer 2 active checks.

The state tests come first: an absent observer or prerequisite must yield
INDETERMINATE or UNTESTED, never ABSENT.
"""

import pytest

from netcheck.budget import LAYER2, Budget, CapExceeded
from netcheck.l2 import register
from netcheck.l2.parse import Bpdu
from netcheck.models import Capture
from netcheck.l2.probes import arp, dhcp, management, port_security, spanning_tree, trunking, vlan
from netcheck.models import ABSENT, INDETERMINATE, PRESENT, UNTESTED
from netcheck.registry import Context, NotStarted, Registry


class Sniffer:
    def __init__(self, replies):
        self.replies = replies

    def stop(self):
        return None


def context(**kwargs):
    replies = kwargs.pop("replies", [])
    sent = kwargs.pop("sent", [])
    saw = kwargs.pop("saw", None)
    defaults = dict(interface="lo", budget=Budget(), capture=Capture(), max_macs=50)
    defaults.update(kwargs)
    made = Context(**defaults)
    made.sender = lambda i, f: sent.append(f)
    made.collector = lambda i, s, m: (replies, Sniffer(replies))
    made.sleeper = lambda s: None
    ticks = iter(range(0, 10_000))
    made.clock = lambda: next(ticks)
    made.observer_query = lambda endpoint, token, timeout: saw
    made.start()
    made.sent = sent
    return made


# State tests.

def test_dai_without_a_test_address_is_untested_never_absent():
    state, _, detail = arp.run(context())
    assert state == UNTESTED
    assert state != ABSENT
    assert "test-ip" in detail


def test_dai_without_an_observer_is_indeterminate():
    state, _, detail = arp.run(context(test_ip="192.0.2.99"))
    assert state == INDETERMINATE
    assert state != ABSENT
    assert "no_observer" in detail


def test_dai_refuses_an_address_seen_in_the_capture():
    capture = Capture()
    capture.add("arp", __import__("netcheck.l2.parse", fromlist=["Arp"]).Arp(
        "00:00:5e:00:53:0a", "192.0.2.99", True))
    state, _, detail = arp.run(context(test_ip="192.0.2.99", capture=capture))
    assert state == UNTESTED
    assert "passive capture" in detail


def test_dai_refuses_an_address_that_answers(monkeypatch):
    replies = [object()]
    made = context(test_ip="192.0.2.99")
    made.collector = lambda i, s, m: (replies, Sniffer(replies))
    state, _, detail = arp.run(made)
    assert state == UNTESTED
    assert "in use" in detail


def test_double_tagging_without_a_target_vlan_is_untested():
    made = context(test_ip="198.51.100.9")
    state, _, _ = vlan.run(made)
    assert state == UNTESTED


def test_double_tagging_without_an_observer_is_indeterminate():
    made = context(test_ip="198.51.100.9")
    made.target_vlan = 20
    state, _, detail = vlan.run(made)
    assert state == INDETERMINATE
    assert state != ABSENT
    assert "one way delivery" in detail.lower() or "one way" in detail


def test_double_tagging_refuses_when_the_target_is_the_native_vlan():
    made = context(test_ip="198.51.100.9")
    made.target_vlan = 1
    state, _, detail = vlan.run(made)
    assert state == UNTESTED
    assert "native VLAN" in detail


def test_client_isolation_without_an_observer_is_indeterminate():
    state, _, detail = management.run_client_isolation(context())
    assert state == INDETERMINATE
    assert state != ABSENT
    assert "no_observer" in detail


def test_switch_management_without_a_disclosed_address_is_untested():
    state, _, detail = management.run_management_reachable(context())
    assert state == UNTESTED
    assert "L2P01" in detail


def test_bpdu_guard_refuses_without_an_observed_root_priority():
    """The safety property cannot be guaranteed without it, so it does not run."""
    state, _, detail = spanning_tree.run(context())
    assert state == UNTESTED
    assert state != ABSENT
    assert "root priority" in detail


def test_dhcp_snooping_with_no_offer_is_indeterminate():
    state, _, detail = dhcp.run(context())
    assert state == INDETERMINATE
    assert state != ABSENT
    assert "says nothing about snooping" in detail


def test_port_security_with_no_reaction_is_indeterminate_not_absent():
    state, _, detail = port_security.run(context())
    assert state == INDETERMINATE
    assert state != ABSENT
    assert "restrict or protect" in detail


def test_discovery_injection_without_reflection_is_indeterminate():
    state, _, detail = trunking.run_lldp_injection(context())
    assert state == INDETERMINATE
    assert state != ABSENT
    assert "neighbour table" in detail


def test_no_dtp_answer_reports_present():
    """Silence here means the port did not offer to negotiate."""
    state, _, _ = trunking.run_dtp(context())
    assert state == PRESENT


# Budget tests.

def test_port_security_respects_its_own_cap():
    sent = []
    made = context(sent=sent, max_macs=7)
    port_security.run(made)
    assert len(sent) == 7


def test_port_security_stops_at_the_frame_budget():
    sent = []
    made = context(sent=sent, budget=Budget(frames=4), max_macs=50)
    port_security.run(made)
    assert len(sent) == 4
    assert made.budget.remaining(LAYER2) == 0


def test_double_tagging_sends_exactly_three_frames():
    sent = []
    made = context(sent=sent, test_ip="198.51.100.9")
    made.target_vlan = 20
    vlan.run(made)
    assert len(sent) == 3


def test_the_bpdu_check_sends_exactly_one_frame():
    sent = []
    capture = Capture()
    capture.add("bpdu", Bpdu("00:00:5e:00:53:01", 32768, "00:00:5e:00:53:01", 4, 32768,
                             "00:00:5e:00:53:01"))
    made = context(sent=sent, capture=capture)
    spanning_tree.run(made)
    assert len(sent) == 1


def test_client_isolation_sends_two_frames():
    sent = []
    made = context(sent=sent, observer="192.0.2.20:9001", saw=False)
    management.run_client_isolation(made)
    assert len(sent) == 2


def test_client_isolation_reports_absent_when_the_observer_saw_the_frames():
    made = context(observer="192.0.2.20:9001", saw=True)
    state, _, _ = management.run_client_isolation(made)
    assert state == ABSENT


def test_an_unreachable_observer_is_indeterminate_not_a_negative():
    made = context(observer="192.0.2.20:9001", saw=None)
    state, _, detail = management.run_client_isolation(made)
    assert state == INDETERMINATE
    assert state != PRESENT
    assert "did not answer" in detail


def test_a_batch_beyond_the_budget_spends_nothing():
    made = context(budget=Budget(frames=2))
    with pytest.raises(CapExceeded):
        made.send_frames([b"\x00" * 60] * 3)
    assert made.budget.frames_sent == 0


def test_nothing_sends_before_the_context_is_started():
    made = Context(interface="lo", budget=Budget())
    made.sender = lambda i, f: None
    with pytest.raises(NotStarted):
        made.send_frames(b"\x00" * 60)


# Registration.

def test_every_layer_two_check_is_registered_once():
    registry = register(Registry())
    identifiers = set(registry.checks)
    assert {"L2P%02d" % n for n in range(1, 14)} <= identifiers
    assert {"L2A%02d" % n for n in range(1, 10)} <= identifiers
    assert len(registry.checks) == 22


def test_passive_checks_run_before_active_ones():
    registry = register(Registry())
    order = registry.identifiers()
    last_passive = max(i for i, name in enumerate(order) if name.startswith("L2P"))
    first_active = min(i for i, name in enumerate(order) if name.startswith("L2A"))
    assert last_passive < first_active


def test_every_active_check_declares_send_capability():
    registry = register(Registry())
    for identifier, check in registry.checks.items():
        if identifier.startswith("L2A"):
            assert "raw_l2_send" in check.requires
        else:
            assert check.requires == frozenset({"raw_l2_capture"})
