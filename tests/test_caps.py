import ast
import pathlib
from datetime import date

import pytest
import yaml

from l2check import authorisation, probes
from l2check.authorisation import (
    ActiveSession,
    AuthorisationError,
    CapExceeded,
    LinkStateChanged,
    NotAuthorised,
    load_authorisation,
    validate_max_macs,
)
from l2check.models import Capture
from l2check.posture import ProbeResult

PROBES_DIR = pathlib.Path("l2check/probes")

VALID = {
    "client": "Example Ltd",
    "engagement": "Internal network assessment",
    "authorised_by": "Jane Mwangi, Head of Infrastructure",
    "contact": "jane@example.co.ke",
    "issued": date(2026, 9, 1),
    "expires": date(2026, 9, 14),
    "segment": "Floor 3 user VLAN, patch panel port 3-14",
    "change_window": True,
}


@pytest.fixture
def gated(tmp_path):
    path = tmp_path / "authorisation.yaml"
    path.write_text(yaml.safe_dump(VALID, sort_keys=False))
    auth = load_authorisation(path, today=date(2026, 9, 7))
    sent = []
    session = ActiveSession(interface="lo", sender=lambda iface, frame: sent.append(frame))
    session.authorise(auth, ["L2A01"])
    return session, sent


def test_max_macs_above_the_cap_is_rejected():
    with pytest.raises(AuthorisationError) as excinfo:
        validate_max_macs(900)
    assert "500" in str(excinfo.value)


def test_max_macs_cap_is_enforced_in_code_not_in_help_text():
    source = pathlib.Path("l2check/authorisation.py").read_text()
    assert "MAX_MACS_CAP = 500" in source
    tree = ast.parse(pathlib.Path("l2check/cli.py").read_text())
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "validate_max_macs"
    ]
    assert calls, "the CLI must route --max-macs through validate_max_macs"


def test_the_total_frame_cap_is_enforced_across_probes(gated):
    session, sent = gated
    session.frame_cap = 5
    session.send([b"\x00" * 60] * 3)
    session.send([b"\x00" * 60] * 2)
    with pytest.raises(CapExceeded):
        session.send(b"\x00" * 60)
    assert session.frames_sent == 5
    assert len(sent) == 5


def test_the_frame_cap_rejects_a_batch_that_would_overshoot(gated):
    session, sent = gated
    session.frame_cap = 4
    with pytest.raises(CapExceeded):
        session.send([b"\x00" * 60] * 5)
    assert session.frames_sent == 0
    assert sent == []


def test_the_default_frame_cap_is_600():
    assert authorisation.TOTAL_FRAME_CAP == 600
    assert ActiveSession(interface="lo").frame_cap == 600


def test_the_runtime_cap_exists_and_stops_sending(gated):
    session, sent = gated
    assert session.runtime_cap == authorisation.TOTAL_RUNTIME_CAP == 600
    clock = iter([0.0, 601.0, 601.0])
    session.clock = lambda: next(clock)
    session.authorise(session.authorisation, ["L2A01"])
    with pytest.raises(CapExceeded):
        session.send(b"\x00" * 60)
    assert sent == []


def test_an_unexpected_link_change_is_a_hard_stop(gated):
    session, sent = gated
    session._baseline_link = "up"
    with pytest.raises(LinkStateChanged):
        session.send(b"\x00" * 60)
    assert sent == []


def test_a_probe_that_expects_a_link_change_may_still_send(gated):
    session, sent = gated
    session._baseline_link = "up"
    session.link_change_expected = True
    session.send(b"\x00" * 60)
    assert len(sent) == 1


def test_no_probe_module_sends_without_going_through_the_session():
    banned = {"sendp", "send", "sr", "sr1", "srp", "srp1", "sendpfast"}
    for path in PROBES_DIR.glob("*.py"):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                names = {alias.name.split(".")[0] for alias in node.names}
                assert not (names & banned), "%s imports a scapy sender" % path
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id not in banned, "%s calls %s" % (path, node.func.id)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr in banned:
                    assert isinstance(node.func.value, ast.Name), str(path)
                    assert node.func.value.id == "session", (
                        "%s sends outside the session" % path
                    )


def test_every_probe_identifier_has_exactly_one_implementation():
    assert sorted(probes.registry()) == sorted(authorisation.ACTIVE_CHECKS)


def test_the_runner_stops_at_a_cap_and_reports_it(gated):
    session, _ = gated
    session.tests = ["L2A01", "L2A02", "L2A04"]
    calls = []
    messages = []

    def first(_session, _capture):
        calls.append("L2A01")
        return ProbeResult("L2A01", "BPDU Guard", "ABSENT", "L2A01", "", 1)

    def second(_session, _capture):
        calls.append("L2A02")
        raise CapExceeded("total frame cap of 600 reached after 600 frames")

    def third(_session, _capture):
        calls.append("L2A04")
        return ProbeResult("L2A04", "DHCP Snooping", "PRESENT", "L2A04", "", 1)

    probes.registry = lambda: {"L2A01": first, "L2A02": second, "L2A04": third}
    try:
        results = probes.run_selected(session, Capture(), out=messages.append)
    finally:
        del probes.registry
    assert calls == ["L2A01", "L2A02"]
    assert len(results) == 1
    assert messages and "frame cap" in messages[0]


def test_the_runner_stops_on_an_unexpected_link_change(gated):
    session, _ = gated
    session.tests = ["L2A01", "L2A04"]
    messages = []

    def boom(_session, _capture):
        raise LinkStateChanged("interface lo went from up to down")

    probes.registry = lambda: {"L2A01": boom, "L2A04": boom}
    try:
        results = probes.run_selected(session, Capture(), out=messages.append)
    finally:
        del probes.registry
    assert results == []
    assert "went from up to down" in messages[0]


def test_the_gate_is_the_only_way_to_reach_the_wire():
    session = ActiveSession(interface="lo", sender=lambda iface, frame: None)
    assert not session.authorised
    with pytest.raises(NotAuthorised):
        session.send(b"\x00" * 60)


def test_port_security_never_asks_for_more_than_the_remaining_budget(gated):
    session, sent = gated
    session.max_macs = 50
    session.frame_cap = 10
    session.frames_sent = 7
    from l2check.probes import port_security

    port_security.GAP_SECONDS = 0
    port_security.SETTLE_SECONDS = 0
    result = port_security.run(session, Capture())
    assert result.frames_sent == 3
    assert session.frames_sent == 10


# The segment probes added for wireless and home networks.

def test_client_isolation_never_enumerates_a_large_network():
    from l2check.probes.segment import neighbour_addresses

    with pytest.raises(ValueError):
        neighbour_addresses("10.0.0.1/8", 25)
    assert len(neighbour_addresses("192.168.1.10/24", 25)) == 25


def test_client_isolation_skips_our_own_address():
    from l2check.probes.segment import neighbour_addresses

    assert "192.168.1.10" not in neighbour_addresses("192.168.1.10/24", 50)


def test_client_isolation_is_bounded_by_the_default_and_the_budget(gated, monkeypatch):
    from l2check.probes import segment

    session, sent = gated
    session.local_cidr = "192.168.1.10/24"
    monkeypatch.setattr(segment, "GAP_SECONDS", 0)
    monkeypatch.setattr(segment, "listen_after_send", lambda s, f, seconds, match: s.send(f) and [])

    result = segment.run_client_isolation(session, Capture())
    assert result.frames_sent == segment.DEFAULT_NEIGHBOURS == 25
    assert len(sent) == 25

    session.frames_sent = 0
    sent.clear()
    session.frame_cap = 4
    result = segment.run_client_isolation(session, Capture())
    assert result.frames_sent == 4
    assert len(sent) == 4


def test_client_isolation_refuses_without_an_address(gated):
    from l2check.probes import segment

    session, sent = gated
    session.local_cidr = None
    result = segment.run_client_isolation(session, Capture())
    assert result.state == "UNTESTED"
    assert sent == []


def test_upnp_probe_sends_exactly_one_frame(gated, monkeypatch):
    from l2check.probes import segment

    session, sent = gated
    session.local_cidr = "192.168.1.10/24"
    monkeypatch.setattr(
        segment, "listen_after_send", lambda s, f, seconds, match: s.send(f) and []
    )
    result = segment.run_upnp(session, Capture())
    assert result.frames_sent == 1
    assert len(sent) == 1


def test_upnp_probe_refuses_without_an_address(gated):
    from l2check.probes import segment

    session, sent = gated
    session.local_cidr = None
    assert segment.run_upnp(session, Capture()).state == "UNTESTED"
    assert sent == []


def test_the_new_probes_are_still_behind_the_gate():
    from l2check.probes import segment

    session = ActiveSession(interface="wlan0", sender=lambda i, f: None)
    session.local_cidr = "192.168.1.10/24"
    with pytest.raises(NotAuthorised):
        segment.run_upnp(session, Capture())
