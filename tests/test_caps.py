import ast
import pathlib

import pytest

from l2check import probes, session as session_module
from l2check.session import (
    ActiveSession,
    CapExceeded,
    ConfigError,
    SessionNotStarted,
    StateChanged,
    validate_max_macs,
    validate_rate,
)
from l2check.models import Capture
from l2check.posture import ProbeResult

PROBES_DIR = pathlib.Path("l2check/probes")
L3_PROBES_DIR = pathlib.Path("l2check/l3/probes")
ALL_PROBE_DIRS = (PROBES_DIR, L3_PROBES_DIR)

@pytest.fixture
def gated(tmp_path):
    """A started session with a stubbed sender, plus the list it sends into."""
    sent = []
    session = ActiveSession(interface="lo", sender=lambda iface, frame: sent.append(frame))
    session.start(["L2A01"])
    return session, sent


def test_the_send_rate_is_the_one_limit_a_flag_cannot_raise():
    assert validate_rate(200) == 200
    assert validate_rate(session_module.RATE_HARD_CAP) == session_module.RATE_HARD_CAP
    with pytest.raises(ConfigError) as excinfo:
        validate_rate(session_module.RATE_HARD_CAP + 1)
    assert "1000" in str(excinfo.value)
    with pytest.raises(ConfigError):
        validate_rate(0)


def test_max_macs_is_now_a_default_not_a_ceiling():
    """Caps became defaults, so a large value is allowed and only zero is not."""
    assert validate_max_macs(900) == 900
    with pytest.raises(ConfigError):
        validate_max_macs(0)


def test_the_rate_cap_is_enforced_in_code_not_in_help_text():
    source = pathlib.Path("l2check/session.py").read_text()
    assert "RATE_HARD_CAP = 1000" in source
    tree = ast.parse(pathlib.Path("l2check/cli.py").read_text())
    calls = [
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    ]
    assert "validate_rate" in calls, "the CLI must route --rate through validate_rate"


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
    assert session_module.FRAME_BUDGET == 600
    assert ActiveSession(interface="lo").frame_cap == 600


def test_the_runtime_cap_exists_and_stops_sending(gated):
    session, sent = gated
    assert session.runtime_cap == session_module.RUNTIME_SECONDS == 900
    clock = iter([0.0, 901.0, 901.0, 901.0])
    session.clock = lambda: next(clock)
    session.start(["L2A01"])
    with pytest.raises(CapExceeded):
        session.send(b"\x00" * 60)
    assert sent == []


def test_an_unexpected_link_change_is_a_hard_stop(gated):
    session, sent = gated
    session._baseline_link = "up"
    with pytest.raises(StateChanged):
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
    for directory in ALL_PROBE_DIRS:
      for path in directory.glob("*.py"):
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


def test_every_registered_check_is_a_known_identifier():
    """The registry may lag the ID list while a layer is being built, never lead it."""
    registered = set(probes.registry())
    assert registered <= set(session_module.ACTIVE_CHECKS)


def test_every_check_identifier_has_exactly_one_implementation():
    assert sorted(probes.registry()) == sorted(session_module.ACTIVE_CHECKS)


def test_the_two_layers_share_no_identifiers():
    assert not set(session_module.L2_ACTIVE_CHECKS) & set(session_module.L3_ACTIVE_CHECKS)


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
        raise StateChanged("interface lo went from up to down")

    probes.registry = lambda: {"L2A01": boom, "L2A04": boom}
    try:
        results = probes.run_selected(session, Capture(), out=messages.append)
    finally:
        del probes.registry
    assert results == []
    assert "went from up to down" in messages[0]


def test_the_gate_is_the_only_way_to_reach_the_wire():
    session = ActiveSession(interface="lo", sender=lambda iface, frame: None)
    assert not session.started
    with pytest.raises(SessionNotStarted):
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
    with pytest.raises(SessionNotStarted):
        segment.run_upnp(session, Capture())


# L2A10 reaches the network over TCP rather than a raw socket, so the caps have
# to cover that path too.

def test_a_connection_is_refused_before_the_gate_passes():
    tried = []
    session = ActiveSession(
        interface="wlan0",
        gateway="192.168.1.1",
        connector=lambda a, p, t: tried.append((a, p)) or True,
    )
    with pytest.raises(SessionNotStarted):
        session.connect("192.168.1.1", 80)
    assert tried == []


def test_connections_are_charged_against_the_frame_budget(gated):
    from l2check.session import CONNECT_FRAME_COST

    session, _ = gated
    session.connector = lambda a, p, t: True
    session.connect("192.168.1.1", 80)
    assert session.frames_sent == CONNECT_FRAME_COST
    session.connect("192.168.1.1", 443)
    assert session.frames_sent == 2 * CONNECT_FRAME_COST


def test_the_frame_cap_stops_connections_too(gated):
    session, _ = gated
    session.connector = lambda a, p, t: True
    session.frame_cap = 4
    session.connect("192.168.1.1", 80)
    with pytest.raises(CapExceeded):
        session.connect("192.168.1.1", 443)


def test_an_unexpected_link_change_stops_connections(gated):
    session, _ = gated
    session.connector = lambda a, p, t: True
    session._baseline_link = "up"
    with pytest.raises(StateChanged):
        session.connect("192.168.1.1", 80)


def test_gateway_probe_reports_only_its_own_spend(gated):
    from l2check.probes import segment

    session, _ = gated
    session.gateway = "192.168.1.1"
    session.connector = lambda a, p, t: p == 23
    session.frames_sent = 90
    result = segment.run_gateway_admin(session, Capture())
    assert result.state == "ABSENT"
    assert result.frames_sent == session.frames_sent - 90


def test_gateway_probe_stops_when_the_budget_runs_out(gated):
    from l2check.session import CONNECT_FRAME_COST
    from l2check.probes import segment

    session, _ = gated
    session.gateway = "192.168.1.1"
    session.connector = lambda a, p, t: True
    session.frame_cap = 2 * CONNECT_FRAME_COST
    result = segment.run_gateway_admin(session, Capture())
    assert session.frames_sent <= session.frame_cap
    assert result.frames_sent == 2 * CONNECT_FRAME_COST


def test_gateway_probe_refuses_without_a_gateway(gated):
    from l2check.probes import segment

    session, _ = gated
    session.gateway = None
    session.connector = lambda a, p, t: pytest.fail("must not connect")
    assert segment.run_gateway_admin(session, Capture()).state == "UNTESTED"


def test_no_probe_opens_its_own_socket():
    """Probes must reach the network through the session, never directly."""
    for directory in ALL_PROBE_DIRS:
      for path in directory.glob("*.py"):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                names = {alias.name.split(".")[0] for alias in node.names}
                assert "socket" not in names, "%s imports socket directly" % path
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr in {"connect", "connect_ex", "create_connection"}:
                    assert isinstance(node.func.value, ast.Name), str(path)
                    assert node.func.value.id == "session", (
                        "%s connects outside the session" % path
                    )


def test_a_named_interface_always_wins_over_autodetection():
    from l2check.cli import resolve_interface

    class Args:
        interface = "eth9"

    assert resolve_interface(Args()) == "eth9"


def test_autodetection_errors_clearly_when_nothing_is_usable(monkeypatch):
    from l2check import cli, doctor

    monkeypatch.setattr(doctor, "suggested_interface", lambda: "")

    class Args:
        interface = None

    with pytest.raises(ConfigError) as excinfo:
        cli.resolve_interface(Args())
    assert "doctor" in str(excinfo.value)


# Two budgets that decrement independently, and a rate limit that paces sends.

def test_the_two_budgets_are_independent(gated):
    from l2check.session import LAYER2, LAYER3

    session, _ = gated
    session.send([b"\x00" * 60] * 5, layer=LAYER2)
    session.send([b"\x00" * 60] * 40, layer=LAYER3)
    assert session.budget.frames_sent == 5
    assert session.budget.packets_sent == 40
    assert session.frames_remaining == session.budget.frames - 5
    assert session.packets_remaining == session.budget.packets - 40


def test_exhausting_one_budget_leaves_the_other_usable(gated):
    from l2check.session import LAYER2, LAYER3

    session, _ = gated
    session.budget.frames = 2
    session.send([b"\x00" * 60] * 2, layer=LAYER2)
    with pytest.raises(CapExceeded):
        session.send(b"\x00" * 60, layer=LAYER2)
    assert session.send([b"\x00" * 60] * 3, layer=LAYER3) == 3


def test_the_send_rate_paces_transmission(gated):
    session, _ = gated
    slept = []
    ticks = iter([0.0] * 40)
    session.sleeper = slept.append
    session.clock = lambda: next(ticks, 0.0)
    session.rate_pps = 10
    session.send(b"\x00" * 60)
    session.send(b"\x00" * 60)
    assert slept, "the second send should have been paced"
    assert abs(slept[-1] - 0.1) < 0.001


def test_a_session_started_with_an_illegal_rate_is_refused():
    session = ActiveSession(interface="lo", rate_pps=5000, sender=lambda i, f: None)
    with pytest.raises(ConfigError):
        session.start(["L2A01"])


def test_a_gateway_mac_change_aborts_the_run(gated, monkeypatch):
    session, sent = gated
    session.gateway = "192.168.1.1"
    session._baseline_gateway_mac = "aa:bb:cc:dd:ee:01"
    monkeypatch.setattr(
        type(session), "gateway_mac", lambda self: "de:ad:be:ef:00:01"
    )
    session.current_check = "L3A02"
    with pytest.raises(StateChanged) as excinfo:
        session.send(b"\x00" * 60)
    assert "changed MAC" in str(excinfo.value)
    assert session.aborted_during == "L3A02"
    assert sent == []


def test_the_runner_records_which_check_was_in_flight(gated):
    session, _ = gated
    session.tests = ["L2A01"]
    messages = []

    def boom(_session, _capture):
        raise StateChanged("gateway 192.168.1.1 stopped responding")

    probes.registry = lambda: {"L2A01": boom}
    try:
        probes.run_selected(session, Capture(), out=messages.append)
    finally:
        del probes.registry
    assert "L2A01" in messages[0]


def test_an_unimplemented_check_id_is_skipped_not_crashed(gated):
    session, _ = gated
    session.tests = ["L2A01", "L3A02"]
    calls = []
    probes.registry = lambda: {
        "L2A01": lambda s, c: calls.append("L2A01") or ProbeResult(
            "L2A01", "BPDU Guard", "ABSENT", "L2A01", "", 1
        )
    }
    try:
        results = probes.run_selected(session, Capture(), out=lambda m: None)
    finally:
        del probes.registry
    assert calls == ["L2A01"]
    assert len(results) == 1


def test_the_parser_builds_for_every_command():
    """A duplicate flag only shows up when the parser is actually constructed."""
    from l2check.cli import build_parser

    parser = build_parser()
    commands = parser._subparsers._group_actions[0].choices
    assert set(commands) == {"listen", "probe", "observe", "posture", "audit", "doctor"}
    for name, sub in commands.items():
        assert sub.format_help()


def test_every_command_parses_a_minimal_invocation():
    from l2check.cli import build_parser

    parser = build_parser()
    for argv in (
        ["listen"],
        ["listen", "--interface", "eth0", "--duration", "5"],
        ["probe", "--active", "--tests", "L3A02"],
        ["probe", "--active", "--all", "--wan"],
        ["observe", "--interface", "eth0", "--port", "9001", "--side", "external"],
        ["posture", "--from", "a.json", "--diff", "b.json"],
        ["audit", "--config", "router.cfg"],
        ["doctor"],
    ):
        assert parser.parse_args(argv)


def test_the_permission_error_names_the_command_that_fixes_it():
    """The message must be pasteable, and must name the command actually typed."""
    from l2check.cli import capability_hint

    class Args:
        interface = "wlan0"
        prog = "netcheck"

    text = capability_hint(Args())
    assert "sudo setcap cap_net_raw,cap_net_admin+eip" in text
    assert ".venv/bin/python3" in text or "python" in text
    assert "netcheck doctor" in text
    assert "l2check doctor" not in text

    class L2Args:
        interface = "eth0"
        prog = "l2check"

    assert "l2check doctor" in capability_hint(L2Args())


def test_no_user_facing_hint_hardcodes_the_wrong_command():
    source = pathlib.Path("l2check/cli.py").read_text()
    assert "'l2check doctor'" not in source
