from l2check import doctor
from l2check.doctor import Interface

ROUTE_TABLE = """Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT
eth0\t0000A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0
wlan0\t00000000\t0164A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0
wlan0\t0064A8C0\t00000000\t0001\t0\t0\t600\t00FFFFFF\t0\t0\t0
"""

NO_DEFAULT = """Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT
eth0\t0000A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0
"""


def test_default_interface_reads_the_default_route(tmp_path, monkeypatch):
    path = tmp_path / "route"
    path.write_text(ROUTE_TABLE)
    monkeypatch.setattr(doctor, "ROUTE", path)
    assert doctor.default_interface() == "wlan0"


def test_default_interface_when_there_is_no_default_route(tmp_path, monkeypatch):
    path = tmp_path / "route"
    path.write_text(NO_DEFAULT)
    monkeypatch.setattr(doctor, "ROUTE", path)
    assert doctor.default_interface() == ""


def test_default_interface_when_proc_is_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(doctor, "ROUTE", tmp_path / "absent")
    assert doctor.default_interface() == ""


def test_can_open_raw_socket_returns_a_boolean():
    assert isinstance(doctor.can_open_raw_socket(), bool)


def test_suggested_interface_skips_loopback_and_down_links(monkeypatch):
    monkeypatch.setattr(
        doctor,
        "interfaces",
        lambda: [
            Interface("lo", "loopback", "unknown", "127.0.0.1/8", False),
            Interface("eth0", "wired", "down", "", False),
            Interface("wlan0", "wireless", "up", "192.168.1.5/24", True),
        ],
    )
    assert doctor.suggested_interface() == "wlan0"


def test_suggested_interface_when_nothing_is_usable(monkeypatch):
    monkeypatch.setattr(
        doctor,
        "interfaces",
        lambda: [Interface("lo", "loopback", "unknown", "127.0.0.1/8", False)],
    )
    assert doctor.suggested_interface() == ""


def test_interfaces_lists_the_real_machine():
    found = doctor.interfaces()
    assert found
    assert all(item.kind in ("wired", "wireless", "loopback") for item in found)
    assert any(item.name == "lo" for item in found)


def test_report_names_every_check_and_ends_with_a_next_step():
    text = doctor.report()
    for expected in ("python", "scapy", "pyyaml", "iw", "frame access", "Interfaces"):
        assert expected in text
    assert "Next step:" in text


def test_report_tells_an_unprivileged_user_what_to_run(monkeypatch):
    monkeypatch.setattr(doctor, "can_open_raw_socket", lambda: False)
    text = doctor.report()
    assert "not permitted" in text
    assert "setup.sh" in text


def test_report_suggests_a_command_when_privileged(monkeypatch):
    monkeypatch.setattr(doctor, "can_open_raw_socket", lambda: True)
    monkeypatch.setattr(
        doctor,
        "interfaces",
        lambda: [Interface("wlan0", "wireless", "up", "192.168.1.5/24", True)],
    )
    text = doctor.report("netcheck")
    assert "netcheck listen --interface wlan0" in text


def test_the_report_names_the_command_you_actually_typed():
    """Running netcheck must not tell you to type l2check, or the reverse."""
    assert doctor.report("netcheck").startswith("netcheck environment check")
    assert doctor.report("l2check").startswith("l2check environment check")


def test_the_suggested_next_step_uses_the_same_command(monkeypatch):
    monkeypatch.setattr(doctor, "can_open_raw_socket", lambda: True)
    monkeypatch.setattr(
        doctor,
        "interfaces",
        lambda: [Interface("wlan0", "wireless", "up", "192.168.1.5/24", True)],
    )
    assert "netcheck listen --interface wlan0" in doctor.report("netcheck")
    assert "l2check listen --interface wlan0" in doctor.report("l2check")


def test_both_console_scripts_are_declared():
    """setup.sh links whatever bin/ holds; pyproject must declare both."""
    import pathlib

    text = pathlib.Path("pyproject.toml").read_text()
    assert 'netcheck = "l2check.cli:main"' in text
    assert 'l2check = "l2check.cli:main_l2check"' in text
    for name in ("netcheck", "l2check"):
        assert pathlib.Path("bin", name).is_file(), "bin/%s missing" % name
