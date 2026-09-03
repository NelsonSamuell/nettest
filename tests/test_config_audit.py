import json


from l2check.l3 import config_audit as audit
from l2check.l3.config_audit import (
    KEYVALUE,
    OPAQUE,
    PLAINTEXT,
    UCI,
    detect_format,
    knows_model,
    match_advisories,
    parse_router_config,
)

UCI_CONFIG = """
config system 'system'
\toption hostname 'OpenWrt'
\toption model 'TP-Link Archer C7 v2'

config upnpd 'config'
\toption enabled '1'

config wifi-iface 'guest'
\toption isolate '0'
\toption encryption 'psk2'

config firewall 'defaults'
\toption syn_flood '1'
"""

NVRAM_CONFIG = """nvram export
router_model=DD-WRT v24
telnetd_enable=1
remote_management=0
upnp_enable=1
firmware=v24-sp2
"""

PLAIN_CONFIG = """Device Model: Example Router X1
Firmware Version: 1.2.3
Remote Management: enabled
WPS: disabled
"""


def write(tmp_path, text, name="router.cfg"):
    path = tmp_path / name
    path.write_text(text)
    return path


def test_detect_format():
    assert detect_format(UCI_CONFIG) == UCI
    assert detect_format(NVRAM_CONFIG) == audit.NVRAM
    assert detect_format("a=1\nb=2\nc=3\n") == KEYVALUE
    assert detect_format("just some prose\nwith no settings\n") == PLAINTEXT
    assert detect_format("") == PLAINTEXT


def test_uci_config_is_parsed(tmp_path):
    config = parse_router_config(write(tmp_path, UCI_CONFIG))
    assert config.format == UCI
    assert config.readable
    assert config.model == "TP-Link Archer C7 v2"
    keys = {setting.key for setting in config.settings}
    assert any("upnp" in key or "enabled" in key for key in keys)


def test_uci_settings_carry_their_enabled_state(tmp_path):
    config = parse_router_config(write(tmp_path, UCI_CONFIG))
    by_key = {setting.key: setting for setting in config.settings}
    assert by_key["upnpd.config.enabled"].enabled is True
    assert by_key["wifi-iface.guest.isolate"].enabled is False


def test_nvram_config_is_parsed(tmp_path):
    config = parse_router_config(write(tmp_path, NVRAM_CONFIG))
    assert config.format == audit.NVRAM
    enabled = {s.key for s in config.settings if s.enabled}
    assert "telnetd_enable" in enabled
    assert "upnp_enable" in enabled
    assert "remote_management" not in enabled


def test_plain_text_fallback_still_finds_settings(tmp_path):
    config = parse_router_config(write(tmp_path, PLAIN_CONFIG))
    assert config.format == PLAINTEXT
    assert config.model == "Example Router X1"
    meanings = {setting.meaning for setting in config.settings}
    assert any("WAN" in meaning for meaning in meanings)


def test_an_encrypted_blob_is_reported_not_failed(tmp_path):
    path = tmp_path / "router.bin"
    path.write_bytes(bytes(range(256)) * 4)
    config = parse_router_config(path)
    assert config.format == OPAQUE
    assert not config.readable
    assert "encrypted or packed" in config.note


def test_an_empty_export_is_treated_as_opaque(tmp_path):
    config = parse_router_config(write(tmp_path, "", name="empty.cfg"))
    assert not config.readable


def test_a_missing_file_says_so(tmp_path):
    config = parse_router_config(tmp_path / "absent.cfg")
    assert not config.readable
    assert "not found" in config.note


def test_host_posture_reads_this_machine():
    posture = audit.read_host_posture()
    assert "net.ipv4.conf.all.accept_redirects" in posture.sysctls
    assert isinstance(posture.listening, list)
    assert isinstance(posture.firewall_rules, int)


def test_accept_ra_is_recorded_but_never_flagged():
    """An IPv6 client is supposed to accept RAs. Flagging it would be wrong."""
    entry = [row for row in audit.SYSCTLS if row[0].endswith("accept_ra")][0]
    assert entry[2] is None


def test_ipv6_source_route_default_of_zero_is_acceptable():
    entry = [row for row in audit.SYSCTLS if row[0].endswith("ipv6.conf.all.accept_source_route")][0]
    assert "0" in entry[1]


def test_advisories_ship_empty_so_nothing_untrue_is_asserted():
    data = audit.load_advisories()
    assert data["entries"] == []
    assert not knows_model("TP-Link Archer C7", data)
    assert match_advisories("TP-Link Archer C7", "1.0", data) == []


def test_advisories_match_on_model_and_firmware_substrings():
    data = {
        "entries": [
            {
                "model": "Archer C7",
                "affected_firmware": ["1.2"],
                "identifier": "EXAMPLE-1",
                "summary": "example",
                "severity": "HIGH",
            }
        ]
    }
    assert match_advisories("TP-Link Archer C7 v2", "1.2.3", data)
    assert not match_advisories("TP-Link Archer C7 v2", "9.9.9", data)
    assert not match_advisories("Some Other Router", "1.2.3", data)
    assert knows_model("TP-Link Archer C7 v2", data)


def test_an_empty_affected_list_means_every_version():
    data = {"entries": [{"model": "X1", "identifier": "E", "summary": "s"}]}
    assert match_advisories("Router X1", "anything", data)


def test_a_missing_advisory_file_yields_no_entries(tmp_path):
    assert audit.load_advisories(tmp_path / "absent.json")["entries"] == []


def test_the_shipped_advisory_file_is_valid_json():
    data = json.loads(audit.ADVISORIES.read_text())
    assert data["schema"] == 1
    assert isinstance(data["entries"], list)
