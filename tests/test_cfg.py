"""Offline audit checks. They send nothing and need no privilege."""

from netcheck.cfg import firmware, host_posture, router_config
from netcheck.cfg.router_config import KEYVALUE, NVRAM, OPAQUE, PLAINTEXT, UCI

UCI_EXPORT = """
config system 'system'
\toption hostname 'OpenWrt'
\toption model 'Example Router X1'

config upnpd 'config'
\toption enabled '1'

config wifi-iface 'guest'
\toption isolate '0'

config firmware 'info'
\toption version '21.02.3'
"""

NVRAM_EXPORT = """nvram export
router_model=Example DD v24
telnetd_enable=1
remote_management=0
upnp_enable=1
firmware=v24-sp2
"""

PLAIN_EXPORT = """Device Model: Example Router X1
Firmware Version: 1.2.3
Remote Management: enabled
WPS: disabled
"""

def write(tmp_path, text, name="router.cfg"):
    path = tmp_path / name
    path.write_text(text)
    return path

def test_format_detection():
    assert router_config.detect_format(UCI_EXPORT) == UCI
    assert router_config.detect_format(NVRAM_EXPORT) == NVRAM
    assert router_config.detect_format("a=1\nb=2\nc=3\n") == KEYVALUE
    assert router_config.detect_format("prose with no settings\n") == PLAINTEXT
    assert router_config.detect_format("") == PLAINTEXT

def test_a_uci_export_is_parsed(tmp_path):
    config = router_config.parse(write(tmp_path, UCI_EXPORT))
    assert config.format == UCI and config.readable
    assert config.model == "Example Router X1"
    assert config.firmware == "21.02.3"
    by_key = {s.key: s for s in config.settings}
    assert by_key["upnpd.config.enabled"].enabled is True
    assert by_key["wifi-iface.guest.isolate"].enabled is False

def test_an_nvram_export_is_parsed(tmp_path):
    config = router_config.parse(write(tmp_path, NVRAM_EXPORT))
    assert config.format == NVRAM
    enabled = {s.key for s in config.settings if s.enabled}
    assert "telnetd_enable" in enabled and "upnp_enable" in enabled
    assert "remote_management" not in enabled

def test_the_plain_text_fallback_still_finds_settings(tmp_path):
    config = router_config.parse(write(tmp_path, PLAIN_EXPORT))
    assert config.format == PLAINTEXT
    assert config.model == "Example Router X1"
    assert any("WAN" in s.meaning for s in config.settings)

def test_an_encrypted_blob_is_reported_not_failed(tmp_path):
    path = tmp_path / "router.bin"
    path.write_bytes(bytes(range(256)) * 4)
    config = router_config.parse(path)
    assert config.format == OPAQUE and not config.readable
    assert "encrypted or packed" in config.note

def test_a_missing_or_empty_export_says_so(tmp_path):
    assert not router_config.parse(tmp_path / "absent.cfg").readable
    assert not router_config.parse(write(tmp_path, "", name="empty.cfg")).readable

def test_host_posture_reads_this_machine():
    posture = host_posture.read()
    assert isinstance(posture.listening, list)
    assert isinstance(posture.firewall_rules, int)
    assert set(posture.sysctls) == set(host_posture.SYSCTL_NAMES)

def test_accept_ra_is_recorded_but_never_flagged():
    """An IPv6 client is supposed to accept router advertisements."""
    entry = [row for row in host_posture.SYSCTLS if row[0].endswith("accept_ra")][0]
    assert entry[2] is None

def test_the_ipv6_source_route_default_is_acceptable():
    entry = [r for r in host_posture.SYSCTLS if r[0].endswith("ipv6.conf.all.accept_source_route")][0]
    assert "0" in entry[1]

def test_advisories_load_through_package_data():
    """It must resolve from an installed wheel and from the zipapp."""
    data = firmware.load()
    assert data["schema"] == 1
    assert isinstance(data["entries"], list)

def test_advisories_ship_empty_so_nothing_untrue_is_asserted():
    data = firmware.load()
    assert data["entries"] == []
    assert not firmware.knows("Example Router X1", data)
    assert firmware.match("Example Router X1", "1.0", data) == []

def test_advisories_match_on_substrings():
    data = {"entries": [{"model": "Router X1", "affected_firmware": ["1.2"],
                         "identifier": "EXAMPLE-1", "summary": "example"}]}
    assert firmware.match("Example Router X1 v2", "1.2.3", data)
    assert not firmware.match("Example Router X1 v2", "9.9.9", data)
    assert not firmware.match("Other Device", "1.2.3", data)
    assert firmware.knows("Example Router X1 v2", data)

def test_an_empty_affected_list_means_every_version():
    data = {"entries": [{"model": "X1", "identifier": "E", "summary": "s"}]}
    assert firmware.match("Router X1", "anything", data)

def test_an_unknown_model_is_not_a_clean_bill_of_health():
    from netcheck.l3 import findings
    from netcheck.models import Capture

    capture = Capture()
    capture.router_config = router_config.RouterConfig(model="Totally Unknown", firmware="1.0")
    results = [f for f in findings(capture) if f.check == "CFG03"]
    assert results and "not a clean bill of health" in results[0].title
