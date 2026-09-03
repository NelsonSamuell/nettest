import pytest
import yaml

from l2check.l3 import targets as targets_module
from l2check.l3.targets import Targets, load
from l2check.session import ConfigError

FULL = {
    "targets": {
        "subnets": ["192.168.1.0/24"],
        "gateway": "192.168.1.1",
        "guest_subnet": "192.168.2.0/24",
    },
    "exclude": ["192.168.1.50"],
    "observers": {"internal": "192.168.1.20:9001", "external": "vps.example.net:9001"},
    "external": {"test_host": "vps.example.net"},
    "limits": {"rate_pps": 100, "packet_budget": 1000, "runtime_minutes": 5},
}


def write(tmp_path, document):
    path = tmp_path / "netcheck.yaml"
    path.write_text(yaml.safe_dump(document, sort_keys=False))
    return path


def test_a_full_file_loads(tmp_path):
    config = load(write(tmp_path, FULL), interface="wlan0")
    assert config.subnets == ["192.168.1.0/24"]
    assert config.gateway == "192.168.1.1"
    assert config.internal_observer == "192.168.1.20:9001"
    assert config.external_observer == "vps.example.net:9001"
    assert config.limits.rate_pps == 100
    assert config.limits.runtime_minutes == 5


def test_exclude_wins_over_targets(tmp_path):
    config = load(write(tmp_path, FULL), interface="wlan0")
    addresses = config.addresses()
    assert "192.168.1.50" not in addresses
    assert "192.168.1.51" in addresses
    assert len(addresses) == 253


def test_an_excluded_prefix_removes_every_address_in_it(tmp_path):
    document = dict(FULL)
    document["exclude"] = ["192.168.1.0/28"]
    config = load(write(tmp_path, document), interface="wlan0")
    addresses = config.addresses()
    assert "192.168.1.1" not in addresses
    assert "192.168.1.14" not in addresses
    assert "192.168.1.20" in addresses


def test_the_wan_address_is_excluded_unless_asked_for():
    config = Targets(subnets=["192.168.1.0/30"], wan_address="192.168.1.2")
    assert "192.168.1.2" not in config.addresses()
    assert "192.168.1.2" in config.addresses(include_wan=True)


def test_a_missing_file_is_not_an_error(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    config = load(interface="")
    assert isinstance(config, Targets)


def test_an_explicitly_named_missing_file_is_an_error(tmp_path):
    with pytest.raises(ConfigError):
        load(tmp_path / "absent.yaml")


def test_a_non_mapping_file_is_an_error(tmp_path):
    path = tmp_path / "netcheck.yaml"
    path.write_text("- a\n- list\n")
    with pytest.raises(ConfigError):
        load(path)


def test_a_bad_subnet_is_rejected(tmp_path):
    with pytest.raises(ConfigError) as excinfo:
        load(write(tmp_path, {"targets": {"subnets": ["not-a-subnet"]}}))
    assert "not-a-subnet" in str(excinfo.value)


def test_a_bad_exclude_entry_is_rejected(tmp_path):
    with pytest.raises(ConfigError):
        load(write(tmp_path, {"exclude": ["999.1.1.1"]}))


def test_an_observer_without_a_port_is_rejected(tmp_path):
    with pytest.raises(ConfigError):
        load(write(tmp_path, {"observers": {"internal": "192.168.1.20"}}))


def test_a_rate_above_the_hard_cap_is_rejected_from_the_file(tmp_path):
    with pytest.raises(ConfigError):
        load(write(tmp_path, {"limits": {"rate_pps": 5000}}))


def test_wide_prefixes_are_reported_with_a_count():
    config = Targets(subnets=["10.0.0.0/8", "192.168.1.0/24"])
    wide = config.wide_prefixes()
    assert len(wide) == 1
    assert wide[0][0] == "10.0.0.0/8"
    assert wide[0][1] > 16_000_000


def test_cgnat_is_detected_because_inbound_testing_cannot_work_behind_it():
    assert Targets(wan_address="100.64.1.1").is_cgnat()
    assert not Targets(wan_address="81.2.3.4").is_cgnat()
    assert not Targets().is_cgnat()


def test_defaults_come_from_the_routing_table():
    config = targets_module.fill_from_system(Targets(), interface="wlan0")
    assert config.subnets
    assert config.gateway
