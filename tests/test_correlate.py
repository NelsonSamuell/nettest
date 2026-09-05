"""The correlation layer, on passive data only."""

from netcheck.correlate import (
    GUEST,
    LAN,
    REACHABLE,
    UNKNOWN,
    UNTESTED_CELL,
    Device,
    correlate,
    findings,
    is_locally_administered,
    reachability,
    segment_of,
    vendor_for,
)
from netcheck.config import Config
from netcheck.l2.parse import Arp, Discovery, ServiceAnnouncement
from netcheck.l3.parse import Host
from netcheck.models import ABSENT, PRESENT, Posture, Capture

HOST = "00:00:5e:00:53:0a"
RANDOM = "02:00:5e:00:00:01"


def checks(results):
    return {f.check for f in results}


def test_locally_administered_addresses_are_identified():
    assert is_locally_administered(RANDOM)
    assert not is_locally_administered(HOST)
    assert not is_locally_administered("nonsense")


def test_a_randomised_address_is_described_without_a_vendor_table():
    assert "randomised" in vendor_for(RANDOM)
    assert vendor_for(HOST) == ""


def test_segments_come_from_the_targets_file():
    config = Config(subnets=["10.0.0.0/24"], guest_subnet="10.1.0.0/24")
    assert segment_of("10.0.0.5", config) == LAN
    assert segment_of("10.1.0.5", config) == GUEST
    assert segment_of("8.8.8.8", config) == "external"
    assert segment_of("not-an-address", config) == UNKNOWN


def test_correlate_joins_addresses_services_and_protocols():
    capture = Capture(
        hosts=[Host(HOST, "10.0.0.5", 4, "arp"), Host(HOST, "fe80::1", 6, "ndp")],
        services=[ServiceAnnouncement("SSDP", HOST, "MediaServer")],
        discovery=[Discovery("LLDP", HOST, device_id="printer")],
    )
    capture.stamp("10.0.0.5@%s" % HOST, 1000.0)
    capture.stamp("10.0.0.5@%s" % HOST, 1500.0)

    devices = correlate(capture)
    assert len(devices) == 1
    device = devices[0]
    assert device.ipv4 == ["10.0.0.5"] and device.ipv6 == ["fe80::1"]
    assert "SSDP MediaServer" in device.services_announced
    assert "LLDP" in device.protocols_spoken
    assert device.first_seen and device.last_seen
    assert device.first_seen <= device.last_seen


def test_correlate_folds_in_arp_only_hosts():
    capture = Capture(arp=[Arp(HOST, "10.0.0.9", True)])
    assert correlate(capture)[0].ipv4 == ["10.0.0.9"]


def test_an_empty_capture_correlates_to_nothing():
    assert correlate(Capture()) == []


def test_a_device_on_two_segments_is_high():
    config = Config(subnets=["10.0.0.0/24"], guest_subnet="10.1.0.0/24")
    capture = Capture(hosts=[Host(HOST, "10.0.0.5", 4, "traffic"),
                             Host(HOST, "10.1.0.5", 4, "traffic")])
    devices = correlate(capture, config)
    assert "+" in devices[0].segment
    results = findings(devices, None, capture)
    assert "COR02" in checks(results)
    assert any(f.severity == "HIGH" for f in results if f.check == "COR02")


def test_one_mac_in_two_subnets_says_it_is_indeterminate_which():
    capture = Capture(hosts=[Host(HOST, "10.0.0.5", 4, "traffic"),
                             Host(HOST, "10.9.0.5", 4, "traffic")])
    results = findings(correlate(capture), None, capture)
    cor01 = [f for f in results if f.check == "COR01"][0]
    assert "cannot be told" in cor01.title


def test_a_control_present_at_l2_and_absent_at_l3_is_the_finding():
    posture = Posture.new()
    posture.set("Client isolation", PRESENT, "L2A08")
    posture.set("Guest segmentation", ABSENT, "L3A09")
    results = findings([], posture, None)
    assert "COR03" in checks(results)
    assert any("bypassed at layer 3" in f.title for f in results)


def test_agreeing_layers_produce_no_finding():
    posture = Posture.new()
    posture.set("Client isolation", PRESENT, "L2A08")
    posture.set("Guest segmentation", PRESENT, "L3A09")
    assert "COR03" not in checks(findings([], posture, None))


def test_the_matrix_from_a_passive_only_run_is_entirely_untested():
    """Every cell reads tested or untested, and nothing was sent to fill it."""
    matrix = reachability(Capture(), None, Config(subnets=["10.0.0.0/24"]))
    assert matrix
    assert set(matrix.values()) == {UNTESTED_CELL}


def test_the_matrix_records_a_tested_pair():
    class Result:
        segments = (GUEST, LAN)
        state = ABSENT

    matrix = reachability(Capture(), [Result()], Config())
    assert matrix[(GUEST, LAN)] == REACHABLE


def test_an_indeterminate_result_leaves_the_cell_untested():
    class Result:
        segments = (GUEST, LAN)
        state = "INDETERMINATE"

    assert reachability(Capture(), [Result()], Config())[(GUEST, LAN)] == UNTESTED_CELL


def test_devices_serialise_for_the_report():
    entry = Device(macs=[HOST], ipv4=["10.0.0.5"]).as_dict()
    assert entry["macs"] == [HOST]
    assert "services_announced" in entry and "segment" in entry
