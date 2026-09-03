from l2check import posture
from l2check.l3 import correlate as cor
from l2check.l3.correlate import Device, correlate, correlation_findings, reachability
from l2check.l3.targets import Targets
from l2check.models import (
    ArpRecord,
    Capture,
    DhcpServerRecord,
    DiscoveryRecord,
    HostRecord,
    ServiceAnnouncement,
)
from l2check.posture import ABSENT, PRESENT, Posture


def checks(results):
    return {finding.check for finding in results}


def test_locally_administered_addresses_are_identified():
    assert cor.is_locally_administered("02:4c:32:00:00:01")
    assert not cor.is_locally_administered("00:00:5e:00:53:0a")
    assert not cor.is_locally_administered("nonsense")


def test_a_randomised_mac_is_described_without_a_vendor_table():
    assert "randomised" in cor.vendor_for("02:4c:32:00:00:01", {})
    assert cor.vendor_for("00:00:5e:00:53:0a", {}) == ""


def test_a_vendor_table_is_used_when_one_exists():
    assert cor.vendor_for("00:00:5e:00:53:0a", {"00:00:5e": "Acme"}) == "Acme"


def test_the_shipped_oui_table_is_empty_so_no_wrong_names_appear():
    assert cor.load_oui() == {}


def test_segments_come_from_the_targets_file():
    targets = Targets(subnets=["192.168.1.0/24"], guest_subnet="192.168.2.0/24")
    assert cor.segment_of("192.168.1.5", targets) == cor.LAN
    assert cor.segment_of("192.168.2.5", targets) == cor.GUEST
    assert cor.segment_of("8.8.8.8", targets) == cor.EXTERNAL
    assert cor.segment_of("not-an-address", targets) == cor.UNKNOWN


def test_correlate_joins_macs_addresses_and_services():
    capture = Capture(
        hosts=[
            HostRecord("aa:bb:cc:dd:ee:01", "192.168.1.5", 4, "arp"),
            HostRecord("aa:bb:cc:dd:ee:01", "fe80::1", 6, "ndp"),
        ],
        services=[ServiceAnnouncement("mDNS", "aa:bb:cc:dd:ee:01", "_ipp._tcp.local")],
        discovery=[DiscoveryRecord("LLDP", "aa:bb:cc:dd:ee:01", device_id="printer")],
    )
    capture.stamp("192.168.1.5@aa:bb:cc:dd:ee:01", 1000.0)
    capture.stamp("192.168.1.5@aa:bb:cc:dd:ee:01", 1500.0)

    devices = correlate(capture)
    assert len(devices) == 1
    device = devices[0]
    assert device.ipv4 == ["192.168.1.5"]
    assert device.ipv6 == ["fe80::1"]
    assert "mDNS _ipp._tcp.local" in device.services_announced
    assert "LLDP" in device.protocols_spoken
    assert device.first_seen == 1000.0
    assert device.last_seen == 1500.0


def test_correlate_folds_in_arp_only_hosts():
    capture = Capture(arp=[ArpRecord("aa:bb:cc:dd:ee:09", "192.168.1.9", True)])
    devices = correlate(capture)
    assert devices[0].ipv4 == ["192.168.1.9"]


def test_an_empty_capture_correlates_to_nothing():
    assert correlate(Capture()) == []


def test_a_device_on_two_segments_is_flagged_high():
    targets = Targets(subnets=["192.168.1.0/24"], guest_subnet="192.168.2.0/24")
    capture = Capture(
        hosts=[
            HostRecord("aa:bb:cc:dd:ee:01", "192.168.1.5", 4, "traffic"),
            HostRecord("aa:bb:cc:dd:ee:01", "192.168.2.5", 4, "traffic"),
        ]
    )
    devices = correlate(capture, targets)
    assert "+" in devices[0].segment
    results = correlation_findings(devices, None, capture)
    assert "COR02" in checks(results)
    assert any(f.severity == "HIGH" for f in results if f.check == "COR02")


def test_one_mac_in_two_subnets_without_a_targets_file():
    capture = Capture(
        hosts=[
            HostRecord("aa:bb:cc:dd:ee:01", "192.168.1.5", 4, "traffic"),
            HostRecord("aa:bb:cc:dd:ee:01", "192.168.2.5", 4, "traffic"),
        ]
    )
    results = correlation_findings(correlate(capture), None, capture)
    assert "COR01" in checks(results)


def test_a_conflict_is_attributed_to_arp_or_dhcp_churn():
    arp_case = Capture(
        arp=[
            ArpRecord("aa:bb:cc:dd:ee:01", "192.168.1.5", True),
            ArpRecord("aa:bb:cc:dd:ee:02", "192.168.1.5", True),
        ]
    )
    results = correlation_findings(correlate(arp_case), None, arp_case)
    cor03 = [f for f in results if f.check == "COR03"][0]
    assert "ARP anomaly" in cor03.title

    dhcp_case = Capture(
        hosts=[
            HostRecord("aa:bb:cc:dd:ee:01", "192.168.1.5", 4, "dhcp"),
            HostRecord("aa:bb:cc:dd:ee:02", "192.168.1.5", 4, "dhcp"),
        ],
        dhcp_servers=[DhcpServerRecord("00:00:5e:00:53:01", "192.168.1.5")],
    )
    results = correlation_findings(correlate(dhcp_case), None, dhcp_case)
    cor03 = [f for f in results if f.check == "COR03"][0]
    assert "DHCP churn" in cor03.title


def test_a_control_present_at_l2_and_absent_at_l3_is_the_finding():
    board = Posture.new(posture.WIRED)
    board.set(posture.CLIENT_ISOLATION, PRESENT, "L2A08 active probe")
    board.set(posture.GUEST_SEGMENTATION, ABSENT, "L3A09 active check")
    results = correlation_findings([], board, None)
    assert "COR04" in checks(results)
    assert any("bypassed at layer 3" in f.title for f in results)


def test_agreeing_layers_produce_no_cor04():
    board = Posture.new(posture.WIRED)
    board.set(posture.CLIENT_ISOLATION, PRESENT, "L2A08 active probe")
    board.set(posture.GUEST_SEGMENTATION, PRESENT, "L3A09 active check")
    assert "COR04" not in checks(correlation_findings([], board, None))


def test_the_matrix_starts_entirely_untested():
    matrix = reachability(Capture(), None, Targets(subnets=["192.168.1.0/24"]))
    assert matrix
    assert set(matrix.values()) == {cor.UNTESTED_CELL}


def test_the_matrix_records_a_tested_pair():
    class Result:
        segments = ("guest", "lan")
        state = "ABSENT"

    matrix = reachability(Capture(), [Result()], Targets(subnets=["192.168.1.0/24"]))
    assert matrix[("guest", "lan")] == cor.REACHABLE


def test_an_indeterminate_result_leaves_the_cell_untested():
    class Result:
        segments = ("guest", "lan")
        state = "INDETERMINATE"

    matrix = reachability(Capture(), [Result()], Targets())
    assert matrix[("guest", "lan")] == cor.UNTESTED_CELL


def test_a_present_result_marks_the_cell_filtered():
    class Result:
        segments = ("guest", "lan")
        state = "PRESENT"

    matrix = reachability(Capture(), [Result()], Targets())
    assert matrix[("guest", "lan")] == cor.FILTERED


def test_devices_serialise_for_the_json_report():
    device = Device(macs=["aa:bb:cc:dd:ee:01"], ipv4=["192.168.1.5"])
    as_dict = device.as_dict()
    assert as_dict["macs"] == ["aa:bb:cc:dd:ee:01"]
    assert "services_announced" in as_dict
