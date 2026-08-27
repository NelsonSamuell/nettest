import pytest

from l2check import posture
from l2check.models import (
    ArpRecord,
    BpduRecord,
    Capture,
    DhcpServerRecord,
    DiscoveryRecord,
    DtpRecord,
    FhrpRecord,
    NameResolutionRecord,
    TaggedFrameRecord,
)
from l2check.posture import (
    ABSENT,
    INDETERMINATE,
    PRESENT,
    UNTESTED,
    Posture,
    ProbeResult,
)


def test_new_posture_is_entirely_untested():
    board = Posture.new()
    assert len(board.controls) == 10
    assert all(control.state == UNTESTED for control in board.controls.values())
    assert board.counts()[UNTESTED] == 10
    assert board.exit_code() == 0


def test_untested_is_not_absent():
    board = Posture.new()
    assert board.counts()[ABSENT] == 0
    assert board.controls[posture.PORT_SECURITY].state != ABSENT


def test_an_unselected_probe_leaves_the_control_untested():
    board, _ = posture.from_capture(Capture())
    assert board.controls[posture.PORT_SECURITY].state == UNTESTED
    assert board.controls[posture.PORT_SECURITY].basis == "probe not selected"


def test_an_empty_capture_makes_nothing_absent():
    board, results = posture.from_capture(Capture())
    assert board.counts() == {PRESENT: 0, ABSENT: 0, INDETERMINATE: 0, UNTESTED: 10}
    assert results == []


def test_root_guard_stays_untested_and_says_why():
    board, _ = posture.from_capture(
        Capture(bpdu=[BpduRecord("00:11:22:33:44:55", 32768, "00:11:22:33:44:55", 4, 32768, "00:11:22:33:44:55")])
    )
    assert board.controls[posture.ROOT_GUARD].state == UNTESTED
    assert "root role" in board.controls[posture.ROOT_GUARD].basis


def test_observed_bpdus_make_bpdu_guard_absent():
    capture = Capture(
        bpdu=[BpduRecord("00:11:22:33:44:55", 32769, "00:11:22:33:44:55", 4, 32769, "00:11:22:33:44:55")]
    )
    board, results = posture.from_capture(capture)
    assert board.controls[posture.BPDU_GUARD].state == ABSENT
    assert board.controls[posture.BPDU_GUARD].basis == "L2P03 passive"
    assert board.exit_code() == 1
    assert any(f.check == "L2P03" and "default priority" in f.title for f in results)


def test_observed_dtp_makes_trunking_absent():
    board, results = posture.from_capture(
        Capture(dtp=[DtpRecord("00:11:22:33:44:55", "dynamic desirable")])
    )
    assert board.controls[posture.DTP_DISABLED].state == ABSENT
    assert [f.severity for f in results if f.check == "L2P02"] == ["HIGH"]


def test_native_vlan_present_and_absent():
    absent, _ = posture.from_capture(
        Capture(discovery=[DiscoveryRecord("CDP", "00:11:22:33:44:55", native_vlan=1)])
    )
    assert absent.controls[posture.NATIVE_VLAN].state == ABSENT
    present, _ = posture.from_capture(
        Capture(discovery=[DiscoveryRecord("CDP", "00:11:22:33:44:55", native_vlan=999)])
    )
    assert present.controls[posture.NATIVE_VLAN].state == PRESENT


def test_two_dhcp_servers_make_snooping_absent_but_one_does_not():
    one = Capture(dhcp_servers=[DhcpServerRecord("00:11:22:33:44:55", "10.3.0.1")])
    board, _ = posture.from_capture(one)
    assert board.controls[posture.DHCP_SNOOPING].state == UNTESTED

    two = Capture(
        dhcp_servers=[
            DhcpServerRecord("00:11:22:33:44:55", "10.3.0.1"),
            DhcpServerRecord("00:11:22:33:44:99", "10.3.0.9"),
        ]
    )
    board, results = posture.from_capture(two)
    assert board.controls[posture.DHCP_SNOOPING].state == ABSENT
    assert any(f.check == "L2P07" for f in results)


def test_conflicting_arp_claims_are_indeterminate_not_absent():
    capture = Capture(
        arp=[
            ArpRecord("00:11:22:33:44:55", "10.3.0.1", True),
            ArpRecord("00:11:22:33:44:99", "10.3.0.1", True),
        ]
    )
    board, results = posture.from_capture(capture)
    assert board.controls[posture.ARP_INSPECTION].state == INDETERMINATE
    assert "failover" in board.controls[posture.ARP_INSPECTION].detail
    assert any(f.check == "L2P08" for f in results)


def test_tagged_frames_make_pruning_absent():
    board, _ = posture.from_capture(
        Capture(tagged=[TaggedFrameRecord("00:11:22:33:44:55", 20)])
    )
    assert board.controls[posture.VLAN_PRUNING].state == ABSENT


def test_unauthenticated_fhrp_is_absent_and_no_value_is_stored():
    record = FhrpRecord("HSRP", "00:00:0c:07:ac:01", 1, 100, "10.3.0.1", False)
    board, results = posture.from_capture(Capture(fhrp=[record]))
    assert board.controls[posture.FHRP_AUTH].state == ABSENT
    finding = [f for f in results if f.check == "L2P10"][0]
    assert "10.3.0.1" in finding.title
    assert not hasattr(record, "auth")


def test_name_resolution_finding_counts_distinct_hosts():
    capture = Capture(
        name_resolution=[
            NameResolutionRecord("LLMNR", "00:11:22:33:44:01", "fileserver"),
            NameResolutionRecord("LLMNR", "00:11:22:33:44:01", "printer"),
            NameResolutionRecord("LLMNR", "00:11:22:33:44:02", "fileserver"),
        ]
    )
    _, results = posture.from_capture(capture)
    finding = [f for f in results if f.check == "L2P09"][0]
    assert "from 2 hosts" in finding.title


def test_findings_are_ordered_most_severe_first():
    capture = Capture(
        discovery=[DiscoveryRecord("CDP", "00:11:22:33:44:55", device_id="sw", native_vlan=1)],
        dtp=[DtpRecord("00:11:22:33:44:55", "dynamic desirable")],
    )
    _, results = posture.from_capture(capture)
    severities = [f.severity for f in results]
    assert severities == sorted(severities, key=lambda s: {"HIGH": 0, "MEDIUM": 1}[s])


def test_probe_results_overwrite_untested():
    board = Posture.new()
    board.apply(
        ProbeResult("L2A04", posture.DHCP_SNOOPING, PRESENT, "L2A04 active probe", "one offer", 1)
    )
    control = board.controls[posture.DHCP_SNOOPING]
    assert control.state == PRESENT
    assert control.basis == "L2A04 active probe"


def test_unknown_control_and_state_are_rejected():
    board = Posture.new()
    with pytest.raises(KeyError):
        board.set("Nonexistent Guard", PRESENT, "test")
    with pytest.raises(ValueError):
        board.set(posture.BPDU_GUARD, "MAYBE", "test")


def test_posture_survives_a_json_roundtrip():
    board, _ = posture.from_capture(
        Capture(dtp=[DtpRecord("00:11:22:33:44:55", "dynamic desirable")])
    )
    restored = Posture.from_dict(board.to_dict())
    assert restored.counts() == board.counts()
    assert restored.controls[posture.DTP_DISABLED].state == ABSENT
    assert restored.controls[posture.PORT_SECURITY].state == UNTESTED
