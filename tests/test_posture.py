import pytest

from l2check import posture
from l2check.models import (
    ArpRecord,
    CleartextRecord,
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
    assert len(board.controls) == len(posture.PROFILES[posture.WIRED])
    assert all(control.state == UNTESTED for control in board.controls.values())
    assert board.counts()[UNTESTED] == len(board.controls)
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
    board, results = posture.from_capture(Capture(), profile=posture.WIRED)
    total = len(posture.PROFILES[posture.WIRED])
    assert board.counts() == {PRESENT: 0, ABSENT: 0, INDETERMINATE: 0, UNTESTED: total}
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


# The wireless profile and the checks that make a home network legible.

from l2check.models import PeerTrafficRecord, RouterAdvertRecord, UpnpRecord
from l2check.wireless import WirelessLink


def wifi(**kwargs):
    defaults = dict(
        interface="wlan0",
        ssid="Example Home",
        bssid="00:00:5e:00:53:01",
        security="WPA2",
        auth_suites=["PSK"],
        pairwise_ciphers=["CCMP"],
        group_cipher="CCMP",
        privacy=True,
    )
    defaults.update(kwargs)
    return WirelessLink(**defaults)


def test_the_two_profiles_hold_different_control_sets():
    wired = Posture.new(posture.WIRED)
    radio = Posture.new(posture.WIRELESS)
    assert posture.BPDU_GUARD in wired.controls
    assert posture.BPDU_GUARD not in radio.controls
    assert posture.LINK_ENCRYPTION in radio.controls
    assert posture.LINK_ENCRYPTION not in wired.controls
    # The common controls are in both, which is the point of the split.
    for name in posture.COMMON_CONTROLS:
        assert name in wired.controls and name in radio.controls


def test_an_unknown_profile_is_rejected():
    with pytest.raises(ValueError):
        Posture.new("carrier pigeon")


def test_profile_is_chosen_from_the_capture():
    assert posture.profile_for(Capture(interface="eth0")) == posture.WIRED
    assert posture.profile_for(Capture(interface="wlan0", wireless=wifi())) == posture.WIRELESS


def test_a_control_outside_the_profile_is_added_not_refused():
    board = Posture.new(posture.WIRELESS)
    board.set(posture.BPDU_GUARD, ABSENT, "L2A02 active probe")
    assert board.controls[posture.BPDU_GUARD].state == ABSENT
    with pytest.raises(KeyError):
        board.set("Imaginary Guard", ABSENT, "nowhere")


def test_name_resolution_queries_now_drive_a_control():
    capture = Capture(
        name_resolution=[
            NameResolutionRecord("mDNS", "00:11:22:33:44:01", "_airplay._tcp.local"),
            NameResolutionRecord("LLMNR", "00:11:22:33:44:02", "printer"),
        ]
    )
    board, _ = posture.from_capture(capture, profile=posture.WIRELESS)
    control = board.controls[posture.NAME_RESOLUTION]
    assert control.state == ABSENT
    assert "2 hosts" in control.detail


def test_cleartext_management_now_drives_a_control():
    capture = Capture(cleartext=[CleartextRecord("Telnet", "10.0.0.7", "10.0.0.1")])
    board, _ = posture.from_capture(capture, profile=posture.WIRELESS)
    assert board.controls[posture.MGMT_ENCRYPTION].state == ABSENT


def test_two_ra_sources_make_ra_guard_absent():
    capture = Capture(
        router_adverts=[
            RouterAdvertRecord("00:00:5e:00:53:01", "fe80::1", "2001:db8::/64", False, 1800),
            RouterAdvertRecord("de:ad:be:ef:00:01", "fe80::666", "2001:db8::/64", False, 1800),
        ]
    )
    board, results = posture.from_capture(capture, profile=posture.WIRELESS)
    assert board.controls[posture.RA_GUARD].state == ABSENT
    assert [f.severity for f in results if f.check == "L2P12"] == ["HIGH"]


def test_one_ra_source_stays_untested_and_refuses_to_prove_it():
    capture = Capture(
        router_adverts=[
            RouterAdvertRecord("00:00:5e:00:53:01", "fe80::1", "2001:db8::/64", False, 1800)
        ]
    )
    board, results = posture.from_capture(capture, profile=posture.WIRELESS)
    control = board.controls[posture.RA_GUARD]
    assert control.state == UNTESTED
    assert "does not" in control.detail
    assert [f.severity for f in results if f.check == "L2P12"] == ["MEDIUM"]


def test_peer_traffic_makes_client_isolation_absent():
    capture = Capture(
        peer_traffic=[PeerTrafficRecord("aa:aa:aa:aa:aa:aa", "ba:bb:cc:dd:ee:02", "IP")]
    )
    board, results = posture.from_capture(capture, profile=posture.WIRELESS)
    assert board.controls[posture.CLIENT_ISOLATION].state == ABSENT
    assert any(f.check == "L2P14" and f.severity == "HIGH" for f in results)


def test_upnp_makes_the_control_absent():
    capture = Capture(upnp=[UpnpRecord("00:00:5e:00:53:01", "192.168.1.1", "MiniUPnPd/1.9")])
    board, results = posture.from_capture(capture, profile=posture.WIRELESS)
    assert board.controls[posture.UPNP_DISABLED].state == ABSENT
    assert any("MiniUPnPd/1.9" in f.title for f in results)


def test_wpa2_ccmp_is_present_and_open_is_absent():
    good, _ = posture.from_capture(Capture(interface="wlan0", wireless=wifi()))
    assert good.controls[posture.LINK_ENCRYPTION].state == PRESENT

    link = wifi(security="Open", privacy=False, auth_suites=[], pairwise_ciphers=[], group_cipher="")
    bad, results = posture.from_capture(Capture(interface="wlan0", wireless=link))
    assert bad.controls[posture.LINK_ENCRYPTION].state == ABSENT
    assert any(f.check == "L2P15" and f.severity == "HIGH" for f in results)


def test_tkip_counts_as_broken_even_under_wpa2():
    link = wifi(pairwise_ciphers=["TKIP", "CCMP"])
    board, results = posture.from_capture(Capture(interface="wlan0", wireless=link))
    assert board.controls[posture.LINK_ENCRYPTION].state == ABSENT
    assert any("TKIP" in f.title for f in results)


def test_pmf_has_three_distinct_outcomes():
    absent, results = posture.from_capture(Capture(interface="wlan0", wireless=wifi()))
    assert absent.controls[posture.PMF].state == ABSENT
    assert any(f.check == "L2P16" and f.severity == "HIGH" for f in results)

    capable = wifi(pmf_capable=True)
    board, results = posture.from_capture(Capture(interface="wlan0", wireless=capable))
    assert board.controls[posture.PMF].state == INDETERMINATE
    assert any(f.check == "L2P16" and f.severity == "MEDIUM" for f in results)

    required = wifi(pmf_capable=True, pmf_required=True)
    board, results = posture.from_capture(Capture(interface="wlan0", wireless=required))
    assert board.controls[posture.PMF].state == PRESENT
    assert not [f for f in results if f.check == "L2P16"]


def test_wps_flips_its_control_both_ways():
    on, results = posture.from_capture(Capture(interface="wlan0", wireless=wifi(wps=True)))
    assert on.controls[posture.WPS_DISABLED].state == ABSENT
    assert any(f.check == "L2P17" for f in results)

    off, _ = posture.from_capture(Capture(interface="wlan0", wireless=wifi()))
    assert off.controls[posture.WPS_DISABLED].state == PRESENT


def test_a_wireless_capture_no_longer_reads_entirely_untested():
    """The whole point of the wireless profile: a home network says something."""
    capture = Capture(
        interface="wlan0",
        wireless=wifi(),
        name_resolution=[NameResolutionRecord("mDNS", "00:11:22:33:44:01", "_airplay._tcp.local")],
        upnp=[UpnpRecord("00:00:5e:00:53:01", "192.168.1.1", "MiniUPnPd/1.9")],
    )
    board, results = posture.from_capture(capture)
    counts = board.counts()
    assert counts[UNTESTED] < len(board.controls)
    assert counts[ABSENT] >= 3
    assert counts[PRESENT] >= 1
    assert results
