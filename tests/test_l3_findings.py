from l2check import posture
from l2check.l3 import findings as l3f
from l2check.l3.config_audit import HostPosture, RouterConfig, Setting
from l2check.models import (
    ArpRecord,
    Capture,
    CleartextRecord,
    DnsAnswerRecord,
    FragmentRecord,
    HopCountRecord,
    HostRecord,
    IcmpRecord,
    IPv6ModeRecord,
    OutboundRecord,
    ResolverRecord,
    ServiceAnnouncement,
)
from l2check.posture import ABSENT, PRESENT, UNTESTED


def checks(results):
    return {finding.check for finding in results}


def test_an_empty_capture_produces_no_layer_three_findings():
    assert l3f.findings_l3(Capture()) == []


def test_layer_three_controls_start_untested():
    board, _ = posture.from_capture(Capture(), profile=posture.WIRED)
    for name in posture.L3_CONTROLS:
        assert board.controls[name].state == UNTESTED


def test_a_private_answer_for_an_external_name_makes_rebinding_absent():
    capture = Capture(dns_answers=[DnsAnswerRecord("tracker.example.net", "192.168.1.1", True)])
    board, results = posture.from_capture(capture, profile=posture.WIRED)
    assert board.controls[posture.DNS_REBINDING].state == ABSENT
    assert "L3P03" in checks(results)


def test_redirect_handling_describes_this_machine_not_the_network():
    accepting = Capture(
        host_posture=HostPosture(sysctls={"net.ipv4.conf.all.accept_redirects": "1"})
    )
    board, _ = posture.from_capture(accepting, profile=posture.WIRED)
    control = board.controls[posture.ICMP_REDIRECTS]
    assert control.state == ABSENT
    assert "not the network" in control.detail

    ignoring = Capture(
        host_posture=HostPosture(
            sysctls={
                "net.ipv4.conf.all.accept_redirects": "0",
                "net.ipv6.conf.all.accept_redirects": "0",
            }
        )
    )
    board, _ = posture.from_capture(ignoring, profile=posture.WIRED)
    assert board.controls[posture.ICMP_REDIRECTS].state == PRESENT


def test_one_address_on_two_macs_is_reported():
    capture = Capture(
        hosts=[
            HostRecord("aa:bb:cc:dd:ee:01", "192.168.1.5", 4, "arp"),
            HostRecord("aa:bb:cc:dd:ee:02", "192.168.1.5", 4, "arp"),
        ]
    )
    results = l3f.findings_l3(capture)
    assert "L3P09" in checks(results)
    assert any("192.168.1.5" in f.title for f in results if f.check == "L3P09")


def test_l3p09_joins_arp_records_as_well_as_host_records():
    capture = Capture(
        hosts=[HostRecord("aa:bb:cc:dd:ee:01", "192.168.1.5", 4, "traffic")],
        arp=[ArpRecord("aa:bb:cc:dd:ee:99", "192.168.1.5", True)],
    )
    assert "L3P09" in checks(l3f.findings_l3(capture))


def test_one_mac_in_two_subnets_is_reported_once_by_the_correlation_layer():
    """COR01 owns this. L3P01 reporting it too would double-count."""
    capture = Capture(
        hosts=[
            HostRecord("aa:bb:cc:dd:ee:01", "192.168.1.5", 4, "traffic"),
            HostRecord("aa:bb:cc:dd:ee:01", "192.168.2.5", 4, "traffic"),
        ]
    )
    _, results = posture.from_capture(capture, profile=posture.WIRED)
    subnet_findings = [f for f in results if "subnet" in f.title]
    assert len(subnet_findings) == 1
    assert subnet_findings[0].check == "COR01"


def test_cleartext_is_not_double_counted_between_the_layers():
    """L2P11 already reports this. L3P02 must not report it again."""
    capture = Capture(cleartext=[CleartextRecord("Telnet", "192.168.1.9", "192.168.1.1")])
    _, results = posture.from_capture(capture, profile=posture.WIRED)
    telnet = [f for f in results if "Telnet" in f.title]
    assert len(telnet) == 1
    assert telnet[0].check == "L2P11"
    assert "L3P02" not in checks(results)


def test_two_resolvers_mean_one_bypasses_dhcp():
    capture = Capture(
        resolvers=[
            ResolverRecord("aa:bb:cc:dd:ee:01", "192.168.1.1", "Do53"),
            ResolverRecord("aa:bb:cc:dd:ee:02", "1.1.1.1", "Do53"),
        ]
    )
    assert any("bypasses" in f.title for f in l3f.findings_l3(capture))


def test_one_resolver_is_not_a_finding():
    capture = Capture(resolvers=[ResolverRecord("aa:bb:cc:dd:ee:01", "192.168.1.1", "Do53")])
    assert not [f for f in l3f.findings_l3(capture) if "bypasses" in f.title]


def test_a_global_ipv6_address_is_high_and_reads_correctly():
    capture = Capture(
        ipv6_modes=[IPv6ModeRecord("aa:bb:cc:dd:ee:01", "2400::1", "global", "slaac", False)]
    )
    finding = [f for f in l3f.findings_l3(capture) if f.check == "L3P04"][0]
    assert finding.severity == "HIGH"
    assert "1 host holds" in finding.title

    two = Capture(
        ipv6_modes=[
            IPv6ModeRecord("aa:bb:cc:dd:ee:01", "2400::1", "global", "slaac", False),
            IPv6ModeRecord("aa:bb:cc:dd:ee:02", "2400::2", "global", "slaac", False),
        ]
    )
    assert "2 hosts hold" in [f for f in l3f.findings_l3(two) if f.check == "L3P04"][0].title


def test_a_link_local_address_is_not_a_finding():
    capture = Capture(
        ipv6_modes=[IPv6ModeRecord("aa:bb:cc:dd:ee:01", "fe80::1", "link-local", "slaac", False)]
    )
    assert "L3P04" not in checks(l3f.findings_l3(capture))


def test_service_announcements_are_grouped_by_protocol():
    capture = Capture(
        services=[
            ServiceAnnouncement("mDNS", "aa:bb:cc:dd:ee:01", "_airplay._tcp.local"),
            ServiceAnnouncement("mDNS", "aa:bb:cc:dd:ee:02", "_ipp._tcp.local"),
            ServiceAnnouncement("SSDP", "aa:bb:cc:dd:ee:03", "MediaServer"),
        ]
    )
    results = [f for f in l3f.findings_l3(capture) if f.check == "L3P05"]
    assert len(results) == 2
    assert any("2 hosts" in f.title for f in results)


def test_redirects_fragments_and_hop_counts_each_report():
    capture = Capture(
        icmp=[IcmpRecord("redirect", "192.168.1.1", "gateway offered 192.168.1.66")],
        fragments=[FragmentRecord("192.168.1.10", 4)],
        hop_counts=[HopCountRecord("192.168.1.12", 61)],
        outbound=[OutboundRecord("192.168.1.8", "8.8.8.8", 443, "tcp")],
    )
    found = checks(l3f.findings_l3(capture))
    assert {"L3P06", "L3P08", "L3P10", "L3P07"} <= found


def test_an_enabled_router_setting_is_reported_and_a_disabled_one_is_not():
    config = RouterConfig(
        model="Example X1",
        settings=[
            Setting("upnpd.config.enabled", "1", "UPnP IGD"),
            Setting("remote_management", "0", "remote administration from the WAN"),
        ],
    )
    results = [f for f in l3f.findings_l3(Capture(router_config=config)) if f.check == "CFG01"]
    assert len(results) == 1
    assert "UPnP" in results[0].title


def test_an_unreadable_config_says_so_rather_than_reporting_nothing():
    config = RouterConfig(readable=False, note="the export is encrypted or packed")
    results = [f for f in l3f.findings_l3(Capture(router_config=config)) if f.check == "CFG01"]
    assert results and "encrypted" in results[0].title


def test_an_unknown_model_is_not_a_clean_bill_of_health():
    config = RouterConfig(model="Totally Unknown Router", firmware="1.0")
    results = [f for f in l3f.findings_l3(Capture(router_config=config)) if f.check == "CFG03"]
    assert results
    assert "not a clean bill of health" in results[0].title


def test_accept_ra_never_becomes_a_finding():
    capture = Capture(
        host_posture=HostPosture(
            firewall="nftables",
            sysctls={"net.ipv6.conf.all.accept_ra": "1"},
        )
    )
    assert "CFG02" not in checks(l3f.findings_l3(capture))


def test_findings_are_ordered_most_severe_first():
    capture = Capture(
        dns_answers=[DnsAnswerRecord("a.example.net", "192.168.1.1", True)],
        services=[ServiceAnnouncement("mDNS", "aa:bb:cc:dd:ee:01", "_ipp._tcp.local")],
        outbound=[OutboundRecord("192.168.1.8", "8.8.8.8", 443, "tcp")],
    )
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    severities = [order[f.severity] for f in l3f.findings_l3(capture)]
    assert severities == sorted(severities)
