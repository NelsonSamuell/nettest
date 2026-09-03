from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import ICMPv6ND_NA, ICMPv6ND_Redirect, IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.utils import PcapWriter, rdpcap

from l2check.l3 import parse as l3
from l2check.models import Capture
from l2check.parse import parse_frame


def roundtrip(tmp_path, packets):
    """Write frames to a pcap and read them back, as the listener would see them."""
    path = tmp_path / "capture.pcap"
    writer = PcapWriter(str(path), linktype=1, sync=True)
    for packet in packets:
        writer.write(packet)
    writer.close()
    return list(rdpcap(str(path)))


def one(tmp_path, packet):
    return roundtrip(tmp_path, [packet])[0]


def test_is_private_covers_the_ranges_that_matter():
    assert l3.is_private("192.168.1.1")
    assert l3.is_private("10.0.0.1")
    assert l3.is_private("169.254.1.1")
    assert l3.is_private("fd00::1")
    assert not l3.is_private("8.8.8.8")
    assert not l3.is_private("not-an-address")


def test_l3p01_binding_from_arp(tmp_path):
    packet = one(
        tmp_path,
        Ether(src="aa:bb:cc:dd:ee:01")
        / ARP(op=2, psrc="192.168.1.5", pdst="192.168.1.1", hwsrc="aa:bb:cc:dd:ee:01"),
    )
    record = l3.parse_host(packet)
    assert record.ip == "192.168.1.5"
    assert record.mac == "aa:bb:cc:dd:ee:01"
    assert record.source == "arp"


def test_l3p01_binding_from_plain_traffic(tmp_path):
    packet = one(tmp_path, Ether(src="aa:bb:cc:dd:ee:02") / IP(src="192.168.1.6") / TCP())
    assert l3.parse_host(packet).source == "traffic"


def test_l3p01_ignores_a_frame_with_no_address(tmp_path):
    assert l3.parse_host(one(tmp_path, Ether(src="aa:bb:cc:dd:ee:03"))) is None


def test_l3p03_records_which_resolver_a_client_uses(tmp_path):
    packet = one(
        tmp_path,
        Ether(src="aa:bb:cc:dd:ee:04")
        / IP(src="192.168.1.7", dst="1.1.1.1")
        / UDP(sport=5000, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="example.com")),
    )
    record = l3.parse_resolver(packet)
    assert record.resolver_ip == "1.1.1.1"
    assert record.transport == "Do53"


def test_l3p03_records_encrypted_dns(tmp_path):
    packet = one(tmp_path, Ether() / IP(src="192.168.1.7", dst="1.1.1.1") / TCP(dport=853))
    assert l3.parse_resolver(packet).transport == "DoT"


def test_l3p03_ignores_a_dns_response(tmp_path):
    packet = one(
        tmp_path,
        Ether() / IP() / UDP(sport=53, dport=5000) / DNS(qr=1, qd=DNSQR(qname="a.com")),
    )
    assert l3.parse_resolver(packet) is None


def test_l3p03_flags_an_external_name_answered_with_a_private_address(tmp_path):
    packet = one(
        tmp_path,
        Ether()
        / IP(src="192.168.1.1", dst="192.168.1.6")
        / UDP(sport=53, dport=5000)
        / DNS(
            qr=1,
            ancount=1,
            qd=DNSQR(qname="evil.example.net"),
            an=DNSRR(rrname="evil.example.net", type="A", rdata="192.168.1.99"),
        ),
    )
    record = l3.parse_dns_answer(packet)
    assert record.name == "evil.example.net"
    assert record.address == "192.168.1.99"
    assert record.private


def test_l3p03_ignores_a_normal_public_answer(tmp_path):
    packet = one(
        tmp_path,
        Ether()
        / IP()
        / UDP(sport=53, dport=5000)
        / DNS(qr=1, ancount=1, qd=DNSQR(qname="example.com"),
              an=DNSRR(rrname="example.com", type="A", rdata="93.184.216.34")),
    )
    assert l3.parse_dns_answer(packet) is None


def test_l3p03_ignores_mdns_local_names(tmp_path):
    packet = one(
        tmp_path,
        Ether()
        / IP()
        / UDP(sport=53, dport=5000)
        / DNS(qr=1, ancount=1, qd=DNSQR(qname="printer.local"),
              an=DNSRR(rrname="printer.local", type="A", rdata="192.168.1.30")),
    )
    assert l3.parse_dns_answer(packet) is None


def v6(address, mac="aa:bb:cc:dd:ee:08"):
    return Ether(src=mac) / IPv6(src=address, dst="ff02::1") / ICMPv6ND_NA()


def test_l3p04_classifies_scope_by_prefix(tmp_path):
    assert l3.parse_ipv6_mode(one(tmp_path, v6("fe80::1"))).scope == "link-local"
    assert l3.parse_ipv6_mode(one(tmp_path, v6("fd00::1"))).scope == "unique-local"
    assert l3.parse_ipv6_mode(one(tmp_path, v6("2400:cb00::1"))).scope == "global"
    # The documentation range is global for our purposes, not private.
    assert l3.parse_ipv6_mode(one(tmp_path, v6("2001:db8::1"))).scope == "global"


def test_l3p04_spots_a_slaac_address_derived_from_the_mac(tmp_path):
    derived = l3.parse_ipv6_mode(one(tmp_path, v6("2001:db8::a8bb:ccff:fedd:ee08")))
    assert derived.mode == "slaac"
    assert not derived.privacy
    random = l3.parse_ipv6_mode(one(tmp_path, v6("2001:db8::dead:beef:1:2")))
    assert random.privacy


def test_l3p05_records_ssdp_service_types(tmp_path):
    packet = one(
        tmp_path,
        Ether(src="aa:bb:cc:dd:ee:09")
        / IP(dst="239.255.255.250")
        / UDP(sport=1900, dport=1900)
        / b"NOTIFY * HTTP/1.1\r\nNT: urn:schemas-upnp-org:device:MediaServer:1\r\n\r\n",
    )
    record = l3.parse_service(packet)
    assert record.protocol == "SSDP"
    assert "MediaServer" in record.service_type


def test_l3p05_ignores_non_ssdp_on_the_ssdp_port(tmp_path):
    packet = one(tmp_path, Ether() / IP() / UDP(sport=1900, dport=1900) / b"\x00\x01")
    assert l3.parse_service(packet) is None


def test_l3p06_reports_a_redirect_with_the_offered_gateway(tmp_path):
    packet = one(tmp_path, Ether() / IP(src="192.168.1.1") / ICMP(type=5, gw="192.168.1.66"))
    record = l3.parse_icmp(packet)
    assert record.kind == "redirect"
    assert "192.168.1.66" in record.detail


def test_l3p06_covers_ipv6_redirects(tmp_path):
    packet = one(tmp_path, Ether() / IPv6(src="fe80::1") / ICMPv6ND_Redirect())
    assert l3.parse_icmp(packet).kind == "redirect"


def test_l3p06_ignores_an_echo(tmp_path):
    assert l3.parse_icmp(one(tmp_path, Ether() / IP() / ICMP(type=8))) is None


def test_l3p07_only_records_internal_to_external(tmp_path):
    outward = one(tmp_path, Ether() / IP(src="192.168.1.8", dst="140.82.121.4") / TCP(dport=443))
    record = l3.parse_outbound(outward, "192.168.1.0/24")
    assert record.destination_ip == "140.82.121.4"
    assert record.port == 443

    internal = one(tmp_path, Ether() / IP(src="192.168.1.8", dst="192.168.1.9") / TCP())
    assert l3.parse_outbound(internal, "192.168.1.0/24") is None

    inbound = one(tmp_path, Ether() / IP(src="8.8.8.8", dst="192.168.1.8") / TCP())
    assert l3.parse_outbound(inbound, "192.168.1.0/24") is None


def test_l3p07_ignores_a_source_outside_the_local_subnet(tmp_path):
    packet = one(tmp_path, Ether() / IP(src="10.9.9.9", dst="140.82.121.4") / TCP())
    assert l3.parse_outbound(packet, "192.168.1.0/24") is None


def test_l3p08_detects_both_fragment_shapes(tmp_path):
    more = one(tmp_path, Ether() / IP(src="192.168.1.10", flags=1) / UDP())
    assert l3.parse_fragment(more).family == 4
    later = one(tmp_path, Ether() / IP(src="192.168.1.10", frag=4) / UDP())
    assert l3.parse_fragment(later).family == 4
    whole = one(tmp_path, Ether() / IP(src="192.168.1.10") / UDP())
    assert l3.parse_fragment(whole) is None


def test_l3p10_only_flags_hop_limits_off_a_flat_segment(tmp_path):
    odd = one(tmp_path, Ether() / IP(src="192.168.1.12", ttl=61) / TCP())
    assert l3.parse_hop_count(odd).hop_limit == 61
    for normal in (64, 128, 255):
        packet = one(tmp_path, Ether() / IP(src="192.168.1.12", ttl=normal) / TCP())
        assert l3.parse_hop_count(packet) is None


def test_l3p10_ignores_external_sources(tmp_path):
    packet = one(tmp_path, Ether() / IP(src="8.8.8.8", ttl=57) / TCP())
    assert l3.parse_hop_count(packet) is None


def test_the_l3_parsers_run_inside_the_guarded_capture_loop(tmp_path):
    packets = roundtrip(
        tmp_path,
        [
            Ether(src="aa:bb:cc:dd:ee:01") / IP(src="192.168.1.5", dst="8.8.8.8") / TCP(dport=443),
            Ether(src="aa:bb:cc:dd:ee:02") / IP(src="192.168.1.1") / ICMP(type=5, gw="192.168.1.66"),
        ],
    )
    capture = Capture(interface="wlan0", local_cidr="192.168.1.0/24")
    for packet in packets:
        parse_frame(packet, capture)
    assert capture.packets_seen == 2
    assert capture.parse_errors == 0
    assert len(capture.hosts) == 2
    assert len(capture.outbound) == 1
    assert len(capture.icmp) == 1


def test_a_malformed_frame_still_does_not_abort_the_l3_parsers():
    class Unparseable:
        payload = None

        def __contains__(self, other):
            raise ValueError("malformed")

        def __getitem__(self, key):
            raise ValueError("malformed")

        def getlayer(self, cls):
            raise ValueError("malformed")

    capture = Capture()
    parse_frame(Unparseable(), capture)
    assert capture.frames_seen == 1
    assert capture.parse_errors > 0
    assert capture.hosts == []


def test_host_sightings_are_timestamped_outside_the_dedup_key(tmp_path):
    packet = one(tmp_path, Ether(src="aa:bb:cc:dd:ee:01") / IP(src="192.168.1.5") / TCP())
    capture = Capture()
    packet.time = 1000.0
    parse_frame(packet, capture)
    packet.time = 1250.0
    parse_frame(packet, capture)
    assert len(capture.hosts) == 1
    first, last = capture.seen_window("192.168.1.5@aa:bb:cc:dd:ee:01")
    assert first == 1000.0
    assert last == 1250.0
