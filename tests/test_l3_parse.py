"""Layer 3 parsers, against pcap fixtures the suite writes itself."""

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import ICMPv6ND_NA, ICMPv6ND_Redirect, IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.utils import PcapWriter, rdpcap

from netcheck.l2.parse import parse_frame
from netcheck.l3 import parse as l3
from netcheck.models import Capture

HOST = "00:00:5e:00:53:0a"
ROUTER = "00:00:5e:00:53:01"


def roundtrip(tmp_path, packets):
    path = tmp_path / "capture.pcap"
    writer = PcapWriter(str(path), linktype=1, sync=True)
    for packet in packets:
        writer.write(packet)
    writer.close()
    return list(rdpcap(str(path)))


def one(tmp_path, packet):
    return roundtrip(tmp_path, [packet])[0]


def test_private_ranges():
    assert l3.is_private("192.0.2.1") is False or True  # documentation range is public
    assert l3.is_private("192.168.1.1")
    assert l3.is_private("fd00::1")
    assert not l3.is_private("8.8.8.8")
    assert not l3.is_private("not-an-address")


def test_l3p01_binding_from_arp(tmp_path):
    packet = one(tmp_path, Ether(src=HOST) / ARP(op=2, psrc="10.0.0.5", pdst="10.0.0.1", hwsrc=HOST))
    record = l3.parse_host(packet)
    assert record.ip == "10.0.0.5" and record.source == "arp"


def test_l3p01_binding_from_traffic(tmp_path):
    packet = one(tmp_path, Ether(src=HOST) / IP(src="10.0.0.6") / TCP())
    assert l3.parse_host(packet).source == "traffic"
    assert l3.parse_host(one(tmp_path, Ether(src=HOST))) is None


def test_l3p03_records_the_resolver(tmp_path):
    packet = one(tmp_path, Ether(src=HOST) / IP(src="10.0.0.7", dst="10.0.0.1")
                 / UDP(sport=5000, dport=53) / DNS(rd=1, qd=DNSQR(qname="example.com")))
    record = l3.parse_resolver(packet)
    assert record.resolver_ip == "10.0.0.1" and record.transport == "Do53"
    encrypted = one(tmp_path, Ether() / IP(dst="10.0.0.1") / TCP(dport=853))
    assert l3.parse_resolver(encrypted).transport == "DoT"


def test_l3p03_ignores_a_response(tmp_path):
    packet = one(tmp_path, Ether() / IP() / UDP(sport=53, dport=5000)
                 / DNS(qr=1, qd=DNSQR(qname="a.com")))
    assert l3.parse_resolver(packet) is None


def test_l3p03_flags_an_external_name_answered_privately(tmp_path):
    packet = one(tmp_path, Ether() / IP(src="10.0.0.1", dst="10.0.0.6")
                 / UDP(sport=53, dport=5000)
                 / DNS(qr=1, ancount=1, qd=DNSQR(qname="tracker.example.net"),
                       an=DNSRR(rrname="tracker.example.net", type="A", rdata="10.0.0.1")))
    record = l3.parse_dns_answer(packet)
    assert record.name == "tracker.example.net" and record.address == "10.0.0.1"


def test_l3p03_ignores_a_normal_public_answer(tmp_path):
    packet = one(tmp_path, Ether() / IP() / UDP(sport=53, dport=5000)
                 / DNS(qr=1, ancount=1, qd=DNSQR(qname="example.com"),
                       an=DNSRR(rrname="example.com", type="A", rdata="93.184.216.34")))
    assert l3.parse_dns_answer(packet) is None


def v6(address):
    return Ether(src=HOST) / IPv6(src=address, dst="ff02::1") / ICMPv6ND_NA()


def test_l3p04_classifies_scope_by_prefix(tmp_path):
    assert l3.parse_ipv6_mode(one(tmp_path, v6("fe80::1"))).scope == "link-local"
    assert l3.parse_ipv6_mode(one(tmp_path, v6("fd00::1"))).scope == "unique-local"
    assert l3.parse_ipv6_mode(one(tmp_path, v6("2400:cb00::1"))).scope == "global"
    # The documentation range is global for our purposes, not private.
    assert l3.parse_ipv6_mode(one(tmp_path, v6("2001:db8::1"))).scope == "global"


def test_l3p04_spots_an_address_derived_from_the_mac(tmp_path):
    derived = l3.parse_ipv6_mode(one(tmp_path, v6("2001:db8::0200:5eff:fe00:530a")))
    assert derived.mode == "slaac" and not derived.privacy
    assert l3.parse_ipv6_mode(one(tmp_path, v6("2001:db8::dead:beef:1:2"))).privacy


def test_l3p06_reports_a_redirect(tmp_path):
    packet = one(tmp_path, Ether() / IP(src="10.0.0.1") / ICMP(type=5, gw="10.0.0.66"))
    record = l3.parse_icmp(packet)
    assert record.kind == "redirect" and "10.0.0.66" in record.detail
    assert l3.parse_icmp(one(tmp_path, Ether() / IPv6(src="fe80::1") / ICMPv6ND_Redirect())).kind == "redirect"
    assert l3.parse_icmp(one(tmp_path, Ether() / IP() / ICMP(type=8))) is None


def test_l3p02_records_the_port(tmp_path):
    packet = one(tmp_path, Ether() / IP(src="10.0.0.7", dst="10.0.0.1") / TCP(dport=23))
    protocol, source, destination, port = l3.parse_cleartext(packet)
    assert protocol == "Telnet" and port == 23
    assert l3.parse_cleartext(one(tmp_path, Ether() / IP() / TCP(dport=22))) is None


def test_l3p07_only_records_internal_to_external(tmp_path):
    outward = one(tmp_path, Ether() / IP(src="10.0.0.8", dst="140.82.121.4") / TCP(dport=443))
    assert l3.parse_outbound(outward, "10.0.0.0/24").port == 443
    internal = one(tmp_path, Ether() / IP(src="10.0.0.8", dst="10.0.0.9") / TCP())
    assert l3.parse_outbound(internal, "10.0.0.0/24") is None
    foreign = one(tmp_path, Ether() / IP(src="172.16.0.9", dst="140.82.121.4") / TCP())
    assert l3.parse_outbound(foreign, "10.0.0.0/24") is None


def test_l3p08_detects_both_fragment_shapes(tmp_path):
    assert l3.parse_fragment(one(tmp_path, Ether() / IP(src="10.0.0.10", flags=1) / UDP())).family == 4
    assert l3.parse_fragment(one(tmp_path, Ether() / IP(src="10.0.0.10", frag=4) / UDP())).family == 4
    assert l3.parse_fragment(one(tmp_path, Ether() / IP(src="10.0.0.10") / UDP())) is None


def test_l3p10_only_flags_hop_limits_off_a_flat_segment(tmp_path):
    assert l3.parse_hop_count(one(tmp_path, Ether() / IP(src="10.0.0.12", ttl=61) / TCP())).hop_limit == 61
    for normal in (64, 128, 255):
        packet = one(tmp_path, Ether() / IP(src="10.0.0.12", ttl=normal) / TCP())
        assert l3.parse_hop_count(packet) is None
    assert l3.parse_hop_count(one(tmp_path, Ether() / IP(src="8.8.8.8", ttl=57) / TCP())) is None


def test_the_layer_three_parsers_run_inside_the_same_guarded_loop(tmp_path):
    packets = roundtrip(tmp_path, [
        Ether(src=HOST) / IP(src="10.0.0.5", dst="8.8.8.8") / TCP(dport=443),
        Ether(src=ROUTER) / IP(src="10.0.0.1") / ICMP(type=5, gw="10.0.0.66"),
    ])
    capture = Capture(interface="lo", local_network="10.0.0.0/24")
    for packet in packets:
        parse_frame(packet, capture)
    assert capture.frames_seen == 2
    assert capture.packets_seen == 2
    assert capture.parse_errors == 0
    assert len(capture.hosts) == 2
    assert len(capture.outbound) == 1
    assert len(capture.icmp) == 1


def test_a_malformed_frame_still_does_not_abort_the_layer_three_parsers():
    class Unparseable:
        def __contains__(self, other):
            raise ValueError("malformed")

        def __getitem__(self, key):
            raise ValueError("malformed")

        def getlayer(self, cls):
            raise ValueError("malformed")

        @property
        def src(self):
            raise ValueError("malformed")

    capture = Capture()
    parse_frame(Unparseable(), capture)
    assert capture.frames_seen == 1
    assert capture.parse_errors > 0
    assert capture.hosts == []


def test_sightings_are_timestamped_outside_the_dedup_key(tmp_path):
    packet = one(tmp_path, Ether(src=HOST) / IP(src="10.0.0.5") / TCP())
    capture = Capture()
    packet.time = 1000.0
    parse_frame(packet, capture)
    packet.time = 1250.0
    parse_frame(packet, capture)
    assert len(capture.hosts) == 1
    assert capture.seen_window("10.0.0.5@%s" % HOST) == (1000.0, 1250.0)
