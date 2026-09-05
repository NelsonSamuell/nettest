"""Layer 2 parsers, against pcap fixtures the suite writes itself."""

from scapy.contrib.cdp import (
    CDPAddrRecordIPv4,
    CDPMsgDeviceID,
    CDPMsgMgmtAddr,
    CDPMsgNativeVLAN,
    CDPMsgPlatform,
    CDPMsgPortID,
    CDPMsgSoftwareVersion,
    CDPMsgVTPMgmtDomain,
    CDPv2_HDR,
)
from scapy.contrib.vtp import VTP
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.hsrp import HSRP
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import ICMPv6ND_RA, ICMPv6NDOptPrefixInfo, IPv6
from scapy.layers.l2 import ARP, LLC, SNAP, Dot1Q, Dot3, Ether
from scapy.layers.vrrp import VRRP
from scapy.utils import PcapWriter, rdpcap

from netcheck.l2 import frames, parse
from netcheck.models import Capture

SWITCH = "00:00:5e:00:53:01"
HOST = "00:00:5e:00:53:0a"
PROBE = frames.probe_mac(1)


def roundtrip(tmp_path, packets):
    path = tmp_path / "capture.pcap"
    writer = PcapWriter(str(path), linktype=1, sync=True)
    for packet in packets:
        writer.write(packet)
    writer.close()
    return list(rdpcap(str(path)))


def one(tmp_path, packet):
    return roundtrip(tmp_path, [packet])[0]


def cdp_frame():
    return (
        Dot3(dst="01:00:0c:cc:cc:cc", src=SWITCH)
        / LLC(dsap=0xAA, ssap=0xAA, ctrl=3)
        / SNAP(OUI=0x00000C, code=0x2000)
        / CDPv2_HDR(msg=[
            CDPMsgDeviceID(val=b"switch-1"),
            CDPMsgPortID(iface=b"GigabitEthernet0/14"),
            CDPMsgPlatform(val=b"example WS-2960X"),
            CDPMsgSoftwareVersion(val=b"OS 15.2"),
            CDPMsgNativeVLAN(vlan=1),
            CDPMsgVTPMgmtDomain(val=b"CORP"),
            CDPMsgMgmtAddr(addr=[CDPAddrRecordIPv4(addr="192.0.2.2")]),
        ])
    )


def test_l2p01_via_cdp(tmp_path):
    record = parse.parse_cdp(one(tmp_path, cdp_frame()))
    assert record.device_id == "switch-1"
    assert record.platform == "example WS-2960X"
    assert record.native_vlan == 1
    assert record.vtp_domain == "CORP"
    assert record.management_address == "192.0.2.2"


def test_l2p01_via_lldp(tmp_path):
    raw = frames.lldp_probe(SWITCH, "switch-1", "Gi0/14", ttl=120)
    record = parse.parse_lldp(one(tmp_path, Ether(raw)))
    assert record.protocol == "LLDP"
    assert record.device_id == "switch-1"
    assert record.port_id == "Gi0/14"


def test_l2p01_ignores_unrelated_frames(tmp_path):
    packet = one(tmp_path, Ether() / IP() / UDP())
    assert parse.parse_cdp(packet) is None
    assert parse.parse_lldp(packet) is None


def test_l2p02_records_the_advertised_mode(tmp_path):
    record = parse.parse_dtp(one(tmp_path, Dot3(frames.dtp_desirable(SWITCH, "CORP"))))
    assert record.mode == "dynamic desirable"
    assert record.domain == "CORP"


def test_l2p03_records_the_root_priority(tmp_path):
    record = parse.parse_bpdu(one(tmp_path, Dot3(frames.bpdu_losing_config(32768, SWITCH))))
    assert record.root_priority == 36864
    assert record.root_path_cost == 0
    assert not record.root_priority_is_default


def test_l2p03_flags_a_default_priority(tmp_path):
    from scapy.layers.l2 import STP

    packet = (
        Dot3(dst="01:80:c2:00:00:00", src=SWITCH)
        / LLC(dsap=0x42, ssap=0x42, ctrl=3)
        / STP(rootid=32769, rootmac=SWITCH, bridgeid=32769)
    )
    assert parse.parse_bpdu(one(tmp_path, packet)).root_priority_is_default


def test_l2p04_vtp(tmp_path):
    packet = (
        Dot3(dst="01:00:0c:cc:cc:cc", src=SWITCH)
        / LLC(dsap=0xAA, ssap=0xAA, ctrl=3)
        / SNAP(OUI=0x00000C, code=0x2003)
        / VTP(domname="CORP", rev=42)
    )
    record = parse.parse_vtp(one(tmp_path, packet))
    assert record.domain == "CORP" and record.revision == 42


def test_l2p06_tagged_frames(tmp_path):
    records = parse.parse_tagged(one(tmp_path, Ether() / Dot1Q(vlan=1) / Dot1Q(vlan=20) / IP()))
    assert [r.vlan for r in records] == [1, 20]
    assert parse.parse_tagged(one(tmp_path, Ether() / IP())) == []


def dhcp_offer(mac, ip):
    return (
        Ether(src=mac, dst=PROBE)
        / IP(src=ip, dst="255.255.255.255")
        / UDP(sport=67, dport=68)
        / BOOTP(op=2, yiaddr="192.0.2.55")
        / DHCP(options=[("message-type", "offer"), ("server_id", ip), "end"])
    )


def test_l2p07_dhcp_offer(tmp_path):
    record = parse.parse_dhcp_server(one(tmp_path, dhcp_offer(SWITCH, "192.0.2.1")))
    assert record.server_mac == SWITCH and record.server_ip == "192.0.2.1"


def test_l2p07_ignores_a_client_discover(tmp_path):
    packet = one(tmp_path, Ether(frames.dhcp_discover(PROBE, 1)))
    assert parse.parse_dhcp_server(packet) is None


def test_l2p08_gratuitous_arp(tmp_path):
    record = parse.parse_arp(one(tmp_path, Ether(frames.gratuitous_arp(HOST, "192.0.2.1"))))
    assert record.gratuitous and record.claimed_ip == "192.0.2.1"
    ordinary = one(tmp_path, Ether() / ARP(op=1, psrc="192.0.2.7", pdst="192.0.2.1"))
    assert not parse.parse_arp(ordinary).gratuitous


def llmnr(name, mac):
    return (
        Ether(src=mac, dst="01:00:5e:00:00:fc")
        / IP(src="192.0.2.7", dst="224.0.0.252")
        / UDP(sport=54321, dport=5355)
        / DNS(rd=0, qd=DNSQR(qname=name))
    )


def test_l2p09_name_queries(tmp_path):
    record = parse.parse_name_query(one(tmp_path, llmnr("fileserver", HOST)))
    assert record.protocol == "LLMNR" and record.query_name == "fileserver"
    assert parse.parse_name_query(one(tmp_path, llmnr("wpad", HOST))).protocol == "WPAD"


def test_l2p09_ignores_responses(tmp_path):
    packet = (
        Ether() / IP(dst="224.0.0.252") / UDP(sport=5355, dport=5355)
        / DNS(qr=1, qd=DNSQR(qname="fileserver"))
    )
    assert parse.parse_name_query(one(tmp_path, packet)) is None


def test_l2p10_hsrp_records_only_whether_authentication_is_present(tmp_path):
    plain = (
        Ether(src=SWITCH) / IP(src="192.0.2.2", dst="224.0.0.2")
        / UDP(sport=1985, dport=1985) / HSRP(group=1, priority=100, virtualIP="192.0.2.1")
    )
    record = parse.parse_fhrp(one(tmp_path, plain))
    assert record.protocol == "HSRP" and record.group == 1
    assert not record.authenticated

    secret = (
        Ether() / IP(src="192.0.2.2", dst="224.0.0.2")
        / UDP(sport=1985, dport=1985) / HSRP(group=1, auth=b"s3cret\x00\x00")
    )
    withauth = parse.parse_fhrp(one(tmp_path, secret))
    assert withauth.authenticated
    assert "s3cret" not in repr(withauth)


def test_l2p10_vrrp(tmp_path):
    packet = (
        Ether() / IP(src="192.0.2.2", dst="224.0.0.18", proto=112)
        / VRRP(vrid=5, priority=120, addrlist=["192.0.2.1"], authtype=0)
    )
    record = parse.parse_fhrp(one(tmp_path, packet))
    assert record.protocol == "VRRP" and record.group == 5 and not record.authenticated


def test_l2p11_cleartext(tmp_path):
    packet = one(tmp_path, Ether() / IP(src="192.0.2.7", dst="192.0.2.2") / TCP(dport=23))
    record = parse.parse_cleartext(packet)
    assert record.protocol == "Telnet"
    encrypted = one(tmp_path, Ether() / IP() / TCP(dport=22))
    assert parse.parse_cleartext(encrypted) is None


def test_l2p12_router_advertisements(tmp_path):
    packet = (
        Ether(src=SWITCH, dst="33:33:00:00:00:01")
        / IPv6(src="fe80::1", dst="ff02::1")
        / ICMPv6ND_RA(routerlifetime=1800)
        / ICMPv6NDOptPrefixInfo(prefix="2001:db8::", prefixlen=64)
    )
    record = parse.parse_router_advert(one(tmp_path, packet))
    assert record.prefix == "2001:db8::/64" and record.lifetime == 1800


def test_l2p13_service_announcements(tmp_path):
    packet = (
        Ether(src=HOST, dst="01:00:5e:7f:ff:fa")
        / IP(dst="239.255.255.250") / UDP(sport=1900, dport=1900)
        / b"NOTIFY * HTTP/1.1\r\nNT: urn:schemas-upnp-org:device:MediaServer:1\r\n\r\n"
    )
    record = parse.parse_service(one(tmp_path, packet))
    assert record.protocol == "SSDP" and "MediaServer" in record.service_type
    noise = one(tmp_path, Ether() / IP() / UDP(sport=1900, dport=1900) / b"\x00\x01")
    assert parse.parse_service(noise) is None


class Unparseable:
    """A frame that raises on every access, as a truncated one can."""

    def __contains__(self, other):
        raise ValueError("malformed")

    def __getitem__(self, key):
        raise ValueError("malformed")

    def getlayer(self, cls):
        raise ValueError("malformed")

    @property
    def src(self):
        raise ValueError("malformed")


def test_a_malformed_frame_does_not_abort_the_capture(tmp_path):
    capture = Capture()
    parse.parse_frame(Unparseable(), capture)
    good = one(tmp_path, llmnr("fileserver", HOST))
    parse.parse_frame(good, capture)
    assert capture.frames_seen == 2
    assert capture.parse_errors > 0
    assert len(capture.names) == 1


def test_records_deduplicate_but_counters_do_not(tmp_path):
    capture = Capture()
    packet = one(tmp_path, Ether(frames.gratuitous_arp(HOST, "192.0.2.5")))
    for _ in range(200):
        parse.parse_frame(packet, capture)
    assert len(capture.arp) == 1
    assert capture.gratuitous_arps == 200


def test_the_capture_caps_record_growth(tmp_path):
    capture = Capture()
    for index in range(parse.MAX_RECORDS + 50):
        capture.add("arp", parse.Arp("00:00:5e:00:53:%02x" % (index % 256),
                                     "192.0.2.%d" % (index % 254), False))
    assert len(capture.arp) == parse.MAX_RECORDS
    assert "arp" in capture.truncated


def test_the_observed_root_priority_feeds_l2a02(tmp_path):
    capture = Capture()
    assert capture.observed_root_priority() is None
    parse.parse_frame(one(tmp_path, Dot3(frames.bpdu_losing_config(32768, SWITCH))), capture)
    assert capture.observed_root_priority() == 36864


def test_the_management_address_feeds_l2a09(tmp_path):
    capture = Capture()
    assert capture.management_address() == ""
    parse.parse_frame(one(tmp_path, cdp_frame()), capture)
    assert capture.management_address() == "192.0.2.2"
