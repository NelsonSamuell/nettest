from scapy.contrib.cdp import (
    CDPMsgDeviceID,
    CDPMsgMgmtAddr,
    CDPMsgNativeVLAN,
    CDPMsgPlatform,
    CDPMsgPortID,
    CDPMsgSoftwareVersion,
    CDPMsgVTPMgmtDomain,
    CDPAddrRecordIPv4,
    CDPv2_HDR,
)
from scapy.contrib.vtp import VTP
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.hsrp import HSRP
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP, LLC, SNAP, Dot1Q, Dot3, Ether
from scapy.layers.vrrp import VRRP
from scapy.utils import PcapWriter, rdpcap

from l2check import frames, parse
from l2check.models import Capture


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


def cdp_frame():
    return (
        Dot3(dst="01:00:0c:cc:cc:cc", src="00:11:22:33:44:55")
        / LLC(dsap=0xAA, ssap=0xAA, ctrl=3)
        / SNAP(OUI=0x00000C, code=0x2000)
        / CDPv2_HDR(
            msg=[
                CDPMsgDeviceID(val=b"sw-floor3"),
                CDPMsgPortID(iface=b"GigabitEthernet0/14"),
                CDPMsgPlatform(val=b"cisco WS-C2960X"),
                CDPMsgSoftwareVersion(val=b"IOS 15.2(4)E10"),
                CDPMsgNativeVLAN(vlan=1),
                CDPMsgVTPMgmtDomain(val=b"CORP"),
                CDPMsgMgmtAddr(addr=[CDPAddrRecordIPv4(addr="10.3.0.2")]),
            ]
        )
    )


def test_parse_cdp(tmp_path):
    record = parse.parse_cdp(one(tmp_path, cdp_frame()))
    assert record.protocol == "CDP"
    assert record.device_id == "sw-floor3"
    assert record.port_id == "GigabitEthernet0/14"
    assert record.platform == "cisco WS-C2960X"
    assert record.software_version == "IOS 15.2(4)E10"
    assert record.native_vlan == 1
    assert record.vtp_domain == "CORP"
    assert record.management_address == "10.3.0.2"


def test_parse_cdp_ignores_other_frames(tmp_path):
    packet = one(tmp_path, Ether() / IP() / UDP())
    assert parse.parse_cdp(packet) is None


def test_parse_lldp(tmp_path):
    raw = frames.lldp_probe("00:11:22:33:44:66", "sw-floor3", "Gi0/14", ttl=120)
    record = parse.parse_lldp(one(tmp_path, Ether(raw)))
    assert record.protocol == "LLDP"
    assert record.device_id == "sw-floor3"
    assert record.port_id == "Gi0/14"


def test_parse_dtp(tmp_path):
    raw = frames.dtp_desirable("00:11:22:33:44:55", domain="CORP")
    record = parse.parse_dtp(one(tmp_path, Dot3(raw)))
    assert record.mode == "dynamic desirable"
    assert record.domain == "CORP"


def test_parse_dtp_reports_operational_trunk(tmp_path):
    from scapy.contrib.dtp import DTP, DTPDomain, DTPStatus, DTPType

    packet = (
        Dot3(dst="01:00:0c:cc:cc:cc", src="00:11:22:33:44:55")
        / LLC(dsap=0xAA, ssap=0xAA, ctrl=3)
        / SNAP(OUI=0x00000C, code=0x2004)
        / DTP(tlvlist=[DTPDomain(), DTPStatus(status=b"\x81"), DTPType()])
    )
    record = parse.parse_dtp(one(tmp_path, packet))
    assert record.mode.startswith("trunking")


def test_parse_bpdu(tmp_path):
    raw = frames.bpdu_losing_config(32768, "00:11:22:33:44:55")
    record = parse.parse_bpdu(one(tmp_path, Dot3(raw)))
    assert record.root_priority == 36864
    assert record.bridge_mac == "00:11:22:33:44:55"
    assert record.root_path_cost == 0
    assert not record.root_priority_is_default


def test_parse_bpdu_flags_default_root_priority(tmp_path):
    from scapy.layers.l2 import STP

    packet = (
        Dot3(dst="01:80:c2:00:00:00", src="00:11:22:33:44:55")
        / LLC(dsap=0x42, ssap=0x42, ctrl=3)
        / STP(rootid=32769, rootmac="00:11:22:33:44:55", bridgeid=32769)
    )
    record = parse.parse_bpdu(one(tmp_path, packet))
    assert record.root_priority_is_default


def test_parse_vtp(tmp_path):
    packet = (
        Dot3(dst="01:00:0c:cc:cc:cc", src="00:11:22:33:44:55")
        / LLC(dsap=0xAA, ssap=0xAA, ctrl=3)
        / SNAP(OUI=0x00000C, code=0x2003)
        / VTP(domname="CORP", rev=42)
    )
    record = parse.parse_vtp(one(tmp_path, packet))
    assert record.domain == "CORP"
    assert record.revision == 42


def test_parse_tagged_frames(tmp_path):
    packet = Ether() / Dot1Q(vlan=1) / Dot1Q(vlan=20) / IP() / UDP()
    records = parse.parse_tagged(one(tmp_path, packet))
    assert [record.vlan for record in records] == [1, 20]


def test_parse_untagged_frame_yields_nothing(tmp_path):
    assert parse.parse_tagged(one(tmp_path, Ether() / IP() / UDP())) == []


def dhcp_offer(server_mac, server_ip):
    return (
        Ether(src=server_mac, dst="02:4c:32:00:00:01")
        / IP(src=server_ip, dst="255.255.255.255")
        / UDP(sport=67, dport=68)
        / BOOTP(op=2, yiaddr="10.3.0.55")
        / DHCP(options=[("message-type", "offer"), ("server_id", server_ip), "end"])
    )


def test_parse_dhcp_offer(tmp_path):
    packet = one(tmp_path, dhcp_offer("00:11:22:33:44:55", "10.3.0.1"))
    record = parse.parse_dhcp_server(packet)
    assert record.server_mac == "00:11:22:33:44:55"
    assert record.server_ip == "10.3.0.1"


def test_parse_dhcp_ignores_client_discover(tmp_path):
    raw = frames.dhcp_discover("02:4c:32:00:00:01", 1)
    assert parse.parse_dhcp_server(one(tmp_path, Ether(raw))) is None


def test_parse_gratuitous_arp(tmp_path):
    raw = frames.gratuitous_arp("00:11:22:33:44:55", "10.3.0.1")
    record = parse.parse_arp(one(tmp_path, Ether(raw)))
    assert record.gratuitous
    assert record.claimed_ip == "10.3.0.1"


def test_parse_arp_request_is_not_gratuitous(tmp_path):
    packet = Ether() / ARP(op=1, psrc="10.3.0.7", pdst="10.3.0.1")
    assert not parse.parse_arp(one(tmp_path, packet)).gratuitous


def llmnr_query(name, src_mac):
    return (
        Ether(src=src_mac, dst="01:00:5e:00:00:fc")
        / IP(src="10.3.0.7", dst="224.0.0.252")
        / UDP(sport=54321, dport=5355)
        / DNS(rd=0, qd=DNSQR(qname=name))
    )


def test_parse_llmnr(tmp_path):
    record = parse.parse_name_resolution(
        one(tmp_path, llmnr_query("fileserver", "00:11:22:33:44:77"))
    )
    assert record.protocol == "LLMNR"
    assert record.query_name == "fileserver"


def test_parse_wpad_is_flagged_separately(tmp_path):
    record = parse.parse_name_resolution(
        one(tmp_path, llmnr_query("wpad", "00:11:22:33:44:77"))
    )
    assert record.protocol == "WPAD"


def test_parse_name_resolution_ignores_responses(tmp_path):
    packet = (
        Ether()
        / IP(dst="224.0.0.252")
        / UDP(sport=5355, dport=5355)
        / DNS(qr=1, qd=DNSQR(qname="fileserver"))
    )
    assert parse.parse_name_resolution(one(tmp_path, packet)) is None


def test_parse_hsrp_without_authentication(tmp_path):
    packet = (
        Ether(src="00:00:0c:07:ac:01")
        / IP(src="10.3.0.2", dst="224.0.0.2")
        / UDP(sport=1985, dport=1985)
        / HSRP(group=1, priority=100, virtualIP="10.3.0.1")
    )
    record = parse.parse_fhrp(one(tmp_path, packet))
    assert record.protocol == "HSRP"
    assert record.group == 1
    assert record.priority == 100
    assert record.virtual_ip == "10.3.0.1"
    assert not record.authenticated


def test_parse_hsrp_with_a_non_default_string_reports_only_the_fact(tmp_path):
    packet = (
        Ether()
        / IP(src="10.3.0.2", dst="224.0.0.2")
        / UDP(sport=1985, dport=1985)
        / HSRP(group=1, auth=b"s3cret\x00\x00")
    )
    record = parse.parse_fhrp(one(tmp_path, packet))
    assert record.authenticated
    assert "s3cret" not in repr(record)


def test_parse_vrrp(tmp_path):
    packet = (
        Ether()
        / IP(src="10.3.0.2", dst="224.0.0.18", proto=112)
        / VRRP(vrid=5, priority=120, addrlist=["10.3.0.1"], authtype=0)
    )
    record = parse.parse_fhrp(one(tmp_path, packet))
    assert record.protocol == "VRRP"
    assert record.group == 5
    assert not record.authenticated


def test_parse_cleartext_telnet(tmp_path):
    packet = Ether() / IP(src="10.3.0.7", dst="10.3.0.2") / TCP(dport=23)
    record = parse.parse_cleartext(one(tmp_path, packet))
    assert record.protocol == "Telnet"
    assert record.source == "10.3.0.7"
    assert record.destination == "10.3.0.2"


def test_parse_cleartext_ignores_ssh(tmp_path):
    packet = Ether() / IP(src="10.3.0.7", dst="10.3.0.2") / TCP(dport=22)
    assert parse.parse_cleartext(one(tmp_path, packet)) is None


def test_parse_frame_dispatches_into_the_capture(tmp_path):
    packets = roundtrip(
        tmp_path,
        [
            cdp_frame(),
            dhcp_offer("00:11:22:33:44:55", "10.3.0.1"),
            dhcp_offer("00:11:22:33:44:99", "10.3.0.9"),
            llmnr_query("wpad", "00:11:22:33:44:77"),
            Ether() / Dot1Q(vlan=20) / IP() / UDP(),
        ],
    )
    capture = Capture(interface="eth0", duration=5)
    for packet in packets:
        parse.parse_frame(packet, capture)
    assert capture.frames_seen == 5
    assert len(capture.discovery) == 1
    assert len(capture.dhcp_servers) == 2
    assert len(capture.name_resolution) == 1
    assert [record.vlan for record in capture.tagged] == [20]
    assert capture.observed_root_priority() is None
    assert "10.3.0.1" in capture.observed_ips()
