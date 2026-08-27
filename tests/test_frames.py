import pytest
from scapy.contrib.dtp import DTP, DTPStatus
from scapy.contrib.lldp import LLDPDU, LLDPDUChassisID, LLDPDUTimeToLive
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import ICMP, IP
from scapy.layers.l2 import ARP, STP, Dot1Q, Dot3, Ether

from l2check import frames
from l2check.frames import UnsafeFrameError


def test_probe_mac_uses_locally_administered_oui():
    mac = frames.probe_mac(1)
    assert mac == "02:4c:32:00:00:01"
    assert int(mac.split(":")[0], 16) & 0x02


def test_unique_macs_are_distinct():
    macs = frames.unique_macs(50)
    assert len(macs) == 50
    assert len(set(macs)) == 50


def test_unique_macs_rejects_negative_count():
    with pytest.raises(ValueError):
        frames.unique_macs(-1)


@pytest.mark.parametrize(
    "observed,expected",
    [
        (0, 4096),
        (4096, 8192),
        (32768, 36864),
        (32769, 36864),
        (36863, 36864),
        (57344, 61440),
    ],
)
def test_worse_bridge_priority_is_strictly_worse(observed, expected):
    worse = frames.worse_bridge_priority(observed)
    assert worse == expected
    assert worse > observed


def test_worse_bridge_priority_refuses_without_observed_root():
    with pytest.raises(UnsafeFrameError):
        frames.worse_bridge_priority(None)


@pytest.mark.parametrize("observed", [61440, 61441, 65535])
def test_worse_bridge_priority_refuses_at_the_boundary(observed):
    with pytest.raises(UnsafeFrameError):
        frames.worse_bridge_priority(observed)


def test_worse_bridge_priority_rejects_non_16_bit_input():
    with pytest.raises(UnsafeFrameError):
        frames.worse_bridge_priority(-1)
    with pytest.raises(UnsafeFrameError):
        frames.worse_bridge_priority(70000)


def test_bpdu_builder_refuses_without_observed_root_priority():
    with pytest.raises(UnsafeFrameError):
        frames.bpdu_losing_config(None, "02:4c:32:00:00:01")


@pytest.mark.parametrize("observed", [0, 4096, 32768, 32769, 57344])
def test_bpdu_priority_is_strictly_worse_than_observed_root(observed):
    pkt = Dot3(frames.bpdu_losing_config(observed, "02:4c:32:00:00:01"))
    stp = pkt[STP]
    assert stp.bridgeid > observed
    assert stp.rootid > observed


def test_bpdu_never_sets_the_topology_change_flag():
    pkt = Dot3(frames.bpdu_losing_config(32768, "02:4c:32:00:00:01"))
    assert pkt[STP].bpduflags == 0
    # bpdutype 0 is a configuration BPDU; 0x80 would be a topology change notice
    assert pkt[STP].bpdutype == 0


def test_bpdu_addressing_and_llc():
    raw = frames.bpdu_losing_config(32768, "02:4c:32:00:00:01")
    assert raw[:6] == bytes.fromhex("0180c2000000")
    pkt = Dot3(raw)
    assert pkt.src == "02:4c:32:00:00:01"
    assert raw[14:17] == b"\x42\x42\x03"
    assert pkt[STP].bridgemac == "02:4c:32:00:00:01"


def test_dtp_desirable_frame():
    raw = frames.dtp_desirable("02:4c:32:00:00:01", domain="")
    assert raw[:6] == bytes.fromhex("01000ccccccc")
    pkt = Dot3(raw)
    assert pkt[DTP].ver == 1
    status = [tlv for tlv in pkt[DTP].tlvlist if isinstance(tlv, DTPStatus)]
    assert status and status[0].status == b"\x03"


def test_lldp_probe_frame():
    raw = frames.lldp_probe("02:4c:32:00:00:01", "l2check", "probe0", ttl=30)
    pkt = Ether(raw)
    assert pkt.dst == "01:80:c2:00:00:0e"
    assert pkt.type == 0x88CC
    assert pkt[LLDPDUChassisID].id == "02:4c:32:00:00:01"
    assert pkt[LLDPDUTimeToLive].ttl == 30
    assert LLDPDU in pkt


def test_dhcp_discover_is_a_discover_and_not_a_request():
    raw = frames.dhcp_discover("02:4c:32:00:00:01", 0x1234)
    pkt = Ether(raw)
    assert pkt[BOOTP].xid == 0x1234
    assert pkt[BOOTP].op == 1
    types = [o[1] for o in pkt[DHCP].options if isinstance(o, tuple) and o[0] == "message-type"]
    assert types == [1]


def test_dhcp_discover_rejects_bad_xid():
    with pytest.raises(ValueError):
        frames.dhcp_discover("02:4c:32:00:00:01", 1 << 33)


def test_gratuitous_arp_claims_only_the_given_address():
    raw = frames.gratuitous_arp("02:4c:32:00:00:01", "10.0.0.99")
    pkt = Ether(raw)
    assert pkt[ARP].op == 2
    assert pkt[ARP].psrc == "10.0.0.99"
    assert pkt[ARP].pdst == "10.0.0.99"
    assert pkt[ARP].hwsrc == "02:4c:32:00:00:01"


def test_arp_probe_claims_no_address():
    pkt = Ether(frames.arp_probe("02:4c:32:00:00:01", "10.0.0.99"))
    assert pkt[ARP].op == 1
    assert pkt[ARP].psrc == "0.0.0.0"


def test_double_tagged_icmp_carries_two_tags_and_the_marker():
    marker = "L2CHECK-DEADBEEF"
    raw = frames.double_tagged_icmp(
        "02:4c:32:00:00:01", "ff:ff:ff:ff:ff:ff", 1, 20,
        "10.0.1.9", "10.0.20.9", marker,
    )
    pkt = Ether(raw)
    tags = []
    layer = pkt.getlayer(Dot1Q)
    while layer is not None:
        tags.append(layer.vlan)
        layer = layer.payload.getlayer(Dot1Q)
    assert tags == [1, 20]
    assert pkt[ICMP].type == 8
    assert pkt[IP].dst == "10.0.20.9"
    assert marker.encode() in raw


def test_double_tagged_icmp_rejects_out_of_range_vlan():
    with pytest.raises(ValueError):
        frames.double_tagged_icmp(
            "02:4c:32:00:00:01", "ff:ff:ff:ff:ff:ff", 1, 4096,
            "10.0.1.9", "10.0.20.9", "L2CHECK-1",
        )


def test_new_marker_is_distinct_each_time():
    assert frames.new_marker() != frames.new_marker()
    assert frames.new_marker().startswith("L2CHECK-")
