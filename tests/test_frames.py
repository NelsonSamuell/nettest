"""Frame builders. The BPDU builder gets the most attention."""

import pytest
from scapy.contrib.dtp import DTP, DTPStatus
from scapy.contrib.lldp import LLDPDU, LLDPDUChassisID, LLDPDUTimeToLive
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import ICMP, TCP
from scapy.layers.l2 import ARP, STP, Dot1Q, Dot3, Ether

from netcheck.l2 import frames
from netcheck.l2.frames import UnsafeFrameError

PROBE = frames.probe_mac(1)


def test_probe_addresses_are_locally_administered():
    assert PROBE == "02:00:5e:00:00:01"
    assert int(PROBE.split(":")[0], 16) & 0x02


def test_unique_addresses_are_distinct():
    macs = frames.unique_macs(50)
    assert len(macs) == len(set(macs)) == 50
    with pytest.raises(ValueError):
        frames.unique_macs(-1)


@pytest.mark.parametrize(
    "observed,expected",
    [(0, 4096), (4096, 8192), (32768, 36864), (32769, 36864), (36863, 36864), (57344, 61440)],
)
def test_the_constructed_priority_is_strictly_worse(observed, expected):
    worse = frames.worse_bridge_priority(observed)
    assert worse == expected
    assert worse > observed


def test_the_builder_refuses_without_an_observed_root_priority():
    """The safety property depends entirely on knowing the current root."""
    with pytest.raises(UnsafeFrameError):
        frames.worse_bridge_priority(None)
    with pytest.raises(UnsafeFrameError):
        frames.bpdu_losing_config(None, PROBE)


@pytest.mark.parametrize("observed", [61440, 61441, 65535])
def test_the_builder_refuses_at_the_boundary(observed):
    """Nothing is worse than the worst valid priority, so nothing is built."""
    with pytest.raises(UnsafeFrameError):
        frames.worse_bridge_priority(observed)


def test_a_priority_outside_sixteen_bits_is_refused():
    with pytest.raises(UnsafeFrameError):
        frames.worse_bridge_priority(-1)
    with pytest.raises(UnsafeFrameError):
        frames.worse_bridge_priority(70000)


@pytest.mark.parametrize("observed", [0, 4096, 32768, 32769, 57344])
def test_the_bpdu_carries_a_losing_priority(observed):
    stp = Dot3(frames.bpdu_losing_config(observed, PROBE))[STP]
    assert stp.bridgeid > observed
    assert stp.rootid > observed


def test_the_bpdu_never_sets_the_topology_change_flag():
    stp = Dot3(frames.bpdu_losing_config(32768, PROBE))[STP]
    assert stp.bpduflags == 0
    # bpdutype 0 is a configuration BPDU; 0x80 would be a topology change notice
    assert stp.bpdutype == 0


def test_the_bpdu_is_addressed_and_encapsulated_correctly():
    raw = frames.bpdu_losing_config(32768, PROBE)
    assert raw[:6] == bytes.fromhex("0180c2000000")
    assert raw[14:17] == b"\x42\x42\x03"
    assert Dot3(raw)[STP].bridgemac == PROBE


def test_the_dtp_frame_offers_desirable():
    raw = frames.dtp_desirable(PROBE)
    assert raw[:6] == bytes.fromhex("01000ccccccc")
    packet = Dot3(raw)
    assert packet[DTP].ver == 1
    status = [t for t in packet[DTP].tlvlist if isinstance(t, DTPStatus)]
    assert status and status[0].status == b"\x03"


def test_the_lldp_frame_carries_a_short_time_to_live():
    packet = Ether(frames.lldp_probe(PROBE, "netcheck", "probe0", ttl=30))
    assert packet.dst == "01:80:c2:00:00:0e"
    assert packet.type == 0x88CC
    assert packet[LLDPDUChassisID].id == PROBE
    assert packet[LLDPDUTimeToLive].ttl == 30
    assert LLDPDU in packet


def test_the_dhcp_frame_is_a_discover_and_not_a_request():
    packet = Ether(frames.dhcp_discover(PROBE, 0x1234))
    assert packet[BOOTP].op == 1
    assert packet[BOOTP].xid == 0x1234
    types = [o[1] for o in packet[DHCP].options if isinstance(o, tuple) and o[0] == "message-type"]
    assert types == [1]
    with pytest.raises(ValueError):
        frames.dhcp_discover(PROBE, 1 << 33)


def test_the_gratuitous_arp_claims_only_the_given_address():
    packet = Ether(frames.gratuitous_arp(PROBE, "192.0.2.99"))
    assert packet[ARP].op == 2
    assert packet[ARP].psrc == packet[ARP].pdst == "192.0.2.99"


def test_the_arp_probe_claims_no_address():
    packet = Ether(frames.arp_probe(PROBE, "192.0.2.99"))
    assert packet[ARP].op == 1
    assert packet[ARP].psrc == "0.0.0.0"


def test_the_double_tagged_frame_carries_two_tags_and_the_marker():
    marker = frames.new_marker()
    raw = frames.double_tagged_icmp(
        PROBE, "ff:ff:ff:ff:ff:ff", 1, 20, "192.0.2.9", "198.51.100.9", marker
    )
    packet = Ether(raw)
    tags = []
    layer = packet.getlayer(Dot1Q)
    while layer is not None:
        tags.append(layer.vlan)
        layer = layer.payload.getlayer(Dot1Q)
    assert tags == [1, 20]
    assert packet[ICMP].type == 8
    assert marker.encode() in raw
    with pytest.raises(ValueError):
        frames.double_tagged_icmp(PROBE, "ff:ff:ff:ff:ff:ff", 1, 4096, "192.0.2.9",
                                  "198.51.100.9", marker)


def test_the_syn_frame_sets_only_syn():
    packet = Ether(frames.tcp_syn(PROBE, "ff:ff:ff:ff:ff:ff", "192.0.2.9", "192.0.2.1", 443))
    assert packet[TCP].dport == 443
    assert str(packet[TCP].flags) == "S"


def test_markers_are_distinct_and_prefixed():
    assert frames.new_marker() != frames.new_marker()
    assert frames.new_marker().startswith("NETCHECK-")
