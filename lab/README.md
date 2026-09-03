# The lab topology

`build_lab.sh` builds a throwaway topology on one machine using Open vSwitch and
network namespaces. It needs root, and `--teardown` removes everything it made.

```
sudo ./lab/build_lab.sh
sudo ./lab/build_lab.sh --teardown
```

## What it builds

**A switched segment**, bridge `l2br0` with RSTP enabled:

| Port | Kind | VLAN |
| --- | --- | --- |
| `l2h1-br` | access, veth into namespace `l2h1` | 10 |
| `l2h2-br` | access, veth into namespace `l2h2` | 20 |
| `l2access` | access, veth end in the root namespace | 10 |
| `l2trunk` | trunk, veth end in the root namespace | native 1, trunks 10 and 20 |

**A routed topology** with a NAT gateway between an inside and an outside:

| Namespace | Address | Purpose |
| --- | --- | --- |
| `l3gw` | 10.20.0.1 inside, 10.30.0.1 outside | NAT gateway with an nftables rule set |
| `l3in` | 10.20.0.10 | run netcheck here |
| `l3out` | 10.30.0.10 | run the external observer here |
| `l3v6` | fd00:dead:beef::10 | global IPv6, no inbound v6 filter |
| `l3guest` | 10.40.0.10 on bridge `l2br1` | the guest segment |

The gateway's rule set has deliberate gaps, one per check, so each active check
has a known good and a known bad case. Read the `nft` block in the script as the
answer key: inbound is dropped except on 8080, and there is no IPv6 rule at all.

```
sudo ip netns exec l3in netcheck listen --interface l3in-l3gw --duration 20
sudo ip netns exec l3out netcheck observe --interface l3out-l3gw --port 9001 --side external
```

## Which checks the lab exercises

| Check | Lab | What is needed otherwise |
| --- | --- | --- |
| L2P01 discovery disclosure | no | a Cisco switch, or `lldpd` in a namespace |
| L2P02 DTP offered | no | real switch hardware or a vendor image |
| L2P03 BPDUs on a port | yes | RSTP is enabled on `l2br0` |
| L2P04 VTP | no | Cisco hardware |
| L2P05 native VLAN | no | CDP or DTP disclosure |
| L2P06 tagged frames | yes | traffic across `l2trunk` |
| L2P07 multiple DHCP servers | partly | run a second DHCP server in a namespace |
| L2P08 gratuitous ARP | yes | traffic between the namespaces |
| L2P09 name resolution | partly | run avahi in a namespace |
| L2P10 FHRP | no | a router speaking HSRP, VRRP or GLBP |
| L2P11 cleartext management | yes | run telnetd in a namespace |
| L2P12 IPv6 RAs | yes | run `radvd` on `l3gw` |
| L2P13 UPnP | partly | run a minimal IGD responder on `l3gw` |
| L2P14 peer traffic | yes | the shared bridge delivers it |
| L2P15 to L2P17 wireless | no | a real access point |
| L2A01 DTP negotiation | no | real switch hardware |
| L2A02 BPDU Guard | yes, negative | Open vSwitch has no BPDU Guard, so it reports ABSENT correctly |
| L2A03 port security | yes, indeterminate | no port security here, so no reaction |
| L2A04 DHCP snooping | partly | a DHCP server in a namespace |
| L2A05 DAI | yes | with an observer in the other namespace |
| L2A06 double tagging | yes | native VLAN 1 on `l2trunk` |
| L2A07 discovery injection | yes | no reflection, so INDETERMINATE |
| L2A08 client isolation | yes | the shared bridge means no isolation |
| L2A09 UPnP reachability | partly | needs an IGD responder |
| L2A10 gateway admin | yes | run a web server on `l3gw` |
| L3P01 to L3P10 | yes | all parse from lab traffic |
| CFG01 router config | yes | export any config file and pass `--config` |
| CFG02 host posture | yes | reads the machine it runs on |
| CFG03 firmware advisory | no | needs a curated advisory file and a real device |
| L3A01 host discovery | yes | ARP across the segment |
| L3A02 TCP inventory | yes | open a listener in a namespace |
| L3A03 UDP inventory | yes | open a UDP listener in a namespace |
| L3A04 management plane | yes | run a web server on `l3gw` |
| L3A05 inbound IPv4 | yes | observer in `l3out`, the 8080 gap is the finding |
| L3A06 UPnP mapping | no | needs a real IGD implementation |
| L3A07 egress filtering | yes | observer in `l3out` |
| L3A08 inbound IPv6 | yes | `l3v6` has a global address and no v6 rule |
| L3A09 guest segmentation | yes | `l3guest` on a separate bridge |
| L3A10 DNS rebinding | no | needs a name server you control |
| L3A11 resolver scoping | partly | run a resolver on `l3gw` |
| L3A12 ICMP redirects | yes | tests the machine it runs on |
| L3A13 anti-spoofing | yes | observer in `l3out` |
| L3A14 fragment handling | yes | observer in `l3out` |
| L3A15 source routing | yes | observer in `l3out` |

## What Open vSwitch cannot do

Being plain about this rather than implying coverage: Open vSwitch does not
implement CDP, DTP, VTP, BPDU Guard, DHCP Snooping, Dynamic ARP Inspection or
port security. Their absence is what the lab demonstrates; it cannot demonstrate
them being present. Nothing here emulates a wireless access point, so the three
wireless checks need real hardware.

The two things the script does not start for you are a UPnP IGD responder and a
DNS server, because both need a package the script would have to install. L3A06
and L3A10 stay untested here.
