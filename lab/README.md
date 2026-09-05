# The lab

`build_lab.sh` builds a throwaway topology on one machine using Open vSwitch and
network namespaces. It needs root, and `--teardown` removes everything it made.

```
sudo ./lab/build_lab.sh
sudo ./lab/build_lab.sh --teardown
```

Stage 1 is built. Stage 2, the routed layer 3 topology, arrives with the layer 3
checks.

## Stage 1, layer 2

One Open vSwitch bridge, `ncbr0`, with RSTP enabled:

| Port | Kind | VLAN |
| --- | --- | --- |
| `nch1-br` | access, veth into namespace `nch1` | 10 |
| `nch2-br` | access, veth into namespace `nch2` | 20 |
| `ncaccess` | access, veth end in the root namespace | 10 |
| `nctrunk` | trunk, veth end in the root namespace | native 1, trunks 10 and 20 |

`ncaccess` and `nctrunk` are there to point the tool at:

```
sudo netcheck listen --interface ncaccess --duration 30
sudo netcheck listen --interface nctrunk --duration 30
```

The native VLAN on the trunk is left at 1 on purpose, because that is the
condition double tagging depends on.

## What the lab exercises

| Check | Lab | What is needed otherwise |
| --- | --- | --- |
| L2P01 discovery disclosure | no | Open vSwitch implements neither CDP nor LLDP. A vendor image, real hardware, or `lldpd` in a namespace |
| L2P02 DTP offered | no | Open vSwitch implements no DTP. Real hardware or a vendor image |
| L2P03 BPDUs on a port | yes | RSTP is enabled on the bridge |
| L2P04 VTP | no | Cisco hardware |
| L2P05 native VLAN | no | needs CDP or DTP disclosure |
| L2P06 tagged frames | yes | traffic across `nctrunk` |
| L2P07 multiple DHCP servers | partly | run a second DHCP server in a namespace |
| L2P08 gratuitous ARP | yes | traffic between the namespaces |
| L2P09 name resolution | partly | run a responder in a namespace |
| L2P10 first-hop redundancy | no | a router speaking HSRP, VRRP or GLBP |
| L2P11 cleartext management | yes | run a telnet or FTP service in a namespace |
| L2P12 router advertisements | partly | run `radvd` in a namespace |
| L2P13 service announcements | partly | run an SSDP responder in a namespace |
| L2A01 DTP negotiation | no | real hardware. It reports PRESENT here, which is an artefact of the lab and not a finding |
| L2A02 BPDU Guard | yes, negative | Open vSwitch has no BPDU Guard, so the link stays up and ABSENT is the correct answer |
| L2A03 port security | yes, indeterminate | no port security here, so there is no reaction to see |
| L2A04 DHCP snooping | partly | a DHCP server in a namespace |
| L2A05 Dynamic ARP Inspection | yes | with `netcheck observe` in the other namespace |
| L2A06 double tagging | yes | native VLAN 1 on `nctrunk`, with an observer on VLAN 20 |
| L2A07 discovery injection | yes | nothing reflects it, so INDETERMINATE is the answer |
| L2A08 client isolation | yes | the shared bridge means no isolation, with an observer in `nch1` |
| L2A09 switch management plane | no | needs a switch that discloses a management address |

## What Open vSwitch cannot do

Being plain rather than implying coverage: Open vSwitch implements neither DTP
nor CDP, so L2P01, L2P02, L2P05 and L2A01 have nothing to observe here. It also
has no BPDU Guard, no DHCP snooping, no Dynamic ARP Inspection and no port
security. Their absence is what the lab demonstrates; it cannot demonstrate them
being present. For that you need real switch hardware or a vendor image.
