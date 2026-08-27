# The lab topology

`build_lab.sh` builds a throwaway layer 2 topology on one machine using Open
vSwitch and network namespaces. It needs root, and `--teardown` removes
everything it made.

```
sudo ./lab/build_lab.sh
sudo ./lab/build_lab.sh --teardown
```

## What it builds

One Open vSwitch bridge, `l2br0`, with RSTP enabled and four ports:

| Port | Kind | VLAN |
| --- | --- | --- |
| `l2h1-br` | access, veth into namespace `l2h1` | 10 |
| `l2h2-br` | access, veth into namespace `l2h2` | 20 |
| `l2access` | access, veth end in the root namespace | 10 |
| `l2trunk` | trunk, veth end in the root namespace | native 1, trunks 10 and 20 |

The namespaces hold `10.10.10.1/24` and `10.10.20.1/24`. `l2access` and
`l2trunk` are there for you to point the tool at:

```
sudo l2check listen --interface l2access --duration 30
sudo l2check listen --interface l2trunk --duration 30
```

## What it represents

An access port and a trunk on the same switch, with a native VLAN left at 1.
That is the ordinary shape of a user floor: hosts on access ports, an uplink
carrying several VLANs, and a native VLAN nobody changed.

## Which checks it exercises

- **L2P03**, BPDUs on a port. RSTP is enabled on the bridge, so BPDUs arrive on
  both taps and the parser sees a real root bridge identifier and path cost.
- **L2P06**, tagged frames. Traffic between the two namespaces crosses the
  trunk tagged, so listening on `l2trunk` shows VLAN 10 and 20.
- **L2P08**, ARP metadata. Traffic between the namespaces produces ARP the
  listener can count.
- **L2A02**, BPDU Guard verification, in its refusing and its negative form.
  Open vSwitch has no BPDU Guard, so a capture on `l2access` gives the probe a
  root priority to be worse than, the BPDU is sent, the link stays up, and the
  probe reports `ABSENT`. That is the correct answer for this bridge.
- **L2A03**, port security threshold, in its `INDETERMINATE` form. Open vSwitch
  has no port security here, so 50 addresses arrive with no reaction.
- **L2A06**, double tagging, with `l2check observe` running in one namespace.
  The native VLAN on `l2trunk` is 1, so the mechanism is present to test.

## Which checks it cannot exercise

Open vSwitch does not implement these at all, so no configuration of this lab
will produce them. They need real switch hardware or a vendor image:

- **CDP** and **DTP**. There is no Cisco discovery or trunk negotiation in Open
  vSwitch, so L2P01 via CDP, L2P02, L2P05 and L2A01 have nothing to observe.
  L2A01 will report `PRESENT` here, and that is an artefact of the lab rather
  than a finding.
- **VTP**, so L2P04 never fires.
- **BPDU Guard**, **DHCP Snooping**, **Dynamic ARP Inspection** and **port
  security** as switch features. Their absence is what the lab demonstrates;
  it cannot demonstrate them being present.
- **HSRP**, **VRRP** and **GLBP**, unless you run a router that speaks them in
  one of the namespaces. L2P10 stays quiet otherwise.

LLDP is available if you run `lldpd` in a namespace, which the script does not
do.
