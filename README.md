# l2check

## What it does

l2check plugs into a switch port and reports which layer 2 protections the
network actually enforces on that port. It listens for discovery, trunking and
spanning tree traffic, then optionally sends bounded probes to determine whether
BPDU Guard, DHCP Snooping, Dynamic ARP Inspection and port security are in
place. The output is a posture table, not an exploit.

## Prove it is possible, never perform it

Every active probe is built so that it cannot cause an outage even when it
succeeds. A BPDU is sent with a priority that cannot win the root election. MAC
addresses are introduced in bounded numbers and never at flood rate. One DHCP
discover is sent and never a request. An ARP announcement is made for an address
the operator has confirmed is unused, never for a gateway.

The caps are enforced in code, across the whole run:

| Limit | Value |
| --- | --- |
| Total frames, all probes combined | 600 |
| Total active runtime | 10 minutes |
| MAC addresses introduced by L2A03 | 50 by default, 500 ceiling |
| Probes run | only those named in `--tests` |

No flag raises any of them, and there is no option to run every probe at once.
If the link state changes when no probe expected it, the run stops.

These are never implemented, behind any flag:

- CAM table overflow at flood rate
- Claiming the spanning tree root role, or forwarding frames as a bridge
- Sustained ARP poisoning, or any interception, relay or forwarding of frames
  belonging to another host
- DHCP pool exhaustion
- Capturing, storing or writing to disk the payload of any frame not addressed
  to or from the tool's own interface

The passive listener records protocol metadata only. It never writes a frame
payload to a pcap or a log.

## Passive and active

Passive is the default and needs no permission from anyone: it transmits
nothing, so plugging in and listening is no different from any other host on the
port. Eleven checks run passively and most real findings come from them.

Active mode requires `--active` and `--authorisation FILE`, and refuses to run
without both. The authorisation file names the client, the person who approved
the test, the segment, and a date window; the tool checks every field, checks
today is inside the window, requires the segment string to be retyped, and
records the SHA-256 of the file in the report. There is no override flag for any
of it. `AUTHORISATION.md` describes each probe in the terms a network manager
needs to approve it.

## Install and run

Linux only. l2check uses `AF_PACKET` directly.

```
pip install .
```

Opening a raw socket needs `CAP_NET_RAW`. Setting the capability on the Python
binary is preferable to running the whole tool as root:

```
sudo setcap cap_net_raw,cap_net_admin+eip "$(readlink -f "$(which python3)")"
```

Then:

```
l2check listen --interface eth0 --duration 120
l2check listen --interface eth0 --json --out posture.json
l2check probe --interface eth0 --active --authorisation auth.yaml --tests L2A01,L2A04
l2check observe --interface eth0 --port 9001
l2check posture --from posture.json
```

Exit codes: 0 when no control is absent, 1 when one or more are, 2 for an input
or authorisation error.

## Checks

| ID | Title | Mode | Frames sent |
| --- | --- | --- | --- |
| L2P01 | Discovery protocol disclosure | passive | 0 |
| L2P02 | Dynamic trunking negotiation offered | passive | 0 |
| L2P03 | Spanning tree BPDUs on an access port | passive | 0 |
| L2P04 | VTP frames observed | passive | 0 |
| L2P05 | Native VLAN is the default | passive | 0 |
| L2P06 | 802.1Q tagged frames on an access port | passive | 0 |
| L2P07 | Multiple DHCP servers observed | passive | 0 |
| L2P08 | Gratuitous ARP anomalies | passive | 0 |
| L2P09 | Name resolution poisoning surface | passive | 0 |
| L2P10 | First-hop redundancy without authentication | passive | 0 |
| L2P11 | Cleartext management protocols | passive | 0 |
| L2A01 | DTP trunk negotiation | active | 1 |
| L2A02 | BPDU Guard verification | active | 1 |
| L2A03 | Port security threshold | active | up to 50, ceiling 500 |
| L2A04 | DHCP snooping | active | 1 |
| L2A05 | Dynamic ARP Inspection | active | 1, plus 2 pre-flight checks |
| L2A06 | Double tagging reachability | active | 3 |
| L2A07 | Discovery protocol injection | active | 1 |

L2A05 and L2A06 need a cooperating listener on the target segment, started with
`l2check observe` and named with `--observer HOST:PORT`.

## The posture table

Ten controls, each in one of four states.

- `PRESENT`: a check produced positive evidence the control is enforcing.
- `ABSENT`: a check produced positive evidence it is not. This is what sets the
  exit code to 1.
- `INDETERMINATE`: a probe ran and the answer was ambiguous. The basis column
  says why, most often that no observer was supplied and one way delivery cannot
  be confirmed from the sending side.
- `UNTESTED`: nothing was learned. The probe was not selected, or it refused to
  run, or nothing relevant arrived during the capture window.

`UNTESTED` is not a pass. A quiet port is not a protected port, and the tool
never collapses `UNTESTED` into `ABSENT` or into `PRESENT` in either direction.
Root Guard is always `UNTESTED`, because testing it would mean sending a BPDU
superior to the current root, which this tool will not do.

## Testing it yourself

`lab/build_lab.sh` builds a topology on one machine with Open vSwitch and
network namespaces: one bridge with RSTP enabled, two access ports in different
VLANs, a trunk with the native VLAN left at 1, and two namespaces with
addresses. `--teardown` removes it.

```
sudo ./lab/build_lab.sh
sudo l2check listen --interface l2trunk --duration 30
sudo ./lab/build_lab.sh --teardown
```

Open vSwitch does not implement CDP, DTP, VTP, BPDU Guard, DHCP Snooping,
Dynamic ARP Inspection or port security. The lab exercises the parsers, the
spanning tree probe and the double tagging probe; the vendor specific checks
need real switch hardware or a vendor image. `lab/README.md` lists exactly which
is which.

## Limits

This tests one port on one segment. A full posture table from a single port
describes that port, not the network: the switch next to it may be configured
differently, and the same tool on the next patch panel can return a different
answer.

Absence of a reaction is not always proof a control is missing. Port security in
`restrict` or `protect` mode drops frames silently and looks identical from the
port to no port security at all, which is why that probe reports
`INDETERMINATE` rather than `ABSENT`. The same applies to anything filtered
upstream of where the tool is listening.

Some probes cannot conclude anything on their own. L2A05 and L2A06 test one way
delivery, so without a cooperating observer on the target segment they report
`INDETERMINATE` and say so, rather than claiming a negative.

Passive checks only report what arrived during the capture window. A segment
that was quiet for two minutes has not been shown to be free of anything.
