# netcheck

## What it does

l2check attaches to a switch port or a wireless link and reports which layer 2
protections the network actually enforces there. It listens for discovery,
trunking, spanning tree, name resolution and router advertisement traffic, then
optionally sends bounded probes to determine whether protections like BPDU
Guard, DHCP Snooping, client isolation and port security are in place. The
output is a posture table, not an exploit.

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
| Neighbours asked by L2A08 | 25 by default, 50 ceiling |
| TCP connections, charged as 3 frames each | the same 600 frame budget |
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
- Monitor mode, deauthentication, handshake capture, or radio injection
- Sending an IPv6 router advertisement, which would reconfigure every host that
  believed it

The passive listener records protocol metadata only. It never writes a frame
payload to a pcap or a log.

## Passive and active

Passive is the default. It transmits nothing, needs no configuration file, and
runs on any interface with no arguments. Most real findings come from it.

Active checks need `--active` and nothing else. This tool is built for a network
you own; there is no authorisation file, no date window and no approval prompt.
That also means it is your job not to point it at a network that is not yours.

A configuration file still exists, but it is a targets file rather than a
permission slip: which subnets to sweep, where the gateway is, where the
observers are. Every field defaults from the routing table, so it is optional.
See "The targets file" below.

## Limits

Limits are defaults, and flags raise them:

| Limit | Default | Flag |
| --- | --- | --- |
| Layer 2 frame budget | 600 | `--frame-budget` |
| Layer 3 packet budget | 5000 | `--packet-budget` |
| Runtime | 15 minutes | `--runtime` |
| Send rate | 200 pps | `--rate`, hard capped at 1000 |

The two budgets decrement independently. When one runs out, the checks that
needed it report `UNTESTED` with reason `budget_exhausted`, never `ABSENT`.

The send rate is the one limit no flag can exceed. Above roughly a thousand
packets per second consumer gateways start dropping responses selectively, and
every silence in the report becomes ambiguous. That is an accuracy constraint,
not a policy one. If you need a faster sweep, use nmap.

A sweep wider than a /24 prints the estimated address count and running time and
needs `--yes` to proceed. It is a warning, not a refusal.

## The targets file

Default location `./netcheck.yaml`, overridden with `--config`. Optional.

```yaml
targets:
  subnets:
    - 192.168.1.0/24
  gateway: 192.168.1.1          # default: from the routing table
  guest_subnet: 192.168.2.0/24  # optional

exclude:
  - 192.168.1.50                # anything you do not want touched

observers:
  internal: 192.168.1.20:9001
  external: vps.example.net:9001

limits:
  rate_pps: 200
  packet_budget: 5000
  runtime_minutes: 15
```

`exclude` wins over `targets`, so a fragile printer or a work laptop stays out
of a sweep. The WAN address is excluded by default; `--wan` includes it.

## Wired and wireless profiles

The controls worth reporting depend on the medium, so there are two control
sets and the interface picks one:

- **wired**, on a switch port: the eight switch controls plus the seven common
  ones.
- **wireless**, on a radio link: link encryption, protected management frames
  and WPS, plus the same seven common ones.

Detection follows `/sys/class/net/<iface>/wireless`, and `--profile wired` or
`--profile wireless` overrides it. The wireless facts come from the kernel's
cached scan results through `iw`, which needs no privileges and transmits
nothing.

Monitor mode is deliberately not used, and neither is deauthentication,
handshake capture or any form of radio injection. Monitor mode would drop the
connection, which is the kind of outage this tool refuses to be able to cause.
That is the limit of what it can say about the radio: it reports what the access
point advertises, not what it does under attack.

## Install and run

Linux only. l2check uses `AF_PACKET` directly.

Run the setup script once:

```
./setup.sh
```

It creates a virtual environment in `.venv`, installs l2check into it, grants
that environment permission to read frames, and links `netcheck` and `l2check` into
`~/.local/bin` so it works from any directory. It asks for `sudo` once, for the
permission step alone. Running it again is safe and skips whatever is already
done.

Then check it worked:

```
netcheck doctor
```

That prints what is installed, whether l2check may read frames, which interfaces
exist, and the exact command to run next. It is the first thing to run when
something does not work.

After that, `--interface` is optional. With no interface named, l2check uses the
one carrying your default route:

```
netcheck listen                      # 120 seconds on your main interface
netcheck listen --duration 30
netcheck listen --interface wlan0 --json --out posture.json
netcheck posture --from posture.json
netcheck posture --from posture.json --diff previous.json
netcheck audit                       # offline checks, sends nothing
```

The active side and the cooperating observer:

```
netcheck probe --interface eth0 --active --tests L2A01,L2A04
netcheck probe --interface eth0 --active --all
netcheck observe --interface eth0 --port 9001 --side internal
```

`l2check` remains as an alias that reports the layer 2 control set only.
`--layers l2|l3|both` selects which controls appear, and `--markdown PATH`
writes the report as Markdown alongside the JSON.

Exit codes: 0 when no control is absent, 1 when one or more are, 2 for an input
or configuration error.

### Why the setup script, and not setcap on the system python

Reading raw frames needs `CAP_NET_RAW`. The obvious way to get it is:

```
sudo setcap cap_net_raw,cap_net_admin+eip "$(readlink -f "$(which python3)")"
```

Do not do this. It grants raw socket access to **every** Python program on the
machine, for every user, permanently. Any script anyone runs can then read all
traffic on every interface. It is a much larger grant than the tool needs.

`setup.sh` builds its virtual environment with `--copies`, so the environment
gets its own `python3` binary rather than a symlink to the system one, and the
capability is granted to that copy alone. Nothing outside `.venv` gains
anything.

If you previously ran the command above, undo it:

```
sudo setcap -r "$(readlink -f "$(which python3)")"
getcap "$(readlink -f "$(which python3)")"    # should print nothing
```

Running the tool as root works too, and is worse: everything the tool does then
runs as root, rather than one binary holding one capability.

### Installing it the manual way

If you would rather not use the script:

```
python3 -m venv --copies --system-site-packages .venv
.venv/bin/pip install -e .
sudo setcap cap_net_raw,cap_net_admin+eip .venv/bin/python3
.venv/bin/netcheck doctor
```

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
| L2P12 | IPv6 router advertisements, rogue RA surface | passive | 0 |
| L2P13 | UPnP and SSDP exposure | passive | 0 |
| L2P14 | Peer station traffic visible, clients not isolated | passive | 0 |
| L2P15 | Wireless link encryption | read-only | 0 |
| L2P16 | Protected management frames, 802.11w | read-only | 0 |
| L2P17 | WPS advertised | read-only | 0 |

`netcheck doctor` is not a check. It inspects your own machine and sends nothing.
| L2A01 | DTP trunk negotiation | active | 1 |
| L2A02 | BPDU Guard verification | active | 1 |
| L2A03 | Port security threshold | active | up to 50, ceiling 500 |
| L2A04 | DHCP snooping | active | 1 |
| L2A05 | Dynamic ARP Inspection | active | 1, plus 2 pre-flight checks |
| L2A06 | Double tagging reachability | active | 3 |
| L2A07 | Discovery protocol injection | active | 1 |
| L2A08 | Client isolation | active | up to 25 |
| L2A09 | UPnP gateway reachability | active | 1 |
| L2A10 | Gateway management exposure | active | 3 per port, 5 ports |

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
superior to the current root, which this tool will not do. IPv6 RA Guard stays
`UNTESTED` when only one router is advertising, for the same reason: proving it
absent would mean sending a router advertisement.

The `--json` output carries a per-protocol record count alongside `frames_seen`,
which is how you tell a segment that was genuinely quiet from a capture that
went wrong. It also reports `parse_errors`, and `truncated` names any check that
hit the per-check record cap, so a capped result is never mistaken for a
complete one.

## Testing it yourself

`lab/build_lab.sh` builds a topology on one machine with Open vSwitch and
network namespaces: one bridge with RSTP enabled, two access ports in different
VLANs, a trunk with the native VLAN left at 1, and two namespaces with
addresses. `--teardown` removes it.

```
sudo ./lab/build_lab.sh
netcheck listen --interface l2trunk --duration 30
sudo ./lab/build_lab.sh --teardown
```

Building the lab needs root because it creates bridges and namespaces. Capturing
on it does not, once `setup.sh` has run.

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

On a wireless link you see less than on a switch port, and the difference is not
the tool. Per-station encryption means another client's unicast traffic never
reaches you, the access point strips VLAN tags before frames arrive, and it does
not forward spanning tree or discovery traffic to clients. Many consumer access
points also suppress or rate-limit multicast, which thins out even the checks
that should work. A wireless run that finds little is describing the medium as
much as the network.
