# netcheck

## What it does

netcheck measures which layer 2 and layer 3 protections a network actually
enforces, from a host attached to it. It answers which controls the switch port
enforces and which controls the network enforces, and reports each as present,
absent, indeterminate or untested. The output is a posture table and a
reachability matrix, not an exploit.

## Operating profiles

**self** is the default. No authorisation file. A targets file only, and that is
optional because every field defaults from the routing table. Budget caps are
defaults that flags can raise. Reports are stamped `profile: self` and say they
are not a client deliverable.

**engagement** is selected with `--profile engagement`. It requires
`--authorisation FILE`, budget caps become ceilings no flag can raise, `--all`
is rejected, and the report carries the authorisation file hash.

The profile appears in the JSON, in the Markdown and on the first line of the
terminal report. A reader never has to guess which produced a report.

## Hard limits, both profiles

No flag changes any of these, and no code implementing them exists:

- CAM table overflow at flood rate
- Claiming the spanning tree root role, or forwarding frames as a bridge
- Sustained ARP poisoning, traffic interception, or relaying another host's frames
- DHCP pool exhaustion
- Credential testing, default password lists, or authentication attempts of any
  kind. Version and banner detection is the boundary
- Exploitation of any identified service
- Payload capture or session reconstruction
- Wireless radio injection, deauthentication, monitor mode, or handshake capture
- A send rate above 1000 packets per second

The rate cap is a measurement constraint as much as a safety one. Above roughly
a thousand packets per second consumer gateways drop responses selectively and
every silence in the report becomes ambiguous. Anything faster is a job for nmap.

## Install and run

```
pipx install netcheck
netcheck doctor
```

Before a release exists:

```
pipx install git+<url>
```

A single file that needs no install, for a host you would rather not change:

```
make dist
python netcheck.pyz doctor
```

Docker, for Linux hosts only:

```
docker build -t netcheck .
docker run --rm --net=host --cap-add=NET_RAW --cap-add=NET_ADMIN netcheck doctor
```

On macOS and Windows, Docker runs inside a virtual machine, so `--net=host`
attaches to the VM's network and not the real LAN. Every result would then be
about a network that does not exist. netcheck detects containerisation and
refuses active checks when the default route is a virtual adapter.

Run `netcheck doctor` first, always. It is the first thing to attach to a bug
report.

## Platform matrix

| Capability | Linux | macOS | Windows |
| ---------- | ----- | ----- | ------- |
| `raw_l2_send` | AF_PACKET | `/dev/bpf`, root | Npcap, some drivers strip 802.1Q |
| `raw_l2_capture` | AF_PACKET | `/dev/bpf`, root | Npcap |
| `raw_l3_send` | raw socket | raw socket, root | Npcap |
| `socket_l4` | yes | yes | yes |
| `routing_read` | `/proc/net`, netlink | `route`, `ifconfig` | `Get-NetRoute` |
| `firewall_read` | nftables, iptables, ufw, firewalld | `pfctl` | `Get-NetFirewallRule` |

What that means in practice:

- Layer 2 active probes are Linux first. macOS injects through BPF, but some
  drivers rewrite or strip VLAN tags, so L2A06 reports INDETERMINATE there
  rather than a false negative. Windows without Npcap is capture only.
- Every layer 3 check works on all three platforms.
- CFG checks need no privilege anywhere.
- CGNAT detection, `doctor` and the offline audit run unprivileged.

A capability is resolved by attempting the operation, not by reading the
platform name. A check whose requirements are unmet is skipped before it runs,
and the report distinguishes `unsupported_platform`, which cannot be fixed, from
`insufficient_privilege`, which tells you what to run.

## Privilege

Root is not required. `doctor` reports what is held and prints the exact command
for the host it is running on, and only that one.

## Configuration

The targets file is optional. It is searched for in this order, first hit wins,
and `doctor` prints which was used:

1. `--config`
2. `NETCHECK_CONFIG`
3. `./netcheck.yaml`
4. the per-user config directory, `~/.config/netcheck/config.yaml` on Linux and
   macOS, `%APPDATA%\netcheck\config.yaml` on Windows

`examples/netcheck.example.yaml` is a complete file. `exclude` always wins over
`targets`. A prefix wider than a /24 prints the estimated packet count and
requires `--yes`; that is a warning, not a refusal. The WAN address is excluded
unless `--wan` is given.

The authorisation file, used only by the engagement profile, is described in
`AUTHORISATION.md`, with `examples/authorisation.example.yaml` as a template.

## Budgets

```
L2 frame budget    600 default    --frame-budget
L3 packet budget   5000 default   --packet-budget
Runtime            15 min         --runtime
Send rate          200 pps        --rate, hard cap 1000 in both profiles
```

The two budgets decrement independently. When one runs out the remaining checks
report UNTESTED with reason `budget_exhausted`, never ABSENT, and the JSON
carries the remaining balances.

## The four states

- `PRESENT`: a check produced positive evidence the control is enforcing.
- `ABSENT`: a check produced positive evidence it is not. This sets the exit code.
- `INDETERMINATE`: a check ran and could not tell. The detail says why.
- `UNTESTED`: nothing was learned. The detail says why not.

`UNTESTED` is not a pass, and neither is a missing capability. A control the
host could not test reports UNTESTED with a reason, never ABSENT.

Any check measuring reachability from the sending side alone returns
INDETERMINATE without a cooperating observer. A local timeout does not
distinguish a filter from a dead host, and most consumer NAT answers a hairpin
test differently from the outside world.

Exit codes: 0 no control absent, 1 one or more absent, 2 input, config or
authorisation error.

## Practical warnings

Consumer routers crash. A fragmented packet, a malformed UPnP request or a UDP
sweep will occasionally take down the web server or the whole box. The abort
watcher detects an unresponsive gateway and halts, recording which check was in
flight. That record is a finding worth writing up.

Know the reset path before starting. Export the router config, note the admin
password, find the physical reset button. L3A06 writes state to the router and a
failed cleanup leaves a mapping behind.

Home routers rate limit ICMP and UDP under load. Keep the send rate low and
treat silence as INDETERMINATE. A fast scan produces a report full of confident
wrong answers, which is worse than no report.

CGNAT is common. If the WAN address is inside 100.64.0.0/10, external inbound
testing cannot work. `doctor` detects this and L3A05 reports UNTESTED with
reason `cgnat`, never PRESENT.

Test when nobody else needs the network. The active checks will drop the
connection at least once.

## Checks

| ID | Title | Mode |
| --- | --- | --- |
| L2P01 | Discovery protocol disclosure | passive |
| L2P02 | Dynamic trunking negotiation offered | passive |
| L2P03 | Spanning tree BPDUs on an access port | passive |
| L2P04 | VTP frames observed | passive |
| L2P05 | Native VLAN is the default | passive |
| L2P06 | 802.1Q tagged frames on an access port | passive |
| L2P07 | Multiple DHCP servers observed | passive |
| L2P08 | Gratuitous ARP anomalies | passive |
| L2P09 | Name resolution poisoning surface | passive |
| L2P10 | First-hop redundancy without authentication | passive |
| L2P11 | Cleartext management protocols | passive |
| L2P12 | Router advertisements observed | passive |
| L2P13 | Service announcement surface | passive |
| L2A01 | DTP trunk negotiation | active, 1 frame |
| L2A02 | BPDU Guard verification | active, 1 frame |
| L2A03 | Port security threshold | active, up to 50, cap 500 |
| L2A04 | DHCP snooping | active, 1 frame |
| L2A05 | Dynamic ARP Inspection | active, 1 frame |
| L2A06 | Double tagging reachability | active, 3 frames |
| L2A07 | Discovery protocol injection | active, 1 frame |
| L2A08 | Client isolation | active, 2 frames |
| L2A09 | Switch management plane reachable | active, 2 frames |

L2A05, L2A06 and L2A08 need an observer and report INDETERMINATE without one.

## The observer

```
netcheck observe --interface <iface> --port 9001 --side internal
```

It records only the marker tokens the checks emit, never frame payloads, and
answers `SEEN <token>` and `SIDE`. Run it on the host or segment a check is
trying to reach.

## Status

Milestones 1 and 2 of six are built: the platform capability layer, the posture
model, config discovery, profiles, both budgets, the abort watcher, the check
registry, the report, `doctor`, packaging, continuous integration, every layer 2
check, the internal observer and lab stage 1.

The layer 3 and offline checks are not built, so their controls report UNTESTED
with reason `not_selected`.
