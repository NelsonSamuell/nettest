# Architecture

How the tool is put together. The first version of this document was a survey of
what the layer 3 work had to fit into. It is kept current as that work lands,
with changes noted per milestone at the end.

## Package layout

```
l2check/
  __init__.py      version only
  cli.py           argparse dispatch, one run_* function per subcommand
  models.py        observation records and the Capture aggregate
  frames.py        pure frame builders, no sockets
  parse.py         one parser per protocol, plus the dispatch table
  listen.py        passive capture, interface facts
  wireless.py      read-only radio facts via iw
  doctor.py        environment check
  posture.py       control names, profiles, states, derivation, findings
  session.py       ActiveSession, the budgets and the run limits
  l3/targets.py    the targets file
  observe.py       cooperating listener and its client
  report.py        text and JSON rendering
  probes/
    __init__.py    listen_after_send, registry(), run_selected()
    trunking.py    L2A01, L2A07
    spanning_tree.py L2A02
    port_security.py L2A03
    dhcp.py        L2A04
    arp.py         L2A05
    vlan_hop.py    L2A06
    segment.py     L2A08, L2A09, L2A10
bin/l2check        launcher that runs .venv/bin/l2check
setup.sh           one time bootstrap
```

The layout is flat: one module per concern, probes in a subpackage. There is no
plugin loader and no dynamic discovery.

## How checks are registered

Two separate mechanisms, and they are deliberately kept in step.

Passive checks are not registered at all. `parse.PARSERS` is a tuple of
`(function, capture_field_name)` pairs that `parse.parse_frame` walks for every
packet. A parser returns a record or None. Adding a passive check means adding a
parser, a record type in `models.py`, a list field on `Capture`, and an entry in
`PARSERS`. The check ID (`L2P07`) exists only in the basis and finding strings;
nothing dispatches on it.

Active checks are registered twice, and a test asserts the two agree:

- `session.ACTIVE_CHECKS` is `L2_ACTIVE_CHECKS + L3_ACTIVE_CHECKS`. `parse_tests`
  validates `--tests` against it. `CFG_CHECKS` is separate: those send nothing.
- `probes.registry()` maps ID to a `run(session, capture) -> ProbeResult`
  callable, importing the probe modules lazily to avoid a circular import.

`tests/test_caps.py` asserts every registered check is a known ID, and every
layer 2 ID has exactly one implementation. The registry may lag the ID list while
a layer is being built, never lead it: `run_selected` skips an unimplemented ID.

`probes.run_selected` sorts the selected IDs by their position in
`ACTIVE_CHECKS`, so declaration order is execution order. There is no dependency
graph today.

## How the frame budget is enforced

The invariant is that `ActiveSession` is the only route to the network. Probes
receive a session and can only ask it to act; they never open a socket.

`ActiveSession.send(frames)` and `ActiveSession.connect(address, port)` both:

1. Refuse unless `started` is True.
2. `check_runtime()`, raising `CapExceeded` past `runtime_cap`.
3. `check_state()`, raising `StateChanged` if the link changed state or the
   gateway changed MAC, unless a probe declared it expected. The check in flight
   is recorded in `aborted_during`.
4. Spend from `Budget`, all or nothing. Layer 2 and layer 3 decrement separately.
5. Pace to `rate_pps`, the one limit no flag can raise.
6. Hand off to the injectable `sender` or `connector`.

A TCP connection is charged `CONNECT_FRAME_COST` (3) against the same budget, so
a transport level probe cannot reach the network through an uncounted path.

Two AST tests in `tests/test_caps.py` enforce the invariant structurally: no
module under `probes/` may import a scapy sender or `socket`, and any `.send`,
`.connect` or `.connect_ex` attribute call must be on a name literally called
`session`.

`probes.run_selected` catches `CapExceeded` and `LinkStateChanged`, reports the
reason and stops the remaining checks rather than continuing blind.

## How the posture table is built

`posture.Control` is `(name, state, basis, detail)`. States are the four strings
`PRESENT`, `ABSENT`, `INDETERMINATE`, `UNTESTED`.

Controls are grouped into profiles. `WIRED_CONTROLS + COMMON_CONTROLS` and
`WIRELESS_CONTROLS + COMMON_CONTROLS`, selected by `profile_for(capture)`, which
checks whether the interface is wireless. `Posture.new(profile)` seeds every
control in that profile as `UNTESTED`.

`Posture.set` accepts a control outside the current profile and adds it, so a
probe aimed at the other medium still reports. It raises `KeyError` for a name
not in `CONTROL_NAMES` at all.

Construction is a pipeline:

1. `Posture.new(profile)` - everything UNTESTED.
2. `apply_passive(posture, capture)` - passive evidence. This can only move a
   control to ABSENT or INDETERMINATE, never PRESENT, because seeing no BPDUs
   does not mean BPDU Guard is on.
3. `apply_wireless(posture, capture.wireless)` - read-only radio facts. These
   may report PRESENT, because nothing had to be transmitted to learn them.
4. `posture.apply(result)` per `ProbeResult` from the active run.

`findings(capture)` builds the severity list separately from the control table.
A check can produce a finding without owning a control, and several do.

`exit_code()` is 1 if any control is ABSENT, else 0.

## How --json output is shaped

`report.to_dict` produces, in order: `profile`, `controls`, `findings`,
`summary`, `frames_sent`, then optionally `capture` and `wireless`.

`capture` carries `interface`, `duration`, `frames_seen`, `parse_errors`,
`truncated` (checks that hit the per-check record cap) and `records`, a
per-parser count. `report.from_dict` rebuilds a posture and findings for
`posture --from`, reading `profile` with a `wired` default.

`Capture.add(name, record)` deduplicates on the record's own field values and
caps each list at `MAX_RECORDS_PER_CHECK` (2000), recording the name in
`capture.truncated`. Counters that must survive deduplication, currently
`gratuitous_arps`, are separate integer fields.

## How observe talks to probe

A line protocol over TCP, deliberately tiny.

`observe.Observer` sniffs with `store=False` and records only marker tokens:
anything matching `L2CHECK-[0-9A-F]{8}` found in frame bytes, plus `ARP:<ip>`
for gratuitous ARPs. It serves one query per connection, `SEEN <token>\n`,
answering `YES <token>` or `NO <token>`.

`observe.ask_observer(endpoint, token)` is the client. It returns True, False,
or None when the observer could not be reached, and the three outcomes are
distinct in every probe that uses it: None gives INDETERMINATE with
"observer unreachable", False gives PRESENT, True gives ABSENT.

The observer has no concept of sides or NAT boundaries today.

## Properties to preserve

- `UNTESTED` never collapses into `ABSENT` or `PRESENT`.
- No observer means `INDETERMINATE`, never a claimed negative.
- The passive path transmits nothing and needs no configuration.
- Records hold protocol metadata only; no payload of a frame that is not to or
  from this interface is retained or written.
- Every parser call is guarded, and a failure increments `parse_errors` rather
  than aborting the capture.
- `ActiveSession` is the only route to the network, and it counts.


## Changes by milestone

**Milestone 1, foundations.** `authorisation.py` became `session.py`. The
`Authorisation` dataclass, the YAML validator, the SHA-256 recording, the date
window and the retyped segment prompt are gone, with `AUTHORISATION.md` and its
tests. `NotAuthorised` became `SessionNotStarted`, `AuthorisationError` became
`ConfigError`, `LinkStateChanged` became `StateChanged`, and
`session.authorise(auth, tests)` became `session.start(tests)`.

Caps became defaults with flags that raise them, except the send rate, capped in
code at 1000 pps for measurement accuracy. `Budget` holds the two independent
allowances. `l3/targets.py` reads the optional targets file.

`netcheck` is the console script; `l2check` is an alias appending `--layers l2`.
The report gained a Markdown writer, a `diff` between saved runs, layer grouping,
and empty-for-now matrix and device sections. `Capture` gained `packets_seen`.
