# Authorisation for the engagement profile

This file is for the person deciding whether to let someone attach this tool to
their network. It applies to `--profile engagement` only. The `self` profile
reads no authorisation file, because it is for a network the operator owns, and
its reports say plainly that they are not a client deliverable.

## What the gate checks

Before a single frame or packet is sent, all of the following must pass. There
is no override flag for any of them.

1. Every field present and non-empty. A missing field is a hard stop.
2. Today falls between `issued` and `expires` inclusive. Outside that window the
   tool prints the window and exits.
3. `--tests` names specific checks. `--all` is rejected in this profile.
4. Every target subnet sits inside `scope_subnets`. Containment is exact: no
   wildcards, and no supernet matching. A target wider than the scope fails.
5. The `segment` string is printed and must be retyped exactly, unless
   `--confirm-segment` supplies it. This is what stops a probe running on the
   wrong port after a break.
6. The SHA-256 of the authorisation file is recorded in the report, so the
   report and the permission it was run under stay tied together.

## What changes in this profile

Budget caps become ceilings. In `self` a flag may raise a budget; in
`engagement` a flag may only lower it. The send rate is capped at 1000 packets
per second in both profiles regardless, and in `engagement` it cannot be raised
above the configured default either.

The hard limits listed in the README apply identically in both profiles. A
profile changes what is adjustable, never what is permitted.

## Template

```yaml
client: Example Ltd
engagement: Internal network assessment
authorised_by: Jane Mwangi, Head of Infrastructure
contact: jane@example.co.ke
issued: 2026-09-01
expires: 2026-09-14
segment: Floor 3 user VLAN, patch panel port 3-14
scope_subnets:
  - 10.30.0.0/16
```

- `client` and `engagement` identify the work.
- `authorised_by` and `contact` are the person who can stop the test, and how to
  reach them while it is running.
- `issued` and `expires` bound the window in whole days, inclusive.
- `segment` describes the one port and segment covered. It is printed back and
  must be retyped, so write it the way the operator will read it off the patch
  panel.
- `scope_subnets` lists every network in scope. A target outside them stops the
  run.
