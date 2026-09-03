# Running an observer

Six checks cannot answer anything without a vantage point somewhere other than
where the tool is running. Without one they report `INDETERMINATE` and say so,
which is correct but not useful. This is how to give them one.

```
netcheck observe --interface eth0 --port 9001 --side internal
netcheck observe --interface eth0 --port 9001 --side external
```

## The two sides

An **internal** observer sits on the target segment. It watches for the marker
tokens the checks emit and answers whether it saw one. That is all it does, and
it is enough for the checks that test whether something crossed a boundary
inside your network.

An **external** observer sits outside the NAT boundary. It does the same, and it
will additionally attempt a connection on request. That second ability is the
only honest way to ask whether something is reachable from the internet: a
hairpin test from inside gives a different answer on most consumer NAT, so the
tool refuses to substitute one.

## Which checks need which

| Check | Needs | Without it |
| --- | --- | --- |
| L3A05 inbound IPv4 | external, plus `--wan` | `INDETERMINATE` |
| L3A07 egress filtering | external, plus `external.test_host` | `INDETERMINATE` |
| L3A08 inbound IPv6 | external | `INDETERMINATE` |
| L3A09 guest segmentation | internal, on the LAN, run from guest | `INDETERMINATE` |
| L3A11 resolver scoping | external, plus `--wan` | `INDETERMINATE` |
| L3A13 anti-spoofing | external, plus `external.test_host` | `INDETERMINATE` |
| L3A14 fragment handling | external, plus `external.test_host` | `INDETERMINATE` |
| L3A15 source routing | external, plus `external.test_host` | `INDETERMINATE` |
| L2A05 ARP inspection | internal | `INDETERMINATE` |
| L2A06 double tagging | internal | `INDETERMINATE` |

## An external observer on a VPS

The cheapest instance any provider sells is enough. It needs a public IPv4
address, a public IPv6 address if you want L3A08 to mean anything, and Python.

```
git clone <your repo> netcheck && cd netcheck
./setup.sh
sudo netcheck observe --interface eth0 --port 9001 --side external
```

Then in your targets file at home:

```yaml
observers:
  external: 203.0.113.9:9001
external:
  test_host: 203.0.113.9
  echo_service: https://your-own-echo-endpoint
```

`test_host` should be the same machine, so the egress and anti-spoofing checks
send to somewhere the observer is actually watching.

Open port 9001 to your home address only. The observer answers anyone who can
reach it, and while it holds nothing sensitive, an open `CONNECT` service is a
small open proxy for connection testing. Restrict it:

```
sudo nft add rule inet filter input tcp dport 9001 ip saddr != <your home IP> drop
```

## What the observer records

Marker tokens and nothing else. It matches `L2CHECK-` followed by eight hex
characters in frame bytes, plus the address from a gratuitous ARP, and keeps a
set of those strings. It never writes a payload, never stores a packet, and
never writes to disk. Stopping it discards everything it held.

## The protocol

One line per connection, so you can test it by hand:

```
$ printf 'SIDE\n' | nc 203.0.113.9 9001
SIDE external

$ printf 'SEEN L2CHECK-DEADBEEF\n' | nc 203.0.113.9 9001
NO L2CHECK-DEADBEEF

$ printf 'CONNECT 198.51.100.4 443\n' | nc 203.0.113.9 9001
open 198.51.100.4 443
```

`CONNECT` answers `open`, `closed` or `filtered`, which are three different
findings and are never collapsed into two. An internal observer refuses
`CONNECT` with an error rather than answering it, so a check that needs an
external vantage point cannot silently get an internal one.

## When the observer cannot be reached

The check reports `INDETERMINATE` with basis "observer unreachable", never a
negative. An observer that did not answer is not an observer that saw nothing.
