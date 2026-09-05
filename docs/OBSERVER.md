# Running an observer

Eleven checks cannot answer anything without a vantage point somewhere other
than where the tool is running. Without one they report INDETERMINATE and say
so, which is correct but not useful. This is how to give them one.

```
netcheck observe --interface <iface> --port 9001 --side internal
netcheck observe --interface <iface> --port 9001 --side external
```

## The two sides

An **internal** observer sits on the segment a check is trying to reach. It
watches for the marker tokens the checks emit and answers whether it saw one.
That is enough for the checks measuring whether something crossed a boundary
inside your network.

An **external** observer sits outside the NAT boundary. It does the same, and it
will additionally attempt a connection on request. That second ability is the
only honest way to ask whether something is reachable from the internet: a
hairpin test from inside gives a different answer on most consumer NAT, so the
tool refuses to substitute one.

An internal observer refuses `CONNECT` with an error rather than answering it,
so a check needing an outside vantage point cannot silently get an inside one.

## Which checks need which

| Check | Needs | Without it |
| --- | --- | --- |
| L2A05 Dynamic ARP Inspection | internal, on the segment | INDETERMINATE |
| L2A06 double tagging | internal, on the target VLAN | INDETERMINATE |
| L2A08 client isolation | internal, on the other host | INDETERMINATE |
| L3A05 inbound IPv4 | external, plus `--wan` | INDETERMINATE |
| L3A07 egress filtering | external, plus `external.test_host` | INDETERMINATE |
| L3A08 inbound IPv6 | external | INDETERMINATE |
| L3A09 guest segmentation | internal, on the LAN, run from guest | INDETERMINATE |
| L3A11 resolver scoping | external, plus `--wan` | INDETERMINATE |
| L3A13 anti-spoofing | external, plus `external.test_host` | INDETERMINATE |
| L3A14 fragment handling | external, plus `external.test_host` | INDETERMINATE |
| L3A15 source routing | external, plus `external.test_host` | INDETERMINATE |

## An external observer on a small server

The cheapest instance any provider sells is enough. It needs a public IPv4
address, a public IPv6 address if you want L3A08 to mean anything, and Python
3.11.

```
pipx install git+<url>
sudo netcheck observe --interface <iface> --port 9001 --side external
```

Then in your targets file at home:

```yaml
observers:
  external: observer.example.net:9001
external:
  test_host: observer.example.net
  echo_service: https://example.net/ip
```

`test_host` should be the same machine, so the egress and anti-spoofing checks
send to somewhere the observer is actually watching.

Restrict the port to your own address. The observer holds nothing sensitive, but
an open `CONNECT` service is a small open proxy for connection testing:

```
sudo nft add rule inet filter input tcp dport 9001 ip saddr != <your address> drop
```

## What the observer records

Marker tokens and nothing else. It matches `NETCHECK-` followed by eight hex
characters in frame bytes, plus the address from a gratuitous ARP, and keeps a
set of those strings. It never writes a payload, never stores a packet, and
never writes to disk. Stopping it discards everything it held.

## The protocol

One line per connection, so it can be tested by hand:

```
$ printf 'SIDE\n' | nc observer.example.net 9001
SIDE external

$ printf 'SEEN NETCHECK-DEADBEEF\n' | nc observer.example.net 9001
NO NETCHECK-DEADBEEF

$ printf 'CONNECT 198.51.100.4 443\n' | nc observer.example.net 9001
open 198.51.100.4 443
```

`CONNECT` answers `open`, `closed` or `filtered`. Those are three different
findings and are never collapsed into two: refused means the host answered and
nothing is listening, filtered means something dropped the packet.

## When the observer cannot be reached

The check reports INDETERMINATE with a basis saying the observer did not answer,
never a negative. An observer that did not answer is not an observer that saw
nothing.
