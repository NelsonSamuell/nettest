# Authorisation for active probes

This file is for the person deciding whether to let someone plug this tool into
their switch. It describes exactly what each active probe puts on the wire, how
many frames, what happens in the worst case if the probe succeeds, and why none
of them can take the segment down.

Passive mode sends nothing at all and is not covered here. Only `l2check probe`
transmits, and it refuses to start without a signed authorisation file.

## Global limits

These are enforced in code, across the whole run, not per probe:

| Limit | Value |
| --- | --- |
| Total frames sent, all probes combined | 600 |
| Total runtime of the active phase | 10 minutes |
| MAC addresses introduced by L2A03 | 50 by default, 500 absolute ceiling |
| Neighbours asked by L2A08 | 25 by default, 50 absolute ceiling |
| TCP connections | charged as 3 frames each against the same 600 |
| Probes run | only those named in `--tests`, one at a time |

There is no flag that raises any of these and no "run everything" option. If
the interface link state changes when no probe was expecting it, the run stops
immediately and the remaining probes do not execute.

## The probes

### L2A01, dynamic trunking negotiation

**Sends** one DTP frame offering to negotiate a trunk, then listens for five
seconds.

**If it succeeds** the switch answers and the report records that the port is
in a dynamic mode.

**Why it cannot cause an outage** the probe never sends the tagged traffic that
would follow a real negotiation, and it never brings a trunk up. A DTP answer
is a message, not a state change; the port is in the same mode afterwards as it
was before. Nothing on the segment is interrupted by one frame.

### L2A02, BPDU Guard verification

**Sends** one 802.1D configuration BPDU, then watches the interface for fifteen
seconds.

**If it succeeds** the port is err-disabled by BPDU Guard, which is the
positive result. Your port goes down and comes back when you clear it or when
`errdisable recovery` runs. That reaction is the finding.

**Why it cannot change the topology** a root election compares the two byte
bridge priority before anything else, and lower wins. The probe reads the root
priority already in use on the segment from the passive capture and advertises
the next valid priority strictly above it, so the frame loses the election
before the bridge MAC address is even looked at. The topology change flag is
left clear, so it cannot trigger a CAM flush either.

If the passive capture saw no BPDU, there is no priority to be worse than, and
the probe refuses to run rather than guessing a value. That refusal is reported
as `UNTESTED`, not as an absent control.

### L2A03, port security threshold

**Sends** up to 50 ARP probe frames, each with a different source MAC address,
one every 200 milliseconds. The ceiling is 500 and cannot be raised.

**If it succeeds** the port shuts down at the configured MAC limit and the
report records the count. Again, that reaction is the finding.

**Why it is not a CAM overflow** a CAM overflow works by filling the switch's
address table faster than it can age, which takes tens of thousands of
addresses at line rate. This introduces at most 500, at five per second. The
frames are RFC 5227 ARP probes with a sender address of 0.0.0.0, so they claim
no address and create no ARP entry on any host that receives them.

### L2A04, DHCP snooping

**Sends** one DHCP discover, then listens for five seconds.

**If it succeeds** one or more servers answer with an offer, and the report
records how many and which.

**Why it cannot exhaust the pool** a discover asks what is available. The probe
never sends a request, so no address is ever bound; an offer that is not
requested is released by the server when it times out, usually in seconds. One
discover cannot consume a lease.

### L2A05, Dynamic ARP Inspection

**Sends** one gratuitous ARP for an address you supply with `--test-ip`, plus
two pre-flight frames that check the address is genuinely unused.

**If it succeeds** the announcement reaches the target segment and a
cooperating observer you run there confirms it.

**Why it cannot poison anything** the address is one you have confirmed is
unused, and the probe refuses to run if it answers the pre-flight check or if
it appeared during the passive capture. There is one announcement, not a
sustained stream, and the tool never answers an ARP request, never forwards a
frame, and never relays traffic for another host. Nothing is drawn away from
anything, because nothing was there.

Without an observer the result is `INDETERMINATE`, since nothing observable
happens at the sending port either way.

### L2A06, double tagging reachability

**Sends** three ICMP echo requests carrying two 802.1Q tags, toward a VLAN and
address you supply.

**If it succeeds** the frames cross into the target VLAN and your observer on
that segment sees them.

**Why it cannot cause harm** three echo requests. The attack is one way by
construction, so nothing comes back and no session is established. Without an
observer confirming arrival, the tool reports `INDETERMINATE` and explicitly
does not claim the control is present.

### L2A07, discovery protocol injection

**Sends** one LLDP frame with the identifier `l2check` and a 30 second time to
live.

**If it succeeds** the frame is accepted or reflected, showing the switch does
not filter injected discovery traffic.

**Why it cannot cause harm** LLDP is advisory. A neighbour entry created by
this frame ages out 30 seconds after the probe finishes, and no switch changes
its forwarding behaviour because of one.

### L2A08, client isolation

**Sends** up to 25 ARP requests, one to each of the first 25 addresses in the
local subnet, at five per second. The ceiling is 50 and it refuses to run on a
network larger than a /16.

**If it succeeds** one or more neighbours answer, and the report records that
stations on this segment can reach each other.

**Why it cannot cause harm** an ARP request is the frame every host sends before
any conversation on a local network. A laptop joining your Wi-Fi sends more of
them than this in its first second. The probe never sends a second frame to an
address that answered, never connects to anything it found, and records only the
address and MAC of who replied.

### L2A09, UPnP gateway reachability

**Sends** one SSDP M-SEARCH for an internet gateway device, then listens for
four seconds.

**If it succeeds** the router answers, showing that any host on the segment can
ask it to open a port through the firewall.

**Why it cannot cause harm** it is the same discovery message a games console or
media player sends when it starts. The probe never sends the follow-up SOAP
request that would actually map a port, so nothing is opened. It records which
addresses answered and nothing else.

### L2A10, gateway management exposure

**Sends** one TCP connection to each of five management ports on the default
gateway: 23, 21, 80, 8080 and 443. Each is closed the instant it is accepted.

**If it succeeds** the gateway answers on a cleartext management port, and the
report records which.

**Why it cannot cause harm** the probe completes a TCP handshake and closes it.
It sends no request, offers no credentials, reads no banner and fetches no page.
Five connections is fewer than a browser opens loading one page, and the finding
is established by the handshake alone: a device either answers on port 23 or it
does not. Nothing is authenticated to and nothing is changed.

Connections are charged against the same 600 frame budget as raw sends, at three
frames each, so this probe cannot reach the network through a path the caps do
not count.

## The wireless checks send nothing

L2P15, L2P16 and L2P17 read the access point's advertised security from the
kernel's cached scan results. No frame is transmitted, no scan is triggered, and
the interface is not reconfigured. They run in passive mode and need no
authorisation.

The tool does not use monitor mode, does not send deauthentication frames, does
not capture handshakes, and does not inject at the radio layer. Monitor mode
would drop the connection outright. This means the wireless findings describe
what the access point advertises, not how it behaves under attack, and the
report says so rather than implying more.

## What the tool never does

No flag enables any of these, and no code implementing them exists:

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

The passive listener records protocol metadata only. It never writes a frame to
a pcap or a log. Where a first hop redundancy protocol carries an
authentication string, the tool records that one was present and never records
its value, not even a vendor default.

## What the gate checks

Before the first frame is sent, `l2check probe` requires all of:

1. An authorisation file with every field below present and non-empty.
2. Today's date inside the issued to expires window, inclusive. Outside it the
   tool prints the window and exits. There is no override flag.
3. `--tests` naming specific probe identifiers. An empty or absent list stops
   the run.
4. The `segment` string retyped exactly, either at a prompt or through
   `--confirm-segment`. This is the check that stops a probe running on the
   wrong port after a break.

The SHA-256 of the authorisation file is recorded in the report, so the report
and the permission it was run under stay tied together.

## Authorisation template

```yaml
client: Example Ltd
engagement: Internal network assessment
authorised_by: Jane Mwangi, Head of Infrastructure
contact: jane@example.co.ke
issued: 2026-09-01
expires: 2026-09-14
segment: Floor 3 user VLAN, patch panel port 3-14
change_window: true
```

Every field is required.

- `client` and `engagement` identify the work.
- `authorised_by` and `contact` are the person who can stop the test, and how
  to reach them while it is running.
- `issued` and `expires` bound the window in whole days, inclusive.
- `segment` describes the one port and segment covered. It is printed back and
  must be retyped, so write it the way the operator will read it off the patch
  panel.
- `change_window` records whether the test falls inside an agreed change
  window. It is written into the report either way.
