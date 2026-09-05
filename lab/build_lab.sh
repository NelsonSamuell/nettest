#!/bin/sh
# A throwaway layer 2 topology using Open vSwitch and network namespaces.
# Stage 1 covers the layer 2 checks. --teardown removes everything it made.
set -eu

BRIDGE=ncbr0
NS1=nch1
NS2=nch2
ACCESS_TAP=ncaccess
TRUNK_TAP=nctrunk

VLAN1=10
VLAN2=20
NATIVE_VLAN=1

# Stage 2, layer 3. A NAT gateway sits between an inside and an outside, so
# egress, inbound filtering and the service checks have something real to run
# against.
GUEST_BRIDGE=ncbr1
NS_GW=ncgw
NS_IN=ncin
NS_OUT=ncout
NS_GUEST=ncguest
NS_V6=ncv6

INSIDE=10.20.0
OUTSIDE=10.30.0
GUEST=10.40.0
V6_PREFIX=fd00:dead:beef

say() { printf '%s\n' "$*"; }

require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        say "this script needs root: it creates a bridge and network namespaces" >&2
        exit 1
    fi
}

teardown() {
    ovs-vsctl --if-exists del-br "$BRIDGE"
    ovs-vsctl --if-exists del-br "$GUEST_BRIDGE"
    for ns in "$NS1" "$NS2" "$NS_GW" "$NS_IN" "$NS_OUT" "$NS_GUEST" "$NS_V6"; do
        ip netns pids "$ns" 2>/dev/null | xargs -r kill 2>/dev/null || true
        ip netns del "$ns" 2>/dev/null || true
    done
    for link in "$NS1-br" "$NS2-br" "$ACCESS_TAP" "$TRUNK_TAP" "$NS_GUEST-br"; do
        ip link del "$link" 2>/dev/null || true
    done
    say "removed both bridges, every namespace and their veth pairs"
}

# A namespace with one veth end inside it and the other on the bridge.
add_host() {
    ns=$1
    address=$2
    ip netns add "$ns"
    ip link add "$ns-br" type veth peer name host0 netns "$ns"
    ip link set "$ns-br" up
    ip -n "$ns" link set lo up
    ip -n "$ns" link set host0 up
    ip -n "$ns" addr add "$address" dev host0
    ovs-vsctl add-port "$BRIDGE" "$ns-br"
}

# A veth end left in the root namespace, so netcheck can be pointed at it.
add_tap() {
    tap=$1
    ip link add "$tap" type veth peer name "$tap-p"
    ip link set "$tap" up
    ip link set "$tap-p" up
    ovs-vsctl add-port "$BRIDGE" "$tap-p"
}

# A routed pair: one veth end in each namespace, addressed and up.
link_pair() {
    left=$1; right=$2; left_ip=$3; right_ip=$4
    ip link add "$left-$right" type veth peer name "$right-$left"
    ip link set "$left-$right" netns "$left"
    ip link set "$right-$left" netns "$right"
    ip -n "$left" addr add "$left_ip" dev "$left-$right"
    ip -n "$left" link set "$left-$right" up
    ip -n "$right" addr add "$right_ip" dev "$right-$left"
    ip -n "$right" link set "$right-$left" up
}

# A minimal SSDP responder advertising an IGD, so L3A06 has something to find.
# It answers the search and serves a description with a control URL; the SOAP
# endpoint accepts AddPortMapping and DeletePortMapping and remembers neither,
# which is the known-bad case the check should report as ABSENT.
start_igd() {
    ip netns exec "$NS_GW" python3 - "$INSIDE.1" <<'PYTHON' &
import http.server, socket, sys, threading

host = sys.argv[1]
DESC = ('<?xml version="1.0"?><root><device><serviceList><service>'
        '<controlURL>/ctl</controlURL></service></serviceList></device></root>')

class Handler(http.server.BaseHTTPRequestHandler):
    def _send(self, body):
        self.send_response(200)
        self.send_header("Content-Type", "text/xml")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body.encode())
    def do_GET(self):
        self._send(DESC)
    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0) or 0))
        self._send("<?xml version=\"1.0\"?><ok/>")
    def log_message(self, *args):
        pass

threading.Thread(
    target=http.server.HTTPServer((host, 5000), Handler).serve_forever, daemon=True
).start()

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(("", 1900))
sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                socket.inet_aton("239.255.255.250") + socket.inet_aton("0.0.0.0"))
reply = ("HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=120\r\n"
         "LOCATION: http://%s:5000/desc.xml\r\n"
         "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n" % host)
while True:
    data, peer = sock.recvfrom(2048)
    if b"M-SEARCH" in data:
        sock.sendto(reply.encode(), peer)
PYTHON
}

# A minimal DNS server answering one name with a private address, which is what
# L3A10 needs in milestone 6.
start_dns() {
    ip netns exec "$NS_GW" python3 - <<'PYTHON' &
import socket, struct

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("", 53))
while True:
    query, peer = sock.recvfrom(512)
    if len(query) < 12:
        continue
    header = struct.pack("!HHHHHH", struct.unpack("!H", query[:2])[0],
                         0x8180, 1, 1, 0, 0)
    body = query[12:]
    end = body.find(b"\x00") + 5
    answer = body[:end] + b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4)
    sock.sendto(header + body[:end] + answer[end:] + b"\x0a\x14\x00\x63", peer)
PYTHON
}

build_l3() {
    for ns in "$NS_GW" "$NS_IN" "$NS_OUT" "$NS_V6"; do
        ip netns add "$ns"
        ip -n "$ns" link set lo up
    done

    link_pair "$NS_GW" "$NS_IN" "$INSIDE.1/24" "$INSIDE.10/24"
    link_pair "$NS_GW" "$NS_OUT" "$OUTSIDE.1/24" "$OUTSIDE.10/24"
    link_pair "$NS_GW" "$NS_V6" "$V6_PREFIX::1/64" "$V6_PREFIX::10/64"

    ip netns exec "$NS_GW" sysctl -qw net.ipv4.ip_forward=1
    ip netns exec "$NS_GW" sysctl -qw net.ipv6.conf.all.forwarding=1
    ip -n "$NS_IN" route add default via "$INSIDE.1"
    ip -n "$NS_OUT" route add default via "$OUTSIDE.1"
    ip -n "$NS_V6" route add default via "$V6_PREFIX::1"

    # The gaps below are deliberate, one per check, so each has a known-good and
    # a known-bad case. Read this block as the answer key.
    ip netns exec "$NS_GW" nft -f - <<NFT
table inet filter {
    chain input {
        type filter hook input priority 0; policy accept;
    }
    chain forward {
        type filter hook forward priority 0; policy accept;
        # Inbound from outside is dropped except on 8080: the gap L3A05 finds.
        iifname "$NS_GW-$NS_OUT" tcp dport != 8080 ct state new drop
        # No IPv6 rule at all. Consumer firewalls are frequently v4 only, and
        # L3A08 exists to find exactly that.
    }
    chain postrouting {
        type nat hook postrouting priority 100; policy accept;
        oifname "$NS_GW-$NS_OUT" masquerade
    }
}
NFT

    start_igd
    start_dns
}

build_guest() {
    ovs-vsctl add-br "$GUEST_BRIDGE"
    ip link set "$GUEST_BRIDGE" up
    ip netns add "$NS_GUEST"
    ip -n "$NS_GUEST" link set lo up
    ip link add "$NS_GUEST-br" type veth peer name guest0 netns "$NS_GUEST"
    ip link set "$NS_GUEST-br" up
    ip -n "$NS_GUEST" addr add "$GUEST.10/24" dev guest0
    ip -n "$NS_GUEST" link set guest0 up
    ovs-vsctl add-port "$GUEST_BRIDGE" "$NS_GUEST-br"
}

build() {
    ovs-vsctl add-br "$BRIDGE"
    # RSTP makes the bridge emit BPDUs, which is what L2P03 looks for and what
    # L2A02 needs a root priority from before it will run.
    ovs-vsctl set bridge "$BRIDGE" rstp_enable=true
    ip link set "$BRIDGE" up

    add_host "$NS1" 192.0.2.1/24
    add_host "$NS2" 198.51.100.1/24

    # An access port carries one VLAN and sends frames untagged, so "tag" alone
    # is the whole configuration.
    ovs-vsctl set port "$NS1-br" tag="$VLAN1"
    ovs-vsctl set port "$NS2-br" tag="$VLAN2"

    add_tap "$ACCESS_TAP"
    add_tap "$TRUNK_TAP"
    ovs-vsctl set port "$ACCESS_TAP-p" tag="$VLAN1"

    # A trunk carries several VLANs tagged. native-untagged means frames in the
    # native VLAN cross it with no tag at all, which is the condition double
    # tagging depends on, so the lab reproduces it on purpose.
    ovs-vsctl set port "$TRUNK_TAP-p" \
        vlan_mode=native-untagged \
        tag="$NATIVE_VLAN" \
        trunks="$VLAN1,$VLAN2"

    build_l3
    build_guest

    say "bridge $BRIDGE up, RSTP enabled"
    say "  access port $ACCESS_TAP in VLAN $VLAN1"
    say "  trunk port  $TRUNK_TAP, native VLAN $NATIVE_VLAN, trunks $VLAN1,$VLAN2"
    say "  namespaces  $NS1 (VLAN $VLAN1) and $NS2 (VLAN $VLAN2)"
    say "routed topology"
    say "  $NS_GW    NAT gateway, inside $INSIDE.1, outside $OUTSIDE.1"
    say "  $NS_IN    inside host $INSIDE.10, run netcheck here"
    say "  $NS_OUT   outside host $OUTSIDE.10, run the external observer here"
    say "  $NS_V6    global IPv6 $V6_PREFIX::10, no inbound v6 filter"
    say "  $NS_GUEST guest segment $GUEST.10 on $GUEST_BRIDGE"
    say "  a UPnP IGD responder and a DNS server run in $NS_GW"
    say ""
    say "try:  netcheck listen --interface $TRUNK_TAP --duration 30"
    say "      ip netns exec $NS_IN netcheck probe --active --tests L3A02"
}

require_root
case "${1:-}" in
    --teardown) teardown ;;
    "") teardown >/dev/null 2>&1 || true; build ;;
    *) say "usage: $0 [--teardown]" >&2; exit 1 ;;
esac
