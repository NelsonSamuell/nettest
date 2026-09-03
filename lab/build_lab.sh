#!/bin/sh
# Build a throwaway layer 2 topology with Open vSwitch and network namespaces.
# One bridge, two access ports in different VLANs, one trunk, RSTP enabled.
set -eu

BRIDGE=l2br0
NS1=l2h1
NS2=l2h2
ACCESS_TAP=l2access
TRUNK_TAP=l2trunk

VLAN1=10
VLAN2=20
NATIVE_VLAN=1

# Layer 3 topology. A NAT gateway namespace sits between an inside and an
# outside namespace, so egress, anti-spoofing and inbound filtering have
# something real to run against.
GUEST_BRIDGE=l2br1
NS_GW=l3gw
NS_IN=l3in
NS_OUT=l3out
NS_GUEST=l3guest
NS_V6=l3v6

INSIDE_NET=10.20.0
OUTSIDE_NET=10.30.0
GUEST_NET=10.40.0
V6_PREFIX=fd00:dead:beef

require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "this script needs root: it creates a bridge and network namespaces" >&2
        exit 1
    fi
}

teardown() {
    ovs-vsctl --if-exists del-br "$BRIDGE"
    ovs-vsctl --if-exists del-br "$GUEST_BRIDGE"
    for ns in "$NS1" "$NS2" "$NS_GW" "$NS_IN" "$NS_OUT" "$NS_GUEST" "$NS_V6"; do
        ip netns del "$ns" 2>/dev/null || true
    done
    for link in "$NS1-br" "$NS2-br" "$ACCESS_TAP" "$TRUNK_TAP" "$NS_GUEST-br"; do
        ip link del "$link" 2>/dev/null || true
    done
    echo "removed both bridges, all namespaces and their veth pairs"
}

# A namespace with one veth end inside it and the other on the bridge.
add_host() {
    ns=$1
    address=$2
    ip netns add "$ns"
    ip link add "$ns-br" type veth peer name eth0 netns "$ns"
    ip link set "$ns-br" up
    ip -n "$ns" link set lo up
    ip -n "$ns" link set eth0 up
    ip -n "$ns" addr add "$address" dev eth0
    ovs-vsctl add-port "$BRIDGE" "$ns-br"
}

# A veth end left in the root namespace, so l2check can be pointed at it.
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

build_l3() {
    for ns in "$NS_GW" "$NS_IN" "$NS_OUT" "$NS_V6"; do
        ip netns add "$ns"
        ip -n "$ns" link set lo up
    done

    link_pair "$NS_GW" "$NS_IN" "$INSIDE_NET.1/24" "$INSIDE_NET.10/24"
    link_pair "$NS_GW" "$NS_OUT" "$OUTSIDE_NET.1/24" "$OUTSIDE_NET.10/24"
    link_pair "$NS_GW" "$NS_V6" "$V6_PREFIX::1/64" "$V6_PREFIX::10/64"

    ip netns exec "$NS_GW" sysctl -qw net.ipv4.ip_forward=1
    ip netns exec "$NS_GW" sysctl -qw net.ipv6.conf.all.forwarding=1
    ip -n "$NS_IN" route add default via "$INSIDE_NET.1"
    ip -n "$NS_OUT" route add default via "$OUTSIDE_NET.1"
    ip -n "$NS_V6" route add default via "$V6_PREFIX::1"

    # The rule set below has deliberate gaps, one per check, so each L3A test
    # has a known good and a known bad case. Read it as the answer key.
    ip netns exec "$NS_GW" nft -f - <<NFT
table inet filter {
    chain forward {
        type filter hook forward priority 0; policy accept;
        # Inbound from outside to inside is dropped except on 8080, which is
        # the intentional gap L3A05 should find.
        iifname "$NS_GW-$NS_OUT" tcp dport != 8080 ct state new drop
        # No IPv6 rule at all: consumer firewalls are frequently v4 only, and
        # L3A08 exists to find exactly that.
    }
    chain postrouting {
        type nat hook postrouting priority 100; policy accept;
        oifname "$NS_GW-$NS_OUT" masquerade
    }
}
NFT
}

build_guest() {
    ovs-vsctl add-br "$GUEST_BRIDGE"
    ip link set "$GUEST_BRIDGE" up
    ip netns add "$NS_GUEST"
    ip -n "$NS_GUEST" link set lo up
    ip link add "$NS_GUEST-br" type veth peer name eth0 netns "$NS_GUEST"
    ip link set "$NS_GUEST-br" up
    ip -n "$NS_GUEST" addr add "$GUEST_NET.10/24" dev eth0
    ip -n "$NS_GUEST" link set eth0 up
    ovs-vsctl add-port "$GUEST_BRIDGE" "$NS_GUEST-br"
}

build() {
    ovs-vsctl add-br "$BRIDGE"
    # RSTP makes the bridge emit BPDUs, which is what L2P03 looks for.
    ovs-vsctl set bridge "$BRIDGE" rstp_enable=true
    ip link set "$BRIDGE" up

    add_host "$NS1" 10.10.10.1/24
    add_host "$NS2" 10.10.20.1/24

    # An access port carries exactly one VLAN and sends frames untagged, so
    # "tag" alone is the whole configuration.
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

    echo "bridge $BRIDGE up"
    echo "  access port $ACCESS_TAP in VLAN $VLAN1"
    echo "  trunk port  $TRUNK_TAP, native VLAN $NATIVE_VLAN, trunks $VLAN1,$VLAN2"
    echo "  namespaces  $NS1 (VLAN $VLAN1, 10.10.10.1) and $NS2 (VLAN $VLAN2, 10.10.20.1)"
    echo "routed topology"
    echo "  $NS_GW  NAT gateway, inside $INSIDE_NET.1, outside $OUTSIDE_NET.1"
    echo "  $NS_IN  inside host $INSIDE_NET.10, run netcheck here"
    echo "  $NS_OUT outside host $OUTSIDE_NET.10, run the external observer here"
    echo "  $NS_V6  global IPv6 $V6_PREFIX::10, no inbound v6 filter, for L3A08"
    echo "  $NS_GUEST guest segment $GUEST_NET.10 on $GUEST_BRIDGE"
    echo ""
    echo "try:  ip netns exec $NS_IN netcheck listen --interface $NS_IN-$NS_GW --duration 20"
}

require_root
case "${1:-}" in
    --teardown) teardown ;;
    "") teardown >/dev/null 2>&1 || true; build ;;
    *) echo "usage: $0 [--teardown]" >&2; exit 1 ;;
esac
