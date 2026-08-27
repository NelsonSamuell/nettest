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

require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "this script needs root: it creates a bridge and network namespaces" >&2
        exit 1
    fi
}

teardown() {
    ovs-vsctl --if-exists del-br "$BRIDGE"
    for ns in "$NS1" "$NS2"; do
        ip netns del "$ns" 2>/dev/null || true
    done
    for link in "$NS1-br" "$NS2-br" "$ACCESS_TAP" "$TRUNK_TAP"; do
        ip link del "$link" 2>/dev/null || true
    done
    echo "removed $BRIDGE, $NS1, $NS2 and their veth pairs"
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

    echo "bridge $BRIDGE up"
    echo "  access port $ACCESS_TAP in VLAN $VLAN1"
    echo "  trunk port  $TRUNK_TAP, native VLAN $NATIVE_VLAN, trunks $VLAN1,$VLAN2"
    echo "  namespaces  $NS1 (VLAN $VLAN1, 10.10.10.1) and $NS2 (VLAN $VLAN2, 10.10.20.1)"
}

require_root
case "${1:-}" in
    --teardown) teardown ;;
    "") teardown >/dev/null 2>&1 || true; build ;;
    *) echo "usage: $0 [--teardown]" >&2; exit 1 ;;
esac
