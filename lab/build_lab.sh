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

say() { printf '%s\n' "$*"; }

require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        say "this script needs root: it creates a bridge and network namespaces" >&2
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
    say "removed $BRIDGE, $NS1, $NS2 and their veth pairs"
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

    say "bridge $BRIDGE up, RSTP enabled"
    say "  access port $ACCESS_TAP in VLAN $VLAN1"
    say "  trunk port  $TRUNK_TAP, native VLAN $NATIVE_VLAN, trunks $VLAN1,$VLAN2"
    say "  namespaces  $NS1 (VLAN $VLAN1) and $NS2 (VLAN $VLAN2)"
    say ""
    say "try:  netcheck listen --interface $TRUNK_TAP --duration 30"
}

require_root
case "${1:-}" in
    --teardown) teardown ;;
    "") teardown >/dev/null 2>&1 || true; build ;;
    *) say "usage: $0 [--teardown]" >&2; exit 1 ;;
esac
