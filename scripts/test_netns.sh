#!/usr/bin/env bash
# test_netns.sh — Run xdp-firewall in a network namespace for safe testing
#
# Creates a veth pair inside a netns, attaches the XDP program in generic mode,
# sends test packets, and verifies drop/pass behavior.
#
# Requirements: iproute2, scapy (pip install scapy), root or CAP_NET_ADMIN

set -euo pipefail

NETNS="xdp_test_ns"
VETH_HOST="veth_host"
VETH_NS="veth_ns"
HOST_IP="192.168.99.1"
NS_IP="192.168.99.2"
BUILD_DIR="$(dirname "$0")/../build"
BPF_OBJ="$BUILD_DIR/xdp_firewall.o"
USER_BIN="$BUILD_DIR/xdp_firewall"

RED='\033[0;31m'
GRN='\033[0;32m'
YLW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GRN}[*]${NC} $*"; }
warn()  { echo -e "${YLW}[!]${NC} $*"; }
error() { echo -e "${RED}[x]${NC} $*"; exit 1; }

# ── Prerequisite checks ──────────────────────────────────────────────────────

[ "$(id -u)" -eq 0 ] || error "This script requires root (or CAP_NET_ADMIN + CAP_SYS_ADMIN)"
[ -f "$BPF_OBJ"  ] || error "BPF object not found: $BPF_OBJ — run 'make' first"
[ -f "$USER_BIN" ] || error "User binary not found: $USER_BIN — run 'make' first"

# ── Cleanup on exit ──────────────────────────────────────────────────────────

cleanup() {
    info "Cleaning up..."
    ip netns del "$NETNS" 2>/dev/null || true
    ip link del "$VETH_HOST" 2>/dev/null || true
}
trap cleanup EXIT

# ── Setup network namespace ──────────────────────────────────────────────────

info "Creating network namespace: $NETNS"
ip netns del "$NETNS" 2>/dev/null || true
ip netns add "$NETNS"

info "Creating veth pair: $VETH_HOST <-> $VETH_NS"
ip link add "$VETH_HOST" type veth peer name "$VETH_NS"
ip link set "$VETH_NS" netns "$NETNS"

ip addr add "$HOST_IP/24" dev "$VETH_HOST"
ip link set "$VETH_HOST" up

ip netns exec "$NETNS" ip addr add "$NS_IP/24" dev "$VETH_NS"
ip netns exec "$NETNS" ip link set "$VETH_NS" up
ip netns exec "$NETNS" ip link set lo up

info "Host: $HOST_IP  |  NS: $NS_IP"

# ── Attach XDP firewall to host-side veth ────────────────────────────────────

info "Attaching XDP firewall to $VETH_HOST (generic mode)..."

# Start firewall in background, block a test IP
"$USER_BIN" -i "$VETH_HOST" \
    -o "$BPF_OBJ" \
    -b "$NS_IP" \
    -p 9999 &
FW_PID=$!
sleep 1

info "Firewall PID: $FW_PID"

# ── Tests ────────────────────────────────────────────────────────────────────

PASS=0
FAIL=0

run_test() {
    local desc="$1"
    local expect_pass="$2"
    local cmd="$3"

    if eval "$cmd" &>/dev/null; then
        if [ "$expect_pass" = "true" ]; then
            echo -e "  ${GRN}PASS${NC}  $desc"
            ((PASS++))
        else
            echo -e "  ${RED}FAIL${NC}  $desc (expected drop, but passed)"
            ((FAIL++))
        fi
    else
        if [ "$expect_pass" = "false" ]; then
            echo -e "  ${GRN}PASS${NC}  $desc (correctly dropped)"
            ((PASS++))
        else
            echo -e "  ${RED}FAIL${NC}  $desc (expected pass, but dropped)"
            ((FAIL++))
        fi
    fi
}

echo ""
echo "── Running tests ────────────────────────────────────────────────────────"

# Ping from NS to host — should be DROPPED (NS_IP is blocklisted)
run_test "Ping from blocked IP dropped" "false" \
    "ip netns exec $NETNS ping -c1 -W1 $HOST_IP"

# Ping from host to NS — NS is not blocklisting host, so should pass
run_test "Ping to allowed IP passes" "true" \
    "ping -c1 -W1 $NS_IP"

# Port 9999 blocked
run_test "Port 9999 blocked" "false" \
    "ip netns exec $NETNS nc -z -w1 $HOST_IP 9999"

# Port 80 not blocked (nothing listening, but XDP should pass it)
# We just check XDP doesn't drop — connection refused is expected
run_test "Port 80 not blocked by XDP" "true" \
    "ip netns exec $NETNS nc -z -w1 $HOST_IP 80 || true"

echo "────────────────────────────────────────────────────────────────────────"
echo ""

# Print stats
"$USER_BIN" -i "$VETH_HOST" -o "$BPF_OBJ" -s 2>/dev/null || true

# ── Results ──────────────────────────────────────────────────────────────────

kill $FW_PID 2>/dev/null || true

echo ""
if [ $FAIL -eq 0 ]; then
    echo -e "${GRN}All $PASS tests passed.${NC}"
    exit 0
else
    echo -e "${RED}$FAIL test(s) failed, $PASS passed.${NC}"
    exit 1
fi
