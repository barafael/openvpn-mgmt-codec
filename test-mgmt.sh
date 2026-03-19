#!/usr/bin/env bash
#
# Starts OpenVPN with a management-only config and connects the CLI.
#
# OpenVPN runs in held mode (no tunnel, no routing changes) with the
# management interface on 127.0.0.1:7505. It is killed automatically
# when the CLI exits.
#
# Usage:
#   ./test-mgmt.sh [/path/to/openvpn]
#
# Do NOT run this script itself under sudo. The script builds the CLI
# as your normal user, then uses sudo only for OpenVPN.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONFIG="$SCRIPT_DIR/test-mgmt.ovpn"
OPENVPN="${1:-}"

if [[ ! -f "$CONFIG" ]]; then
    echo "error: config not found: $CONFIG" >&2
    exit 1
fi

# --- Locate openvpn -------------------------------------------------------
if [[ -z "$OPENVPN" ]]; then
    if command -v openvpn &>/dev/null; then
        OPENVPN="$(command -v openvpn)"
    else
        echo "error: cannot find openvpn. Pass the path as an argument." >&2
        exit 1
    fi
fi

echo "Using OpenVPN: $OPENVPN"
echo ""

# --- Build the CLI first (as the current user) ----------------------------
echo "Building ovpn-mgmt-cli..."
cargo build -p ovpn-mgmt-cli
CLI="$SCRIPT_DIR/target/debug/ovpn-mgmt-cli"

# --- Start OpenVPN (needs root) ------------------------------------------
echo "Starting OpenVPN (management on 127.0.0.1:7505, held)..."
sudo "$OPENVPN" --config "$CONFIG" &
OVPN_PID=$!

cleanup() {
    if kill -0 "$OVPN_PID" 2>/dev/null; then
        echo ""
        echo "Stopping OpenVPN (PID $OVPN_PID)..."
        sudo kill "$OVPN_PID"
        wait "$OVPN_PID" 2>/dev/null
    fi
}
trap cleanup EXIT

# Give it a moment to open the management port.
sleep 2

if ! kill -0 "$OVPN_PID" 2>/dev/null; then
    echo "error: OpenVPN exited immediately. Is sudo working?" >&2
    exit 1
fi

echo "OpenVPN running (PID $OVPN_PID). Connecting CLI..."
echo ""

# --- Run the pre-built CLI (as the current user) -------------------------
"$CLI" 127.0.0.1:7505
