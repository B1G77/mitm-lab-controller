#!/usr/bin/env bash
# Launch the MITM Lab Controller. The tool needs root (it reconfigures the
# interface, firewall and services), so this handles the root↔X11 handshake and
# elevates for you.  Usage:  ./run.sh
set -u
cd "$(dirname "$0")"

# Let root reach the current user's X session (no-op if already allowed).
xhost +SI:localuser:root >/dev/null 2>&1 || true

exec sudo python3 mitm_lab.py "$@"
