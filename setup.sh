#!/usr/bin/env bash
# One-shot installer for the MITM Lab Controller + Monitor (Kali/Debian).
#
#   git clone https://github.com/B1G77/mitm-lab-controller.git
#   cd mitm-lab-controller
#   ./setup.sh        # auto-elevates with sudo; installs everything
#   ./run.sh          # launch
#
# Installs system packages, the Python GeoIP reader, the offline globe library,
# and the GeoIP database, then grants non-root capture rights. Safe to re-run.
set -u
cd "$(dirname "$0")"

# --- elevate -----------------------------------------------------------------
if [ "$(id -u)" -ne 0 ]; then
  echo "→ re-running with sudo…"
  exec sudo -E bash "$0" "$@"
fi
RUN_USER="${SUDO_USER:-root}"
run_as_user() { if [ "$RUN_USER" != "root" ]; then sudo -u "$RUN_USER" "$@"; else "$@"; fi; }

say()  { printf "\n\033[1;32m==>\033[0m %s\n" "$1"; }
warn() { printf "\033[1;33m  ! %s\033[0m\n" "$1"; }

if ! command -v apt-get >/dev/null 2>&1; then
  warn "This installer targets Debian/Kali (apt). Install the deps in README.md manually."
  exit 1
fi

# --- system packages ---------------------------------------------------------
CORE="hostapd isc-dhcp-server iw iptables python3 python3-tk python3-pip \
      wireshark-common tshark tcpdump curl gzip ca-certificates"
OPTIONAL="bettercap qterminal xdg-utils"

say "Installing core packages"
export DEBIAN_FRONTEND=noninteractive
# Pre-answer wireshark's setuid prompt so non-root users can capture.
echo "wireshark-common wireshark-common/install-setuid boolean true" | debconf-set-selections
apt-get update -y
apt-get install -y $CORE || { warn "core package install failed"; exit 1; }

say "Installing optional tools (non-fatal)"
apt-get install -y $OPTIONAL || warn "some optional tools were unavailable — that's fine"

# --- python deps -------------------------------------------------------------
say "Installing Python dependencies (system-wide, for the root-run capture)"
pip3 install -r requirements.txt --break-system-packages 2>/dev/null \
  || pip3 install -r requirements.txt \
  || warn "geoip2 install failed — the globe will still work without coordinates"

# --- offline assets (downloaded as the real user, not root) ------------------
say "Fetching the offline globe library + earth texture"
run_as_user bash web/fetch_libs.sh || warn "globe fetch failed — Geo view falls back to a CDN/dark sphere"

say "Downloading the free DB-IP City Lite GeoIP database"
run_as_user bash download_geoip.sh || warn "GeoIP download failed — destinations show without coordinates"

# --- capture privileges ------------------------------------------------------
say "Granting capture rights (so the Monitor can sniff without extra sudo)"
DEBIAN_FRONTEND=noninteractive dpkg-reconfigure wireshark-common >/dev/null 2>&1 || true
setcap cap_net_raw,cap_net_admin=eip "$(command -v dumpcap)" 2>/dev/null || true
if [ "$RUN_USER" != "root" ]; then
  usermod -aG wireshark "$RUN_USER" 2>/dev/null \
    && warn "Added $RUN_USER to the 'wireshark' group — log out/in for it to take effect."
fi

chmod +x run.sh setup.sh 2>/dev/null || true
say "Done. Launch with:  ./run.sh    (or:  sudo python3 mitm_lab.py)"
