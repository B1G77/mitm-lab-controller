#!/usr/bin/env bash
# Download the free DB-IP City Lite database (CC-licensed, no account) for the
# Ops Dashboard's GeoIP arcs. DB-IP publishes a new file each month; this grabs
# the current month and falls back one month if the new one isn't up yet.
#   Usage:  bash download_geoip.sh
set -e
DIR="$(cd "$(dirname "$0")" && pwd)/geoip"
mkdir -p "$DIR"
OUT="$DIR/dbip-city-lite.mmdb"

try_month() {
  local ym="$1"
  local url="https://download.db-ip.com/free/dbip-city-lite-${ym}.mmdb.gz"
  echo "Trying $url"
  if curl -fL "$url" -o "$DIR/tmp.mmdb.gz"; then
    gunzip -f "$DIR/tmp.mmdb.gz"
    mv "$DIR/tmp.mmdb" "$OUT"
    return 0
  fi
  return 1
}

THIS=$(date +%Y-%m)
PREV=$(date -d "last month" +%Y-%m 2>/dev/null || date -v-1m +%Y-%m 2>/dev/null)

if try_month "$THIS" || { [ -n "$PREV" ] && try_month "$PREV"; }; then
  echo "GeoIP database ready at $OUT"
else
  echo "Download failed. Get the .mmdb manually from https://db-ip.com/db/download/ip-to-city-lite"
  echo "and place it at: $OUT"
  exit 1
fi
