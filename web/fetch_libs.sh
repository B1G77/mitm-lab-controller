#!/usr/bin/env bash
# Download globe.gl (bundles three.js) locally so the dashboard works offline.
# Run once on the machine that will show the demo:  bash web/fetch_libs.sh
set -e
DIR="$(cd "$(dirname "$0")" && pwd)/static"
mkdir -p "$DIR"
echo "Fetching globe.gl (includes three.js) → $DIR/globe.gl.min.js"
curl -fL "https://unpkg.com/globe.gl" -o "$DIR/globe.gl.min.js"
echo "Fetching earth night texture → $DIR/earth-night.jpg"
curl -fL "https://unpkg.com/three-globe/example/img/earth-night.jpg" \
  -o "$DIR/earth-night.jpg" || echo "  (texture optional — globe falls back to a dark sphere)"
echo "Done. The dashboard now loads the globe AND texture without internet."
