#!/usr/bin/env bash
# Download globe.gl (bundles three.js) locally so the dashboard works offline.
# Run once on the machine that will show the demo:  bash web/fetch_libs.sh
set -e
DIR="$(cd "$(dirname "$0")" && pwd)/static"
mkdir -p "$DIR"
echo "Fetching globe.gl (includes three.js) → $DIR/globe.gl.min.js"
curl -fL "https://unpkg.com/globe.gl" -o "$DIR/globe.gl.min.js"
echo "Done. The dashboard will now load the globe without internet."
