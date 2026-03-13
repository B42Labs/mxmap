#!/usr/bin/env bash
# Build a simplified TopoJSON of German municipalities (Gemeinden) from BKG VG250 data.
# Requires: curl, unzip, npx (for mapshaper)
#
# Output: config/geo/de-gemeinden.json (~2-5 MB)

set -euo pipefail

BKG_URL="https://daten.gdz.bkg.bund.de/produkte/vg/vg250_ebenen_0101/aktuell/vg250_01-01.gk3.shape.ebenen.zip"
WORK_DIR=$(mktemp -d)
OUTPUT_DIR="config/geo"
OUTPUT_FILE="$OUTPUT_DIR/de-gemeinden.json"

echo "==> Downloading VG250 from BKG..."
curl -L -o "$WORK_DIR/vg250.zip" "$BKG_URL"

echo "==> Extracting..."
unzip -q "$WORK_DIR/vg250.zip" -d "$WORK_DIR/vg250"

echo "==> Finding Gemeinden shapefile..."
GEM_SHP=$(find "$WORK_DIR/vg250" -name "VG250_GEM.*" -name "*.shp" | head -1)
if [ -z "$GEM_SHP" ]; then
    echo "ERROR: Could not find VG250_GEM.shp in archive"
    echo "Contents:"
    find "$WORK_DIR/vg250" -name "*.shp" | head -20
    rm -rf "$WORK_DIR"
    exit 1
fi
echo "    Found: $GEM_SHP"

echo "==> Converting to simplified TopoJSON..."
mkdir -p "$OUTPUT_DIR"
npx --yes mapshaper "$GEM_SHP" \
    -proj wgs84 \
    -filter-fields AGS,GEN,BEZ \
    -rename-fields id=AGS,name=GEN,type=BEZ \
    -simplify 15% keep-shapes \
    -clean \
    -o format=topojson "$OUTPUT_FILE" id-field=id

echo "==> Cleaning up..."
rm -rf "$WORK_DIR"

SIZE=$(du -h "$OUTPUT_FILE" | cut -f1)
echo "==> Done: $OUTPUT_FILE ($SIZE)"
