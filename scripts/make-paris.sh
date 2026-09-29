#!/usr/bin/env bash
# Build the Paris sample COG from IGN's open orthophotos.
#
# Source: BD ORTHO via the Géoplateforme WMTS, Licence Ouverte (Etalab 2.0).
# Attribution: © IGN. See data/paris-landmarks.LICENSE.
#
# GDAL's own WMTS driver silently produces an all-black raster against this
# endpoint -- the TILEMATRIX identifiers it sends do not match what the server
# advertises -- so the tiles are fetched directly and georeferenced with world
# files, which GDAL then mosaics. Verified by checking the result is not blank
# before it is written, because an all-black COG is exactly what the failure
# looks like.
set -euo pipefail

Z=${Z:-18}
OUT=${OUT:-data/paris-landmarks.tif}
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# Eiffel Tower, Trocadéro and the Arc de Triomphe, with room around them.
LON_MIN=2.2830 LAT_MIN=48.8530
LON_MAX=2.3050 LAT_MAX=48.8780

LAYER="ORTHOIMAGERY.ORTHOPHOTOS"
TMS="PM_0_19"
BASE="https://data.geopf.fr/wmts?SERVICE=WMTS&REQUEST=GetTile&VERSION=1.0.0"

echo "Planning tiles at zoom ${Z}…"
python3 - "$Z" "$LON_MIN" "$LAT_MIN" "$LON_MAX" "$LAT_MAX" "$WORK" <<'PY' > "$WORK/tiles.txt"
import math, sys
z = int(sys.argv[1])
lon0, lat0, lon1, lat1 = map(float, sys.argv[2:6])
work = sys.argv[6]
n = 2 ** z
def xt(lon): return (lon + 180.0) / 360.0 * n
def yt(lat): return (1.0 - math.asinh(math.tan(math.radians(lat))) / math.pi) / 2.0 * n
x0, x1 = int(xt(lon0)), int(xt(lon1))
y0, y1 = int(yt(lat1)), int(yt(lat0))
# Mercator metres per pixel at this zoom, and the world origin.
res = 2 * 20037508.342789244 / (256 * n)
origin = -20037508.342789244
for x in range(x0, x1 + 1):
    for y in range(y0, y1 + 1):
        print(f"{x} {y}")
        # A world file georeferences the plain JPEG: pixel size, no rotation,
        # and the CENTRE of the top-left pixel -- not its corner.
        ulx = origin + x * 256 * res + res / 2
        uly = -origin - y * 256 * res - res / 2
        with open(f"{work}/{x}_{y}.wld", "w") as f:
            f.write(f"{res}\n0.0\n0.0\n{-res}\n{ulx}\n{uly}\n")
        with open(f"{work}/{x}_{y}.prj", "w") as f:
            f.write('PROJCS["WGS 84 / Pseudo-Mercator",GEOGCS["WGS 84",'
                    'DATUM["WGS_1984",SPHEROID["WGS 84",6378137,298.257223563]],'
                    'PRIMEM["Greenwich",0],UNIT["degree",0.0174532925199433]],'
                    'PROJECTION["Mercator_1SP"],PARAMETER["central_meridian",0],'
                    'PARAMETER["scale_factor",1],PARAMETER["false_easting",0],'
                    'PARAMETER["false_northing",0],UNIT["metre",1],'
                    'AXIS["Easting",EAST],AXIS["Northing",NORTH]]')
print(f"# {(x1 - x0 + 1) * (y1 - y0 + 1)} tiles", file=sys.stderr)
PY

COUNT=$(grep -c . "$WORK/tiles.txt")
echo "Fetching $COUNT tiles…"
# Eight at a time: enough to be quick, few enough to be a polite client.
grep . "$WORK/tiles.txt" | xargs -P 8 -n 2 sh -c '
  url="'"$BASE"'&LAYER='"$LAYER"'&STYLE=normal&FORMAT=image/jpeg&TILEMATRIXSET='"$TMS"'&TILEMATRIX='"$Z"'&TILECOL=$1&TILEROW=$2"
  curl -sf --retry 3 --retry-delay 1 -o "'"$WORK"'/$1_$2.jpg" "$url" || echo "MISS $1 $2" >&2
' sh

FETCHED=$(ls "$WORK"/*.jpg 2>/dev/null | wc -l | tr -d ' ')
echo "Fetched $FETCHED of $COUNT."
if [ "$FETCHED" -lt "$COUNT" ]; then
  echo "Some tiles are missing; the mosaic would have holes." >&2
  exit 1
fi

echo "Mosaicking…"
gdalbuildvrt -q "$WORK/mosaic.vrt" "$WORK"/*.jpg

# The check that matters: GDAL's own WMTS path fails by producing black, so
# assert there is a picture here before writing the sample.
MEAN=$(gdalinfo -stats "$WORK/mosaic.vrt" 2>/dev/null | awk -F= '/STATISTICS_MEAN/ {print int($2); exit}')
echo "Mean pixel value: $MEAN"
if [ -z "$MEAN" ] || [ "$MEAN" -lt 5 ]; then
  echo "The mosaic is blank. The tile endpoint returned nothing usable." >&2
  exit 1
fi

echo "Writing ${OUT}…"
# 256-pixel tiles, not 512: at this resolution that is ~100 m of ground per
# tile, so a landmark occupies a handful and withholding one is legible rather
# than a quarter of the city going dark.
gdal_translate -q -b 1 -b 2 -b 3 "$WORK/mosaic.vrt" "$OUT" \
  -of COG \
  -co COMPRESS=JPEG -co QUALITY=85 -co BLOCKSIZE=256 \
  -co OVERVIEWS=IGNORE_EXISTING -co BIGTIFF=NO

gdalinfo "$OUT" | sed -n '1,8p'
ls -la "$OUT"
