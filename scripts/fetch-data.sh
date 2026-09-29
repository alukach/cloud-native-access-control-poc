#!/usr/bin/env bash
# Fetch the sample files the tests and the demo read.
#
# They are not in the repository: 24 MB of binaries that never change, and the
# demo needs them on a host that serves byte ranges with CORS anyway, so there
# is one copy and it is the one everything uses.
#
# Source Cooperative, and the same objects the deployed demo reads:
#   https://data.source.coop/alukach/alukach-experimentation/cloud-native-access-control/
#
# Checksummed, because a sample that changed silently would invalidate every
# measurement in docs/findings.md without a single test failing -- the numbers
# there are properties of these exact bytes.
set -euo pipefail

BASE="https://data.source.coop/alukach/alukach-experimentation/cloud-native-access-control"
DEST="${DEST:-data}"

# sha256  name
FILES=(
  "b5d75724dd5ae4ae4eb431b3d6c888b08e765ae22d3a3b44e4529f4d398d6f5d  nyc-taxi-8rg.parquet"
  "0657c8284e8f8ab0debff4a8a6d03662f5a539c2c3f5eb69f384a2377bbe5219  s2-tci-512.tif"
  "d6d5167af8b03db4bcafabe6384e690b5906688956f91367eae65e42328ce6ec  paris-landmarks.tif"
)

sha256() {
  if command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | cut -d' ' -f1
  else sha256sum "$1" | cut -d' ' -f1
  fi
}

mkdir -p "$DEST"
for entry in "${FILES[@]}"; do
  want="${entry%% *}"
  name="${entry##* }"
  path="$DEST/$name"

  if [ -f "$path" ] && [ "$(sha256 "$path")" = "$want" ]; then
    echo "ok       $name"
    continue
  fi

  echo "fetching $name"
  # To a temporary name first: a half-written file that happens to parse is a
  # worse failure than no file at all.
  curl -fsSL --retry 3 --retry-delay 2 -o "$path.part" "$BASE/$name"
  got=$(sha256 "$path.part")
  if [ "$got" != "$want" ]; then
    rm -f "$path.part"
    echo "FAIL     $name checksum mismatch" >&2
    echo "         want $want" >&2
    echo "         got  $got" >&2
    echo "         The object at $BASE/$name is not the one this repository was" >&2
    echo "         measured against. Do not update the checksum without re-running" >&2
    echo "         the numbers in docs/findings.md." >&2
    exit 1
  fi
  mv "$path.part" "$path"
  echo "ok       $name"
done

echo
echo "Samples in $DEST/. Regenerate rather than fetch with:"
echo "  ./scripts/make-fixtures.sh all   # the Parquet and the Sentinel granule"
echo "  ./scripts/make-paris.sh          # the Paris orthophoto"
