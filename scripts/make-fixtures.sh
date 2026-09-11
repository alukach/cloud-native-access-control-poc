#!/usr/bin/env bash
#
# Regenerate every binary this repo commits: the two demo files under `data/`
# and the six resolver fixtures under `tests/fixtures/`.
#
#   ./scripts/make-fixtures.sh            # everything
#   ./scripts/make-fixtures.sh fixtures   # tests/fixtures/ only (fast, no bulk download)
#   ./scripts/make-fixtures.sh demo       # data/ only
#   ./scripts/make-fixtures.sh verify     # re-verify what is already on disk
#
# Requires `duckdb`, `gdal_translate`, `gdalinfo`, `curl` and `python3` on
# PATH, plus -- for the two fixtures DuckDB physically cannot produce -- two
# pinned pyarrow interpreters, named by $PYARROW11 and $PYARROW. Both parquet
# steps are SKIPPED with a warning when those are unset, so the rest of the
# script still runs on a machine with neither.
#
# The pyarrow dependency was resisted and is now load-bearing. Every Parquet
# fixture in this repository used to come from DuckDB, and a resolver tested
# only against its own writer's output is a test that passes because the
# fixture and the code share an author -- which is exactly how issue #23
# survived: 495 unclassified spans in a Hugging Face file, zero in everything
# committed here. DuckDB emits no page index and no inline `ColumnMetaData`, so
# no DuckDB flag reaches either shape.
#
#   PYARROW11  a python with pyarrow 11.0.0 -- the LAST parquet-cpp that wrote
#              a copy of each chunk's ColumnMetaData into the data stream.
#              Arrow 12 stopped, so a current pyarrow cannot make this file:
#                uv venv --python 3.11 .venv311
#                uv pip install --python .venv311/bin/python \
#                    'pyarrow==11.0.0' 'numpy<2'
#   PYARROW    any python with pyarrow >= 13, for `write_page_index=True`,
#              which pyarrow 11 has no parameter for:
#                python3 -m venv .venv && .venv/bin/pip install pyarrow
#
# Nothing large is ever written into the repository. The Parquet sources are
# read straight over HTTPS by DuckDB's httpfs (which range-requests only the
# row groups the LIMIT needs), the fixture rasters are read through GDAL's
# /vsicurl (which range-requests only the tiles the -srcwin needs), and the one
# case that genuinely needs the whole source -- the demo COG, which reads every
# pixel -- stages it in a mktemp directory removed on exit.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DATA="$ROOT/data"
FIX="$ROOT/tests/fixtures"

# ---------------------------------------------------------------------------
# Pinned sources
# ---------------------------------------------------------------------------
#
# Both are public and stable, but they are third-party and they do age. If one
# 404s, substitute an equivalent -- any NYC TLC yellow-taxi month, any
# sentinel-cogs TCI.tif -- and re-run the verification section, because the
# numbers the demo files are chosen for (below) are properties of the source.

# NYC TLC yellow taxi, January 2024. 19 columns, ~2.96M rows, ~50 MB.
TAXI_URL="https://d37ci6vzurychx.cloudfront.net/trip-data/yellow_tripdata_2024-01.parquet"

# Sentinel-2 L2A true-colour composite, tile 10SEG (Monterey Bay / Santa Cruz
# Mountains), 2024-09-23. 10980x10980 RGB uint8, ~57 MB.
#
# Scene choice is load-bearing and is NOT interchangeable with "any TCI.tif".
# This granule sits on the edge of the swath, so roughly a third of the tile
# carries imagery and the rest is nodata. That is what puts the JPEG-compressed
# 512px tiles at ~7 KB apiece and the whole file at ~5 MB. A full-coverage
# granule at the same settings measures ~76 KB per tile and ~37 MB total, which
# is both too large to commit and structurally wrong for the demo: a tile
# bigger than geotiff.js's 64 KB block never shares a block with another tile,
# so the coalescing the demo exists to show cannot happen. Verified, not
# assumed -- S2A_10SEH_20240930 (0% nodata) was measured at 36,831,723 bytes.
S2_URL="https://sentinel-cogs.s3.us-west-2.amazonaws.com/sentinel-s2-l2a-cogs/10/S/EG/2024/9/S2A_10SEG_20240923_0_L2A/TCI.tif"

# Window into the Sentinel granule that every raster fixture is cut from:
# 256x256 pixels at (1024, 4096), which lands on land rather than in the
# nodata wedge. All-nodata input compresses to a couple of KB and would make
# every byte-offset fixture degenerate.
SRCWIN=(-srcwin 1024 4096 256 256)

log() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

# ---------------------------------------------------------------------------
# data/ -- the demo files
# ---------------------------------------------------------------------------
#
# These exist to make range coalescing MEASURABLE. A file small enough for a
# client to fetch in one range straddles nothing, so a demo built on one
# reports zero straddles and quietly proves the opposite of the point. Both
# sizes below are chosen against a specific reader's coalescing rule.

make_demo_parquet() {
  log "data/nyc-taxi-8rg.parquet"
  mkdir -p "$DATA"

  # ROW_GROUP_SIZE 50000 is MANDATORY, not a tuning knob. DuckDB's default is
  # 1M rows, which puts all 400k rows in ONE row group -- one row group is one
  # coalesced fetch, so there is nothing for a per-row-group policy to
  # distinguish and nothing for a straddle counter to count. DuckDB rounds the
  # request up to a multiple of its 2048-row vector size, so 50000 becomes
  # 51200 and 400000 rows land as 7x51200 + 41600 = 8 row groups.
  #
  # The resulting ~1.05 MB per row group is the number that matters: it is
  # under hyparquet's 2 MB `runLimit`, so hyparquet's default read collapses
  # all 19 column chunks of a row group into a single request. Push the row
  # groups over 2 MB and hyparquet splits them, and the demo measures a
  # different thing than it claims to.
  #
  # COMPRESSION SNAPPY, not ZSTD (DuckDB's default): hyparquet decodes
  # uncompressed and snappy natively, and needs the separate
  # hyparquet-compressors package for anything else. ZSTD here costs the web
  # demo a dependency for no benefit.
  duckdb -c "
    COPY (SELECT * FROM read_parquet('$TAXI_URL') LIMIT 400000)
    TO '$DATA/nyc-taxi-8rg.parquet'
    (FORMAT PARQUET, COMPRESSION SNAPPY, ROW_GROUP_SIZE 50000);"
}

make_demo_cog() {
  log "data/s2-tci-512.tif"
  mkdir -p "$DATA"

  # This is the one step that reads every pixel of its source, so /vsicurl
  # would issue thousands of range requests. Stage the source in a temp
  # directory instead and delete it on the way out.
  local tmp
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN
  echo "staging $S2_URL -> $tmp"
  curl -sSfL -o "$tmp/TCI.tif" "$S2_URL"

  # BLOCKSIZE=512 rather than the COG driver's 512 default made explicit, and
  # rather than the source's 1024: at 512 the base level is a 22x22 grid of 484
  # tiles and the pyramid is 484/121/36/9/4/1 = 655 tiles in six levels. That
  # tile count is the experiment. At ~7 KB per tile a single 64 KB geotiff.js
  # block spans about nine of them, so a client asking for one tile is handed
  # eight it did not ask for -- which is the straddle the decision function
  # has to catch.
  #
  # OVERVIEWS=IGNORE_EXISTING forces the pyramid to be rebuilt at the new block
  # size. Reusing the source's overviews would leave them on a 1024 grid, and
  # the per-level tile counts above would not hold.
  #
  # QUALITY=75 is the visual/size trade-off; see the S2_URL note for why the
  # resulting bytes-per-tile is a property of the scene and not only of this
  # number.
  gdal_translate "$tmp/TCI.tif" "$DATA/s2-tci-512.tif" -of COG \
    -co BLOCKSIZE=512 -co COMPRESS=JPEG -co QUALITY=75 -co OVERVIEWS=IGNORE_EXISTING
}

# ---------------------------------------------------------------------------
# tests/fixtures/ -- small, adversarial
# ---------------------------------------------------------------------------
#
# Each of these pins one edge case a resolver can get wrong silently. See
# tests/fixtures/README.md for what each one is FOR; the comments here explain
# why the FLAGS produce it.

make_parquet_fixtures() {
  log "tests/fixtures/*.parquet"
  mkdir -p "$FIX"

  # nested.parquet -- a top-level `salary` AND a `salary` field inside a
  # struct, so the footer carries both `salary` and `employee.salary` as
  # distinct `path_in_schema` values. A resolver that keys regions on the leaf
  # name collapses the two, and `region.column <> 'salary'` then blocks a
  # column the policy never named. The two must stay different types
  # (INT32 vs INT32 under a different parent) and both must be present:
  # a fixture with only the nested one cannot detect the collapse.
  #
  # 100 rows keeps every chunk on one page, so offsets stay easy to reason
  # about in a golden test.
  duckdb -c "
    COPY (SELECT i AS id,
                 (i * 1000)::INTEGER AS salary,
                 {'name': 'emp' || i, 'salary': (i * 1100)::INTEGER} AS employee
          FROM range(1, 101) t(i))
    TO '$FIX/nested.parquet' (FORMAT PARQUET, COMPRESSION SNAPPY);"

  # dict.parquet -- 5000 rows over 4 distinct strings. The cardinality is the
  # point: DuckDB dictionary-encodes a column this repetitive, which emits a
  # dictionary page and sets `dictionary_page_offset` BELOW `data_page_offset`.
  # A resolver that starts the column chunk's extent at `data_page_offset`
  # leaves the dictionary page unclaimed -- and for a low-cardinality column
  # the dictionary page literally IS the set of distinct values, so the bytes
  # it fails to protect are the ones a policy would most want protected.
  #
  # `id` and `value` are deliberately high-cardinality so they stay PLAIN with
  # a NULL dictionary_page_offset: the fixture has to show both cases, or a
  # test cannot tell "handles dictionaries" from "adds a fixed offset".
  duckdb -c "
    COPY (SELECT i AS id,
                 (['alpha','beta','gamma','delta'])[(i % 4) + 1] AS region_code,
                 i::DOUBLE AS value
          FROM range(0, 5000) t(i))
    TO '$FIX/dict.parquet' (FORMAT PARQUET, COMPRESSION SNAPPY);"

  # multi-rg.parquet -- the plain case, for row_group indexing. ROW_GROUP_SIZE
  # 2048 is DuckDB's minimum (one vector); 12000 rows gives 5 full row groups
  # plus a short 1760-row tail, and the short tail matters -- a resolver that
  # derives a chunk's extent from a fixed rows-per-group rather than from the
  # footer's own offsets gets the last group wrong and only the last group.
  duckdb -c "
    COPY (SELECT i AS id, (i * 2)::INTEGER AS doubled, 'r' || (i % 7) AS label
          FROM range(0, 12000) t(i))
    TO '$FIX/multi-rg.parquet' (FORMAT PARQUET, COMPRESSION SNAPPY, ROW_GROUP_SIZE 2048);"
}

# Two Parquet fixtures from a writer that is not DuckDB. See the header for why
# this needs two pinned pyarrow versions and why neither shape is reachable
# from DuckDB.
make_foreign_parquet_fixtures() {
  log "tests/fixtures/{inline-colmeta,page-index}.parquet"
  mkdir -p "$FIX"

  # The same 2000-row, 3-column table in both, at 500 rows per row group, so
  # the two files differ ONLY in the writer and its options. `region_code` has
  # four distinct values so parquet-cpp dictionary-encodes it; `id` and `value`
  # are high-cardinality and stay PLAIN. 12 chunks either way.
  local table
  table=$(cat <<'PY'
import pyarrow as pa, pyarrow.parquet as pq, sys
t = pa.table({'id': pa.array(range(2000), pa.int32()),
              'region_code': pa.array([['alpha','beta','gamma','delta'][i%4]
                                       for i in range(2000)]),
              'value': pa.array([float(i) for i in range(2000)])})
kw = {}
if sys.argv[2] == 'page_index':
    kw['write_page_index'] = True
pq.write_table(t, sys.argv[1], row_group_size=500, compression='snappy',
               write_statistics=True, **kw)
print(pq.ParquetFile(sys.argv[1]).metadata.created_by)
PY
)

  # inline-colmeta.parquet -- parquet-cpp writes a copy of each chunk's
  # `ColumnMetaData` thrift into the data stream, immediately after that
  # chunk's last page, and points `ColumnChunk.file_offset` at it. Nothing
  # records its LENGTH, so a resolver that maps only
  # `min(dict, data) .. + total_compressed_size` leaves one unclassified span
  # per chunk -- ~80 bytes each here, ~92 in the Hugging Face file this was cut
  # down from. Unmapped denies, so those spans denied every read that straddled
  # one; worse, the structure names the column and carries its chunk-level min
  # and max, so it survived `rewrite`'s by-column scrub in plaintext. Arrow 12
  # stopped writing it, which is why the pin is to 11.0.0 and not to "pyarrow".
  if [ -n "${PYARROW11:-}" ]; then
    "$PYARROW11" -c "$table" "$FIX/inline-colmeta.parquet" plain
  else
    echo "SKIP inline-colmeta.parquet: \$PYARROW11 unset" >&2
  fi

  # page-index.parquet -- a real ColumnIndex and OffsetIndex per chunk, written
  # because the writer was asked to rather than because a test built one
  # in-process. DuckDB emits NEITHER, so before this file the only coverage of
  # the page-index path was a synthetic arrow-rs file built inside
  # `src/parquet.rs`. parquet-cpp also lays them out differently from arrow-rs:
  # every ColumnIndex first, then every OffsetIndex, after the last row group.
  if [ -n "${PYARROW:-}" ]; then
    "$PYARROW" -c "$table" "$FIX/page-index.parquet" page_index
  else
    echo "SKIP page-index.parquet: \$PYARROW unset" >&2
  fi
}

make_tiff_fixtures() {
  log "tests/fixtures/*.tif"
  mkdir -p "$FIX"

  # /vsicurl + -srcwin: GDAL range-requests only the source tiles the window
  # touches, so these three regenerate in seconds off a 57 MB remote file
  # without ever downloading it.
  local src="/vsicurl/$S2_URL"

  # striped.tif -- TILED=NO is the whole fixture. A striped TIFF has
  # StripOffsets (tag 273) and NO TileOffsets (tag 324), so a tile-based
  # resolver finds nothing to map and returns an EMPTY region set. Under the
  # conjunctive decision rule `regions.iter().all(..)`, an empty set is
  # `true` -- the entire image would be readable. The resolver must map a
  # striped TIFF wholly to `RegionKind::Unmapped` (or refuse it), and this is
  # the file that proves which it does.
  #
  # JPEG rather than DEFLATE only to keep the fixture at ~11 KB; the codec is
  # irrelevant to the edge case.
  gdal_translate -q -of GTiff "${SRCWIN[@]}" \
    -co TILED=NO -co COMPRESS=JPEG -co JPEG_QUALITY=75 -co PHOTOMETRIC=YCBCR \
    "$src" "$FIX/striped.tif"

  # planar2.tif -- INTERLEAVE=BAND sets PlanarConfiguration=2 (tag 284), which
  # changes what the TileOffsets array MEANS: with 3 samples per pixel it holds
  # 3 x (tile grid) entries, band-major, not one entry per tile. A resolver
  # written for PlanarConfiguration=1 reads index 16 of 48 as "tile 16" when it
  # is really tile 0 of band 2, and every region past the first band is
  # attributed to the wrong pixels -- silently, with no error and no gap for
  # `Unmapped` to catch. The resolver must REJECT this file rather than
  # mis-index it.
  #
  # DEFLATE, not JPEG: libtiff will not write JPEG with PlanarConfiguration=2.
  # PREDICTOR=2 and ZLEVEL=9 are only there to hold the fixture under the
  # ~200 KB budget.
  gdal_translate -q -of GTiff "${SRCWIN[@]}" \
    -co TILED=YES -co BLOCKXSIZE=64 -co BLOCKYSIZE=64 -co INTERLEAVE=BAND \
    -co COMPRESS=DEFLATE -co PREDICTOR=2 -co ZLEVEL=9 \
    "$src" "$FIX/planar2.tif"

  # odd-tag.tif -- tiny-cog.tif plus one metadata item, chosen so that the
  # ASCII `GDAL_METADATA` value (tag 42112) comes out an ODD number of bytes.
  # TIFF requires every value to begin on a word boundary, so the next value is
  # preceded by one filler byte that belongs to no structure -- and a resolver
  # that maps a value as exactly its length leaves that byte `Unmapped`, in the
  # middle of the metadata prefix, which denies the header read every reader
  # makes first. This is not a contrived shape: every COG on
  # sentinel-cogs.s3.us-west-2.amazonaws.com is written this way, and
  # S2A_10SEG_20240923_0_L2A/TCI.tif measured exactly one unmapped byte at
  # 1303. `-mo NOTE=odd` is the smallest edit that reproduces it in 19 KB.
  #
  # If `verify` reports zero unmapped-capable padding here, change the length
  # of the NOTE value by one and re-run: the parity of the GDAL_METADATA XML is
  # what the fixture is FOR, and GDAL will happily produce an even one.
  gdal_translate -q -of COG "${SRCWIN[@]}" \
    -co BLOCKSIZE=64 -co COMPRESS=JPEG -co QUALITY=75 -co OVERVIEWS=IGNORE_EXISTING \
    -mo "NOTE=odd" \
    "$src" "$FIX/odd-tag.tif"

  # tiny-cog.tif -- the happy path, for golden offsets. BLOCKSIZE=64 against a
  # 256x256 window gives 4x4 base tiles and two overview levels (2x2, 1x1);
  # the COG driver stops generating overviews once a level fits in one block,
  # so a larger BLOCKSIZE here would yield fewer levels than the multi-level
  # indexing this fixture is for. GDAL warns that 64 is below its recommended
  # 128 -- that warning is expected and the file is still LAYOUT=COG.
  #
  # A compressed COG also carries GDAL's ghost area, declaring
  # BLOCK_LEADER=SIZE_AS_UINT4 and BLOCK_TRAILER=LAST_4_BYTES_REPEATED. That
  # means each tile's real bytes run from offset-4 (a uint32 length) to
  # offset+len+4 (the last four bytes repeated). A resolver that maps only
  # [offset, offset+len) leaves those 8 bytes per tile unclaimed, which is
  # correct-but-fragmented; one that trusts the leader without bounds-checking
  # it against TileByteCounts is reading an attacker-controlled length. Either
  # way the behaviour needs a file to pin it against.
  gdal_translate -q -of COG "${SRCWIN[@]}" \
    -co BLOCKSIZE=64 -co COMPRESS=JPEG -co QUALITY=75 -co OVERVIEWS=IGNORE_EXISTING \
    "$src" "$FIX/tiny-cog.tif"
}

# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------
#
# Every claim the comments above make is re-measured here. A fixture that does
# not exhibit its edge case is worse than no fixture, because a test passes
# against it and proves nothing.

verify() {
  log "verify: sizes"
  ls -l "$DATA"/*.parquet "$DATA"/*.tif "$FIX"/*.parquet "$FIX"/*.tif |
    awk '{printf "%10d  %s\n", $5, $NF}'

  log "verify: data/nyc-taxi-8rg.parquet -- expect 8 row groups x 19 columns, ~1.05 MB each, SNAPPY"
  duckdb -c "
    SELECT row_group_id, count(*) AS columns, min(row_group_num_rows) AS rows,
           sum(total_compressed_size) AS row_group_bytes,
           min(compression) AS codec, max(compression) AS codec_max
    FROM parquet_metadata('$DATA/nyc-taxi-8rg.parquet')
    GROUP BY row_group_id ORDER BY row_group_id;"

  log "verify: data/s2-tci-512.tif -- expect 6 levels, 484/121/36/9/4/1 tiles, ~7 KB each"
  tiff_structure "$DATA/s2-tci-512.tif"

  log "verify: nested.parquet -- expect BOTH 'salary' and 'employee.salary'"
  duckdb -c "
    SELECT path_in_schema, type, data_page_offset, total_compressed_size
    FROM parquet_metadata('$FIX/nested.parquet');"

  log "verify: dict.parquet -- expect region_code RLE_DICTIONARY with dictionary_page_offset < data_page_offset"
  duckdb -c "
    SELECT path_in_schema, encodings, dictionary_page_offset, data_page_offset,
           data_page_offset - dictionary_page_offset AS dictionary_page_bytes
    FROM parquet_metadata('$FIX/dict.parquet');"

  log "verify: multi-rg.parquet -- expect 6 row groups x 3 columns, last one short"
  duckdb -c "
    SELECT row_group_id, count(*) AS columns, min(row_group_num_rows) AS rows
    FROM parquet_metadata('$FIX/multi-rg.parquet')
    GROUP BY row_group_id ORDER BY row_group_id;"

  log "verify: inline-colmeta.parquet -- expect created_by parquet-cpp-arrow 11, and a GAP after every chunk"
  duckdb -c "
    SELECT created_by FROM parquet_file_metadata('$FIX/inline-colmeta.parquet');"
  inline_gaps "$FIX/inline-colmeta.parquet"

  log "verify: page-index.parquet -- expect a ColumnIndex AND an OffsetIndex for all 12 chunks"
  page_index_extent "$FIX/page-index.parquet"

  log "verify: odd-tag.tif -- expect an ODD-length value for tag 42112, so the next value is preceded by a pad byte"
  tag_value_padding "$FIX/odd-tag.tif"

  log "verify: striped.tif -- expect STRIPED (no TileOffsets); planar2.tif -- expect planar=2 with 3x the tile grid"
  tiff_structure "$FIX/striped.tif" "$FIX/planar2.tif" "$FIX/tiny-cog.tif"

  log "verify: tiny-cog.tif -- expect LAYOUT=COG and a leader/trailer on every tile"
  gdalinfo "$FIX/tiny-cog.tif" | grep -E 'LAYOUT|Overviews:' || true
  head -c 200 "$FIX/tiny-cog.tif" | strings | grep -E 'BLOCK_LEADER|BLOCK_TRAILER|LAYOUT' || true
  cog_leader_trailer "$FIX/tiny-cog.tif"
}

# The gap between the end of each column chunk and the start of the next, and
# whether that gap begins exactly at the chunk's `file_offset`. For a
# parquet-cpp file every one of them does, and the gap holds that chunk's
# inline `ColumnMetaData`.
#
# This looks only at chunks, so a DuckDB file reports one gap -- the bloom
# filter block between the last chunk and the footer, which the resolver maps
# from `bloom_filter_offset`. What matters is `gaps_at_file_offset`: 0 for
# DuckDB, one per chunk for parquet-cpp.
inline_gaps() {
  duckdb -c "
    WITH extent AS (
      SELECT least(coalesce(dictionary_page_offset, data_page_offset),
                   data_page_offset) AS start,
             total_compressed_size AS len, file_offset
      FROM parquet_metadata('$1')),
    ordered AS (
      -- The last chunk's gap runs to the footer, not to a next chunk, and it
      -- is a gap like any other: coalesce rather than let `lead` drop it.
      SELECT start + len AS chunk_end, file_offset,
             coalesce(lead(start) OVER (ORDER BY start),
                      (SELECT file_size_bytes - footer_size - 8
                       FROM parquet_file_metadata('$1'))) AS next_start
      FROM extent)
    SELECT count(*) AS chunks,
           count(*) FILTER (next_start > chunk_end) AS gaps,
           coalesce(sum(next_start - chunk_end)
                    FILTER (next_start > chunk_end), 0) AS gap_bytes,
           count(*) FILTER (next_start > chunk_end
                            AND file_offset = chunk_end) AS gaps_at_file_offset
    FROM ordered;"
  # The first gap, spelled out: the bytes really are a ColumnMetaData thrift,
  # which is legible enough that the column name reads straight out of it.
  python3 - "$1" <<'PY'
import subprocess, sys
q = ("SELECT least(coalesce(dictionary_page_offset, data_page_offset), "
     "data_page_offset) + total_compressed_size, file_offset "
     f"FROM parquet_metadata('{sys.argv[1]}') ORDER BY 1 LIMIT 1;")
out = subprocess.run(['duckdb', '-csv', '-noheader', '-c', q],
                     capture_output=True, text=True).stdout.strip()
end, file_offset = (int(x) for x in out.split(','))
d = open(sys.argv[1], 'rb').read()
print(f'  first chunk ends at {end}, its file_offset is {file_offset}')
print(f'  bytes there: {d[end:end+56]!r}')
PY
}

# A page index is not visible to `parquet_metadata`, so this measures the space
# it occupies: everything between the last column chunk and the footer.
page_index_extent() {
  duckdb -c "
    WITH e AS (
      SELECT max(least(coalesce(dictionary_page_offset, data_page_offset),
                       data_page_offset) + total_compressed_size) AS data_end,
             count(*) AS chunks
      FROM parquet_metadata('$1')),
    f AS (SELECT file_size_bytes, footer_size, created_by
          FROM parquet_file_metadata('$1'))
    SELECT created_by, chunks, data_end,
           file_size_bytes - footer_size - 8 AS footer_start,
           file_size_bytes - footer_size - 8 - data_end AS between_data_and_footer
    FROM e, f;"
  echo "  (the per-chunk offsets are asserted in src/parquet.rs::"
  echo "   a_real_page_index_written_by_another_implementation_is_classified)"
}

# The parity of every out-of-line tag value, and therefore where TIFF's
# word-alignment padding falls.
tag_value_padding() {
  python3 - "$1" <<'PY'
import struct, sys

TSZ = {1:1, 2:1, 3:2, 4:4, 5:8, 6:1, 7:1, 8:2, 9:4, 10:8, 11:4, 12:8, 13:4}
d = open(sys.argv[1], 'rb').read()
bo = '<' if d[:2] == b'II' else '>'
off = struct.unpack(bo + 'I', d[4:8])[0]
n = struct.unpack(bo + 'H', d[off:off+2])[0]
values = []
for i in range(n):
    e = d[off + 2 + i*12 : off + 14 + i*12]
    tag, typ = struct.unpack(bo + 'HH', e[:4])
    cnt = struct.unpack(bo + 'I', e[4:8])[0]
    size = TSZ.get(typ, 0) * cnt
    if size > 4:
        at = struct.unpack(bo + 'I', e[8:12])[0]
        values.append((at, at + size, tag, size))
values.sort()
pads = 0
for (a, b, tag, size), (na, _, ntag, _) in zip(values, values[1:]):
    if na == b + 1:
        pads += 1
        print(f'  tag {tag}: {a}..{b} ({size} bytes, odd) then ONE pad byte at '
              f'{b}, next value (tag {ntag}) at {na}')
print(f'  {len(values)} out-of-line values in IFD 0, '
      f'{pads} word-alignment pad byte(s)')
if not pads:
    raise SystemExit('  FAIL: this fixture exists for the pad byte and has none')
PY
}

# Walk the IFD chain and report, per level, the tile/strip count and mean block
# size. `gdalinfo` reports overview dimensions but not how many tiles each
# level actually has, and the tile count IS the claim being checked -- so this
# reads TileOffsets/TileByteCounts (324/325) and StripOffsets/StripByteCounts
# (273/279) out of the file itself.
tiff_structure() {
  python3 - "$@" <<'PY'
import struct, sys

TSZ = {1:1, 2:1, 3:2, 4:4, 5:8, 6:1, 7:1, 8:2, 9:4, 10:8, 11:4, 12:8, 16:8, 17:8, 18:8}
FMT = {1:'B', 3:'H', 4:'I', 6:'b', 8:'h', 9:'i', 16:'Q'}

def dump(path):
    d = open(path, 'rb').read()
    bo = '<' if d[:2] == b'II' else '>'
    ver = struct.unpack(bo + 'H', d[2:4])[0]
    big = ver == 43
    if ver not in (42, 43):
        raise SystemExit(f'{path}: not a TIFF')
    off = struct.unpack(bo + ('Q' if big else 'I'), d[8:16] if big else d[4:8])[0]
    print(f'{path}: {"BigTIFF" if big else "classic TIFF"}, byte order {bo}')
    level = 0
    while off:
        if big:
            n = struct.unpack(bo + 'Q', d[off:off+8])[0]; p, esz = off + 8, 20
        else:
            n = struct.unpack(bo + 'H', d[off:off+2])[0]; p, esz = off + 2, 12
        tags = {}
        for i in range(n):
            e = d[p + i*esz : p + (i+1)*esz]
            tag, typ = struct.unpack(bo + 'HH', e[:4])
            if big:
                cnt = struct.unpack(bo + 'Q', e[4:12])[0]; inline = e[12:20]
            else:
                cnt = struct.unpack(bo + 'I', e[4:8])[0]; inline = e[8:12]
            nb = TSZ.get(typ, 0) * cnt
            if typ not in FMT:
                continue
            if nb > len(inline):
                vo = struct.unpack(bo + ('Q' if big else 'I'), inline[:8 if big else 4])[0]
                raw = d[vo:vo+nb]
            else:
                raw = inline[:nb]
            tags[tag] = list(struct.unpack(bo + FMT[typ] * cnt, raw))
        one = lambda t: tags.get(t, [None])[0]
        w, h, tw, th = one(256), one(257), one(322), one(323)
        tiled = 324 in tags
        offs, byts = (tags.get(324), tags.get(325)) if tiled else (tags.get(273), tags.get(279))
        mean = sum(byts) / len(byts) if byts else 0
        if tiled:
            grid = f'{-(-w//tw)}x{-(-h//th)}={-(-w//tw) * -(-h//th)}'
            shape = f'TILED {tw}x{th}, grid {grid}'
        else:
            shape = f'STRIPED (no TileOffsets), rowsperstrip={one(278)}'
        print(f'  level {level}: {w}x{h} subfiletype={one(254)} {shape}')
        print(f'           planar={one(284)} compression={one(259)} samples={one(277)} '
              f'blocks={len(offs) if offs else 0} mean_bytes={mean:.0f} total={sum(byts) if byts else 0}')
        p2 = p + n * esz
        off = struct.unpack(bo + ('Q' if big else 'I'), d[p2 : p2 + (8 if big else 4)])[0]
        level += 1

for a in sys.argv[1:]:
    dump(a)
PY
}

# GDAL's COG ghost area only DECLARES the leader and trailer. Check that every
# tile actually has them: the uint32 immediately before the tile offset must
# equal TileByteCounts, and the four bytes immediately after the tile must
# repeat the tile's own last four.
cog_leader_trailer() {
  python3 - "$1" <<'PY'
import struct, sys

d = open(sys.argv[1], 'rb').read()
bo = '<' if d[:2] == b'II' else '>'
off = struct.unpack(bo + 'I', d[4:8])[0]
n = struct.unpack(bo + 'H', d[off:off+2])[0]
tags = {}
for i in range(n):
    e = d[off + 2 + i*12 : off + 14 + i*12]
    tag, typ = struct.unpack(bo + 'HH', e[:4])
    if typ not in (1, 3, 4):
        continue
    cnt = struct.unpack(bo + 'I', e[4:8])[0]
    nb = {1:1, 3:2, 4:4}[typ] * cnt
    raw = d[struct.unpack(bo + 'I', e[8:12])[0]:][:nb] if nb > 4 else e[8:8+nb]
    tags[tag] = list(struct.unpack(bo + {1:'B', 3:'H', 4:'I'}[typ] * cnt, raw))

to, tb = tags[324], tags[325]
lead = sum(struct.unpack(bo + 'I', d[o-4:o])[0] == b for o, b in zip(to, tb))
trail = sum(d[o+b-4:o+b] == d[o+b:o+b+4] for o, b in zip(to, tb))
print(f'  base level: {len(to)} tiles; leader==TileByteCounts {lead}/{len(to)}; '
      f'trailer repeats last 4 bytes {trail}/{len(to)}')
print(f'  first tile: offset={to[0]} len={tb[0]} leader uint32 at {to[0]-4} = '
      f'{struct.unpack(bo + "I", d[to[0]-4:to[0]])[0]}')
PY
}

case "${1:-all}" in
  demo)     make_demo_parquet; make_demo_cog ;;
  fixtures) make_parquet_fixtures; make_foreign_parquet_fixtures; make_tiff_fixtures ;;
  verify)   ;;
  all)      make_demo_parquet; make_demo_cog; make_parquet_fixtures
            make_foreign_parquet_fixtures; make_tiff_fixtures ;;
  *)        echo "usage: $0 [all|demo|fixtures|verify]" >&2; exit 2 ;;
esac

verify
