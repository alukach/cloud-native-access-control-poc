# Resolver fixtures

Small, adversarial files. Each pins one edge case a resolver can get wrong
*silently* — no panic, no error, just a region set that authorizes the wrong
bytes. Regenerate with `./scripts/make-fixtures.sh fixtures`, which also
re-measures every property claimed below.

A binary blob with no explanation is untestable knowledge, so: what each file is
**for**, and the measured evidence that it actually is that.

| file | size | what it is FOR |
| --- | --- | --- |
| `nested.parquet` | 2.2 KB | A struct column with a `salary` field, so the footer carries `employee.salary` **and** a separate top-level `salary`. A rule spelled `region.column <> 'salary'` must not block the nested one — the resolver has to key regions on the full dotted `path_in_schema`, not the leaf. |
| `dict.parquet` | 41 KB | A low-cardinality column with a dictionary page, so a column chunk's extent must start at `dictionary_page_offset`, not `data_page_offset`. For a low-cardinality column the dictionary page *is* the set of distinct values — exactly the bytes a policy is trying to withhold. |
| `inline-colmeta.parquet` | 24 KB | **Not written by DuckDB.** parquet-cpp (pyarrow) wrote a *copy* of each chunk's `ColumnMetaData` thrift into the data stream, right after that chunk's pages, until Arrow 12 — and nothing in the footer records its length. A resolver that maps only `min(dict, data) .. + total_compressed_size` leaves one unclassified span per chunk. `Unmapped` denies, so those spans denied every read that straddled one; worse, the structure names the column and carries its chunk-level min and max, so it survived `rewrite`'s by-column scrub in plaintext. |
| `page-index.parquet` | 24 KB | **Not written by DuckDB.** A real `ColumnIndex` *and* `OffsetIndex` for every chunk. DuckDB emits neither, so before this file the only test of the page-index path ran against a synthetic arrow-rs file built inside `src/parquet.rs` — a resolver checking its own arithmetic. parquet-cpp also orders them differently: every `ColumnIndex` first, then every `OffsetIndex`. |
| `odd-tag.tif` | 19 KB | An **odd-length** out-of-line tag value. TIFF requires every value to start on a word boundary, so the next one is preceded by a filler byte that belongs to no structure. A resolver that maps a value as exactly its length leaves that byte `Unmapped` *inside the metadata prefix*, which denies the header read every reader makes first. Every COG on `sentinel-cogs.s3.us-west-2.amazonaws.com` is written this way. |
| `multi-rg.parquet` | 98 KB | The plain case: several row groups, a few columns, and a short final row group, for `row_group` indexing and for catching a resolver that derives extents from a fixed rows-per-group instead of from the footer. |
| `striped.tif` | 11 KB | A **non-tiled** TIFF: `StripOffsets`, no `TileOffsets`. A tile-based resolver maps nothing, and `[].iter().all(..)` is `true`, so under the conjunctive decision the entire image would be readable. The resolver must map it wholly to `Unmapped` (or refuse it). |
| `planar2.tif` | 128 KB | `PlanarConfiguration=2`, where `TileOffsets` is band-major and holds `samples × grid` entries, not one per tile. A resolver written for `PlanarConfiguration=1` attributes every band past the first to the wrong pixels with no gap for `Unmapped` to catch. It must reject the file. |
| `tiny-cog.tif` | 18 KB | The happy path, for golden offsets: a tiled COG with two overview levels and GDAL's block leader/trailer, so tile bytes really run from `offset-4` to `offset+len+4`. |

## Measured properties

Re-measure any of these with `./scripts/make-fixtures.sh verify`.

**`nested.parquet`** — `parquet_metadata` reports four leaves; `salary` and
`employee.salary` are distinct chunks at distinct offsets:

```
path_in_schema     type        data_page_offset  total_compressed_size
id                 INT64                      4                    457
salary             INT32                    461                    432
employee.name      BYTE_ARRAY               893                    440
employee.salary    INT32                   1333                    432
```

**`dict.parquet`** — only `region_code` is dictionary-encoded, and its
dictionary page is the 49 bytes a `data_page_offset` start would skip. The two
`PLAIN` columns are there so a test can tell "handles dictionaries" from "adds a
fixed offset":

```
path_in_schema  encodings       dictionary_page_offset  data_page_offset  dict bytes
id              PLAIN                             NULL                 4        NULL
region_code     RLE_DICTIONARY                   20804             20853          49
value           PLAIN                             NULL             20981        NULL
```

**`inline-colmeta.parquet`** — `created_by = parquet-cpp-arrow version 11.0.0`;
3 columns × 4 row groups = 12 chunks, and **12 gaps totalling 1,044 bytes**,
every one of them starting exactly at that chunk's `file_offset`
(`gaps_at_file_offset = 12/12`). The same query over any DuckDB fixture reports
`0/…`. The first gap is at 2655, and the bytes there are a thrift struct with
the column name in the clear:

```
b'&\xbe)\x1c\x15\x02\x195\x10\x00\x06\x19\x18\x02id\x15\x02\x16\xe8\x07...'
                                              ^^ "id"
```

The resolver classifies all 12 as `column_metadata` regions belonging to their
column, and the file indexes with **zero unmapped bytes**. The same writer's
output at scale — Hugging Face's `adult-census-income` (`parquet-cpp-arrow
11.0.0`, 15 columns × 33 row groups, 553,790 bytes) — had **495 spans and
45,498 unmapped bytes** before the fix and **zero** after.

**`page-index.parquet`** — `created_by = parquet-cpp-arrow version 25.0.1`;
12 chunks, the last of which ends at 21,301, and the footer starts at 21,840:
**539 bytes of page index** between them, which the resolver attributes as 24
`column_index` regions (one `ColumnIndex` and one `OffsetIndex` per chunk).
Zero unmapped bytes.

**`odd-tag.tif`** — 11 out-of-line values in IFD 0, of which `GDAL_METADATA`
(tag 42112) is **185 bytes at 652–837**, an odd length. `ModelPixelScale` (tag
33550) begins at 838, so byte 837 is TIFF's word-alignment pad. It is folded
into the `tag_values` region that ends there — `[652, 838)` — rather than given
a metadata name of its own, and the file indexes with zero unmapped bytes. Real
files measured the same way, before the fix: `S2A_10SEG_20240923_0_L2A/TCI.tif`
1 unmapped byte at 1303, `B01.tif` 1 at 835, `B04.tif` 1 at 1291, `AOT.tif` and
`SCL.tif` 0 (their metadata happens to be an even number of bytes).

**`multi-rg.parquet`** — 6 row groups × 3 columns = 18 chunks; row groups 0–4
hold 2048 rows and row group 5 holds 1760.

**`striped.tif`** — 256×256, `RowsPerStrip=32`, 8 strips, **no tag 324**.

**`planar2.tif`** — 256×256, tiled 64×64 (a 4×4 = 16 grid), `PlanarConfiguration=2`,
`samples=3`, and **48 `TileOffsets` entries** — three per grid cell. Index 16 of
48 is tile 0 of band 2, not tile 16.

**`tiny-cog.tif`** — `LAYOUT=COG`; three IFDs (256×256 base, then 128×128 and
64×64 overviews) tiled 64×64, so 16 / 4 / 1 tiles. The ghost area declares
`BLOCK_LEADER=SIZE_AS_UINT4` and `BLOCK_TRAILER=LAST_4_BYTES_REPEATED`, and all
16 base tiles honour both: the `uint32` at `offset-4` equals `TileByteCounts`,
and the four bytes at `offset+len` repeat the tile's last four. The first tile
is at offset 6898, length 740, leader at 6894.

## Provenance

The four rasters are 256×256 windows at pixel `(1024, 4096)` of Sentinel-2 L2A
scene `S2A_10SEG_20240923_0_L2A` (`TCI.tif`, EPSG:32610, public, from
`sentinel-cogs.s3.us-west-2.amazonaws.com`), read through GDAL's `/vsicurl` so
regenerating them never downloads the 57 MB source. The window is on land: an
all-nodata window compresses to a couple of KB and makes every byte offset
degenerate. The Parquet files are generated from DuckDB literals and need no
source at all.

`odd-tag.tif` is the same window with one extra metadata item (`-mo NOTE=odd`),
chosen only so the `GDAL_METADATA` string comes out an odd number of bytes.

`inline-colmeta.parquet` and `page-index.parquet` are the exception to
everything above: they are the only files here that DuckDB cannot produce, and
they exist because every other Parquet fixture in this repository came from
DuckDB. A resolver tested only against its own writer's output passes because
the fixture and the code share an author, which is how issue #23 survived — 495
unclassified spans in a file from the internet, zero in everything committed
here. They need two pinned pyarrow versions, because no single one writes both
shapes:

```sh
uv venv --python 3.11 .venv311
uv pip install --python .venv311/bin/python 'pyarrow==11.0.0' 'numpy<2'
python3 -m venv .venv && .venv/bin/pip install pyarrow   # >= 13

PYARROW11=.venv311/bin/python PYARROW=.venv/bin/python \
    ./scripts/make-fixtures.sh fixtures
```

Arrow 12 stopped writing the inline `ColumnMetaData`, so 11.0.0 is the last
version that can make the first file; `write_page_index` did not exist before
13, so an old pyarrow cannot make the second. Both steps are skipped with a
warning when the variables are unset, so the rest of the script still runs
without pyarrow.
