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

The three rasters are 256×256 windows at pixel `(1024, 4096)` of Sentinel-2 L2A
scene `S2A_10SEG_20240923_0_L2A` (`TCI.tif`, EPSG:32610, public, from
`sentinel-cogs.s3.us-west-2.amazonaws.com`), read through GDAL's `/vsicurl` so
regenerating them never downloads the 57 MB source. The window is on land: an
all-nodata window compresses to a couple of KB and makes every byte offset
degenerate. The Parquet files are generated from DuckDB literals and need no
source at all.
