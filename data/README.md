# Sample data

The files in here are **not committed**. Fetch them:

```sh
./scripts/fetch-data.sh
```

They come from
[Source Cooperative](https://data.source.coop/alukach/alukach-experimentation/cloud-native-access-control/)
— the same objects the deployed demo reads — and the script verifies each
against a pinned SHA-256.

| file | used by | what it is |
| --- | --- | --- |
| `nyc-taxi-8rg.parquet` | tests, demo | 400,000 rows × 19 columns, 8 row groups. Sized so a 64 KiB read spans more than one column chunk. |
| `s2-tci-512.tif` | tests, demo | Sentinel-2 true colour, 10 m, 655 tiles across 6 levels. |
| `paris-landmarks.tif` | demo only | IGN orthophoto at 0.4 m over the Eiffel Tower and the Arc de Triomphe. |

## Why the checksums matter

The numbers in [`docs/findings.md`](../docs/findings.md) are properties of
these exact bytes — 27 of 27 straddling reads, 49 tiles against 25, 21 tiles
withheld. A sample that changed silently would invalidate all of them without
a single test failing. If the script reports a mismatch, do not update the
checksum until the measurements have been re-run.

## Regenerating instead of fetching

```sh
./scripts/make-fixtures.sh all   # the Parquet and the Sentinel granule
./scripts/make-paris.sh          # the Paris orthophoto
```

Both need `gdal`, and `make-fixtures.sh` also needs `duckdb`. `make-paris.sh`
re-fetches 476 tiles from IGN's WMTS, so it is slower than the download and
exists to document provenance rather than to be run routinely.

`paris-landmarks.LICENSE` is committed, because attribution is a condition of
the licence and should not depend on a download succeeding.
