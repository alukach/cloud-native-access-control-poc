# Sub-object access control for cloud-native formats

**Date:** 2026-09-10
**Status:** Design, revised after review. Not yet implemented.

## Problem

Cloud-native formats — Parquet, COG, Zarr, Icechunk — are read by HTTP range
requests against object storage. Access control today is all-or-nothing. We
want finer grain: an analyst who reads every column but `salary`, a licensee
who reads full-resolution imagery inside their AOI and overviews everywhere
else.

A range request is opaque. `bytes=1234-5678` carries no hint of which column or
tile it lands in. Everything here follows from recovering that meaning.

## What this proof of concept must decide

Whether `multistore` should adopt sub-object access control. That turns on
whether real readers issue boundary-aligned ranges. **Measurement of the two
readers we care about is already done, and the answer is conditional:**

| Reader | Default behavior | Aligned behavior |
| --- | --- | --- |
| hyparquet | Coalesces column chunks into runs up to a 2 MB `runLimit` — with ~1 MB row groups, all 19 columns merge into **one** fetch | Passing `columns: [...]` yields **one exact fetch per column chunk**, `[min(dict,data)_page_offset, +total_compressed_size)` |
| geotiff.js | `fromUrl` defaults `blockSize: 65536`, so reads are 64 KB-block-aligned, not tile-aligned — one block spans ~9 tiles at 7 KB/tile | `blockSize: undefined` disables blocking |

So **column-level masking is not pointless, but it is conditional on the reader
projecting columns.** Without projection pushdown, a full-table scan coalesces
across the very boundary the policy draws and every request straddles.

That reframes the deliverable. The question is no longer "does coalescing
break this" — it does, by default, in both readers. It is:

> Given that aligned reads are achievable in both readers by configuration,
> what does a gateway do about clients it does not control?

The demo answers it by making both modes a toggle and showing the counters
side by side: ranges issued, ranges straddling a boundary, query outcome.

**Adopt** if aligned mode is reachable for the clients that matter (DuckDB,
pyarrow, GDAL all push projection down) and the gateway can detect and reject
unaligned reads with a comprehensible error. **Do not adopt** if the common
path is a coalesced scan that cannot be nudged, because then the feature only
ever returns 403.

## Non-goals

- No `multistore` integration.
- No identity or authentication. The principal is a mocked JSON object.
- No writes.
- No hiding that data exists. See "What this does not do".

## Mechanism

Two stages, strictly separated.

**Resolve** maps a byte range to logical regions, using a `LayoutIndex` built
once per object from its footer.

**Decide** evaluates the policy against every overlapped region.

### Decision semantics

These four rules are the security core. They were all unstated in the first
draft and each one is a bypass when guessed wrong.

1. **Conjunctive.** *Every* overlapped region must satisfy the policy. The
   decision is `all`, not `any`, short-circuiting on the first denial.
   Under `any`, `bytes=<footer start>-<salary chunk end>` matches the metadata
   rule and serves the salary column.
2. **Total coverage.** Regions partition `[0, object_size)` with no holes.
   Bytes belonging to nothing get an explicit `{"kind":"unmapped"}` region that
   no policy can match. Without this, `all` over an empty set returns `true`
   and any unmapped range is authorized — Parquet's `PAR1` magic, inter-chunk
   padding, page index and bloom filter pages, or a *striped* GeoTIFF where
   `TileOffsets` is absent and therefore nothing at all maps.
3. **Absent Range means the whole object.** Normalize a missing header,
   `bytes=0-`, and `bytes=-N` to an explicit range and decide it like any
   other. A reader that gets 403 on a coalesced range commonly retries as a
   full-object GET, walking straight into this.
4. **Half-open internally, inclusive on the wire.** HTTP `bytes=a-b` includes
   `b`; `Region { start, len }` does not. Canonicalize at the boundary. Getting
   this wrong makes `bytes=<salary_start - 1>-<salary_start>` read one
   protected byte per request without ever tripping a denial.

### The API returns ranges, not a verdict

```rust
fn check(index: &LayoutIndex, policy: &Policy, ctx: &Value, req: &RangeRequest)
    -> Decision;

enum Decision {
    Authorized { canonical: Vec<Range<u64>> },
    Denied { reason: DenyReason },
}
```

The caller **must fetch exactly `canonical`, must not forward the client's
original `Range` header, and must reject any backend response whose
`Content-Range` differs.**

This matters because the gateway's Range parser and the backend's need not
agree, and RFC 9110 says an origin that does not understand a Range header
*must ignore it and return 200 with the entire representation*. So
`bytes=0-0, items=100-200` can be allowed by a lenient parser and answered
with the whole object. Same class: `If-Range` with a stale validator, and
multi-range requests answered as `multipart/byteranges`. Never forwarding the
client's header closes all of them at once, and is backend-independent.

`Denied` must not carry the resolved regions off-box — a 403 that echoes them
hands back the protected column's name and byte extent.

### Types

```rust
struct Region { start: u64, len: u64, kind: RegionKind, props: Value }
```

`build_index(footer: &[u8], object_size: u64, format: Format) -> LayoutIndex`
is **synchronous and pure**. There is no `RangeFetcher` trait: the caller
fetches. In the browser that caller is hyparquet's `AsyncBuffer` or
geotiff.js's source, which are already range-fetchers written in the language
that owns the network. An async trait across the WASM boundary would buy an
`async-trait` dependency, a `Send`/`?Send` split, and an error type spanning
`JsValue` and `io::Error`, for one implementation.

Regions are a sorted `Vec`, binary-searched. `props` JSON is built inside the
hit loop, so non-overlapping regions never materialize any.

## Format resolvers

Parquet and COG ship first: columnar masking and spatial masking are the two
genuinely different shapes. `resolve` takes the object key as well as the
range, which is what makes Zarr nearly free later.

### Parquet

- **Never use `ColumnChunk.file_offset`.** It is deprecated in
  `parquet.thrift`, which records that implementations disagreed about whether
  it points at the `ColumnMetaData` or the first page, and that "in many cases
  the `ColumnMetaData` at this location is wrong."
- Extent is `min(dictionary_page_offset, data_page_offset)` through
  `+ total_compressed_size`. Starting at `data_page_offset` leaves the
  dictionary page outside every region — and for a low-cardinality column the
  dictionary page *is* the set of distinct values.
- `ColumnChunkMetaData::byte_range()` in arrow-rs **panics** on negative
  offsets, which violates fail-closed. Read the fields and deny on malformed
  input.
- **`region.column` must be the full dotted `path_in_schema`**, which is a
  `list<string>`. `region.column NOT IN ('salary')` does not block
  `employee.salary`. Normalize case and pin the convention in the schema.
- **Page index and bloom filters are column-attributed regions**, not generic
  metadata: `{"kind":"column_index","column":"salary"}`. `ColumnIndex` leaks
  per-**page** min/max and null counts; `OffsetIndex` leaks per-page row
  counts. Both sit outside `total_compressed_size`.
- Their offsets and lengths are **in the footer**, so classifying them needs no
  second read — we need to know where they are, not what they contain. If
  `bloom_filter_offset` is set without `bloom_filter_length`, mark from the
  offset to the next known region as `unmapped` rather than guessing.
- If `ColumnChunk.file_path` is set, the data is in another object. Deny.

### COG

- **GDAL block leader/trailer, the finding that would have broken the demo on
  its first real file.** GDAL COGs declare `BLOCK_LEADER=SIZE_AS_UINT4` and
  `BLOCK_TRAILER=LAST_4_BYTES_REPEATED` in a ghost area. `TileOffsets[i]`
  points at the *payload*, so COG-aware readers fetch
  `offset - 4 .. offset + len + 4`. A resolver mapping only
  `[offset, offset+len)` sees every legitimate tile request overlap 8
  unclassified bytes and, under default deny, denies all of them. The leader
  and trailer belong to the tile region.
- **Overview level is not the IFD index.** Derive it from the `ImageWidth`
  ratio against full resolution. Masks are their own IFDs
  (`NewSubfileType` bit 2), overviews set bit 0, masks of overviews set both.
  Numbering by chain position mislabels masks as overview levels, and getting
  the direction backwards silently inverts `region.overview_level >= 2` into
  "anyone may read full resolution."
- Follow `SubIFDs` (tag 330). GDAL ≥ 3.2 hangs overviews and masks there; a
  resolver walking only the main chain leaves all their tile bytes unmapped.
- `PlanarConfiguration = 2` makes tile count `SamplesPerPixel × TilesPerImage`
  with per-plane grouping. Props have no plane component. Detect and fail
  closed.
- Tag values over 4 bytes (8 in BigTIFF) live outside the IFD, so
  `TileOffsets`/`TileByteCounts`/GeoTIFF keys are **their own metadata
  regions**, sitting between the IFDs and the pixel data. "The first N bytes
  are metadata" is wrong even for well-formed COGs.
- Support BigTIFF — anything over 4 GB is BigTIFF, and the doc's own
  "100,000 regions" case implies it. Version `0x2B`, 16-byte header, 20-byte
  IFD entries, u64 counts.
- Georeferencing: handle `ModelTransformationTag` (rotated rasters make a tile
  a quadrilateral, not a bbox) and fail closed on multi-tiepoint GCP-only
  files. Overview IFDs generally do **not** repeat the georeferencing tags;
  scale the full-resolution transform, and the OGC COG standard permits 2–10×
  decimation, so the ratio is not necessarily a power of two.

Use `tiff` 0.11, which exposes `Tag::Unknown(u16)` and `tag_iter()`, so private
tags like `GDAL_METADATA` are reachable without a hand-rolled IFD parser.
`async-tiff` has better primitives (`tile_byte_range`) but couples to
`object_store`, whose `http` feature is the one arrow-rs path known broken on
wasm32.

### Zarr and Icechunk, deferred

Recorded because they change the shape of things, not scheduled:

- Zarr chunk identity is in the **key**, but the key grammar is not fixed —
  v3 defaults to `precip/c/0/3/2`, v2 to a configurable `dimension_separator`.
  Parsing a key requires first reading that array's metadata.
  **Canonicalize the key and reject non-canonical forms** rather than
  normalizing silently: `precip/../restricted/0.0.0` and its encoded variants
  are a parser differential where policy sees one array and the backend serves
  another.
- Sharded v3 puts the index at `end` *by default*, not always
  (`index_location` may be `start`), and the shard object is **not
  self-describing** — index size is computed from array metadata as
  `16 × chunks_per_shard + 4`. A shard index classified as blanket `metadata`
  is a read *inside* a data object, and it leaks per-chunk compressed sizes,
  which is a coarse content oracle.
- Icechunk chunk refs have three variants, not one: **inline** (bytes live in
  the manifest, so there is no byte range in any data object), native, and
  **virtual** (a URL to a foreign object). Resolving one chunk costs up to four
  round trips, manifests are zstd-compressed FlatBuffers with no random access,
  and they index chunk→bytes while we need bytes→chunk, so the index is
  per-snapshot and requires ingesting every manifest. `ObjectId` cannot select
  it and ETag cannot key it. Virtual refs are a confused-deputy primitive:
  an attacker-authored manifest names any object the gateway's credentials
  reach. Allowlist virtual targets and re-authorize against the target's own
  policy.

## Policy language

CQL2, evaluated by `developmentseed/cql2-rs` (v0.6). The audience already
writes CQL2 against STAC.

The real signature is
`Expr::matches(self, Option<&Value>) -> Result<bool, Error>` — it *consumes*
`self`, so per-region evaluation clones the expression.

```yaml
# role: licensee
allow:
  - "region.kind = 'metadata'"
  - "region.kind = 'column_chunk' AND region.column NOT IN ('salary','ssn')"
  - "region.kind = 'tile' AND region.overview_level >= 2"
  - "user.role = 'licensee' AND region.kind = 'tile' AND S_INTERSECTS(region.geom, POLYGON((...)))"
```

Filters are OR'd over a default deny. There is no `effect: deny`, because
`deny` is syntactic sugar for `NOT` and CQL2 is closed under negation. An
explicit effect buys only precedence across independently authored policies,
which is out of scope, and costs documented precedence rules. This is the known
extension point.

### Verified behavior, and what it forces

Every claim below was executed against the crate, not read.

- **`S_INTERSECTS` against a bare `bbox` array never returns true.** Untagged
  deserialization matches `[-105,40,-104,41]` as `Array` before anything
  geometric, and `is_region()` accepts only `Geometry` and `BBox`. It returns
  `Err("Could not reduce expression to boolean")`. The normative cql2-json
  schema defines a bbox literal as the *object* `{"bbox":[...]}`. **Props emit
  a GeoJSON geometry under `region.geom`**, plus `{"bbox":[...]}` under
  `region.bbox` for arithmetic rules.
- **Property typos cannot be caught at evaluation time.** `matches()` returns
  `Err(NonReduced)` for a simple unresolved property, but `region.knid IS NULL`
  returns `Ok(true)` — `isNull` folds an absent property to true — and boolean
  absorption (`FALSE AND x`, `TRUE OR x`) swallows a typo'd operand whenever a
  sibling decides the result. So the obvious test passes while proving nothing.
  **Policies are validated at load** by walking `Expr::Property` nodes against
  a declared queryables schema per format and per region kind. `IS NULL` is
  banned in policies.
- **`Err` from `matches()` denies the whole request**, not just that rule. An
  unguarded rule such as `region.column NOT IN (...)` errors against every tile
  region, so guard clauses like `region.kind = 'column_chunk' AND ...` are
  load-bearing security controls, enforced today only by author discipline —
  hence load-time validation.
- Type mismatch is a hard error: `region.overview_level >= '2'` dies against a
  numeric property. YAML is string-typed; this will bite.
- `IN` compares rendered text, so `region.x IN (12)` is true and
  `region.x IN ('12')` is false for the same number.
- Identifiers are case-sensitive; operator spellings are not.
- **Props must be scalars plus one whitelisted geometry.** `Expr::try_from`
  is untagged, so a props value shaped like `{"property":"user.id"}` or
  `{"op":...}` becomes that AST node rather than data. Props are synthesized
  from file-derived metadata (Parquet key-value metadata, TIFF tags). Never
  pass raw nested file JSON through. Never emit `null` — absent and null are
  indistinguishable and comparing against null errors.
- The evaluation context must not contain a `properties` key: lookup falls back
  to `properties.{name}`, so data could shadow a policy name.
- **Build filters as AST nodes, never by string concatenation.** Interpolating
  a polygon into filter *text* is a CQL2 injection whenever the AOI comes from
  a licence record rather than a literal.
- **Performance: ~20.6 µs per AOI evaluation**, almost all of it re-parsing the
  policy's GeoJSON through WKT on every call, because `matches` consumes the
  expression. 200 tiles × 4 rules ≈ 16 ms natively, worse in WASM. The fix —
  pre-convert literal geometry operands at policy load and add
  `matches(&self, ..)` — is upstream work in our own crate. Named as work, not
  assumed away.
- `matches()` has **one upstream test**, and it does not cover the `Err` path
  our fail-closed story depends on. cnac owns testing it.

### CRS is a fail-open hazard

`geo` is planar and CRS-agnostic. Tile bboxes come from the raster's own CRS
(usually projected metres); the AOI polygon is written by a human. A policy
polygon authored in Web Mercator metres **contains every degree-scale bbox in
a 4326 raster**, so `S_INTERSECTS` is true for every tile at every level and
the whole image is served. Nothing errors.

Carry the CRS and axis order in props and in the policy, and **refuse to
evaluate a spatial predicate across mismatched CRS.**

## Denial semantics

403. This breaks readers mid-query, which is honest about the cost. Zero-fill
(plausible for COG tiles, corrupt for Parquet without synthesized null pages)
and footer rewriting (best client experience, most work) are the alternatives,
and neither is built here.

## Implementation shape

One crate. `src/`, `web/`, `data/`. The wasm-bindgen shim is ~40 lines behind
`#[cfg(target_arch = "wasm32")]`; a second crate would buy a workspace, two
manifests and version sync for that.

Pins, all verified to build for `wasm32-unknown-unknown`:
`parquet 59.3` with `default-features = false` (footer thrift is never
compressed, so no codec features are needed), `tiff 0.11`, `geo 0.33`,
`cql2 0.6`, and `getrandom` as a **direct** dependency with the `wasm_js`
feature — a transitive dependency cannot have that feature enabled.

Bundle is **~1.4 MiB** once real symbols are exported (measured at Task 1 with
a representative `S_INTERSECTS` export; an empty cdylib measures 312 bytes
because LTO strips the whole graph, which is not a meaningful baseline). That
is ~60% above the pre-implementation estimate of ~900 KB. Of it, **cql2 is the
dominant share**: it has no
`[features]` section, so `sqlparser`, `jiff` + tzdb and `jsonschema` are all
mandatory. Feature-gating them upstream is the only lever that matters, and
nothing else we do to bundle size will show. Do not reuse the published
`cql2-wasm` npm package (3.75 MB, no release profile, and behind the crate).

## Web demo

Static, on GitHub Pages, WASM over the same crate.

**GitHub Pages serves ranges correctly** — verified against a live `*.github.io`
asset: `accept-ranges: bytes`, `206` for `bytes=0-19`, suffix `bytes=-20` (the
Parquet footer pattern), and open-ended `bytes=100-`; `416` past EOF.
Multi-range returns `200` with the full file, which is harmless since
geotiff.js defaults `maxRanges = 0`.

Two hosting traps, both measured:

- **Pages applies Range *after* gzip.** On a compressed type, a ranged request
  returns a slice of the *compressed* stream with a `content-range` against the
  compressed length. Browsers always send `Accept-Encoding: gzip` and that
  header is Fetch-forbidden, so this is unfixable from JS. It does not fire for
  us — `application/octet-stream` (`.parquet`), `image/tiff` and
  `application/wasm` are not compressed by Pages — but it is one MIME-database
  change from silently breaking. **CI asserts the sample files come back with
  no `content-encoding`.**
- **Git LFS does not work on Pages.** It serves the pointer text. Commit the
  binaries directly.

Interception is at each library's own range seam, not a `fetch` shim:

```js
// hyparquet: supply an AsyncBuffer
{ byteLength: size, async slice(start, end) { /* end exclusive */ } }

// geotiff.js: subclass BaseSource, pass to GeoTIFF.fromSource
class PolicySource extends BaseSource {
  async fetch(slices, signal) {}   // slices: [{offset, length}]
  get fileSize() {}
}
```

Denials propagate cleanly in both. hyparquet rejects the `parquetRead` promise;
geotiff.js's source throws on a non-ok response, and `allowFullFile` defaults
`false` so even a 200 throws rather than silently accepting a full file. No
hangs, no silent garbage.

Two configuration traps that will otherwise eat a day:

- hyparquet's footer read defaults to a **512 KB tail**. On an 8 MB file that
  straddles the last row group's chunks, so the demo's own bootstrap read trips
  the coalescing rule and nothing ever loads. Pass `initialFetchSize` ~8 KB.
- geotiff.js documents `blockSize: null` to disable blocking, but
  `maybeWrapInBlockedSource` tests `=== undefined`, so `null` yields NaN block
  math. Use `blockSize: undefined`.

The UI:

- Parquet renders as a row-group × column grid, COG as a tile grid per overview
  level. CSS grid, not canvas.
- Spatial policy uses two or three **preset AOI polygons** pasted into the
  policy textarea. Real `S_INTERSECTS` over `geo`, real tiles going dark, for a
  string constant each. Click-to-draw is ~150 lines of screen→pixel→geo
  transform and is not the finding.
- **An alignment toggle** — projection on/off for Parquet, blocking on/off for
  COG — with the counters visible in both positions. This is the deliverable.
- The heatmap is a second colorway on the same grid, fed by the log live mode
  already emits. No separate replay mode and no log format: a recorded log
  cannot surface coalescing, because coalescing is a behavior of the live
  reader.
- Denying `region.kind = 'metadata'` is permitted, and breaks everything.

### Sample files

Sized so coalescing bites in default mode. Both are demonstrable in both modes.

| file | size | structure |
| --- | --- | --- |
| `nyc-taxi-8rg.parquet` | 8.4 MB | 8 row groups × 19 columns = 152 chunks, 630 B – 275 KB each; ~1.05 MB per row group, under the 2 MB `runLimit`, so a default read collapses each row group to one fetch |
| `s2-tci-512.tif` | 4.7 MB | 6 overview levels, 484/121/36/9/4/1 tiles at 512 px; ~7 KB per tile, so one 64 KB block spans ~9 tiles |

```sh
# Parquet - ROW_GROUP_SIZE is mandatory; the 1M-row default yields ONE row group.
# SNAPPY, not ZSTD: hyparquet handles uncompressed and snappy natively.
duckdb -c "COPY (SELECT * FROM read_parquet('yellow_tripdata_2024-01.parquet') LIMIT 400000)
  TO 'nyc-taxi-8rg.parquet' (FORMAT PARQUET, COMPRESSION SNAPPY, ROW_GROUP_SIZE 50000);"

gdal_translate TCI.tif s2-tci-512.tif -of COG \
  -co BLOCKSIZE=512 -co COMPRESS=JPEG -co QUALITY=75 -co OVERVIEWS=IGNORE_EXISTING
```

Sources: NYC TLC yellow taxi trip data, Sentinel-2 L2A TCI. ~13 MB committed,
against a 1 GB Pages limit and a 100 MB per-file limit.

## Testing

- **Coverage invariant.** The union of all regions equals `[0, object_size)`.
  One assertion, and it kills the unmapped-range bypass and the Parquet
  dictionary-page gap together.
- **Golden offsets** against checked-in fixtures, including a nested-column
  Parquet and a GDAL COG with leader/trailer, overviews, and a mask IFD.
- **Boundary cases at ±1** around every region edge, plus suffix, open-ended,
  zero-length, past-EOF, and absent-Range requests.
- **Fail closed**: a policy referencing an undeclared property is rejected *at
  load*; `Err` from `matches` denies.
- **Hosting regression**: CI asserts the sample files are served by Pages with
  `accept-ranges: bytes` and no `content-encoding`.

## What this does not do

This reduces access and enforces licensing. **It is not confidentiality, and
it is not an access gate** — it is a sub-object filter that presumes an
object-level authorization decision made elsewhere. Where no policy matches a
path, deny.

- Metadata is served intact, so a denied column's name, type and size leak.
  Footer statistics and any bloom filter leak values — and the page index makes
  that **per-page** (~20k rows) min/max, null counts and row counts, not
  per-row-group. For a sorted column that approaches reconstructing the
  distribution.
- **The AOI is recoverable.** Probing tile ranges and observing 403 versus 206
  recovers the licensed boundary at tile granularity in O(tiles) requests. The
  AOI is often itself the sensitive thing.
- **Data outside the AOI is delivered.** `S_INTERSECTS` at tile granularity
  serves any tile *touching* the AOI, in full. The effective licensed area is
  the AOI dilated to tile boundaries; an AOI smaller than one tile yields a
  whole tile.
- **The web demo enforces nothing.** Policy, principal and interception all run
  client-side, and the sample files are readable by `curl`. It visualizes a
  decision; it is not an enforcement point.
- Index construction is reachable by a principal who may read nothing: a denied
  request still costs the gateway a privileged footer read, and cache-occupancy
  timing reveals whether someone else recently touched an object.
- `endpoint` must never derive from client input, or it is a credentialed SSRF
  primitive.
- Allow/deny is *not* a value oracle — the decision depends only on layout,
  never on data values. The value leakage is entirely through served metadata.

### Cache validity

Key the index cache on the full tuple `(endpoint, bucket, key, version_id,
format, etag)`, never the ETag alone. ETag is not a trustworthy content digest:
S3 multipart ETags are hash-of-hashes, SSE-KMS ETags are not content hashes,
CDNs rewrite them, and single-part ETags are MD5 — which is chosen-prefix
collidable, so where a principal can write the protected path they can swap in
a file whose *footer relabels the column chunks* while the ETag is unchanged.
The sound fix is `If-Match: <etag the index was built from>` on the authorized
data fetch, so the backend refuses to serve bytes from a different version.
