# Sub-object access control for cloud-native formats

**Date:** 2026-09-10
**Status:** Approved design, not yet implemented

## Problem

Cloud-native formats — Parquet, COG, Zarr, Icechunk — are read by HTTP range
requests against object storage. Access control today is all-or-nothing: a
principal may read the object or may not. We want finer grain. An analyst
should read every column but `salary`. A licensee should read full-resolution
imagery inside their AOI and overviews everywhere else.

A range request is opaque. `bytes=1234-5678` carries no hint of which column or
which tile it lands in. Everything here follows from recovering that meaning.

## Goals

1. Determine whether a principal may read a given byte range of a given object,
   using rules written in a concise, expressive language.
2. Reuse the same machinery in reverse: given a log of past range requests,
   report which columns, tiles, or areas were read most.
3. Ship a static web UI on GitHub Pages that demonstrates both against real
   files, so the approach can be evaluated before `multistore` changes.

## Non-goals

- No `multistore` integration. This project produces a crate and a demo; wiring
  it into the gateway is separate work informed by what we learn here.
- No identity or authentication. The principal is a mocked JSON object.
- No writes. Read paths only.
- No hiding that data exists. See "What this does not do".

## Mechanism

Two stages, strictly separated.

**Resolve** maps a byte range to logical regions. Each format keeps a metadata
block that describes its own byte layout; parsing it yields a `LayoutIndex`
that is built once per object and cached.

**Decide** evaluates a policy against each overlapped region. Default deny.

### Format coverage

| Format | Range to meaning | Notes |
| --- | --- | --- |
| Parquet | Footer `FileMetaData` gives each column chunk's offset and length | Exact, cheap |
| COG | IFD `TileOffsets` / `TileByteCounts` per overview level; bbox from `ModelTiepoint` and `ModelPixelScale` | Exact; index can be large |
| Zarr | Chunk is its own object; the key (`precip/0.3.2`) carries the coordinates | No byte parsing at all |
| Zarr v3 sharded | Shard index at the end of the shard object | Mechanically like Parquet |
| Icechunk | Manifests hold `(object, offset, length)` chunk references | Needs a manifest read first |

Parquet and COG ship first. They are the two genuinely different shapes:
columnar masking and spatial masking. Zarr and Icechunk follow within this
project's life.

Because Zarr's region identity lives in the object key rather than in bytes,
`resolve` accepts the key alongside the range from the start. That one decision
makes Zarr close to free later.

### Request flow

On a cache miss the gateway must read the object's footer before it can
authorize anything:

```
GET /path/file.parquet   Range: bytes=1234-5678
  -> no LayoutIndex cached for this object
  -> gateway issues its own backend reads: HEAD for size, GET last ~64KB
  -> parse footer -> LayoutIndex -> cache
  -> resolve(key, 1234-5678) -> [Region]
  -> decide(policy, {user, region}) -> allow | deny
```

`ObjectId { endpoint, bucket, key }` is load-bearing three times: fetching the
footer, keying the index cache, and selecting which policy applies. It is not a
variable inside a filter — by evaluation time the data's shape is known and the
policy was already chosen for this dataset.

Policies should key on the **gateway-facing path**, not the resolved backend
endpoint. `multistore` exists to make backend migrations invisible; binding
policy to physical location would make a migration silently change who can read
what.

### Types

```rust
struct ObjectId { endpoint: String, bucket: String, key: String }

struct Region { start: u64, len: u64, props: Value }
// parquet: {"kind":"column_chunk", "column":"salary", "row_group":3}
// cog:     {"kind":"tile", "overview_level":0, "x":12, "y":5, "bbox":[..]}
// either:  {"kind":"metadata"}

trait RangeFetcher {
    async fn get(&self, id: &ObjectId, r: Range<u64>) -> Result<Bytes>;
}
```

`RangeFetcher` has two real implementations from the first day — `fetch()` in
the browser, the existing backend client in the gateway — which is why the
interface exists at all.

### Index representation

A large COG carries one `TileOffsets` entry per tile per overview level;
100,000 regions is ordinary. The index therefore stores the raw numeric arrays
and **synthesizes `props` JSON lazily**, only for regions a request actually
overlaps. Memory stays flat and CQL2 evaluates over three objects rather than
a hundred thousand.

Lookup is binary search over a sorted `Vec`. An interval tree buys nothing at
this scale.

### Cache validity

An index is valid only while the object is byte-identical. Key the cache on
ETag and invalidate when it changes. Free for immutable data, required for
anything versioned.

Format detection sniffs the key's extension, with a configuration override
later.

## Policy language

CQL2, evaluated by `developmentseed/cql2-rs`. That crate already provides
`Expr::matches(&Value) -> bool`, genuinely computed spatial predicates over the
`geo` crate, temporal and array operators, a `wasm` workspace member published
as `cql2-wasm`, and `ToDuckSQL`. It is our own crate, so anything we have to
fix is in-house work that STAC benefits from too.

The audience already writes CQL2 filters against STAC. They learn nothing new.

A policy is a list of CQL2 filters, OR'd, over a default deny:

```yaml
# role: analyst
allow:
  - "region.kind = 'metadata'"
  - "region.kind = 'column_chunk' AND region.column NOT IN ('salary','ssn')"
  - "region.kind = 'tile' AND region.overview_level >= 2"
  - "region.kind = 'tile' AND S_INTERSECTS(region.bbox, POLYGON((...)))"
```

The last two rules are the case worth demonstrating: anyone may browse
overviews, full resolution only inside a licensed AOI.

### Why there is no allow/deny effect

`deny` is syntactic sugar for `NOT`. CQL2 is closed under negation, so default
deny plus one expression is formally complete. An explicit effect buys only
precedence across independently authored policies — an org policy, a dataset
policy, a user grant — which is out of scope. It is not free: adding `deny`
obliges us to document precedence, and precedence bugs are the expensive kind.

Add it when a second policy source actually appears. This is the known
extension point.

### Fail closed

Every failure denies: an unparseable range header, a missing index, a CQL2
evaluation error, a filter naming a property that does not exist. `cql2-rs`
leaves unresolvable properties unfolded rather than erroring, so a typo in a
property name must be caught by the wrapper and denied. This is a test case,
not a comment.

Metadata regions are the sole exception, and only because a policy explicitly
allows them.

## Denial semantics

The proof of concept returns **403**. This breaks readers mid-query, which is
honest about the cost.

Two alternatives are worth naming and neither is built here:

- **Zero-fill.** Return the correct byte count, zeroed. Works acceptably for
  COG tiles, which render black. Produces corrupt pages in Parquet unless valid
  all-null pages are synthesized, which is real work.
- **Rewrite the footer.** Serve a Parquet footer or TIFF IFD in which the
  forbidden columns or tiles do not appear. Much the best client experience —
  the data simply is not there — and much the most implementation.

## Range coalescing

Readers merge nearby ranges into single fetches. One request can therefore
straddle a permitted and a forbidden column and be denied as a whole, failing a
query that should have succeeded. This is the main practical obstacle to the
whole approach.

The demo surfaces it explicitly rather than hiding it, because how often it
bites in practice is the finding that should decide whether `multistore` adopts
this.

## Analytics

The same resolver, pointed at a log of past requests, counts hits per region
instead of authorizing them. CQL2 filters the log the same way it filters
access — one language, both features. `ToDuckSQL` makes a log stored as Parquet
queryable directly.

## Web demo

Static, hosted on GitHub Pages, WASM over the same core crate.

- **Live mode.** `hyparquet` and `geotiff.js` read real sample files through a
  `fetch` shim that applies the policy to every `Range` header. Watch a query
  work, tighten the policy, watch it fail. The gateway's own footer read appears
  in the log as its own entry.
- **Replay mode.** Recorded logs drive the heatmap.
- Parquet renders as a row-group by column grid. COG renders as a tile grid per
  overview level with a click-drawn AOI. No basemap.
- Denying `region.kind = 'metadata'` is allowed, and breaks everything. That
  teaches the constraint better than a paragraph does.

The WASM boundary is two functions:

```
build_index(fetcher, object_id, format) -> LayoutIndex
check(index, policy, ctx, range_header) -> {decision, regions, matched_rule}
```

## Layout

```
crates/cnac-core/   resolvers (parquet, cog), policy evaluation over cql2::Expr
crates/cnac-wasm/   the two exported functions
web/                static site for GitHub Pages
data/               small sample .parquet and .tif, recorded request logs
```

## Testing

- **Round trip.** For every region in an index, a request for exactly its byte
  range resolves to exactly that region and nothing else.
- **Golden offsets.** Known column chunk and tile offsets in checked-in sample
  files resolve to the expected identities.
- **Fail closed.** A filter naming a nonexistent property denies.
- **Coalescing.** A range spanning a permitted and a forbidden region denies.

## What this does not do

This reduces access and enforces licensing. It is not confidentiality.

Metadata is served intact, so a denied Parquet column still reveals its name,
its type, its size, and — through footer statistics and any bloom filter — its
per-row-group minimum and maximum and answers to membership queries. Hiding
that a column exists requires rewriting the footer, which is out of scope.

Do not deploy this as a privacy control.
