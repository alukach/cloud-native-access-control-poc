# cloud-native-access-control

**Can you enforce access control on *part* of a file in object storage?**

A proof of concept for column-level and area-level access control over
Parquet, COG, Zarr and Icechunk — enforced at an S3 gateway, using
[CQL2](https://docs.ogc.org/is/21-065r2/21-065r2.html) as the rule language.

> **Status: design complete, implementation not started.**
> This repository exists to decide whether
> [multistore](https://github.com/developmentseed/multistore) should adopt this
> approach. It is not production software and enforces nothing today.
> See [the design document](docs/plans/2026-09-10-cloud-native-access-control-design.md).

## The problem

Cloud-native formats are read by HTTP range requests. Access control today is
all-or-nothing: you may read the object, or you may not. We want finer grain.

- An analyst who may read every column **except** `salary`.
- A licensee who may read full-resolution imagery **inside their AOI**, and
  overviews everywhere else.

The obstacle is that a range request is opaque. `bytes=1234-5678` says nothing
about which column or which tile it lands in. Everything here follows from
recovering that meaning.

## The idea

Every one of these formats keeps a metadata block describing its own byte
layout. Parse it once, and byte ranges become meaningful.

| Format | Range → meaning |
| --- | --- |
| **Parquet** | Footer gives each column chunk's offset and length → `(row_group, column)` |
| **COG** | `TileOffsets` / `TileByteCounts` per IFD → tile → bbox via the geotransform |
| **Zarr** | Chunk is its own object; the *key* carries the coordinates — no byte parsing |
| **Icechunk** | Manifests hold chunk references; some chunks are inline, some virtual |

Then it's two stages:

**Resolve** — `(key, byte range) → regions`, from a `LayoutIndex` built once
per object and cached.

**Decide** — evaluate a CQL2 filter against every overlapped region.

```yaml
# role: licensee
allow:
  - "region.kind = 'metadata'"
  - "region.kind = 'column_chunk' AND region.column NOT IN ('salary','ssn')"
  - "region.kind = 'tile' AND region.overview_level >= 2"
  - "user.role = 'licensee' AND region.kind = 'tile' AND S_INTERSECTS(region.geom, POLYGON((...)))"
```

Those last two are the case worth demonstrating: anyone may browse overviews,
full resolution only inside a licensed area.

CQL2 because the audience already writes it against STAC, and because
[cql2-rs](https://github.com/developmentseed/cql2-rs) evaluates it in-process
with real spatial predicates and compiles to WASM — so the browser demo and the
gateway share one implementation rather than two that drift.

## The same machinery, backwards

Point the resolver at a log of past range requests instead of a live one and it
counts hits per region rather than authorizing them. Which columns get read.
Which tiles. Which areas. One resolver, two features.

## Why this is harder than it looks

Findings from the design review, each of which would have broken a naive
implementation:

**Readers coalesce.** hyparquet merges column chunks into runs up to 2 MB, so a
full-table scan collapses all 19 columns of a row group into *one* request that
straddles every policy boundary you drew. Passing `columns: [...]` makes it
issue one exact fetch per column chunk instead. geotiff.js block-aligns reads
to 64 KB, not to tiles, unless `blockSize` is `undefined`. **Column masking
works only when the reader projects columns** — that conditional is the finding
this project exists to characterize.

**`Range` is advisory, not a contract.** [RFC 9110 §14.2](https://www.rfc-editor.org/rfc/rfc9110#field.range)
says a server MAY ignore a `Range` header, and an origin server **MUST** ignore
a range unit it does not understand — returning `200` with the *entire*
representation. §13.1.5 says the same when an `If-Range` validator doesn't
match. So if a gateway parses `bytes=0-0, items=100-200` leniently, authorizes
one byte, and forwards the header to a backend that rejects it as unparseable,
the backend answers with the whole file and the gateway streams it onward.
Nothing errors. The gateway authorized one byte and delivered the object.

The consequence: **authorization must be verified against the response, not
just the request.** The gateway sends its own canonical range, never the
client's header, and rejects any response whose `Content-Range` isn't what it
authorized.

**Default-deny over an empty set allows everything.** If a byte belongs to no
known region — Parquet's `PAR1` magic, inter-chunk padding, the page index, or
a *striped* GeoTIFF where `TileOffsets` doesn't exist at all — then "every
overlapped region satisfies the policy" is vacuously true. Regions must cover
`[0, size)` completely, with explicit unmapped regions that nothing can match.

**GDAL COGs have hidden bytes around every tile.** A 4-byte size leader before
and a 4-byte trailer after, so readers fetch `offset-4 .. offset+len+4`. Map
only `[offset, offset+len)` and every legitimate tile request overlaps
unclassified bytes and gets denied.

**Parquet's `file_offset` is deprecated and often wrong.** The chunk starts at
`min(dictionary_page_offset, data_page_offset)`. Start at `data_page_offset`
and the dictionary page falls outside every region — and for a low-cardinality
column, the dictionary page *is* the set of distinct values.

## What this does not do

This reduces access and enforces licensing. **It is not confidentiality, and it
is not an access gate** — it's a sub-object filter that presumes an
object-level decision made elsewhere.

- **Metadata is served intact.** A denied column still reveals its name, type
  and size. Footer statistics, the page index and bloom filters leak values —
  per *page* (~20k rows), not per row group. Hiding that a column exists needs
  footer rewriting, which is out of scope.
- **The AOI is recoverable.** Probing tile ranges and watching 403 versus 206
  recovers the licensed boundary at tile granularity. The AOI is often itself
  the sensitive thing.
- **Data outside the AOI is delivered.** `S_INTERSECTS` at tile granularity
  serves any tile *touching* the AOI in full. An AOI smaller than one tile
  yields a whole tile.
- **The demo enforces nothing.** Policy, principal and interception all run in
  the browser, and the sample files are readable with `curl`. It visualizes a
  decision; it is not an enforcement point.

## Layout

```
src/          Rust: resolvers, policy evaluation, wasm bindings
web/          static demo for GitHub Pages
data/         sample Parquet and COG
docs/plans/   design and implementation plan
```

## License

MIT
