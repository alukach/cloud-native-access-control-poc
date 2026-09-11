# cloud-native-access-control

**Can you enforce access control on *part* of a file in object storage?**

A proof of concept for column-level and area-level access control over
Parquet, COG, Zarr and Icechunk — enforced at an S3 gateway, using
[CQL2](https://docs.ogc.org/is/21-065r2/21-065r2.html) as the rule language.

> **Status: the crate works and the browser demo runs.**
> Both resolvers parse real files, policies evaluate, the decision function is
> covered by 140 tests, and the demo drives hyparquet and geotiff.js against
> the sample files over real range requests. This repository exists to decide whether
> [multistore](https://github.com/developmentseed/multistore) should adopt the
> approach — it is not production software and enforces nothing today.
> See the [design](docs/plans/2026-09-10-cloud-native-access-control-design.md)
> and [implementation plan](docs/plans/2026-09-10-cloud-native-access-control-plan.md).

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

**Clients batch their reads, and that decides everything.** hyparquet merges
column chunks into runs up to 2 MB, so a full-table scan collapses all 19
columns of a row group into *one* request straddling every boundary you drew;
passing `columns: [...]` makes it chunk-exact instead. geotiff.js block-aligns
to 64 KB rather than to tiles unless `blockSize` is `undefined`.

And **DuckDB — the client people actually use — straddles unavoidably.** It
pushes projection down and prunes row groups by footer statistics, fetching
11.9% of the object where a naive reader takes 98%. But its physical reads are
64 KiB power-of-two blocks, so *27 of 27* of its content requests cross a column
chunk it never projected. Deny a column and a query for its physical neighbour
is refused; deny it and query something far away in the file and nothing
happens. **Adjacency in the file decides, not the query.** That is why the
denial mode, not the reader configuration, turns out to be the design decision
([#24](https://github.com/alukach/cloud-native-access-control-poc/issues/24)).

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

## Footer rewrite + scrub: the mode that works for every client

Refusing ranges is honest and it cannot serve a block-aligned reader. The fix is
to stop arguing with the client's I/O layer: serve a **valid Parquet file whose
footer never mentions the withheld columns**, leaving their bytes physically in
place but **zeroed**. Coalescing becomes harmless, because nothing parses the
hole.

`src/rewrite.rs` builds both halves from the *same* `LayoutIndex` the refusal
path uses — `ColumnChunk`, `ColumnIndex` and `BloomFilter` are exactly the
extents a withheld column owns. `examples/gate.rs` serves it over HTTP from one
file handle plus the rewritten ~14 KB tail; the object is never materialized.

Measured on `data/nyc-taxi-8rg.parquet`, withholding `fare_amount` and
`tip_amount`, against a client that widens every read to whole 64 KiB blocks —
which is what duckdb-wasm and GDAL `/vsicurl` do:

| mode | result | requests | straddling a withheld extent |
| --- | --- | ---: | --- |
| `refuse` | **failed on request #1** — 403 on the tail read | 1 | 1, refused |
| `rewrite` + `scrub` | **OK**, 400,000 rows, correct sums | 33 | **31, all served** |

31 of 33 reads span withheld bytes and none of them matter. DuckDB 1.4.1 over
`httpfs` returns `md5 = 56ecb5901d6327f22af12281188edaae` over all 400,000 rows
× 17 surviving columns — **byte-identical to the original file**; parquet-rs
59.3 full-scans it; the withheld column is a binder error rather than nulls.

The address map is two cases, which is what makes it servable from a proxy:
`footer_start` is unchanged and every byte below it keeps its offset, so a
virtual offset is either the same physical offset (scrubbed) or an index into
the resident tail. The virtual length goes in `HEAD`/`Content-Length` and in
every `Content-Range` complete-length.

Three things this costs, all of them real:

- **The origin's `ETag`, `Content-MD5` and `ListObjects` size all disagree with
  what you serve.** `Rewrite::etag` synthesizes a validator over the rewritten
  tail, the scrub set and the original length — the same for every principal
  whose policy withholds the same columns, so many principals collapse onto one
  cache entry. Clients must not be allowed to revalidate against the origin.
- **`ARROW:schema` has to be stripped**, and stripping is lossy: arrow type
  fidelity that lives only in that flatbuffer — timezones, extension types,
  dictionary encoding — does not survive. Leaving it in is both a plaintext
  leak of every original column name and a hard failure in arrow-rs
  (`incompatible arrow schema, expected 2 struct fields got 4`).
- **Scrubbing is mandatory, not optional.** With the footer rewritten and
  nothing else done, `Range: bytes=863208-863247` still returns live SNAPPY
  pages of the withheld column. `--mode rewrite` exists so that can be
  demonstrated rather than described.

This closes [#16](https://github.com/alukach/cloud-native-access-control-poc/issues/16)
for the rewrite path: the served footer contains zero chunks for the withheld
columns — no statistics, no bloom-filter pointers, no page-index pointers, and
no name anywhere in the 14 KB tail.

## What this does not do

This reduces access and enforces licensing. **It is not confidentiality, and it
is not an access gate** — it's a sub-object filter that presumes an
object-level decision made elsewhere.

- **Under `DenialMode::Refuse`, metadata is served intact.** A denied column
  still reveals its name, type and size. Footer statistics, the page index and
  bloom filters leak values — per *page* (~20k rows), not per row group. Footer
  rewrite removes all of that, at the cost of the ETag and arrow-fidelity
  problems above.
- **The AOI is recoverable.** Probing tile ranges and watching 403 versus 206
  recovers the licensed boundary at tile granularity. The AOI is often itself
  the sensitive thing.
- **Data outside the AOI is delivered.** `S_INTERSECTS` at tile granularity
  serves any tile *touching* the AOI in full. An AOI smaller than one tile
  yields a whole tile.
- **The demo enforces nothing.** Policy, principal and interception all run in
  the browser, and the sample files are readable with `curl`. It visualizes a
  decision; it is not an enforcement point.

Each of these is tracked as a GitHub issue, along with the deferred formats
(Zarr, Icechunk) and the gateway-integration contract multistore would need to
honour. See [all open issues](https://github.com/alukach/cloud-native-access-control-poc/issues),
or the [`known-limitation`](https://github.com/alukach/cloud-native-access-control-poc/labels/known-limitation)
and [`security`](https://github.com/alukach/cloud-native-access-control-poc/labels/security)
labels specifically.

## Running it locally

**Prerequisites:** Rust (the exact compiler is pinned in `rust-toolchain.toml`
and `rustup` installs it automatically). For the browser demo you also need
[`wasm-pack`](https://rustwasm.github.io/wasm-pack/installer/).

### The crate

```sh
cargo test          # 183 tests; the test names are the specification
cargo clippy --all-targets -- -D warnings
```

The tests are the most honest picture of what this does. They run against the
real sample files in `data/` and the adversarial fixtures in `tests/fixtures/`,
not synthetic data — `tests/fixtures/README.md` says what each file is for and
which failure it is there to catch.

Worth reading by name, since each pins a bug that would otherwise have shipped:

| test | what it defends |
| --- | --- |
| `a_conjunctive_decision_over_an_empty_result_is_vacuously_true` | why `LayoutIndex` fills gaps at all |
| `a_tile_region_includes_its_gdal_leader_and_trailer` | otherwise every COG tile request is denied |
| `whitespace_is_rejected_not_trimmed` | the RFC 9110 lenient-parse bypass |
| `a_typo_is_rejected_inside_every_container_variant` | CQL2 property typos that fail open |
| `end_at_u64_max_clamps_instead_of_overflowing` | wraps to `0..0` in release, panics in debug |
| `the_codec_reproduces_every_fixture_footer_byte_for_byte` | the round-trip identity every footer rewrite rests on |
| `withholding_a_groups_only_leaf_prunes_the_group_rather_than_emptying_it` | `num_children=0` silently reshapes the schema |

### The gateway

```sh
cargo run --release --example gate -- \
    --file data/nyc-taxi-8rg.parquet \
    --policy examples/withhold-fares.yaml \
    --user '{"role":"analyst"}' \
    --port 8899 --mode scrub        # or: rewrite, refuse
```

It prints the plan as JSON — which columns went, which region kinds the policy
denied, how many bytes are scrubbed, which schema groups were pruned, which
`key_value_metadata` keys were stripped — then serves
`http://127.0.0.1:8899/f.parquet` to any reader. `--mode refuse` serves the
original object through `decision::check` instead, so the same client can be
run against both.

Never serve the sample files with `python3 -m http.server`: it ignores `Range`
and returns the whole object, which makes every measurement meaningless.

### The demo

```sh
wasm-pack build --release --target web --out-dir web/pkg
npx serve .                        # from the repository root
# then open the printed URL and append /web/
```

Serve from the repository root, not from `web/` — the page reads the sample
files in `data/`.

You build a query, set a policy, and see what each client actually fetched.
The query is a column picker taken from the loaded file's own schema; the
policy is CQL2, validated as you type; and the run executes the same query
through every client at once, gating every range it issues. Measured here
against the sample files:

| client | ranges | refused | bytes | outcome |
| --- | ---: | ---: | ---: | --- |
| hyparquet, no projection | 10 | 8 | 15.9 kB | fails at the first row group |
| hyparquet, columns pushed down | 34 | 0 | 1.41 MB | 400,000 rows from 4 columns |
| geotiff.js, 64 KB blocks | 2 | 1 | 65.5 kB | fails at the first tile block |
| geotiff.js, one structure per range | 13 | 0 | 111 kB | 1000×1000 px at full resolution |

Change the column picker and the numbers move: one column instead of four
gives 10 ranges and 1.1% of the file. Pick a column the policy withholds and
the projected client flips to *fails* — and note it fails with **nothing
straddling**, a flat refusal rather than a boundary crossing, which is a
different failure worth being able to tell apart.

**The denial mode is the design decision.** A gate can refuse any request
covering forbidden bytes, or serve it with those bytes blanked. The crate
supports both (`DenialMode`); the page currently runs refuse-only and says so.
Which one you need is not a preference — it depends on the client. A projecting
engine never parses the blanked bytes, so zero-fill is lossless for it; a client
that reads every column parses the zeros and gets corrupt data instead of a
clean refusal. Footer rewrite removes the dependence on the client entirely, by
making the withheld columns invisible rather than forbidden — see above.

> **Do not use `python3 -m http.server`.** It ignores `Range` entirely and
> answers `200` with the whole file (measured: a request for 20 bytes returns
> all 8,422,357). The demo would fetch 8 MB where it asked for 8 KB and
> mis-parse it. This is exactly the RFC 9110 §14.2 behaviour described above,
> and a good illustration of why a gateway must verify `Content-Range` on the
> response rather than trusting that its request was honoured.

Any server that implements byte ranges will do. Two that are already on most
machines, both verified to return `206 Partial Content` here:

```sh
npx serve .                   # Node
ruby -run -e httpd . -p 8000  # Ruby, no install needed on macOS
```

#### Pointing it at your own file

The **Data source** panel takes a URL to any Parquet or COG. The format comes
from the extension and can be overridden; a `.zarr` path or an Icechunk
repository layout is named as such and refused with its tracking issue, because
"no magic bytes" is not an answer anyone can act on.

Nearly every failure here is the host, so the page says which one:

| what happened | what it means |
| --- | --- |
| the fetch threw, no status | CORS, or nothing listening. A cross-origin ranged GET needs `Access-Control-Allow-Origin`, an `OPTIONS` answer with `Access-Control-Allow-Headers: Range`, and `Access-Control-Expose-Headers: Content-Range`. |
| `403` / `404` | the host answered and said no: private object, wrong key, requester-pays |
| `200` with the whole body | the §14.2 case above, and the demo stops: the bytes that arrived are not the bytes it asked for |

Two public objects verified to serve CORS *and* ranges to a browser are offered
as examples — a Sentinel-2 COG on AWS Open Data and a 540 kB Parquet on Hugging
Face. Most buckets fail at the preflight.

#### Sharing a configuration

Every control is in the query string, rewritten with `replaceState` as you go,
and **copy link** puts the current URL on the clipboard. The policy and the
principal are deflated with `CompressionStream` and base64url'd — a 1,347-byte
policy document becomes a 401-character parameter — and each value names its own
encoding in its first character, so an uncompressed or hand-written link still
reads. A link with no parameters is the page at its defaults.

### Regenerating the sample data

Only needed if you change the fixtures. Requires `duckdb` and `gdal`:

```sh
./scripts/make-fixtures.sh all      # or: demo | fixtures | verify
```

The script re-measures every property it claims rather than asserting it, and
explains why each flag matters. The scene choice for the COG is load-bearing:
a full-coverage Sentinel-2 granule yields ~76 KB per tile, so no tile ever
shares a 64 KB block with another and the coalescing this project measures
cannot occur. Do not substitute an arbitrary `TCI.tif`.

## Layout

```
src/              Rust: range parsing, layout index, policy, decision, resolvers,
                  and rewrite.rs (footer rewrite + scrub)
examples/         gate.rs, an HTTP gateway serving a filtered view of a file
web/              static demo for GitHub Pages (web/pkg/ is built, gitignored)
data/             sample Parquet and COG, sized so coalescing actually bites
tests/fixtures/   small adversarial files, one per edge case
scripts/          fixture regeneration
docs/plans/       design and implementation plan
.github/          CI, and the Pages deploy that asserts range support
```

## License

MIT
