# Findings

**What this proof of concept was built to decide:** whether
[multistore](https://github.com/developmentseed/multistore) should adopt
sub-object access control — column-level and area-level policies enforced at an
S3 gateway over HTTP range requests.

**The answer:** yes, but not the way the design started. Refusing range
requests that cover forbidden bytes works only for clients that read exact
chunk extents. Serving a *rewritten view* — a valid file whose index never
mentions the withheld data, with those bytes zeroed in place — works for every
client we measured, because its correctness does not depend on how a client
batches its reads.

Everything below was measured against real files and real clients. Where
something is assumed rather than measured, it says so.

---

## 1. The obstacle, restated

A range request is opaque. `bytes=1234-5678` says nothing about which column or
tile it lands in. Parsing the format's own metadata recovers that: a
`LayoutIndex` maps byte extents to logical regions, and a CQL2 policy is
evaluated against every region a request overlaps.

That part works. Both resolvers parse real files and cover them completely, and
the decision function is exercised by 183 tests.

**The obstacle is not resolution. It is that a byte range tells you what a
client fetched, not what it will use.** Clients batch reads because object
storage has high per-request latency. When a batch spans a policy boundary, a
gateway cannot distinguish "fetched because needed" from "fetched because
adjacent" — the information is not in the request.

## 2. Client behaviour is a property of the I/O layer

The single most useful thing we learned, and it corrected an earlier conclusion
of ours that was wrong.

| client | reads | straddles a boundary |
| --- | --- | --- |
| DuckDB native CLI | chunk extents, merging only across *needed* chunks within 16 KiB | **0** |
| pyarrow, either `pre_buffer` mode | chunk extents | **0** ¹ |
| hyparquet with `columns: [...]` | chunk extents | **0** |
| geotiff.js with `blockSize: undefined` | tile extents | **0** |
| duckdb-wasm | 16/64 KiB power-of-two blocks | **27 of 27** |
| hyparquet, default | coalesces whole row groups | 8 of 10 |
| geotiff.js, default | 64 KiB blocks | 2 of 3 |
| **anything behind GDAL `/vsicurl`** | 16 KiB-aligned block cache | **2 of 3, and no knob fixes it** |

¹ pyarrow's only straddle in any run is a fixed 64 KiB footer tail probe that
reaches back over the bloom filters. Permit those and it is clean everywhere.

The decisive observation: DuckDB, projecting two columns that sit either side of
a withheld one, issued `bytes=840537-863207`. The withheld `fare_amount@rg0`
ends at **exactly 840537**; the withheld `tip_amount@rg0` begins at **exactly
863208**. It coalesced the two chunks it needed and stopped dead on both
forbidden boundaries, then declined to bridge a 67 KB withheld gap, issuing 16
separate exact reads instead. Its merge window is a 16 KiB compile-time constant
(bisected at 15,770 B merging and 16,408 B not; unchanged under 80 ms injected
latency).

**Block alignment belongs to the transport, not the format reader.** pyarrow is
chunk-exact standalone and block-aligned when the same Arrow reader is driven
through GDAL `/vsicurl`. So a gateway cannot infer a client's read granularity
from what it is reading, only from how it connects — which it usually cannot
see.

For GDAL specifically, no configuration fixes it:
`GDAL_HTTP_MERGE_CONSECUTIVE_RANGES=NO` and `GDAL_HTTP_MULTIRANGE=NO` have no
effect, and `CPL_VSIL_CURL_CHUNK_SIZE` only resizes a grid that still cannot
land on tile boundaries. **That is the case that matters most for geospatial
work**, because GDAL is the client.

## 3. Three modes, and what each is actually for

### Refuse — reject any range covering a forbidden byte

Correct, simple, and safe for a client the gateway knows nothing about: you get
the bytes you asked for or a clean refusal, never something in between.

Interoperable with chunk-exact clients **today, with zero false denials**. Dead
for everything else — under a 64 KiB block-aligning client it fails on request
number one, the footer read, before the schema is even parsed.

### Zero-fill — serve the range with forbidden bytes blanked

**Verified for DuckDB.** Using a gateway linked against this crate, with
correctness checked by an order-sensitive digest over *every cell of every row*:
30 requests, 28 carrying zeroed bytes, one 64 KiB block arriving **99.5%
zeroes** — and 400,000 rows byte-identical to an unrestricted run. Including the
adjacency case that refusal denied outright.

It fails loudly where it should: querying a withheld column gives
`TProtocolException: Invalid data` in both wasm and native, because a zeroed
Thrift page header is a missing-required-field error.

Two caveats. It is lossless only for clients that do not *parse* what they did
not project — hyparquet without a column list reads all 19 columns and would
parse the zeros. And metadata still leaks: statistics, bloom filters and the
page index continue to describe the withheld columns.

### Rewrite + scrub — serve a valid file that never mentions the withheld data

Rewrite the footer so the withheld columns do not appear, leave their bytes in
place, and zero them. Coalescing becomes harmless because nothing parses the
hole.

Verified against three independent implementations reading the same rewritten
file:

| check | result |
| --- | --- |
| DuckDB 1.4.1 over httpfs | md5 over 400,000 rows × 17 surviving columns **identical** to the original |
| parquet-rs 59.3 | 400,000 rows, `sum(mta_tax)=191971.90` — identical |
| hyparquet | matches to the cent |
| withheld column | `Binder Error: … not found` — absent, not null |
| withheld bytes | 32 regions / 1,135,491 bytes: **zero** non-zero bytes served |
| footer | **zero** occurrences of the withheld names; the original leaked min/max, distinct counts and bloom pointers per row group |
| block-aligned client | refusal **fails on request #1**; scrub completes in 33 requests, **31 straddling**, all served |

It is servable from a proxy without materializing the object. `footer_start` is
unchanged and every byte below it stays at its original offset, so the address
map is two cases: below → original offset, scrubbed; at or above → an index into
a resident ~14 KB blob. The virtual length goes in `HEAD`, `Content-Length` and
every `Content-Range`. Planning costs 3–5 ms and the artifact is cacheable on
(object, withheld-column-set), so many principals share one entry.

**It also closes the metadata leak outright** — the rewritten footer contains no
statistics, no bloom-filter pointers and no page-index pointers for the withheld
columns. That was previously an accepted limitation of the whole approach.

### The COG analogue: sparsify + scrub

The same idea, and it lands better. To withhold a tile, zero its `TileOffsets`
and `TileByteCounts` entries — which is precisely how a *sparse* COG represents
a tile that was never written, and GDAL handles it natively.

Measured with GDAL 3.13.3 against `data/s2-tci-512.tif`:

| check | result |
| --- | --- |
| `gdalinfo` | same raster, CRS, `LAYOUT=COG` and five overviews — **no warning, no error** |
| withheld pixels | all zero; 6,193,631 of them were non-zero in the original |
| live pixels | **byte-identical**, 6,553,600 px × 3 bands |
| nodata declared? | **irrelevant** — repeated on a COG built `-a_nodata none`, withheld tiles still read zero. The declaration decides what zero *means*, not whether the read works |
| `/vsicurl` over HTTP | identical |

End to end through the gateway, withholding 459 of 484 full-resolution tiles:

| mode | `gdal_translate` | requests | straddling |
| --- | --- | ---: | --- |
| refuse | **failed** — `TIFFFillTile: Read error … got 0 bytes, expected 35803` on the first tile read | 4 | 3, all refused |
| scrub | **ok** | 6 | **5, all served** |

Three things make this cleaner than Parquet. The edit is **always same-length**
— both halves are zeroes, so there is no re-serialization and no rewritten tail
(17 spans, 272 bytes resident), and `virtual_size() == object_size()`, so `HEAD`
and `ListObjects` still agree with the origin. There is no thrift codec and none
of the schema traps. And planning costs ~19 ms for 459 tiles.

Two refusals are deliberate. **Mask images are refused outright**: sparsify
serves everything it does not blank, so a withheld tile's mask — a per-pixel map
of exactly the footprint just removed — would go out live. Under `check` this
was survivable because mask bytes were `Unmapped` and therefore denied; under
sparsify it is a strict regression, so the object is refused until
[#21](../../issues/21) lands a mask region kind. That generalizes to the rule
the whole mode needs: **any object containing an unclassified byte is refused**,
which also covers striped TIFFs and unknown TIFF field types.

## 4. Recommendation

**Build the rewrite-and-scrub path — `rewrite` for Parquet, `sparsify` for COG.
Keep refuse as the default for formats where neither is implemented.**

The argument is not that rewriting is elegant. It is that every other mode
requires the gateway to know how its clients batch reads, and §2 shows that is a
property of the transport rather than of the client — so the same reader flips
between safe and unsafe depending on how it is wired, and a gateway cannot see
the difference. Rewriting removes the dependency instead of managing it.

The work already done carries over unchanged: the resolvers classify exactly the
regions the scrub set needs, and the policy engine is untouched. What changes is
the response to a straddling read — zeroed bytes and a rewritten index, rather
than a 403.

The cost is a **format-specific write path**, and it is real: a full thrift
re-serialization per (object, policy), a set of schema traps that fail silently
if got wrong, and the loss of `ARROW:schema` fidelity unless the flatbuffer is
rewritten too.

## 5. What is not resolved

- **Fixture provenance.** [#23](../../issues/23) is fixed — the 495 unmapped
  spans in a foreign Parquet were inline `ColumnMetaData` copies that
  parquet-cpp wrote after every chunk until Arrow 12, and **they were a live
  leak**: the scrub skipped them because an unmapped region carries no column,
  so a rewritten footer stopped naming a withheld column while structures
  spelling out its name and min/max survived below the footer in plaintext.
  Every reachable file now indexes with zero unmapped bytes, and the fixture
  set spans four writers. But every committed fixture is still generated by a
  script in this repository: the suite tests the resolver against *writers* we
  did not write, not against *files* we did not make. Closing that needs CI
  indexing a pinned remote URL.
- **[#27](../../issues/27) — one policy, two meanings.** `check()` gates a
  range, so metadata regions participate; `plan()` produces a representation and
  must serve the footer unconditionally. The same rule is load-bearing in one
  mode and dead in the other, and a row-group-scoped denial silently widens to
  the whole column.
- **[#28](../../issues/28) — scrubbed bytes are a valid-looking Thrift STOP.**
  Every reader measured seeks by footer offset and never looks at them. One that
  scans sequentially would see a plausible empty structure rather than
  corruption. This is not a defragmented file.
- **Breadth.** One Parquet file, one codec, one flat schema; one COG. Untested:
  nested and repeated types, v2 data pages, encrypted files, hive datasets,
  BigTIFF, and every engine other than the five measured.

## 6. A pattern worth naming

The two most valuable findings in this work came from the same shape: **a
property that held on files we generated, and failed on files we did not.**

Coverage was total on both bundled samples and left 45 kB unmapped on a
stranger's Parquet. Refusal looked interoperable across five clients and was an
artifact of measuring only browser libraries. In both cases the code was
correct about the world it had been shown.

The corrective is cheap and worth building in from the start: test against
artefacts produced by tools you did not run, and measure clients you did not
configure.

## 7. Things worth knowing regardless of which mode you pick

- **Permit `bloom_filter` and `column_index` for every column you permit.**
  DuckDB parses bloom filters for equality predicates and pyarrow's footer probe
  reaches over them. Withholding one breaks a query with a corruption-shaped
  error rather than a policy denial. Two independent investigations found this
  from opposite directions.
- **Never forward the client's `Range` header.** RFC 9110 §14.2 requires an
  origin to ignore a range unit it does not understand and return `200` with the
  entire representation, so any parser disagreement is a full-object disclosure.
  Send the canonical range and verify `Content-Range` on the response.
- **A CDN can strip ranges entirely.** Found while deploying this repository's
  own demo. Same RFC clause, arriving as an infrastructure problem.
- **Never recommend DuckDB's `disable_parquet_prefetching`.** It disables the
  exact-chunk planner and falls back to 1 MB buffered reads, taking a clean
  client to 8 of 10 straddling.

## 8. Reproducing this

```sh
cargo test                                    # 208 tests
cargo run --example gate -- --help            # the rewrite+scrub gateway
./scripts/make-fixtures.sh verify             # re-measure the sample files
```

The demo at <https://alukach.com/cloud-native-access-control-poc/> runs the
resolvers and the policy engine in the browser against the same sample files,
and will load any Parquet or COG by URL.
