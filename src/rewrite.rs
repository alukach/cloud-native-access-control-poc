//! Footer rewrite + scrub: serve a *valid* Parquet file that never mentions the
//! columns a policy withholds.
//!
//! # Why this exists, and what it replaces
//!
//! [`decision::check`](crate::decision::check) refuses any range covering a
//! forbidden byte. That is the only honest answer for an unknown client, and
//! [`DenialMode`](crate::decision::DenialMode) records the measurement that
//! makes it unusable for half of them: a reader behind a **block-aligned
//! cache** -- duckdb-wasm, hyparquet at its defaults, anything behind GDAL
//! `/vsicurl` -- puts a forbidden byte in nearly every request it makes,
//! whether or not its query ever touched that column. For `/vsicurl` no
//! configuration fixes it (issue #26): the 16 KiB grid cannot be made to land
//! on chunk boundaries.
//!
//! Footer rewrite sidesteps the client entirely. The gateway serves a file
//! whose footer describes only the permitted columns. The withheld bytes stay
//! **physically where they were**, so every surviving offset in the footer is
//! still correct and no byte below the footer moves -- but nothing references
//! them, so a coalesced read that spans them is harmless. Nothing parses the
//! hole.
//!
//! Rewriting alone **hides** the bytes; it does not withhold them. With the
//! footer rewritten and nothing else done, `Range: bytes=863208-863307` still
//! returns live SNAPPY pages of the withheld column to anyone who kept the
//! original footer or simply guessed. So the second half is mandatory: the
//! withheld extents are **zeroed in flight**. That is the scrub set, and it is
//! strictly larger than the column chunks -- see [`Rewrite::scrub`].
//!
//! # The regions are not re-derived
//!
//! Everything this module needs about *where* the withheld bytes are already
//! exists in [`LayoutIndex`]: [`RegionKind::ColumnChunk`],
//! [`RegionKind::ColumnIndex`] and [`RegionKind::BloomFilter`] are exactly the
//! extents a withheld column owns, and the `Metadata { name: "footer" }` region
//! is where the rewritten footer goes. A second offset derivation here would be
//! a second place to get `dictionary_page_offset` wrong.
//!
//! # Why the footer is re-serialized and not patched
//!
//! Measured: the longest common prefix between the original footer of
//! `data/nyc-taxi-8rg.parquet` and the rewritten one is **4 bytes**. The schema
//! is field 2 of `FileMetaData`, so dropping one element shortens the list and
//! shifts its length varint, and every byte after it moves. There is no patch;
//! there is only a re-encode.
//!
//! # Why a generic thrift codec and not `ParquetMetaDataWriter`
//!
//! arrow-rs can write a `ParquetMetaData` back out, and it is the wrong tool
//! here for four reasons, each read off `parquet-59.3.0/src/file/metadata/`:
//!
//! 1. **It is lossy.** `RowGroupMetaData` has no field for
//!    `RowGroup.total_compressed_size` (thrift field 6), so a round-trip
//!    silently drops it. Anything else `parquet.thrift` gains and arrow-rs has
//!    not modelled yet drops the same way, and this crate would not notice.
//! 2. **It fabricates `column_orders`.** `ThriftMetadataWriter::finish`
//!    unconditionally synthesizes one `TYPE_DEFINED_ORDER` entry per leaf. A
//!    DuckDB-written file has no `column_orders` at all; a round-trip through
//!    arrow-rs invents one.
//! 3. **It relocates the page index.** If the `ParquetMetaData` carries page
//!    indexes, `write_column_indexes` writes their *bytes* into the output and
//!    overwrites `column_index_offset` to point there. This architecture
//!    depends on those offsets still addressing the original object.
//! 4. **There is no round-trip identity to test against.** The safety property
//!    this module rests on is that re-encoding an *unedited* tree reproduces
//!    the original footer byte for byte -- so any difference in the output is
//!    caused by the edit and by nothing else. [`plan`] asserts it on every
//!    call ([`RewriteError::CodecNotFaithful`]). No typed model can offer that,
//!    because a typed model normalizes.
//!
//! The generic codec also costs nothing at the wasm size budget this crate
//! watches: ~300 lines of varint handling with no new dependency, where the
//! arrow-rs write path would pull the `arrow` feature back in.
//!
//! # The traps, each found by measurement
//!
//! * **Emptying a schema group silently corrupts the file.** Removing a
//!   group's last child leaves `num_children = 0`, which `parquet.thrift`
//!   cannot represent and readers do not reject: DuckDB swallowed the *next
//!   sibling* into the emptied group and reported a plausible schema with no
//!   error at all. Emptied groups are pruned recursively upward -- see
//!   [`prune`].
//! * **The tree shape is read before anything is mutated.** Decrementing a
//!   `num_children` mid-walk corrupts every parent lookup that follows it,
//!   because the walk finds children by counting them.
//! * **`column_orders` is positional**, one entry per leaf in schema order. It
//!   has to lose entries at exactly the indices the schema lost leaves at.
//! * **`ARROW:schema` names every original column in plaintext.** It is a
//!   base64 flatbuffer in `key_value_metadata`; leaving it is both a leak and a
//!   hard failure in arrow-rs (`incompatible arrow schema, expected 2 struct
//!   fields got 4`), which DuckDB tolerates. It is stripped, and **stripping is
//!   lossy**: arrow type fidelity that lives only in that flatbuffer --
//!   timezones, extension types, dictionary encoding -- does not survive. The
//!   same applies to `pandas`.
//! * **`SortingColumn.column_idx` is an index into the row group's column
//!   list**, which this module shortens. Entries naming a withheld column are
//!   dropped and the rest are renumbered.
//!
//! # What this module does not decide
//!
//! It does not decide whether a *request* is allowed; there is no request. It
//! produces a filtered representation of an object, once, for a principal. The
//! gateway then serves ranges of that representation.

use crate::{
    decision::{DenyReason, Verdict},
    index::{LayoutIndex, RegionKind},
    policy::Policy,
};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

use thrift::{Struct, ThriftError, Val};

/// `FileMetaData` field ids, from `parquet.thrift`.
mod fm {
    pub const SCHEMA: i16 = 2;
    pub const ROW_GROUPS: i16 = 4;
    pub const KEY_VALUE_METADATA: i16 = 5;
    pub const COLUMN_ORDERS: i16 = 7;
}
/// `SchemaElement` field ids.
mod se {
    pub const NAME: i16 = 4;
    pub const NUM_CHILDREN: i16 = 5;
}
/// `RowGroup` field ids.
mod rg {
    pub const COLUMNS: i16 = 1;
    pub const TOTAL_BYTE_SIZE: i16 = 2;
    pub const SORTING_COLUMNS: i16 = 4;
    pub const FILE_OFFSET: i16 = 5;
    pub const TOTAL_COMPRESSED_SIZE: i16 = 6;
}
/// `ColumnChunk` field ids.
mod cc {
    pub const META_DATA: i16 = 3;
}
/// `ColumnMetaData` field ids.
mod cm {
    pub const PATH_IN_SCHEMA: i16 = 3;
    pub const TOTAL_UNCOMPRESSED_SIZE: i16 = 6;
    pub const TOTAL_COMPRESSED_SIZE: i16 = 7;
    pub const DATA_PAGE_OFFSET: i16 = 9;
    pub const DICTIONARY_PAGE_OFFSET: i16 = 11;
}
/// `SortingColumn` field ids.
mod sc {
    pub const COLUMN_IDX: i16 = 1;
}
/// `KeyValue` field ids.
mod kv {
    pub const KEY: i16 = 1;
}

/// `key_value_metadata` keys that re-state the schema in plaintext. Both name
/// every original column, so both leak the withheld ones, and `ARROW:schema`
/// additionally makes arrow-rs refuse the file outright when its field count
/// disagrees with the thrift schema.
const SCHEMA_RESTATING_KEYS: &[&[u8]] = &[b"ARROW:schema", b"pandas"];

/// The 4-byte footer length plus the trailing `PAR1`.
const TRAILER_LEN: u64 = 8;

/// Why a filtered representation could not be produced.
///
/// Every variant is a refusal to serve. There is no partial rewrite: a footer
/// that half-describes the object is a corrupt file, which presents to a
/// reader as data loss rather than as a policy decision.
#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum RewriteError {
    /// The index has no `Metadata { name: "footer" }` region, so it did not
    /// come from [`parquet::build_index`](crate::parquet::build_index) and
    /// nothing here knows where the footer is.
    #[error("the index does not describe a Parquet footer")]
    NoFooterRegion,
    /// The supplied footer body is not the one the index classified.
    #[error("footer body is {got} bytes; the index says {want}")]
    FooterLength { got: u64, want: u64 },
    /// The footer thrift did not decode.
    #[error("footer did not decode: {0}")]
    Thrift(#[from] ThriftError),
    /// Re-encoding the **unmodified** tree did not reproduce the original
    /// footer, so this codec does not round-trip these bytes and any edit made
    /// through it would be a diff of unknown extent.
    ///
    /// This is the safety property the whole module rests on, checked on every
    /// call rather than only in a test, because the input is a file and the
    /// tests only ever saw the files someone thought to write.
    #[error("re-encoding the unmodified footer produced {got} bytes, not {want}")]
    CodecNotFaithful { got: usize, want: usize },
    /// The footer's schema list is not a well-formed pre-order tree, or some
    /// other structural expectation about `FileMetaData` did not hold.
    #[error("footer metadata is malformed: {0}")]
    Schema(String),
    /// A row group names a column the schema has no leaf for. The footer
    /// disagrees with itself.
    #[error("row group names column `{0}`, which the schema does not contain")]
    UnknownColumn(String),
    /// Every leaf is withheld, so there is no file to serve. Refused rather
    /// than emitted, because a `FileMetaData` with an empty schema is not a
    /// representable Parquet file.
    #[error("the policy withholds every column; there is nothing to serve")]
    NothingToServe,
    /// A withheld region lies at or above the footer. Scrubbing it would
    /// destroy the structure the surviving columns are found through, and a
    /// column whose bytes are up there is not a column this resolver
    /// classified.
    #[error("withheld region at {start} lies at or above the footer at {footer_start}")]
    WithheldAboveFooter { start: u64, footer_start: u64 },
    /// A row group lost all of its columns while the schema kept leaves. The
    /// two disagree and the result would not be readable.
    #[error("row group {0} would have no columns left")]
    EmptyRowGroup(usize),
}

/// One column the policy withheld, and why.
///
/// Reported rather than merely counted because the most likely policy mistake
/// is invisible otherwise: a rule that permits a column's chunks but not its
/// `bloom_filter` withholds the whole column here (fail-closed), and the
/// operator needs to see that it was the bloom filter that did it. Issue #26
/// measured the cost of getting this wrong the other way -- DuckDB equality
/// predicates fail with a corruption-shaped error when a *permitted* column's
/// bloom filter is withheld.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Withheld {
    /// The full dotted `path_in_schema`, the same spelling a policy names.
    pub column: String,
    /// The `region.kind` values the policy denied for this column, sorted.
    /// A column appears here if *any* of its regions was denied.
    pub denied_kinds: Vec<String>,
    /// How many regions of this column are scrubbed, across all row groups.
    pub regions: usize,
    /// How many bytes of this column are scrubbed.
    pub bytes: u64,
}

/// A filtered representation of one object for one principal.
///
/// The address map is two cases and no more, which is what makes this servable
/// from a proxy that holds one file handle:
///
/// ```text
/// virtual offset <  footer_start  ->  the same physical offset, scrubbed
/// virtual offset >= footer_start  ->  an offset into a ~14 KB in-memory tail
/// ```
///
/// `footer_start` is **unchanged** from the original object and every byte
/// below it keeps its original offset. Only the tail differs, and only in
/// length: removal shrinks lists and varints, so the rewritten footer came out
/// smaller than the original for every policy measured (14016-15191 bytes
/// against 15857, across all 190 one- and two-column policies on the sample
/// file). Nothing guarantees that in general, and nothing here relies on it.
#[derive(Debug, Clone)]
pub struct Rewrite {
    footer: Vec<u8>,
    footer_start: u64,
    original_size: u64,
    scrub: Vec<Range<u64>>,
    withheld: Vec<Withheld>,
    groups_pruned: Vec<String>,
    stripped_keys: Vec<String>,
}

impl Rewrite {
    /// The rewritten `FileMetaData` thrift body, without the trailer.
    pub fn footer(&self) -> &[u8] {
        &self.footer
    }

    /// Everything from `footer_start` to the end of the virtual object: the
    /// rewritten footer, its little-endian length, and `PAR1`.
    ///
    /// This is the whole of what a gateway holds in memory.
    pub fn tail(&self) -> Vec<u8> {
        let mut tail = Vec::with_capacity(self.footer.len() + TRAILER_LEN as usize);
        tail.extend_from_slice(&self.footer);
        // The cast cannot truncate: `plan` refuses a rewritten footer that does
        // not fit in the u32 the wire format has for its length.
        tail.extend_from_slice(&(self.footer.len() as u32).to_le_bytes());
        tail.extend_from_slice(b"PAR1");
        tail
    }

    /// Where the footer begins, in both the original and the virtual object.
    pub fn footer_start(&self) -> u64 {
        self.footer_start
    }

    /// The length to advertise in `HEAD`, `Content-Length` and the
    /// complete-length of a `Content-Range`.
    ///
    /// **Not the origin's length.** A client that validates this against a
    /// `ListObjects` size, an origin `ETag` or a `Content-MD5` will find all
    /// three disagree; see [`Rewrite::etag`].
    pub fn virtual_size(&self) -> u64 {
        self.footer_start + self.footer.len() as u64 + TRAILER_LEN
    }

    /// The original object's length, for the caller that has to read from it.
    pub fn original_size(&self) -> u64 {
        self.original_size
    }

    /// The absolute byte extents, all below [`Rewrite::footer_start`], that
    /// must be zeroed before any byte reaches the client. Sorted, non-empty,
    /// pairwise disjoint and never merely abutting.
    ///
    /// **This set is larger than the column chunks.** It is every region the
    /// index attributes to a withheld column: the chunk in each row group, its
    /// `ColumnIndex` and `OffsetIndex`, and its bloom filter -- and the last of
    /// those lives *outside* `total_compressed_size`. On the sample file the
    /// two withheld columns carry 84,232 bytes of bloom filter beyond their
    /// chunk bytes, 1,465,760 bytes across 32 regions in total. A scrub set
    /// derived from `total_compressed_size` alone would leave the bloom filters
    /// live, and a bloom filter answers membership queries outright.
    pub fn scrub(&self) -> &[Range<u64>] {
        &self.scrub
    }

    /// The columns the policy withheld, sorted by name.
    pub fn withheld(&self) -> &[Withheld] {
        &self.withheld
    }

    /// Schema groups removed because withholding their leaves emptied them.
    /// Non-empty means the nested-schema trap was live on this file.
    pub fn groups_pruned(&self) -> &[String] {
        &self.groups_pruned
    }

    /// `key_value_metadata` keys dropped because they re-state the schema.
    /// See the module docs: stripping `ARROW:schema` costs arrow type
    /// fidelity, and this is how a caller finds out it happened.
    pub fn stripped_keys(&self) -> &[String] {
        &self.stripped_keys
    }

    /// A strong entity tag for the **virtual** representation.
    ///
    /// The origin's `ETag` describes an object this gateway does not serve, and
    /// so do its `Content-MD5` and its `ListObjects` size. A client allowed to
    /// revalidate against the origin would be told a fresh copy is stale -- or,
    /// far worse for a shared cache, that a differently filtered copy is the
    /// same representation. So the tag is synthesized here, over the three
    /// things that actually distinguish one filtered view from another: the
    /// rewritten tail, the scrub set, and the original length.
    ///
    /// Two principals whose policies withhold the same columns get the same
    /// tag, which is the point -- it collapses many principals onto one cache
    /// entry. It is deliberately **not** derived from the principal.
    ///
    /// FNV-1a is not a cryptographic digest and this is not an integrity
    /// check; it is a cache key. A deployment needing an unforgeable validator
    /// should hash the same three inputs with something else.
    pub fn etag(&self) -> String {
        let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
        let mut eat = |bytes: &[u8]| {
            for b in bytes {
                hash ^= u64::from(*b);
                hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
            }
        };
        eat(&self.tail());
        eat(&self.original_size.to_le_bytes());
        for span in &self.scrub {
            eat(&span.start.to_le_bytes());
            eat(&span.end.to_le_bytes());
        }
        format!("\"cnac-{hash:016x}\"")
    }

    /// The verdict for a range of the **original object**, in the shape
    /// [`Verdict::redact`] consumes.
    ///
    /// `object_range` must lie entirely below [`Rewrite::footer_start`]; the
    /// caller has already split the request there. The returned
    /// [`Verdict::Serve`] carries `canonical == object_range` and the scrub
    /// extents clipped to it, so the gateway reads those bytes and calls
    /// `redact` -- and the absolute-to-buffer subtraction stays in the one
    /// audited place it already lives, rather than being written a second time
    /// here.
    ///
    /// A range that is empty, or that reaches into the footer, is
    /// [`Verdict::Denied`]. Not because it is an authorization failure -- there
    /// is no request to authorize -- but because a caller that got the split
    /// wrong must not get bytes.
    pub fn object_verdict(&self, object_range: &Range<u64>) -> Verdict {
        if object_range.start >= object_range.end || object_range.end > self.footer_start {
            return Verdict::Denied {
                reason: DenyReason::NotPermitted,
            };
        }
        let blank = self
            .scrub
            .iter()
            .filter(|s| s.start < object_range.end && s.end > object_range.start)
            .map(|s| s.start.max(object_range.start)..s.end.min(object_range.end))
            .collect();
        Verdict::Serve {
            canonical: object_range.clone(),
            blank,
        }
    }
}

/// Produce the filtered representation of `index`'s object for `user`.
///
/// `footer_body` is the `FileMetaData` thrift exactly -- the bytes of the
/// index's `Metadata { name: "footer" }` region, with no trailer and no magic.
///
/// # Which columns are withheld
///
/// Every region the index attributes to a column is evaluated against the
/// policy, and a column is withheld if **any** of its regions is denied. That
/// is fail-closed, and it is also the only representable answer: a footer can
/// drop a column, but it cannot drop one row group's chunk of a column without
/// leaving the row groups ragged, and it cannot keep a column while dropping
/// its bloom filter without lying about where that bloom filter is.
///
/// # What is NOT evaluated
///
/// Regions with no column -- `Metadata` and `Unmapped` -- are not policy inputs
/// here, and this is the one place this module's semantics diverge from
/// [`check`](crate::decision::check). Under refusal those regions gate a
/// *range*, so a policy denying the footer refuses the request. Under rewrite
/// there is no range to gate: the footer, the magic and the inter-chunk padding
/// are the structure the permitted columns are found through, and a
/// representation withholding them would not be a Parquet file at all. A
/// deployment that wants to deny a principal the object denies it the object,
/// rather than expressing that as a region rule.
pub fn plan(
    index: &LayoutIndex,
    footer_body: &[u8],
    policy: &Policy,
    user: &Value,
) -> Result<Rewrite, RewriteError> {
    let footer_region = index
        .regions()
        .iter()
        .find(|r| matches!(&r.kind, RegionKind::Metadata { name } if name == "footer"))
        .ok_or(RewriteError::NoFooterRegion)?;
    let footer_start = footer_region.start;
    if footer_body.len() as u64 != footer_region.len {
        return Err(RewriteError::FooterLength {
            got: footer_body.len() as u64,
            want: footer_region.len,
        });
    }

    // Which columns lose which kinds. Ordered maps so the report and the ETag
    // derived from it are stable across runs.
    let mut denied: BTreeMap<&str, BTreeSet<String>> = BTreeMap::new();
    for region in index.regions() {
        let Some(column) = region.column() else {
            continue;
        };
        let props = region.props();
        if policy.permits(&json!({"user": user, "region": props})) {
            continue;
        }
        let kind = props
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string();
        denied.entry(column).or_default().insert(kind);
    }

    // Every region of every withheld column is scrubbed, including the ones the
    // policy permitted individually: once the column is gone from the footer,
    // its page index and its bloom filter are unreferenced bytes that still
    // answer questions about it.
    let withheld_names: BTreeSet<&str> = denied.keys().copied().collect();
    let mut spans: Vec<Range<u64>> = Vec::new();
    let mut per_column: BTreeMap<&str, (usize, u64)> = BTreeMap::new();
    for region in index.regions() {
        let Some(column) = region.column() else {
            continue;
        };
        if !withheld_names.contains(column) {
            continue;
        }
        if region.end() > footer_start {
            return Err(RewriteError::WithheldAboveFooter {
                start: region.start,
                footer_start,
            });
        }
        let entry = per_column.entry(column).or_insert((0, 0));
        entry.0 += 1;
        entry.1 += region.len;
        spans.push(region.start..region.end());
    }
    // The index's regions are already sorted and disjoint, so this only
    // coalesces the abutting ones -- a chunk and the page index immediately
    // after it -- into extents rather than internal boundaries.
    spans.sort_by_key(|s| s.start);
    let mut scrub: Vec<Range<u64>> = Vec::with_capacity(spans.len());
    for span in spans {
        match scrub.last_mut() {
            Some(last) if span.start <= last.end => last.end = last.end.max(span.end),
            _ => scrub.push(span),
        }
    }

    let withheld: Vec<Withheld> = denied
        .iter()
        .map(|(column, kinds)| {
            let (regions, bytes) = per_column.get(column).copied().unwrap_or((0, 0));
            Withheld {
                column: (*column).to_string(),
                denied_kinds: kinds.iter().cloned().collect(),
                regions,
                bytes,
            }
        })
        .collect();

    let withheld_paths: BTreeSet<String> =
        withheld_names.iter().map(|c| (*c).to_string()).collect();
    let edit = rewrite_footer(footer_body, &withheld_paths)?;
    if edit.footer.len() > u32::MAX as usize {
        return Err(RewriteError::Schema(
            "rewritten footer does not fit in the u32 length trailer".into(),
        ));
    }

    Ok(Rewrite {
        footer: edit.footer,
        footer_start,
        original_size: index.size(),
        scrub,
        withheld,
        groups_pruned: edit.groups_pruned,
        stripped_keys: edit.stripped_keys,
    })
}

#[derive(Debug)]
struct FooterEdit {
    footer: Vec<u8>,
    groups_pruned: Vec<String>,
    stripped_keys: Vec<String>,
}

/// Decode, edit and re-encode a `FileMetaData`.
///
/// Split out from [`plan`] so the tests can drive it against a hand-built
/// footer, which is the only way to cover a schema shape no fixture in this
/// repository has.
fn rewrite_footer(body: &[u8], withheld: &BTreeSet<String>) -> Result<FooterEdit, RewriteError> {
    let mut meta = thrift::decode_struct(body)?;

    // The safety property, checked on real input and not only in a test: if the
    // codec does not reproduce THIS footer byte for byte, then the diff between
    // the output and the original is not the edit, and nobody can say what it
    // is. Refuse rather than serve a file we cannot account for.
    let faithful = thrift::encode_struct(&meta);
    if faithful != body {
        return Err(RewriteError::CodecNotFaithful {
            got: faithful.len(),
            want: body.len(),
        });
    }

    let schema = meta
        .get(fm::SCHEMA)
        .and_then(Val::as_coll)
        .ok_or_else(|| RewriteError::Schema("no schema list".into()))?;
    let tree = read_tree(schema)?;

    let mut targets = Vec::with_capacity(withheld.len());
    for path in withheld {
        let index = tree
            .leaves
            .iter()
            .find(|leaf| tree.paths[**leaf] == *path)
            .ok_or_else(|| RewriteError::UnknownColumn(path.clone()))?;
        targets.push(*index);
    }

    let pruned = prune(&tree, &targets);
    if pruned.remaining[0] == 0 {
        return Err(RewriteError::NothingToServe);
    }

    // 1. The schema list: write back the surviving counts, then drop the
    //    subtrees. In that order, because the counts are indexed by the
    //    positions the list still has.
    let schema = meta
        .get_mut(fm::SCHEMA)
        .and_then(Val::as_coll_mut)
        .expect("the immutable borrow above already found it");
    for (i, element) in schema.iter_mut().enumerate() {
        if pruned.dropped.contains(&i) || tree.children[i] == pruned.remaining[i] {
            continue;
        }
        // Only ever a decrement of an existing field. A group that had a
        // `num_children` still has one; nothing here creates the field, which
        // would change the field-header delta chain and move bytes for a reason
        // unrelated to the edit.
        let Some(Val::Int(n)) = element.get_mut(se::NUM_CHILDREN) else {
            return Err(RewriteError::Schema(format!(
                "schema element {i} is a group with no num_children"
            )));
        };
        *n = pruned.remaining[i] as i64;
    }
    retain_by_index(schema, |i| !pruned.dropped.contains(&i));

    // 2. `column_orders` is positional: one entry per leaf, in schema order.
    if let Some(orders) = meta.get_mut(fm::COLUMN_ORDERS).and_then(Val::as_coll_mut) {
        // A file whose `column_orders` disagrees with its schema is one we do
        // not understand, and dropping entries positionally from it would
        // reassign the sort order of the columns that survive.
        if orders.len() != tree.leaves.len() {
            return Err(RewriteError::Schema(format!(
                "column_orders has {} entries for {} leaves",
                orders.len(),
                tree.leaves.len()
            )));
        }
        let keep: Vec<bool> = tree
            .leaves
            .iter()
            .map(|leaf| !pruned.dropped.contains(leaf))
            .collect();
        retain_by_index(orders, |i| keep[i]);
    }

    // 3. Row groups: drop the chunks, repair the aggregates.
    let row_groups = meta
        .get_mut(fm::ROW_GROUPS)
        .and_then(Val::as_coll_mut)
        .ok_or_else(|| RewriteError::Schema("no row_groups list".into()))?;
    for (ordinal, group) in row_groups.iter_mut().enumerate() {
        rewrite_row_group(group, ordinal, withheld)?;
    }

    // 4. `key_value_metadata` that re-states the schema.
    let mut stripped_keys = Vec::new();
    if let Some(entries) = meta
        .get_mut(fm::KEY_VALUE_METADATA)
        .and_then(Val::as_coll_mut)
    {
        entries.retain(|entry| match entry.get(kv::KEY).and_then(Val::as_binary) {
            Some(key) if SCHEMA_RESTATING_KEYS.contains(&key) => {
                stripped_keys.push(String::from_utf8_lossy(key).into_owned());
                false
            }
            _ => true,
        });
    }

    Ok(FooterEdit {
        footer: thrift::encode_struct(&meta),
        groups_pruned: pruned.groups_pruned,
        stripped_keys,
    })
}

/// `Vec::retain` with the element's original index rather than its value.
///
/// Written once because the three places that need it -- the schema list,
/// `column_orders` and a row group's columns -- each drop by position, and a
/// closure that counted calls instead would silently depend on `retain`
/// visiting in order.
fn retain_by_index<T>(items: &mut Vec<T>, keep: impl Fn(usize) -> bool) {
    let mut index = 0usize;
    items.retain(|_| {
        let k = keep(index);
        index += 1;
        k
    });
}

fn rewrite_row_group(
    group: &mut Val,
    ordinal: usize,
    withheld: &BTreeSet<String>,
) -> Result<(), RewriteError> {
    let group = group
        .as_struct_mut()
        .ok_or_else(|| RewriteError::Schema(format!("row group {ordinal} is not a struct")))?;
    let columns = group
        .get(rg::COLUMNS)
        .and_then(Val::as_coll)
        .ok_or_else(|| RewriteError::Schema(format!("row group {ordinal} has no columns")))?;

    let mut drop_flags = Vec::with_capacity(columns.len());
    let mut freed_uncompressed = 0i64;
    let mut freed_compressed = 0i64;
    let mut kept_starts: Vec<i64> = Vec::new();
    for chunk in columns {
        let chunk_meta = chunk
            .get(cc::META_DATA)
            .and_then(Val::as_struct)
            .ok_or_else(|| {
                RewriteError::Schema(format!("row group {ordinal} chunk has no meta_data"))
            })?;
        let path = chunk_path(chunk_meta)?;
        let drop = withheld.contains(&path);
        drop_flags.push(drop);
        if drop {
            freed_uncompressed += chunk_meta
                .get(cm::TOTAL_UNCOMPRESSED_SIZE)
                .and_then(Val::as_int)
                .unwrap_or(0);
            freed_compressed += chunk_meta
                .get(cm::TOTAL_COMPRESSED_SIZE)
                .and_then(Val::as_int)
                .unwrap_or(0);
        } else {
            kept_starts.push(chunk_start(chunk_meta));
        }
    }
    let Some(first_kept) = kept_starts.iter().copied().min() else {
        return Err(RewriteError::EmptyRowGroup(ordinal));
    };

    // `SortingColumn.column_idx` indexes the list that is about to shrink.
    // Renumber before the list changes; drop entries naming a withheld column,
    // because there is no index left that means them.
    let new_index: Vec<Option<i64>> = {
        let mut next = 0i64;
        drop_flags
            .iter()
            .map(|drop| {
                if *drop {
                    None
                } else {
                    next += 1;
                    Some(next - 1)
                }
            })
            .collect()
    };
    if let Some(sorting) = group
        .get_mut(rg::SORTING_COLUMNS)
        .and_then(Val::as_coll_mut)
    {
        sorting.retain_mut(|entry| {
            let Some(Val::Int(idx)) = entry.get_mut(sc::COLUMN_IDX) else {
                // No readable `column_idx`, so nothing to renumber it to.
                return false;
            };
            match usize::try_from(*idx).ok().and_then(|i| new_index.get(i)) {
                Some(Some(mapped)) => {
                    *idx = *mapped;
                    true
                }
                _ => false,
            }
        });
    }

    let columns = group
        .get_mut(rg::COLUMNS)
        .and_then(Val::as_coll_mut)
        .expect("the immutable borrow above already found it");
    retain_by_index(columns, |i| !drop_flags[i]);

    if let Some(Val::Int(total)) = group.get_mut(rg::TOTAL_BYTE_SIZE) {
        *total -= freed_uncompressed;
    }
    if let Some(Val::Int(total)) = group.get_mut(rg::TOTAL_COMPRESSED_SIZE) {
        *total -= freed_compressed;
    }
    // `file_offset` points at the row group's first chunk. If that chunk is
    // gone it addresses bytes nothing references -- which, after the scrub, are
    // zeroes.
    if let Some(Val::Int(offset)) = group.get_mut(rg::FILE_OFFSET) {
        *offset = first_kept;
    }
    Ok(())
}

/// The first byte of a column chunk: the dictionary page when it really
/// precedes the data page, otherwise the data page. The same rule
/// [`parquet::build_index`](crate::parquet::build_index) applies, for the same
/// reason -- a writer emitting a dictionary offset after the data page is not
/// describing a dictionary page.
fn chunk_start(chunk_meta: &Struct) -> i64 {
    let data_page = chunk_meta
        .get(cm::DATA_PAGE_OFFSET)
        .and_then(Val::as_int)
        .unwrap_or(0);
    match chunk_meta
        .get(cm::DICTIONARY_PAGE_OFFSET)
        .and_then(Val::as_int)
    {
        Some(dictionary) if dictionary > 0 && dictionary <= data_page => dictionary,
        _ => data_page,
    }
}

fn chunk_path(chunk_meta: &Struct) -> Result<String, RewriteError> {
    let parts = chunk_meta
        .get(cm::PATH_IN_SCHEMA)
        .and_then(Val::as_coll)
        .ok_or_else(|| RewriteError::Schema("column chunk has no path_in_schema".into()))?;
    let mut path = String::new();
    for part in parts {
        let part = part.as_binary().ok_or_else(|| {
            RewriteError::Schema("path_in_schema is not a list of strings".into())
        })?;
        if !path.is_empty() {
            path.push('.');
        }
        path.push_str(&String::from_utf8_lossy(part));
    }
    Ok(path)
}

/// The shape of the schema list, read **before** anything is mutated.
///
/// `parquet.thrift` encodes the schema as a flat pre-order walk in which every
/// element declares how many children follow it. Finding a node's parent means
/// counting those children -- so decrementing one mid-walk silently reparents
/// everything after it. Capturing the shape once removes the possibility.
struct SchemaTree {
    /// Parent of each element; `parent[0]` is `0` and is never read.
    parent: Vec<usize>,
    /// One past the last index of each element's subtree.
    end: Vec<usize>,
    /// The original `num_children` of each element.
    children: Vec<usize>,
    /// The dotted path of each element; the root's is empty.
    paths: Vec<String>,
    /// Every leaf's index, in schema order -- which is also `column_orders`
    /// order and `path_in_schema` order.
    leaves: Vec<usize>,
}

fn read_tree(schema: &[Val]) -> Result<SchemaTree, RewriteError> {
    let n = schema.len();
    if n == 0 {
        return Err(RewriteError::Schema("schema list is empty".into()));
    }
    let mut children = Vec::with_capacity(n);
    for element in schema {
        let count = element
            .as_struct()
            .ok_or_else(|| RewriteError::Schema("schema element is not a struct".into()))?
            .get(se::NUM_CHILDREN)
            .and_then(Val::as_int)
            .unwrap_or(0);
        children.push(
            usize::try_from(count)
                .map_err(|_| RewriteError::Schema(format!("negative num_children ({count})")))?,
        );
    }

    let mut parent = vec![0usize; n];
    let mut end = vec![0usize; n];
    let mut paths = vec![String::new(); n];
    let mut leaves = Vec::new();
    // (element index, children still to be attached)
    let mut open: Vec<(usize, usize)> = Vec::new();

    for i in 0..n {
        if i == 0 {
            if children[0] == 0 {
                return Err(RewriteError::Schema("schema root has no children".into()));
            }
            open.push((0, children[0]));
            continue;
        }
        let name = schema[i]
            .get(se::NAME)
            .and_then(Val::as_binary)
            .map(|b| String::from_utf8_lossy(b).into_owned())
            .ok_or_else(|| RewriteError::Schema(format!("schema element {i} has no name")))?;
        let Some(top) = open.last_mut() else {
            return Err(RewriteError::Schema(
                "schema list has elements after the root's subtree".into(),
            ));
        };
        parent[i] = top.0;
        let prefix = &paths[top.0];
        paths[i] = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}.{name}")
        };
        top.1 -= 1;
        if children[i] == 0 {
            end[i] = i + 1;
            leaves.push(i);
        } else {
            open.push((i, children[i]));
        }
        // Close every parent this element completed. They all end here.
        while open.last().is_some_and(|t| t.1 == 0) {
            let (done, _) = open.pop().expect("just checked");
            end[done] = i + 1;
        }
    }
    if !open.is_empty() {
        return Err(RewriteError::Schema(
            "schema declares more children than the list holds".into(),
        ));
    }
    Ok(SchemaTree {
        parent,
        end,
        children,
        paths,
        leaves,
    })
}

struct Pruned {
    dropped: BTreeSet<usize>,
    remaining: Vec<usize>,
    groups_pruned: Vec<String>,
}

/// Drop the subtrees rooted at `targets`, pruning emptied groups upward.
///
/// # The trap this exists for
///
/// Removing a group's last child leaves it with `num_children = 0`.
/// `parquet.thrift` has no representation for an empty group -- a zero count
/// means "leaf" -- and no reader rejects one. DuckDB read such a file as
/// `deep: STRUCT(a STRUCT(tags BIGINT[]))`: it had absorbed the *next sibling*
/// into the group we emptied, and reported a perfectly plausible schema with no
/// error. The file is not corrupt-looking, it is wrong-looking, which is worse.
fn prune(tree: &SchemaTree, targets: &[usize]) -> Pruned {
    let mut dropped = BTreeSet::new();
    let mut remaining = tree.children.clone();
    let mut groups_pruned = Vec::new();

    // Iterative, not recursive: the upward walk is bounded by the tree depth,
    // but the tree comes from a file and this crate compiles to wasm32, where a
    // stack overflow aborts the module instance rather than unwinding.
    let mut queue: Vec<usize> = targets.to_vec();
    while let Some(i) = queue.pop() {
        if i == 0 || dropped.contains(&i) {
            continue;
        }
        dropped.extend(i..tree.end[i]);
        let parent = tree.parent[i];
        remaining[parent] = remaining[parent].saturating_sub(1);
        // The root is allowed to empty -- `rewrite_footer` refuses that case by
        // name. Any other emptied group has no valid encoding.
        if remaining[parent] == 0 && parent != 0 {
            groups_pruned.push(tree.paths[parent].clone());
            queue.push(parent);
        }
    }
    groups_pruned.sort();

    Pruned {
        dropped,
        remaining,
        groups_pruned,
    }
}

/// A generic thrift compact-protocol codec.
///
/// Generic on purpose: it decodes a struct into a tree of
/// `(field id, wire type, value)` with no knowledge of `parquet.thrift`, so
/// re-encoding an unmodified tree must reproduce the input byte for byte. That
/// identity is the evidence that any difference in a rewritten footer was
/// caused by the edit; [`super::rewrite_footer`] checks it on every call.
///
/// Doubles are kept as their eight raw bytes rather than decoded. Nothing here
/// needs their value, and Thrift implementations disagree about the byte order
/// of a compact-protocol double -- a decode-and-re-encode would be a place for
/// that disagreement to change bytes we never meant to touch.
mod thrift {
    pub const STOP: u8 = 0x00;
    pub const BOOL_TRUE: u8 = 0x01;
    pub const BOOL_FALSE: u8 = 0x02;
    pub const I8: u8 = 0x03;
    pub const I16: u8 = 0x04;
    pub const I32: u8 = 0x05;
    pub const I64: u8 = 0x06;
    pub const DOUBLE: u8 = 0x07;
    pub const BINARY: u8 = 0x08;
    pub const LIST: u8 = 0x09;
    pub const SET: u8 = 0x0a;
    pub const MAP: u8 = 0x0b;
    pub const STRUCT: u8 = 0x0c;

    /// Deeper than any real `FileMetaData`, shallow enough that the recursive
    /// decoder cannot overflow a wasm stack. `parquet.thrift` bottoms out
    /// around six levels; a footer claiming more than this is hostile, not
    /// unusual. The limit matters because this crate compiles to wasm32, where
    /// the panic runtime aborts and a stack overflow poisons the whole module
    /// instance rather than failing one request.
    const MAX_DEPTH: usize = 64;

    #[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
    pub enum ThriftError {
        #[error("ran out of bytes at offset {0}")]
        Eof(usize),
        #[error("unknown compact type {ttype} at offset {at}")]
        UnknownType { ttype: u8, at: usize },
        #[error("nested deeper than {MAX_DEPTH} levels at offset {0}")]
        TooDeep(usize),
        #[error("varint at offset {0} does not terminate")]
        BadVarint(usize),
        #[error("field id {id} at offset {at} does not fit in an i16")]
        BadFieldId { id: i64, at: usize },
        #[error("collection at offset {at} declares {len} elements, more than the buffer holds")]
        BadLength { at: usize, len: u64 },
        #[error("{trailing} bytes trail the struct")]
        Trailing { trailing: usize },
    }

    /// A decoded value. The wire type is carried by whatever contains it -- a
    /// field header or a collection header -- never by the value itself, which
    /// is how the encoder reproduces the original type nibbles exactly.
    #[derive(Debug, Clone, PartialEq)]
    pub enum Val {
        Bool(bool),
        I8(i8),
        /// `i16`, `i32` and `i64` are all a zigzag varint on the wire. Which
        /// one it was lives in the containing field's `ttype`.
        Int(i64),
        Double([u8; 8]),
        Binary(Vec<u8>),
        Coll {
            etype: u8,
            items: Vec<Val>,
        },
        Map {
            ktype: u8,
            vtype: u8,
            items: Vec<(Val, Val)>,
        },
        Struct(Struct),
    }

    #[derive(Debug, Clone, PartialEq, Default)]
    pub struct Struct {
        pub fields: Vec<Field>,
    }

    #[derive(Debug, Clone, PartialEq)]
    pub struct Field {
        pub id: i16,
        pub ttype: u8,
        pub value: Val,
    }

    impl Struct {
        pub fn get(&self, id: i16) -> Option<&Val> {
            self.fields.iter().find(|f| f.id == id).map(|f| &f.value)
        }
        pub fn get_mut(&mut self, id: i16) -> Option<&mut Val> {
            self.fields
                .iter_mut()
                .find(|f| f.id == id)
                .map(|f| &mut f.value)
        }
    }

    impl Val {
        pub fn as_int(&self) -> Option<i64> {
            match self {
                Val::Int(n) => Some(*n),
                Val::I8(n) => Some(i64::from(*n)),
                _ => None,
            }
        }
        pub fn as_binary(&self) -> Option<&[u8]> {
            match self {
                Val::Binary(b) => Some(b),
                _ => None,
            }
        }
        pub fn as_coll(&self) -> Option<&Vec<Val>> {
            match self {
                Val::Coll { items, .. } => Some(items),
                _ => None,
            }
        }
        pub fn as_coll_mut(&mut self) -> Option<&mut Vec<Val>> {
            match self {
                Val::Coll { items, .. } => Some(items),
                _ => None,
            }
        }
        pub fn as_struct(&self) -> Option<&Struct> {
            match self {
                Val::Struct(s) => Some(s),
                _ => None,
            }
        }
        pub fn as_struct_mut(&mut self) -> Option<&mut Struct> {
            match self {
                Val::Struct(s) => Some(s),
                _ => None,
            }
        }
        /// Field lookup through a value that ought to be a struct, for the
        /// `chunk.get(META_DATA)` chains. `None` both when the field is absent
        /// and when the value is not a struct at all.
        pub fn get(&self, id: i16) -> Option<&Val> {
            self.as_struct()?.get(id)
        }
        pub fn get_mut(&mut self, id: i16) -> Option<&mut Val> {
            self.as_struct_mut()?.get_mut(id)
        }
    }

    struct Reader<'a> {
        buf: &'a [u8],
        pos: usize,
    }

    impl Reader<'_> {
        fn u8(&mut self) -> Result<u8, ThriftError> {
            let b = *self.buf.get(self.pos).ok_or(ThriftError::Eof(self.pos))?;
            self.pos += 1;
            Ok(b)
        }

        /// An unsigned LEB128. Capped at ten bytes because that is the most a
        /// `u64` can need; without the cap a run of continuation bytes is an
        /// unbounded loop over attacker-supplied input.
        fn varint(&mut self) -> Result<u64, ThriftError> {
            let at = self.pos;
            let mut result: u64 = 0;
            for shift in 0..10u32 {
                let b = self.u8()?;
                result |= u64::from(b & 0x7f) << (shift * 7);
                if b & 0x80 == 0 {
                    return Ok(result);
                }
            }
            Err(ThriftError::BadVarint(at))
        }

        fn zigzag(&mut self) -> Result<i64, ThriftError> {
            let n = self.varint()?;
            Ok(((n >> 1) as i64) ^ -((n & 1) as i64))
        }

        fn binary(&mut self) -> Result<Vec<u8>, ThriftError> {
            let at = self.pos;
            let len = self.varint()?;
            let len = self.guard_len(at, len)?;
            let end = self.pos + len;
            let out = self.buf[self.pos..end].to_vec();
            self.pos = end;
            Ok(out)
        }

        /// Every element of a collection costs at least one byte on the wire --
        /// a bool is a byte, an empty struct is its STOP byte -- and so does
        /// every byte of a binary. So a declared length past the remaining
        /// buffer is a lie, and rejecting it before allocating is what stops a
        /// four-byte header from asking for a gigabyte.
        fn guard_len(&self, at: usize, len: u64) -> Result<usize, ThriftError> {
            if len > (self.buf.len() - self.pos) as u64 {
                return Err(ThriftError::BadLength { at, len });
            }
            Ok(len as usize)
        }

        fn value(&mut self, ttype: u8, depth: usize) -> Result<Val, ThriftError> {
            if depth > MAX_DEPTH {
                return Err(ThriftError::TooDeep(self.pos));
            }
            match ttype {
                BOOL_TRUE => Ok(Val::Bool(true)),
                BOOL_FALSE => Ok(Val::Bool(false)),
                I8 => Ok(Val::I8(self.u8()? as i8)),
                I16 | I32 | I64 => Ok(Val::Int(self.zigzag()?)),
                DOUBLE => {
                    let bytes = self
                        .buf
                        .get(self.pos..self.pos + 8)
                        .ok_or(ThriftError::Eof(self.pos))?;
                    let mut raw = [0u8; 8];
                    raw.copy_from_slice(bytes);
                    self.pos += 8;
                    Ok(Val::Double(raw))
                }
                BINARY => Ok(Val::Binary(self.binary()?)),
                LIST | SET => self.collection(depth),
                MAP => self.map(depth),
                STRUCT => Ok(Val::Struct(self.struct_body(depth)?)),
                other => Err(ThriftError::UnknownType {
                    ttype: other,
                    at: self.pos,
                }),
            }
        }

        fn collection(&mut self, depth: usize) -> Result<Val, ThriftError> {
            let at = self.pos;
            let header = self.u8()?;
            let etype = header & 0x0f;
            let short = (header >> 4) & 0x0f;
            let len = if short == 15 {
                self.varint()?
            } else {
                u64::from(short)
            };
            let len = self.guard_len(at, len)?;
            let mut items = Vec::with_capacity(len);
            for _ in 0..len {
                // A bool inside a collection is a whole byte, not a type
                // nibble, so it cannot come through `value`.
                if etype == BOOL_TRUE || etype == BOOL_FALSE {
                    items.push(Val::Bool(self.u8()? == BOOL_TRUE));
                } else {
                    items.push(self.value(etype, depth + 1)?);
                }
            }
            Ok(Val::Coll { etype, items })
        }

        fn map(&mut self, depth: usize) -> Result<Val, ThriftError> {
            let at = self.pos;
            let len = self.varint()?;
            if len == 0 {
                // An empty map writes its size and no key/value byte at all, so
                // there is no type information to preserve.
                return Ok(Val::Map {
                    ktype: 0,
                    vtype: 0,
                    items: Vec::new(),
                });
            }
            let len = self.guard_len(at, len)?;
            let kv = self.u8()?;
            let (ktype, vtype) = ((kv >> 4) & 0x0f, kv & 0x0f);
            let mut items = Vec::with_capacity(len);
            for _ in 0..len {
                let key = self.value(ktype, depth + 1)?;
                let value = self.value(vtype, depth + 1)?;
                items.push((key, value));
            }
            Ok(Val::Map {
                ktype,
                vtype,
                items,
            })
        }

        fn struct_body(&mut self, depth: usize) -> Result<Struct, ThriftError> {
            if depth > MAX_DEPTH {
                return Err(ThriftError::TooDeep(self.pos));
            }
            let mut fields = Vec::new();
            let mut last: i16 = 0;
            loop {
                let at = self.pos;
                let header = self.u8()?;
                let ttype = header & 0x0f;
                if ttype == STOP {
                    return Ok(Struct { fields });
                }
                let delta = (header >> 4) & 0x0f;
                let id = if delta == 0 {
                    let id = self.zigzag()?;
                    i16::try_from(id).map_err(|_| ThriftError::BadFieldId { id, at })?
                } else {
                    last.checked_add(i16::from(delta))
                        .ok_or(ThriftError::BadFieldId {
                            id: i64::from(last) + i64::from(delta),
                            at,
                        })?
                };
                last = id;
                let value = self.value(ttype, depth + 1)?;
                fields.push(Field { id, ttype, value });
            }
        }
    }

    #[derive(Default)]
    struct Writer {
        out: Vec<u8>,
    }

    impl Writer {
        fn varint(&mut self, mut n: u64) {
            loop {
                if n < 0x80 {
                    self.out.push(n as u8);
                    return;
                }
                self.out.push((n as u8 & 0x7f) | 0x80);
                n >>= 7;
            }
        }

        fn zigzag(&mut self, n: i64) {
            self.varint(((n << 1) ^ (n >> 63)) as u64);
        }

        fn value(&mut self, val: &Val) {
            match val {
                // Carried in the field header's type nibble, or in the
                // collection element byte the caller writes.
                Val::Bool(_) => {}
                Val::I8(n) => self.out.push(*n as u8),
                Val::Int(n) => self.zigzag(*n),
                Val::Double(raw) => self.out.extend_from_slice(raw),
                Val::Binary(bytes) => {
                    self.varint(bytes.len() as u64);
                    self.out.extend_from_slice(bytes);
                }
                Val::Coll { etype, items } => {
                    if items.len() < 15 {
                        self.out.push(((items.len() as u8) << 4) | *etype);
                    } else {
                        self.out.push(0xf0 | *etype);
                        self.varint(items.len() as u64);
                    }
                    for item in items {
                        if *etype == BOOL_TRUE || *etype == BOOL_FALSE {
                            self.out.push(match item {
                                Val::Bool(true) => BOOL_TRUE,
                                _ => BOOL_FALSE,
                            });
                        } else {
                            self.value(item);
                        }
                    }
                }
                Val::Map {
                    ktype,
                    vtype,
                    items,
                } => {
                    self.varint(items.len() as u64);
                    if !items.is_empty() {
                        self.out.push((ktype << 4) | vtype);
                        for (key, value) in items {
                            self.value(key);
                            self.value(value);
                        }
                    }
                }
                Val::Struct(s) => self.struct_body(s),
            }
        }

        fn struct_body(&mut self, s: &Struct) {
            let mut last: i16 = 0;
            for field in &s.fields {
                // A bool's value lives in its type nibble, so the nibble is
                // derived from the value rather than trusted from the decode.
                let ttype = match field.value {
                    Val::Bool(true) => BOOL_TRUE,
                    Val::Bool(false) => BOOL_FALSE,
                    _ => field.ttype,
                };
                let delta = i32::from(field.id) - i32::from(last);
                if delta > 0 && delta <= 15 {
                    self.out.push(((delta as u8) << 4) | ttype);
                } else {
                    self.out.push(ttype);
                    self.zigzag(i64::from(field.id));
                }
                last = field.id;
                self.value(&field.value);
            }
            self.out.push(STOP);
        }
    }

    /// Decode a whole buffer as one struct, refusing trailing bytes.
    ///
    /// Trailing bytes are refused rather than ignored because a re-encode would
    /// not reproduce them, and the round-trip identity check in
    /// [`super::rewrite_footer`] would then be comparing against the wrong
    /// thing.
    pub fn decode_struct(buf: &[u8]) -> Result<Struct, ThriftError> {
        let mut reader = Reader { buf, pos: 0 };
        let s = reader.struct_body(0)?;
        if reader.pos != buf.len() {
            return Err(ThriftError::Trailing {
                trailing: buf.len() - reader.pos,
            });
        }
        Ok(s)
    }

    pub fn encode_struct(s: &Struct) -> Vec<u8> {
        let mut writer = Writer::default();
        writer.struct_body(s);
        writer.out
    }
}

#[cfg(test)]
mod tests {
    use super::thrift::{Field, Struct, ThriftError, Val};
    use super::*;
    use crate::index::LayoutIndex;
    use crate::policy::QUERYABLES;

    const NYC: &str = "data/nyc-taxi-8rg.parquet";
    const NESTED: &str = "tests/fixtures/nested.parquet";
    const DICT: &str = "tests/fixtures/dict.parquet";
    const MULTI_RG: &str = "tests/fixtures/multi-rg.parquet";

    /// A whole object plus the index of it, which is how a gateway starts.
    struct Sample {
        bytes: Vec<u8>,
        index: LayoutIndex,
    }

    impl Sample {
        fn load(path: &str) -> Self {
            let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("{path}: {e}"));
            let size = bytes.len() as u64;
            let index = crate::parquet::build_index(&bytes, size).expect("build_index");
            Sample { bytes, index }
        }

        fn footer_region(&self) -> &crate::index::Region {
            self.index
                .regions()
                .iter()
                .find(|r| matches!(&r.kind, RegionKind::Metadata { name } if name == "footer"))
                .expect("a footer region")
        }

        fn footer_body(&self) -> &[u8] {
            let r = self.footer_region();
            &self.bytes[r.start as usize..r.end() as usize]
        }

        fn plan(&self, withheld: &[&str]) -> Rewrite {
            plan(
                &self.index,
                self.footer_body(),
                &policy_withholding(withheld),
                &json!({"role": "analyst"}),
            )
            .expect("plan")
        }

        /// The object a gateway would serve, assembled end to end. Built only
        /// so a reader can be pointed at it; the gateway itself never
        /// materializes this.
        fn served(&self, rewrite: &Rewrite) -> Vec<u8> {
            let start = rewrite.footer_start();
            let mut out = self.bytes[..start as usize].to_vec();
            let verdict = rewrite.object_verdict(&(0..start));
            verdict.redact(&mut out).expect("redact");
            out.extend_from_slice(&rewrite.tail());
            assert_eq!(out.len() as u64, rewrite.virtual_size());
            out
        }
    }

    /// A policy permitting the structure and every column but `withheld` --
    /// chunks, page index and bloom filter alike, which is the shape issue #26
    /// says a policy must have.
    fn policy_withholding(withheld: &[&str]) -> Policy {
        let mut yaml = String::from("allow:\n  - \"region.kind = 'metadata'\"\n");
        let clauses: Vec<String> = withheld
            .iter()
            .map(|c| format!("region.column <> '{c}'"))
            .collect();
        let rule = if clauses.is_empty() {
            "region.column IS NOT NULL".to_string()
        } else {
            clauses.join(" AND ")
        };
        yaml.push_str(&format!("  - \"{rule}\"\n"));
        Policy::load(&yaml, QUERYABLES).expect("policy")
    }

    /// Permit everything, so a rewrite withholds nothing.
    fn permit_all() -> Policy {
        Policy::load("allow:\n  - \"1 = 1\"\n", QUERYABLES).expect("policy")
    }

    // ---- the codec ------------------------------------------------------

    /// The property the whole module rests on. If re-encoding an unmodified
    /// tree did not reproduce the input, then the diff between a rewritten
    /// footer and the original would not be the edit, and nothing downstream
    /// could be trusted to be about the columns we meant to remove.
    #[test]
    fn the_codec_reproduces_every_fixture_footer_byte_for_byte() {
        for path in [NYC, NESTED, DICT, MULTI_RG] {
            let sample = Sample::load(path);
            let body = sample.footer_body();
            let decoded =
                super::thrift::decode_struct(body).unwrap_or_else(|e| panic!("{path}: {e}"));
            let encoded = super::thrift::encode_struct(&decoded);
            assert_eq!(encoded, body, "{path} did not round-trip");
        }
    }

    #[test]
    fn a_lying_collection_length_is_refused_before_it_allocates() {
        // Field 1, type LIST, long form declaring 2^32 struct elements in a
        // buffer that holds none. Reserving for them would be the OOM.
        let buf = [0x19u8, 0xfc, 0xff, 0xff, 0xff, 0x0f];
        assert!(matches!(
            super::thrift::decode_struct(&buf),
            Err(ThriftError::BadLength { .. })
        ));
    }

    #[test]
    fn a_deeply_nested_struct_is_refused_rather_than_overflowing_the_stack() {
        // 200 nested one-field structs. On wasm32 the panic runtime aborts, so
        // a stack overflow here is an availability bug for every request the
        // worker would have served, not a failed parse.
        let mut buf = vec![0x1cu8; 200];
        buf.extend(std::iter::repeat_n(0x00u8, 200));
        assert!(matches!(
            super::thrift::decode_struct(&buf),
            Err(ThriftError::TooDeep(_))
        ));
    }

    #[test]
    fn a_varint_that_never_terminates_is_refused() {
        let mut buf = vec![0x15u8]; // field 1, i32
        buf.extend(std::iter::repeat_n(0xffu8, 12));
        assert!(matches!(
            super::thrift::decode_struct(&buf),
            Err(ThriftError::BadVarint(_) | ThriftError::Eof(_))
        ));
    }

    #[test]
    fn trailing_bytes_after_the_struct_are_refused() {
        let mut buf = super::thrift::encode_struct(&Struct::default());
        buf.push(0x00);
        assert!(matches!(
            super::thrift::decode_struct(&buf),
            Err(ThriftError::Trailing { trailing: 1 })
        ));
    }

    // ---- the identity case ----------------------------------------------

    #[test]
    fn withholding_nothing_reproduces_the_original_footer_exactly() {
        let sample = Sample::load(NYC);
        let rewrite = plan(
            &sample.index,
            sample.footer_body(),
            &permit_all(),
            &json!({"role": "analyst"}),
        )
        .expect("plan");
        assert_eq!(rewrite.footer(), sample.footer_body());
        assert!(rewrite.scrub().is_empty());
        assert!(rewrite.withheld().is_empty());
        assert_eq!(rewrite.virtual_size(), sample.index.size());
        assert_eq!(sample.served(&rewrite), sample.bytes);
    }

    // ---- the real file --------------------------------------------------

    #[test]
    fn the_rewritten_footer_holds_no_trace_of_a_withheld_column() {
        let sample = Sample::load(NYC);
        let rewrite = sample.plan(&["fare_amount", "tip_amount"]);

        // Not a substring anywhere in the thrift: no `path_in_schema`, no
        // `SchemaElement.name`, and nothing hiding in a key/value blob. This is
        // the claim issue #16 recorded as an accepted limitation.
        for name in ["fare_amount", "tip_amount"] {
            assert!(
                !rewrite
                    .footer()
                    .windows(name.len())
                    .any(|w| w == name.as_bytes()),
                "`{name}` still appears in the rewritten footer"
            );
        }

        // And parquet-rs agrees about what is left, including that no surviving
        // chunk points at a withheld column's statistics, page index or bloom
        // filter -- those pointers live on the chunks, so losing the chunks
        // loses them.
        let meta =
            ::parquet::file::metadata::ParquetMetaDataReader::decode_metadata(rewrite.footer())
                .expect("parquet-rs decodes the rewritten footer");
        let leaves: Vec<String> = meta
            .file_metadata()
            .schema_descr()
            .columns()
            .iter()
            .map(|c| c.path().string())
            .collect();
        assert_eq!(leaves.len(), 17);
        assert!(!leaves
            .iter()
            .any(|l| l == "fare_amount" || l == "tip_amount"));
        assert_eq!(meta.num_row_groups(), 8);
        for group in meta.row_groups() {
            assert_eq!(group.num_columns(), 17);
        }
        assert_eq!(meta.file_metadata().num_rows(), 400_000);
    }

    /// The scrub set is not "the column chunks". A scrub derived from
    /// `total_compressed_size` would leave live bloom filters behind, and a
    /// bloom filter answers membership queries about the withheld values
    /// outright.
    #[test]
    fn the_scrub_set_reaches_past_the_column_chunks_to_the_bloom_filters() {
        let sample = Sample::load(NYC);
        let rewrite = sample.plan(&["fare_amount", "tip_amount"]);

        let regions: Vec<&crate::index::Region> = sample
            .index
            .regions()
            .iter()
            .filter(|r| matches!(r.column(), Some("fare_amount" | "tip_amount")))
            .collect();
        let chunk_bytes: u64 = regions
            .iter()
            .filter(|r| matches!(r.kind, RegionKind::ColumnChunk { .. }))
            .map(|r| r.len)
            .sum();
        let bloom_bytes: u64 = regions
            .iter()
            .filter(|r| matches!(r.kind, RegionKind::BloomFilter { .. }))
            .map(|r| r.len)
            .sum();
        let scrubbed: u64 = rewrite.scrub().iter().map(|s| s.end - s.start).sum();

        assert_eq!(
            regions.len(),
            32,
            "8 row groups x 2 columns, chunk and bloom each"
        );
        assert_eq!(chunk_bytes, 1_108_611);
        assert_eq!(bloom_bytes, 26_880);
        assert!(bloom_bytes > 0, "the sample must carry bloom filters");
        assert_eq!(scrubbed, chunk_bytes + bloom_bytes);
        assert!(scrubbed > chunk_bytes);

        // Sorted, disjoint, non-empty, and all below the footer.
        let mut previous = 0u64;
        for span in rewrite.scrub() {
            assert!(span.start < span.end);
            assert!(
                span.start >= previous,
                "scrub spans are not sorted/disjoint"
            );
            assert!(span.end <= rewrite.footer_start());
            previous = span.end;
        }
    }

    #[test]
    fn the_served_object_indexes_as_parquet_and_holds_zeroes_where_the_columns_were() {
        let sample = Sample::load(NYC);
        let rewrite = sample.plan(&["fare_amount", "tip_amount"]);
        let served = sample.served(&rewrite);

        // Every scrubbed byte is zero...
        for span in rewrite.scrub() {
            assert!(
                served[span.start as usize..span.end as usize]
                    .iter()
                    .all(|b| *b == 0),
                "live bytes survived at {span:?}"
            );
            // ...and they were not zero to begin with, or the assertion above
            // would pass on a rewrite that scrubbed nothing at all.
            assert!(sample.bytes[span.start as usize..span.end as usize]
                .iter()
                .any(|b| *b != 0));
        }

        // Every byte below the footer that is NOT scrubbed is untouched, so a
        // permitted column's chunk is bit-identical to the original.
        let mut cursor = 0u64;
        for span in rewrite.scrub() {
            let gap = cursor as usize..span.start as usize;
            assert_eq!(served[gap.clone()], sample.bytes[gap]);
            cursor = span.end;
        }

        // The result is a Parquet object this crate's own resolver accepts.
        let index = crate::parquet::build_index(&served, served.len() as u64)
            .expect("the served object indexes as Parquet");
        assert_eq!(index.size(), rewrite.virtual_size());
        assert!(!index
            .regions()
            .iter()
            .any(|r| matches!(r.column(), Some("fare_amount" | "tip_amount"))));
    }

    /// Fail-closed, and visibly so. A policy that permits a column's chunks but
    /// not its bloom filter withholds the whole column -- issue #26 measured
    /// what happens when a permitted column loses its bloom filter (DuckDB
    /// equality predicates fail with a corruption-shaped error), so the only
    /// safe reading of such a policy is that the column goes.
    #[test]
    fn a_column_whose_bloom_filter_is_denied_is_withheld_whole() {
        let sample = Sample::load(NYC);
        let policy = Policy::load(
            "allow:\n  - \"region.kind = 'metadata'\"\n  \
             - \"region.kind = 'column_chunk'\"\n  \
             - \"region.kind = 'column_index'\"\n  \
             - \"region.kind = 'bloom_filter' AND region.column <> 'trip_distance'\"\n",
            QUERYABLES,
        )
        .unwrap();
        let rewrite = plan(
            &sample.index,
            sample.footer_body(),
            &policy,
            &json!({"role": "analyst"}),
        )
        .expect("plan");
        assert_eq!(rewrite.withheld().len(), 1);
        let withheld = &rewrite.withheld()[0];
        assert_eq!(withheld.column, "trip_distance");
        assert_eq!(withheld.denied_kinds, vec!["bloom_filter".to_string()]);
        // The report names the bloom filter, but the scrub still takes every
        // region of the column: once it is gone from the footer, its chunks are
        // unreferenced bytes that still decode.
        assert_eq!(withheld.regions, 16);
    }

    #[test]
    fn withholding_every_column_is_refused_rather_than_served_empty() {
        let sample = Sample::load(NESTED);
        let policy =
            Policy::load("allow:\n  - \"region.kind = 'metadata'\"\n", QUERYABLES).unwrap();
        let err = plan(
            &sample.index,
            sample.footer_body(),
            &policy,
            &json!({"role": "nobody"}),
        )
        .unwrap_err();
        assert_eq!(err, RewriteError::NothingToServe);
    }

    // ---- nested schemas -------------------------------------------------

    #[test]
    fn a_group_that_keeps_a_leaf_is_not_pruned() {
        let sample = Sample::load(NESTED);
        let rewrite = sample.plan(&["employee.name"]);
        assert!(rewrite.groups_pruned().is_empty());

        let meta =
            ::parquet::file::metadata::ParquetMetaDataReader::decode_metadata(rewrite.footer())
                .expect("decode");
        let leaves: Vec<String> = meta
            .file_metadata()
            .schema_descr()
            .columns()
            .iter()
            .map(|c| c.path().string())
            .collect();
        assert_eq!(leaves, ["id", "salary", "employee.salary"]);
    }

    /// The trap: a group whose last child is withheld would be left with
    /// `num_children = 0`, which `parquet.thrift` cannot express and readers do
    /// not reject -- DuckDB absorbed the next sibling into the emptied group and
    /// reported a plausible schema with no error.
    #[test]
    fn withholding_a_groups_last_leaves_prunes_the_group() {
        let sample = Sample::load(NESTED);
        let rewrite = sample.plan(&["employee.name", "employee.salary"]);
        assert_eq!(rewrite.groups_pruned(), ["employee"]);

        let meta =
            ::parquet::file::metadata::ParquetMetaDataReader::decode_metadata(rewrite.footer())
                .expect("decode");
        let leaves: Vec<String> = meta
            .file_metadata()
            .schema_descr()
            .columns()
            .iter()
            .map(|c| c.path().string())
            .collect();
        // The top-level `salary` survives, which is the collision this fixture
        // exists for: keyed on the leaf name the two columns are one.
        assert_eq!(leaves, ["id", "salary"]);
        assert!(!rewrite.footer().windows(8).any(|w| w == b"employee"));

        // And the group really is gone rather than emptied: the schema list is
        // the root plus two leaves, with no element left carrying children.
        let decoded = super::thrift::decode_struct(rewrite.footer()).unwrap();
        let schema = decoded.get(fm::SCHEMA).and_then(Val::as_coll).unwrap();
        assert_eq!(schema.len(), 3);
        assert_eq!(
            schema[0].get(se::NUM_CHILDREN).and_then(Val::as_int),
            Some(2)
        );
        for element in &schema[1..] {
            assert!(element
                .get(se::NUM_CHILDREN)
                .and_then(Val::as_int)
                .is_none_or(|n| n == 0));
        }
    }

    // ---- the hand-built footer ------------------------------------------
    //
    // No fixture in this repository has a single-leaf group, a `column_orders`
    // list, an `ARROW:schema` key or a `sorting_columns` entry -- DuckDB writes
    // none of them. Building the thrift directly is the only way to cover them.

    fn f(id: i16, ttype: u8, value: Val) -> Field {
        Field { id, ttype, value }
    }
    fn st(fields: Vec<Field>) -> Val {
        Val::Struct(Struct { fields })
    }
    fn i32f(id: i16, n: i64) -> Field {
        f(id, super::thrift::I32, Val::Int(n))
    }
    fn i64f(id: i16, n: i64) -> Field {
        f(id, super::thrift::I64, Val::Int(n))
    }
    fn bin(id: i16, s: &str) -> Field {
        f(
            id,
            super::thrift::BINARY,
            Val::Binary(s.as_bytes().to_vec()),
        )
    }
    fn list(id: i16, etype: u8, items: Vec<Val>) -> Field {
        f(id, super::thrift::LIST, Val::Coll { etype, items })
    }

    fn schema_element(name: &str, children: Option<i64>) -> Val {
        let mut fields = vec![i32f(1, 2), i32f(3, 1), bin(4, name)];
        if let Some(n) = children {
            fields.push(i32f(5, n));
        }
        st(fields)
    }

    fn column_chunk(path: &[&str], start: i64, compressed: i64) -> Val {
        let meta = st(vec![
            i32f(1, 2),
            list(2, super::thrift::I32, vec![Val::Int(0)]),
            list(
                3,
                super::thrift::BINARY,
                path.iter()
                    .map(|p| Val::Binary(p.as_bytes().to_vec()))
                    .collect(),
            ),
            i32f(4, 0),
            i64f(5, 10),
            i64f(6, compressed * 2),
            i64f(7, compressed),
            i64f(9, start),
        ]);
        st(vec![i64f(2, start), f(3, super::thrift::STRUCT, meta)])
    }

    /// `root { id, geo { lat }, label }` -- one row group, `column_orders`,
    /// `sorting_columns` naming the middle column, and an `ARROW:schema` key.
    fn hand_built_footer() -> Vec<u8> {
        let schema = list(
            2,
            super::thrift::STRUCT,
            vec![
                schema_element("root", Some(3)),
                schema_element("id", None),
                schema_element("geo", Some(1)),
                schema_element("lat", None),
                schema_element("label", None),
            ],
        );
        let row_group = st(vec![
            list(
                1,
                super::thrift::STRUCT,
                vec![
                    column_chunk(&["id"], 4, 100),
                    column_chunk(&["geo", "lat"], 104, 200),
                    column_chunk(&["label"], 304, 50),
                ],
            ),
            i64f(2, 700),
            i64f(3, 10),
            list(4, super::thrift::STRUCT, vec![st(vec![i32f(1, 2)])]),
            i64f(5, 4),
            i64f(6, 350),
            f(7, super::thrift::I16, Val::Int(0)),
        ]);
        let meta = Struct {
            fields: vec![
                i32f(1, 1),
                schema,
                i64f(3, 10),
                list(4, super::thrift::STRUCT, vec![row_group]),
                list(
                    5,
                    super::thrift::STRUCT,
                    vec![
                        st(vec![bin(1, "ARROW:schema"), bin(2, "id,geo.lat,label")]),
                        st(vec![bin(1, "keep-me"), bin(2, "opaque")]),
                    ],
                ),
                bin(6, "cnac test"),
                list(
                    7,
                    super::thrift::STRUCT,
                    vec![
                        st(vec![f(1, super::thrift::STRUCT, st(vec![]))]),
                        st(vec![f(1, super::thrift::STRUCT, st(vec![]))]),
                        st(vec![f(1, super::thrift::STRUCT, st(vec![]))]),
                    ],
                ),
            ],
        };
        super::thrift::encode_struct(&meta)
    }

    #[test]
    fn withholding_a_groups_only_leaf_prunes_the_group_rather_than_emptying_it() {
        let body = hand_built_footer();
        let withheld = BTreeSet::from(["geo.lat".to_string()]);
        let edit = rewrite_footer(&body, &withheld).expect("rewrite");
        assert_eq!(edit.groups_pruned, ["geo"]);

        let out = super::thrift::decode_struct(&edit.footer).unwrap();
        let schema = out.get(fm::SCHEMA).and_then(Val::as_coll).unwrap();
        let names: Vec<String> = schema
            .iter()
            .map(|e| {
                String::from_utf8_lossy(e.get(se::NAME).and_then(Val::as_binary).unwrap_or(b"root"))
                    .into_owned()
            })
            .collect();
        assert_eq!(names, ["root", "id", "label"]);
        // The decisive assertion: `geo` is absent, NOT present with zero
        // children. A zero there reads as a leaf, and the next sibling gets
        // absorbed into it with no error anywhere.
        assert_eq!(
            schema[0].get(se::NUM_CHILDREN).and_then(Val::as_int),
            Some(2)
        );
        assert!(schema
            .iter()
            .all(|e| e.get(se::NUM_CHILDREN).and_then(Val::as_int) != Some(0)));
    }

    #[test]
    fn column_orders_lose_exactly_the_indices_the_schema_lost() {
        let body = hand_built_footer();
        let before = super::thrift::decode_struct(&body).unwrap();
        assert_eq!(
            before
                .get(fm::COLUMN_ORDERS)
                .and_then(Val::as_coll)
                .unwrap()
                .len(),
            3
        );

        let edit = rewrite_footer(&body, &BTreeSet::from(["geo.lat".to_string()])).unwrap();
        let after = super::thrift::decode_struct(&edit.footer).unwrap();
        // Positional: one entry per surviving leaf, and the list must shrink in
        // step or every survivor's sort order shifts by one.
        assert_eq!(
            after
                .get(fm::COLUMN_ORDERS)
                .and_then(Val::as_coll)
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn schema_restating_key_value_metadata_is_stripped_and_the_rest_kept() {
        let body = hand_built_footer();
        let edit = rewrite_footer(&body, &BTreeSet::from(["geo.lat".to_string()])).unwrap();
        assert_eq!(edit.stripped_keys, ["ARROW:schema"]);

        let after = super::thrift::decode_struct(&edit.footer).unwrap();
        let kvs = after
            .get(fm::KEY_VALUE_METADATA)
            .and_then(Val::as_coll)
            .unwrap();
        let keys: Vec<String> = kvs
            .iter()
            .map(|e| {
                String::from_utf8_lossy(e.get(kv::KEY).and_then(Val::as_binary).unwrap())
                    .into_owned()
            })
            .collect();
        assert_eq!(keys, ["keep-me"]);
        // The flatbuffer named every original column in plaintext; with it gone
        // so is the name.
        assert!(!edit.footer.windows(3).any(|w| w == b"lat"));
    }

    #[test]
    fn sorting_columns_are_renumbered_onto_the_shortened_column_list() {
        let body = hand_built_footer();

        // Withholding the FIRST column renumbers the entry that names the third
        // one from 2 to 1.
        let edit = rewrite_footer(&body, &BTreeSet::from(["id".to_string()])).unwrap();
        let after = super::thrift::decode_struct(&edit.footer).unwrap();
        let group = &after.get(fm::ROW_GROUPS).and_then(Val::as_coll).unwrap()[0];
        let sorting = group
            .get(rg::SORTING_COLUMNS)
            .and_then(Val::as_coll)
            .unwrap();
        assert_eq!(sorting.len(), 1);
        assert_eq!(
            sorting[0].get(sc::COLUMN_IDX).and_then(Val::as_int),
            Some(1)
        );

        // Withholding the column the entry names drops the entry, because there
        // is no index left that means it.
        let edit = rewrite_footer(&body, &BTreeSet::from(["label".to_string()])).unwrap();
        let after = super::thrift::decode_struct(&edit.footer).unwrap();
        let group = &after.get(fm::ROW_GROUPS).and_then(Val::as_coll).unwrap()[0];
        assert!(group
            .get(rg::SORTING_COLUMNS)
            .and_then(Val::as_coll)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn row_group_aggregates_and_file_offset_follow_the_columns_that_are_left() {
        let body = hand_built_footer();
        let edit = rewrite_footer(&body, &BTreeSet::from(["id".to_string()])).unwrap();
        let after = super::thrift::decode_struct(&edit.footer).unwrap();
        let group = &after.get(fm::ROW_GROUPS).and_then(Val::as_coll).unwrap()[0];
        // 700 - 200 uncompressed, 350 - 100 compressed.
        assert_eq!(
            group.get(rg::TOTAL_BYTE_SIZE).and_then(Val::as_int),
            Some(500)
        );
        assert_eq!(
            group.get(rg::TOTAL_COMPRESSED_SIZE).and_then(Val::as_int),
            Some(250)
        );
        // `file_offset` pointed at `id`. Left alone it would address bytes
        // nothing references -- which, after the scrub, are zeroes.
        assert_eq!(group.get(rg::FILE_OFFSET).and_then(Val::as_int), Some(104));
    }

    #[test]
    fn a_row_group_that_would_lose_every_column_is_refused() {
        let body = hand_built_footer();
        let withheld =
            BTreeSet::from(["id".to_string(), "geo.lat".to_string(), "label".to_string()]);
        assert_eq!(
            rewrite_footer(&body, &withheld).unwrap_err(),
            RewriteError::NothingToServe
        );
    }

    #[test]
    fn a_column_the_schema_does_not_have_is_refused() {
        let body = hand_built_footer();
        assert_eq!(
            rewrite_footer(&body, &BTreeSet::from(["nope".to_string()])).unwrap_err(),
            RewriteError::UnknownColumn("nope".into())
        );
    }

    // ---- the address map ------------------------------------------------

    #[test]
    fn a_range_reaching_into_the_footer_gets_no_object_bytes() {
        let sample = Sample::load(NYC);
        let rewrite = sample.plan(&["fare_amount"]);
        let start = rewrite.footer_start();
        assert!(matches!(
            rewrite.object_verdict(&(start - 10..start + 1)),
            Verdict::Denied { .. }
        ));
        assert!(matches!(
            rewrite.object_verdict(&(start..start)),
            Verdict::Denied { .. }
        ));
        assert!(matches!(
            rewrite.object_verdict(&(start - 10..start)),
            Verdict::Serve { .. }
        ));
    }

    /// The block-aligned read the whole architecture exists for: a 64 KiB block
    /// straddling a withheld chunk is served, with the withheld bytes zeroed
    /// and every permitted byte intact.
    #[test]
    fn a_block_that_straddles_a_withheld_chunk_is_served_with_a_hole_in_it() {
        let sample = Sample::load(NYC);
        let rewrite = sample.plan(&["fare_amount"]);
        let chunk = sample
            .index
            .regions()
            .iter()
            .find(|r| matches!(&r.kind, RegionKind::ColumnChunk { column, .. } if column == "fare_amount"))
            .unwrap();

        const BLOCK: u64 = 64 * 1024;
        let lo = (chunk.start / BLOCK) * BLOCK;
        let hi = lo + BLOCK;
        assert!(lo < chunk.start && hi > chunk.start, "must straddle");

        let verdict = rewrite.object_verdict(&(lo..hi));
        let mut buf = sample.bytes[lo as usize..hi as usize].to_vec();
        verdict.redact(&mut buf).expect("redact");

        for (i, byte) in buf.iter().enumerate() {
            let at = lo + i as u64;
            let scrubbed = rewrite.scrub().iter().any(|s| s.contains(&at));
            if scrubbed {
                assert_eq!(*byte, 0, "byte {at} should be scrubbed");
            } else {
                assert_eq!(*byte, sample.bytes[at as usize], "byte {at} was altered");
            }
        }
        // The block really did carry permitted bytes as well, so the assertion
        // above is not vacuous.
        assert!(lo < chunk.start);
    }

    #[test]
    fn the_etag_tracks_the_withheld_set_and_not_the_principal() {
        let sample = Sample::load(NYC);
        let one = plan(
            &sample.index,
            sample.footer_body(),
            &policy_withholding(&["tip_amount"]),
            &json!({"role": "analyst"}),
        )
        .unwrap();
        let another_principal = plan(
            &sample.index,
            sample.footer_body(),
            &policy_withholding(&["tip_amount"]),
            &json!({"role": "auditor", "level": 7}),
        )
        .unwrap();
        let other_columns = plan(
            &sample.index,
            sample.footer_body(),
            &policy_withholding(&["fare_amount"]),
            &json!({"role": "analyst"}),
        )
        .unwrap();

        // Many principals, one cache entry.
        assert_eq!(one.etag(), another_principal.etag());
        // Different filtered view, different representation.
        assert_ne!(one.etag(), other_columns.etag());
        assert!(one.etag().starts_with("\"cnac-"));
    }

    #[test]
    fn a_footer_body_that_is_not_the_indexed_one_is_refused() {
        let sample = Sample::load(NYC);
        let short = &sample.footer_body()[..100];
        let err = plan(
            &sample.index,
            short,
            &permit_all(),
            &json!({"role": "analyst"}),
        )
        .unwrap_err();
        assert!(matches!(err, RewriteError::FooterLength { got: 100, .. }));
    }

    #[test]
    fn an_index_with_no_footer_region_is_refused() {
        let index = LayoutIndex::try_new(Vec::new(), 1024).unwrap();
        let err = plan(&index, &[], &permit_all(), &json!({"role": "analyst"})).unwrap_err();
        assert_eq!(err, RewriteError::NoFooterRegion);
    }
}
