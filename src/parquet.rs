//! The Parquet resolver: a footer in, a [`LayoutIndex`] out.
//!
//! [`build_index`] is synchronous and pure. It never fetches: the caller reads
//! the bytes and hands them over, because the reader in a gateway already has a
//! cache, a credential and a retry policy, and this crate should have none of
//! the three.
//!
//! # One read, not two
//!
//! `footer` must be a **contiguous suffix of the object** that contains the
//! whole footer -- the thrift body plus the 8-byte trailer. The whole file is a
//! valid argument, since an object is a suffix of itself; so is a speculative
//! tail read. A buffer that stops short of the footer body is refused with
//! [`ParquetError::Truncated`], which names the number of bytes from the end
//! that would have been enough, so a caller that guessed too small can widen
//! its read and retry rather than fail.
//!
//! One read is enough to classify *everything*, including the structures that
//! do not live in the footer. The page index and the bloom filters sit outside
//! `total_compressed_size` and outside the footer, but their offsets and
//! lengths are fields of `ColumnChunk` in the footer thrift
//! (`column_index_offset`, `offset_index_offset`, `bloom_filter_offset`, and
//! the matching lengths). Classification needs to know WHERE they are, not what
//! they contain, so `ParquetMetaDataReader::read_page_indexes` -- which fetches
//! the index bytes themselves -- is not called and is not needed. That claim is
//! asserted against a real 8.4 MB file whose bloom filters sit 150 KB before
//! the footer, classified from a 64 KiB tail read.
//!
//! # The format rules, each from a specification review
//!
//! 1. **`ColumnChunk.file_offset` is never read.** `parquet.thrift` deprecates
//!    it and records that implementations disagreed about whether it points at
//!    the `ColumnMetaData` or at the first page, and that "in many cases the
//!    `ColumnMetaData` at this location is wrong".
//! 2. **A chunk runs from `min(dictionary_page_offset, data_page_offset)` for
//!    `total_compressed_size` bytes.** Starting at the data page leaves the
//!    dictionary page outside every region, and for a low-cardinality column
//!    the dictionary page IS the set of distinct values -- exactly what a
//!    policy on that column withholds. Some writers emit a dictionary offset
//!    that is not where a dictionary page is, so it is believed only when it
//!    sits at or before the data page.
//! 3. **`ColumnChunkMetaData::byte_range()` is not called.** It asserts on a
//!    negative offset, and this crate compiles to wasm32 where the panic
//!    runtime aborts: a crafted footer would poison the module instance and
//!    take out every request that worker would have served. The fields are read
//!    directly and a negative one is [`ParquetError::NegativeOffset`].
//! 4. **A region's column is the full dotted `path_in_schema`.** A file can
//!    hold a top-level `salary` and a nested `employee.salary` as distinct
//!    chunks; keyed on the leaf name they collide, and a rule written about one
//!    silently decides the other.
//! 5. **The page index and the bloom filters are column-attributed**, not
//!    generic metadata. A `ColumnIndex` leaks per-page min/max and null counts
//!    and an `OffsetIndex` per-page row counts, so both are a partial disclosure
//!    of the column and must answer to a rule about THAT column rather than to
//!    a blanket metadata allow. [`RegionKind`] has no `OffsetIndex` variant and
//!    this task does not add one: both structures become
//!    [`RegionKind::ColumnIndex`], which is the honest classification of what
//!    they leak, if not of which struct they are.
//! 6. **A bloom filter offset with no length emits nothing.** Recovering the
//!    length needs a `BloomFilterHeader` parse at that offset, which is the
//!    second read this resolver does not make. The bytes fall to `Unmapped`,
//!    which denies. Safe but blunt; tracked as issue #7.
//! 7. **A chunk with `file_path` set is refused.** The data is in another
//!    object, so the offsets are not offsets into this one, and mapping them
//!    anyway attaches a column's name to whatever happens to sit there.
//! 8. **Metadata regions are named and the set of names is closed** --
//!    `magic`, `footer`, `footer_trailer`. `index.rs` is explicit that metadata
//!    must never be a fallback classification, because a blanket
//!    `region.kind = 'metadata'` allow plus a catch-all is a wildcard over the
//!    bytes the resolver understood least. Unrecognized bytes are `Unmapped`.
//! 9. **An encrypted footer (`PARE`) is refused.** Out of scope, and out of
//!    scope has to mean an error rather than a partial classification; tracked
//!    as issue #7.

use crate::index::{IndexError, LayoutIndex, Region, RegionKind};

// `::parquet` and not `parquet`: this module IS `crate::parquet`, so a bare
// path would be ambiguous between it and the crate it wraps.
use ::parquet::file::metadata::{ColumnChunkMetaData, FooterTail, ParquetMetaDataReader};

/// The leading `PAR1`.
const MAGIC: &[u8; 4] = b"PAR1";
const MAGIC_LEN: u64 = 4;
/// The trailer: a 4-byte little-endian footer length, then the magic again.
const TRAILER_LEN: u64 = 8;

/// Why a Parquet object could not be turned into a layout index.
///
/// Every variant is a refusal to classify, and a refusal to classify is a
/// refusal to serve: there is no partial index. These are build-time errors on
/// a trusted path -- the object's owner is indexing their own object -- so
/// unlike [`DenyReason`](crate::decision::DenyReason) they may name the column
/// and the offset that caused them.
#[derive(Debug, thiserror::Error)]
pub enum ParquetError {
    /// Smaller than `PAR1` plus a trailer, so it cannot be a Parquet object.
    #[error("object is {size} bytes, too small to be a Parquet file")]
    TooSmall { size: u64 },
    /// The buffer is longer than the object it claims to describe, so it is not
    /// a suffix of it and every offset derived from it would be a guess.
    #[error("footer buffer is {buffer} bytes of a {size}-byte object")]
    NotASuffix { buffer: u64, size: u64 },
    /// The buffer does not reach back to the start of the footer body.
    /// `needed` is the number of bytes from the END of the object that would.
    #[error("footer needs the last {needed} bytes of the object")]
    Truncated { needed: u64 },
    /// The trailer's magic is neither `PAR1` nor `PARE`, or the declared footer
    /// length does not fit inside the object.
    #[error("not a Parquet object: {0}")]
    NotParquet(String),
    /// A `PARE` trailer. The footer thrift is encrypted, so its offsets are
    /// unreadable and nothing can be classified. Tracked as issue #7.
    #[error("encrypted footers are not supported")]
    EncryptedFooter,
    /// The footer thrift did not decode.
    #[error("footer did not decode: {0}")]
    Malformed(String),
    /// `ColumnChunk.file_path` is set: this chunk's bytes are in a different
    /// object and its offsets do not address the one being indexed.
    #[error("column `{column}` is stored in another object")]
    ExternalData { column: String },
    /// An offset or a length that cannot be a position in an object. Reading
    /// the fields rather than calling `byte_range()` is what turns this from an
    /// abort into an error; see rule 3.
    #[error("column `{column}` has a negative offset or length ({field} = {value})")]
    NegativeOffset {
        column: String,
        field: &'static str,
        value: i64,
    },
    /// The regions this resolver produced are not a valid layout: they overlap,
    /// they run past the end of the object, or an extent overflows. Every one
    /// of those means the footer disagrees with itself or with the object size
    /// the caller supplied, and the whole index is refused rather than the
    /// offending region dropped -- a dropped region is a hole, and a hole under
    /// `Unmapped` at least denies, but a hole made by silently discarding a
    /// column chunk hides that the file was lying.
    #[error("footer does not describe a valid layout: {0}")]
    Layout(#[from] IndexError),
}

/// Parse a Parquet footer into the layout index of the object it belongs to.
///
/// `footer` is a contiguous suffix of the object (the whole object is one) that
/// contains the entire footer; `object_size` is the object's full length, which
/// is what a `Content-Length` or a HEAD gives the caller. See the module docs
/// for why one read of the tail suffices even for structures that live far from
/// it.
///
/// Coverage of `[0, object_size)` is total, because
/// [`LayoutIndex::try_new`] fills whatever this resolver did not claim with
/// [`RegionKind::Unmapped`].
pub fn build_index(footer: &[u8], object_size: u64) -> Result<LayoutIndex, ParquetError> {
    let buffer = footer.len() as u64;
    if buffer > object_size {
        return Err(ParquetError::NotASuffix {
            buffer,
            size: object_size,
        });
    }
    if object_size < MAGIC_LEN + TRAILER_LEN {
        return Err(ParquetError::TooSmall { size: object_size });
    }
    if buffer < TRAILER_LEN {
        return Err(ParquetError::Truncated {
            needed: TRAILER_LEN,
        });
    }

    // The last 8 bytes: footer length, then magic. `FooterTail` is arrow-rs's
    // own parse of them, so the magic check and the length decode cannot drift
    // from the decoder that reads the body immediately below.
    // `try_from`, not `try_new` on a `[u8; 8]` this function slices out itself:
    // the fallible conversion has no panicking step to get wrong.
    let tail = FooterTail::try_from(&footer[footer.len() - 8..])
        .map_err(|e| ParquetError::NotParquet(e.to_string()))?;
    if tail.is_encrypted_footer() {
        return Err(ParquetError::EncryptedFooter);
    }

    let footer_len = tail.metadata_length() as u64;
    // Everything from the start of the footer body to the end of the object.
    let needed = footer_len + TRAILER_LEN; // both are bounded by u32::MAX + 8
    let footer_start = object_size
        .checked_sub(needed)
        .ok_or(ParquetError::NotParquet(format!(
            "footer declares {footer_len} bytes, more than the {object_size}-byte object holds"
        )))?;
    if footer_start < MAGIC_LEN {
        // The footer would start inside (or before) the leading magic. A file
        // this short is not one this footer came from.
        return Err(ParquetError::NotParquet(format!(
            "footer of {footer_len} bytes starts at {footer_start}, inside the leading magic"
        )));
    }
    if buffer < needed {
        return Err(ParquetError::Truncated { needed });
    }
    // The buffer is a suffix, so absolute `footer_start` maps to this offset.
    let body_end = footer.len() - TRAILER_LEN as usize;
    let body = &footer[body_end - footer_len as usize..body_end];

    // When the caller handed us the whole object we can check the leading magic
    // instead of assuming it. When it handed us a tail we cannot, and we do not
    // pretend to: the `magic` region below is a claim about bytes this function
    // may never have seen, which is why it is 4 bytes of named metadata rather
    // than anything a policy would grant on.
    if buffer == object_size && &footer[..4] != MAGIC {
        return Err(ParquetError::NotParquet(
            "object does not start with PAR1".into(),
        ));
    }

    let metadata = ParquetMetaDataReader::decode_metadata(body)
        .map_err(|e| ParquetError::Malformed(e.to_string()))?;

    let mut regions = vec![
        Region {
            start: 0,
            len: MAGIC_LEN,
            kind: named("magic"),
        },
        Region {
            start: footer_start,
            len: footer_len,
            kind: named("footer"),
        },
        Region {
            start: object_size - TRAILER_LEN,
            len: TRAILER_LEN,
            kind: named("footer_trailer"),
        },
    ];
    for (row_group, group) in metadata.row_groups().iter().enumerate() {
        for column in group.columns() {
            push_column_regions(column, row_group, &mut regions)?;
        }
    }

    Ok(LayoutIndex::try_new(regions, object_size)?)
}

fn named(name: &str) -> RegionKind {
    RegionKind::Metadata { name: name.into() }
}

/// Every region one column chunk owns: the chunk itself, its page index
/// structures, and its bloom filter.
fn push_column_regions(
    column: &ColumnChunkMetaData,
    row_group: usize,
    out: &mut Vec<Region>,
) -> Result<(), ParquetError> {
    // Rule 4: the full dotted path. `path_in_schema` is a `list<string>` in the
    // thrift and `ColumnPath::string` joins it with dots, which is the spelling
    // a policy author sees in `parquet-tools` and writes in a rule.
    let name = column.column_path().string();

    // Rule 7, checked before any offset is read: with `file_path` set, none of
    // the offsets below address this object at all.
    if column.file_path().is_some() {
        return Err(ParquetError::ExternalData { column: name });
    }

    let checked = |value: i64, field: &'static str| -> Result<u64, ParquetError> {
        u64::try_from(value).map_err(|_| ParquetError::NegativeOffset {
            column: name.clone(),
            field,
            value,
        })
    };

    // Rule 1: `file_offset` is deprecated and disagreed about, and is not read.
    let data_page = column.data_page_offset();
    let len = checked(column.compressed_size(), "total_compressed_size")?;
    // Rule 2. The dictionary page precedes the data pages and is counted inside
    // `total_compressed_size`, so believing an offset that sits AFTER the data
    // page would move the start forward past pages the length still covers --
    // leaving them to `Unmapped` at best and overlapping the previous chunk at
    // worst. A negative one is rule 3's error rather than a fallback: it is not
    // a writer quirk, it is a corrupt or hostile footer, and the rest of its
    // offsets have earned no trust either.
    let start = match column.dictionary_page_offset() {
        Some(dictionary) if dictionary < 0 => {
            return Err(ParquetError::NegativeOffset {
                column: name,
                field: "dictionary_page_offset",
                value: dictionary,
            })
        }
        Some(dictionary) if dictionary <= data_page => dictionary,
        _ => data_page,
    };
    out.push(Region {
        start: checked(start, "data_page_offset")?,
        len,
        kind: RegionKind::ColumnChunk {
            column: name.clone(),
            row_group,
        },
    });

    // Rule 5. Both structures are per-page disclosures about this column, so
    // both are attributed to it. An offset without its length is not emitted at
    // all -- the same reasoning as rule 6 -- because an extent this resolver
    // has to guess at is worse than bytes it admits it cannot classify.
    for (offset, length, field) in [
        (
            column.column_index_offset(),
            column.column_index_length(),
            "column_index_offset",
        ),
        (
            column.offset_index_offset(),
            column.offset_index_length(),
            "offset_index_offset",
        ),
    ] {
        if let (Some(offset), Some(length)) = (offset, length) {
            out.push(Region {
                start: checked(offset, field)?,
                len: checked(length.into(), field)?,
                kind: RegionKind::ColumnIndex {
                    column: name.clone(),
                },
            });
        }
    }

    // Rule 6: an offset with no length emits nothing and the bytes become
    // `Unmapped`, which denies.
    if let (Some(offset), Some(length)) =
        (column.bloom_filter_offset(), column.bloom_filter_length())
    {
        out.push(Region {
            start: checked(offset, "bloom_filter_offset")?,
            len: checked(length.into(), "bloom_filter_length")?,
            kind: RegionKind::BloomFilter { column: name },
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::{check, Decision, DenyReason};
    use crate::index::{Region, RegionKind};
    use crate::policy::{Policy, QUERYABLES};
    use serde_json::json;
    use std::path::{Path, PathBuf};

    // `::parquet` and not `parquet`: this module IS `crate::parquet`, so a bare
    // path would be ambiguous between it and the crate of the same name.
    use ::parquet::basic::{Compression, Repetition, Type as PhysicalType};
    use ::parquet::data_type::Int32Type;
    use ::parquet::file::metadata::{
        ParquetMetaDataReader, ParquetMetaDataWriter, RowGroupMetaData,
    };
    use ::parquet::file::properties::{EnabledStatistics, WriterProperties};
    use ::parquet::file::writer::SerializedFileWriter;
    use ::parquet::schema::types::Type;
    use std::sync::Arc;

    // ---- fixtures ----------------------------------------------------------

    fn repo(rel: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join(rel)
    }

    fn read(rel: &str) -> Vec<u8> {
        std::fs::read(repo(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
    }

    /// Every Parquet file committed to this repository, found by walking the
    /// directories rather than by listing names, so that a fixture added later
    /// is covered by the invariant tests without anyone remembering to add it.
    fn every_parquet_file() -> Vec<(String, Vec<u8>)> {
        let mut found = Vec::new();
        for dir in ["data", "tests/fixtures"] {
            for entry in std::fs::read_dir(repo(dir)).unwrap() {
                let path = entry.unwrap().path();
                if path.extension().is_some_and(|e| e == "parquet") {
                    let bytes = std::fs::read(&path).unwrap();
                    found.push((path.file_name().unwrap().to_string_lossy().into(), bytes));
                }
            }
        }
        found.sort_by(|a: &(String, Vec<u8>), b| a.0.cmp(&b.0));
        // The loop is only an invariant test while it actually loops over
        // something: an empty `read_dir` would make every assertion below pass.
        assert!(
            found.len() >= 4,
            "expected the committed fixtures, got {found:?}"
        );
        found
    }

    /// The whole object is a valid `footer` argument -- it is a suffix of
    /// itself -- and it is what a test has in hand.
    fn index(bytes: &[u8]) -> LayoutIndex {
        build_index(bytes, bytes.len() as u64).expect("build_index")
    }

    fn kinds_of<'a>(idx: &'a LayoutIndex, column: &str) -> Vec<&'a Region> {
        idx.regions()
            .iter()
            .filter(|r| r.column() == Some(column))
            .collect()
    }

    /// The column-chunk region for `column` in row group `group`, as
    /// `(start, end)`.
    fn chunk_in(idx: &LayoutIndex, column: &str, group: usize) -> (u64, u64) {
        let found: Vec<_> = idx
            .regions()
            .iter()
            .filter(|r| {
                matches!(&r.kind,
                    RegionKind::ColumnChunk { column: c, row_group } if c == column && *row_group == group)
            })
            .collect();
        assert_eq!(found.len(), 1, "{column} in row group {group}: {found:?}");
        (found[0].start, found[0].end())
    }

    /// The single column-chunk region for `column` in a one-row-group file.
    fn chunk(idx: &LayoutIndex, column: &str) -> (u64, u64) {
        let found: Vec<_> = idx
            .regions()
            .iter()
            .filter(|r| matches!(&r.kind, RegionKind::ColumnChunk { column: c, .. } if c == column))
            .collect();
        assert_eq!(found.len(), 1, "{column}: {found:?}");
        (found[0].start, found[0].end())
    }

    fn metadata_named<'a>(idx: &'a LayoutIndex, name: &str) -> &'a Region {
        idx.regions()
            .iter()
            .find(|r| matches!(&r.kind, RegionKind::Metadata { name: n } if n == name))
            .unwrap_or_else(|| panic!("no metadata region named {name}"))
    }

    /// Split a Parquet object into everything before the footer body and the
    /// footer body itself.
    fn split_footer(buf: &[u8]) -> (&[u8], &[u8]) {
        let len = buf.len();
        let footer_len = u32::from_le_bytes(buf[len - 8..len - 4].try_into().unwrap()) as usize;
        (
            &buf[..len - 8 - footer_len],
            &buf[len - 8 - footer_len..len - 8],
        )
    }

    /// A real fixture with its footer re-serialized after `edit` has doctored
    /// the row-group metadata.
    ///
    /// Every rejection this resolver owes an error for -- an external
    /// `file_path`, a negative offset, a bloom filter with no length -- is
    /// something no writer in the fixture toolchain emits, so the alternative
    /// to doctoring is hand-rolled thrift. This keeps the column chunks, the
    /// schema and every offset of a real file and changes exactly one field.
    fn doctored(fixture: &str, edit: impl Fn(&mut [RowGroupMetaData])) -> Vec<u8> {
        let buf = read(fixture);
        let (prefix, body) = split_footer(&buf);
        let metadata = ParquetMetaDataReader::decode_metadata(body).unwrap();
        let mut row_groups = metadata.row_groups().to_vec();
        edit(&mut row_groups);
        let metadata = metadata.into_builder().set_row_groups(row_groups).build();
        let mut out = prefix.to_vec();
        ParquetMetaDataWriter::new(&mut out, &metadata)
            .finish()
            .unwrap();
        out
    }

    /// A two-column file carrying a page index.
    ///
    /// The one synthetic input in this module, and it is here under protest:
    /// DuckDB writes every committed Parquet fixture and DuckDB does not emit
    /// a `ColumnIndex` or an `OffsetIndex` at all, so there is no real file in
    /// the repository whose page-index offsets a test could assert against.
    /// This is a genuinely formatted file written by arrow-rs, not a hand-built
    /// region set: the offsets asserted against it are read back out of its
    /// footer, not invented.
    fn with_page_index() -> Vec<u8> {
        let field = |name: &str| {
            Arc::new(
                Type::primitive_type_builder(name, PhysicalType::INT32)
                    .with_repetition(Repetition::REQUIRED)
                    .build()
                    .unwrap(),
            )
        };
        let schema = Arc::new(
            Type::group_type_builder("schema")
                .with_fields(vec![field("id"), field("secret")])
                .build()
                .unwrap(),
        );
        let props = Arc::new(
            WriterProperties::builder()
                // No codecs are compiled in: this crate takes `parquet` with
                // default features off, which is where the wasm bundle budget
                // comes from.
                .set_compression(Compression::UNCOMPRESSED)
                // Page-level statistics are what make the writer emit the
                // ColumnIndex and OffsetIndex this fixture exists for.
                .set_statistics_enabled(EnabledStatistics::Page)
                .set_bloom_filter_enabled(true)
                .build(),
        );
        let mut buf = Vec::new();
        let mut writer = SerializedFileWriter::new(&mut buf, schema, props).unwrap();
        let mut group = writer.next_row_group().unwrap();
        while let Some(mut col) = group.next_column().unwrap() {
            col.typed::<Int32Type>()
                .write_batch(&[1, 2, 3, 4], None, None)
                .unwrap();
            col.close().unwrap();
        }
        group.close().unwrap();
        writer.close().unwrap();
        buf
    }

    // ---- rule 2: the extent starts at the dictionary page ------------------

    // `dict.parquet` exists for this. `region_code` has
    // dictionary_page_offset=20804 and data_page_offset=20853: a resolver that
    // starts at the data page leaves those 49 bytes to `Unmapped` -- and for a
    // low-cardinality column the dictionary page IS the set of distinct values,
    // which is the thing a policy on that column is withholding.
    #[test]
    fn a_column_chunk_starts_at_its_dictionary_page_not_its_data_page() {
        let idx = index(&read("tests/fixtures/dict.parquet"));
        assert_eq!(chunk(&idx, "region_code"), (20804, 20981));
        // The two PLAIN columns pin the other half of the property: this is
        // "reads the dictionary offset", not "subtracts a constant".
        assert_eq!(chunk(&idx, "id"), (4, 20804));
        assert_eq!(chunk(&idx, "value"), (20981, 40921));
    }

    // ---- rule 4: the full dotted path, not the leaf ------------------------

    // `nested.parquet` carries a top-level `salary` and a nested
    // `employee.salary` as distinct chunks. A resolver that keys on the leaf
    // name gives them the same `region.column`, and then a rule written about
    // one of them silently decides the other.
    #[test]
    fn nested_columns_are_keyed_by_the_full_dotted_path() {
        let idx = index(&read("tests/fixtures/nested.parquet"));
        assert_eq!(chunk(&idx, "id"), (4, 461));
        assert_eq!(chunk(&idx, "salary"), (461, 893));
        assert_eq!(chunk(&idx, "employee.name"), (893, 1333));
        assert_eq!(chunk(&idx, "employee.salary"), (1333, 1765));
    }

    // The consequence spelled out in the language a deployment actually writes:
    // `NOT IN ('salary')` is about the top-level column and must not reach the
    // nested one.
    #[test]
    fn a_policy_denying_salary_does_not_deny_employee_salary() {
        let idx = index(&read("tests/fixtures/nested.parquet"));
        let policy = Policy::load(
            "allow:\n  - \"region.kind = 'column_chunk' AND region.column NOT IN ('salary')\"",
            QUERYABLES,
        )
        .unwrap();
        let permits = |column: &str| {
            let (start, _) = chunk(&idx, column);
            let region = idx
                .regions()
                .iter()
                .find(|r| r.start == start)
                .unwrap()
                .props();
            policy.permits(&json!({"user": {"role": "analyst"}, "region": region}))
        };
        assert!(!permits("salary"));
        assert!(permits("employee.salary"));
        assert!(permits("employee.name"));
    }

    // ---- row groups --------------------------------------------------------

    // `multi-rg.parquet` is 6 row groups x 3 columns, the last one short. A
    // resolver that derived extents from a fixed rows-per-group instead of from
    // the footer gets the last group wrong.
    #[test]
    fn every_chunk_carries_the_row_group_it_belongs_to() {
        let idx = index(&read("tests/fixtures/multi-rg.parquet"));
        let mut seen: Vec<(usize, String)> = idx
            .regions()
            .iter()
            .filter_map(|r| match &r.kind {
                RegionKind::ColumnChunk { column, row_group } => Some((*row_group, column.clone())),
                _ => None,
            })
            .collect();
        seen.sort();
        assert_eq!(seen.len(), 18, "6 row groups x 3 columns");
        for group in 0..6 {
            let columns: Vec<_> = seen
                .iter()
                .filter(|(g, _)| *g == group)
                .map(|(_, c)| c.as_str())
                .collect();
            assert_eq!(columns, ["doubled", "id", "label"], "row group {group}");
        }
        // Chunks are in file order and row groups do not interleave.
        let starts: Vec<_> = idx
            .regions()
            .iter()
            .filter_map(|r| match &r.kind {
                RegionKind::ColumnChunk { row_group, .. } => Some(*row_group),
                _ => None,
            })
            .collect();
        let mut sorted = starts.clone();
        sorted.sort();
        assert_eq!(starts, sorted);
    }

    // ---- rule 5: the page index and bloom filters belong to their column ---

    // Both sit OUTSIDE `total_compressed_size`, so a resolver that maps only
    // column chunks leaves them unclassified. `Unmapped` denies, which is safe
    // -- but a `ColumnIndex` carries per-page min/max and null counts and an
    // `OffsetIndex` per-page row counts, so they are a leak of the column's
    // contents and must answer to a rule about THAT column, not to a blanket
    // metadata allow.
    #[test]
    fn bloom_filters_are_attributed_to_their_column() {
        let idx = index(&read("tests/fixtures/dict.parquet"));
        let regions = kinds_of(&idx, "region_code");
        let bloom: Vec<_> = regions
            .iter()
            .filter(|r| matches!(r.kind, RegionKind::BloomFilter { .. }))
            .collect();
        assert_eq!(bloom.len(), 1);
        assert_eq!((bloom[0].start, bloom[0].end()), (40921, 40968));
        // Not metadata, and not swallowed by the footer region.
        assert_eq!(bloom[0].props()["kind"], "bloom_filter");
        assert_eq!(bloom[0].props()["column"], "region_code");
    }

    #[test]
    fn page_index_regions_are_attributed_to_their_column() {
        let buf = with_page_index();
        let idx = index(&buf);
        let (_, body) = split_footer(&buf);
        let metadata = ParquetMetaDataReader::decode_metadata(body).unwrap();
        let mut expected: Vec<(u64, u64, String)> = Vec::new();
        for column in metadata.row_groups()[0].columns() {
            let name = column.column_path().string();
            for (offset, length) in [
                (column.column_index_offset(), column.column_index_length()),
                (column.offset_index_offset(), column.offset_index_length()),
            ] {
                let (offset, length) = (offset.unwrap(), length.unwrap());
                expected.push((offset as u64, offset as u64 + length as u64, name.clone()));
            }
        }
        // The fixture is only evidence if the writer really emitted a page
        // index for both columns.
        assert_eq!(expected.len(), 4);

        let mut got: Vec<(u64, u64, String)> = idx
            .regions()
            .iter()
            .filter_map(|r| match &r.kind {
                RegionKind::ColumnIndex { column } => Some((r.start, r.end(), column.clone())),
                _ => None,
            })
            .collect();
        got.sort();
        expected.sort();
        assert_eq!(got, expected);
    }

    // ---- rule 8: named metadata, never a fallback --------------------------

    #[test]
    fn the_magic_and_the_footer_trailer_are_named_metadata_regions() {
        for (name, bytes) in every_parquet_file() {
            let idx = index(&bytes);
            let size = bytes.len() as u64;
            let magic = metadata_named(&idx, "magic");
            assert_eq!((magic.start, magic.end()), (0, 4), "{name}");
            let trailer = metadata_named(&idx, "footer_trailer");
            assert_eq!((trailer.start, trailer.end()), (size - 8, size), "{name}");
            let footer = metadata_named(&idx, "footer");
            let (prefix, body) = split_footer(&bytes);
            assert_eq!(
                (footer.start, footer.end()),
                (prefix.len() as u64, (prefix.len() + body.len()) as u64),
                "{name}"
            );
        }
    }

    // `Metadata` must NEVER be a fallback classification: a blanket
    // `region.kind = 'metadata'` allow plus a catch-all is a wildcard over the
    // bytes the resolver understood least. So the set of metadata names is
    // closed, and everything else the resolver did not recognize is `Unmapped`.
    #[test]
    fn metadata_names_are_a_closed_set() {
        for (file, bytes) in every_parquet_file() {
            for region in index(&bytes).regions() {
                if let RegionKind::Metadata { name } = &region.kind {
                    assert!(
                        ["magic", "footer", "footer_trailer"].contains(&name.as_str()),
                        "{file}: unexpected metadata name {name}"
                    );
                }
            }
        }
    }

    // ---- the invariant that closes the unmapped-range bypass ---------------

    // Under a conjunctive decision, a byte belonging to no region is authorized
    // by the empty-set convention. `LayoutIndex::try_new` fills the gaps, so
    // this asserts what the resolver hands it does not make that impossible --
    // and it runs over every real file in the repository, in a loop, so a
    // fixture added later is covered without anyone remembering to add it.
    #[test]
    fn coverage_is_total_for_every_parquet_file_in_the_repo() {
        for (file, bytes) in every_parquet_file() {
            let size = bytes.len() as u64;
            let idx = index(&bytes);
            let mut cursor = 0u64;
            let mut unmapped = 0u64;
            for region in idx.regions() {
                assert_eq!(region.start, cursor, "{file}: hole before {}", region.start);
                if matches!(region.kind, RegionKind::Unmapped) {
                    unmapped += region.len;
                }
                cursor = region.end();
            }
            assert_eq!(cursor, size, "{file}: coverage stops short");
            assert_eq!(idx.size(), size, "{file}");
            // Total coverage is satisfied by classifying NOTHING at all --
            // `LayoutIndex::try_new` would fill the whole object with one
            // `Unmapped` region and every assertion above would pass. So pin
            // the other half: the classified bytes must be the bulk of the
            // file. Measured today, every committed fixture comes out at
            // exactly zero unmapped bytes (DuckDB pads nothing), but a writer
            // that aligns its row groups would leave real gaps; 5% is room for
            // that and no room for a resolver that dropped a column.
            assert!(
                unmapped * 20 < size,
                "{file}: {unmapped} of {size} bytes unmapped"
            );
        }
    }

    // ---- one read, not two -------------------------------------------------

    // The page index and the bloom filters live outside the footer, but their
    // offsets and lengths live INSIDE it, so classifying them needs no second
    // read: we need to know where they are, not what they contain. This is the
    // claim the caller's read pattern rests on, so it is asserted against a
    // real file with a tail read that provably does not reach them.
    #[test]
    fn a_tail_read_that_covers_only_the_footer_classifies_the_whole_object() {
        let bytes = read("data/nyc-taxi-8rg.parquet");
        let size = bytes.len() as u64;
        let tail = 64 * 1024;
        let idx = build_index(&bytes[bytes.len() - tail..], size).unwrap();
        let window_start = size - tail as u64;

        let blooms: Vec<_> = idx
            .regions()
            .iter()
            .filter(|r| matches!(r.kind, RegionKind::BloomFilter { .. }))
            .collect();
        assert_eq!(blooms.len(), 136, "17 of 19 columns x 8 row groups");
        assert!(
            blooms.iter().any(|r| r.start < window_start),
            "no bloom filter outside the read window: the test proves nothing"
        );
        // ...and the classification is identical to the one a whole-object read
        // produces, which is the property that lets a caller read only the tail.
        assert_eq!(idx.regions(), index(&bytes).regions());
    }

    // A buffer that stops short of the footer body cannot be classified, and
    // the error says how many bytes from the end would be enough -- so a caller
    // that guessed its tail read too small can retry instead of giving up.
    #[test]
    fn a_buffer_shorter_than_the_footer_asks_for_the_bytes_it_needs() {
        let bytes = read("data/nyc-taxi-8rg.parquet");
        let size = bytes.len() as u64;
        let (prefix, body) = split_footer(&bytes);
        let needed = body.len() as u64 + 8;
        let short = &bytes[prefix.len() + 16..];
        match build_index(short, size) {
            Err(ParquetError::Truncated { needed: n }) => assert_eq!(n, needed),
            other => panic!("expected Truncated, got {other:?}"),
        }
        // One byte more than `needed` is enough, and exactly `needed` is too.
        assert!(build_index(&bytes[bytes.len() - needed as usize..], size).is_ok());
    }

    // ---- rule 7 and rule 9: files this resolver must refuse ----------------

    // `ColumnChunk.file_path` means the chunk lives in ANOTHER object, so every
    // offset in this footer describes bytes that are not in the object being
    // authorized. Mapping them anyway would attach a column's name to whatever
    // happens to sit at that offset here.
    #[test]
    fn a_chunk_stored_in_another_object_is_rejected() {
        let external = doctored("tests/fixtures/multi-rg.parquet", |row_groups| {
            let column = &mut row_groups[0].columns_mut()[1];
            *column = column
                .clone()
                .into_builder()
                .set_file_path("elsewhere.parquet".into())
                .build()
                .unwrap();
        });
        assert!(matches!(
            build_index(&external, external.len() as u64),
            Err(ParquetError::ExternalData { .. })
        ));
        // The same bytes without the doctoring: the assertion above must fail
        // for the file_path and not for the re-serialization.
        let clean = doctored("tests/fixtures/multi-rg.parquet", |_| {});
        assert!(build_index(&clean, clean.len() as u64).is_ok());
    }

    // A `PARE` trailer is an encrypted footer: the thrift is unreadable and
    // every offset with it. Out of scope, and out of scope must mean an error
    // rather than a partial classification (tracked as #7).
    #[test]
    fn an_encrypted_footer_is_rejected() {
        let mut bytes = read("tests/fixtures/dict.parquet");
        let len = bytes.len();
        bytes[len - 4..].copy_from_slice(b"PARE");
        assert!(matches!(
            build_index(&bytes, len as u64),
            Err(ParquetError::EncryptedFooter)
        ));
    }

    // arrow-rs's `ColumnChunkMetaData::byte_range()` asserts on a negative
    // offset, and this crate compiles to wasm32 where a panic aborts the module
    // instance -- an availability bug for every request that worker would have
    // served. So the fields are read directly and a negative one is an error.
    #[test]
    fn a_negative_offset_is_an_error_and_not_a_panic() {
        for doctor in [
            |c: ::parquet::file::metadata::ColumnChunkMetaDataBuilder| c.set_data_page_offset(-1),
            |c: ::parquet::file::metadata::ColumnChunkMetaDataBuilder| {
                c.set_dictionary_page_offset(Some(-4096))
            },
            |c: ::parquet::file::metadata::ColumnChunkMetaDataBuilder| {
                c.set_total_compressed_size(-8)
            },
            |c: ::parquet::file::metadata::ColumnChunkMetaDataBuilder| {
                c.set_column_index_offset(Some(-1))
                    .set_column_index_length(Some(8))
            },
            |c: ::parquet::file::metadata::ColumnChunkMetaDataBuilder| {
                c.set_bloom_filter_offset(Some(-1))
                    .set_bloom_filter_length(Some(8))
            },
        ] {
            let bytes = doctored("tests/fixtures/dict.parquet", |row_groups| {
                let column = &mut row_groups[0].columns_mut()[0];
                *column = doctor(column.clone().into_builder()).build().unwrap();
            });
            let result = build_index(&bytes, bytes.len() as u64);
            assert!(
                matches!(result, Err(ParquetError::NegativeOffset { .. })),
                "{result:?}"
            );
        }
    }

    // ---- rule 2's other half, and rule 6 -----------------------------------

    // Some writers emit a dictionary page offset that is not where the
    // dictionary page is. Believing one that sits after the data page would
    // move the chunk's start forward and leave the pages before it unmapped --
    // or, worse, overlap the previous chunk. The offset is used only when it
    // is where a dictionary page could be.
    #[test]
    fn a_dictionary_offset_after_the_data_page_is_not_believed() {
        // `id` is PLAIN-encoded and has no dictionary page at all: its chunk is
        // 4..20804. A writer that stamps a nonzero dictionary offset on it
        // anyway would move the start to 10000 and carry the full
        // `total_compressed_size` from there, past the end of the chunk and
        // into the two columns that follow.
        let bytes = doctored("tests/fixtures/dict.parquet", |row_groups| {
            let column = &mut row_groups[0].columns_mut()[0];
            *column = column
                .clone()
                .into_builder()
                .set_dictionary_page_offset(Some(10_000))
                .build()
                .unwrap();
        });
        let idx = build_index(&bytes, bytes.len() as u64).unwrap();
        assert_eq!(chunk(&idx, "id"), (4, 20804));

        // And when a bogus offset leaves the footer inconsistent with itself --
        // here `region_code`'s dictionary moved past its own data page, so the
        // fallback extent runs into the next column -- the whole index is
        // refused rather than the offending chunk trimmed or dropped. A dropped
        // chunk is a hole that `Unmapped` would deny, but it would also hide
        // that the file was lying.
        let inconsistent = doctored("tests/fixtures/dict.parquet", |row_groups| {
            let column = &mut row_groups[0].columns_mut()[1];
            *column = column
                .clone()
                .into_builder()
                // `region_code`'s data page is at 20853.
                .set_dictionary_page_offset(Some(20_900))
                .build()
                .unwrap();
        });
        assert!(matches!(
            build_index(&inconsistent, inconsistent.len() as u64),
            Err(ParquetError::Layout(IndexError::Overlap(_)))
        ));
    }

    // Recovering a bloom filter's length needs a `BloomFilterHeader` parse at
    // its offset, which is a second read this resolver does not make. Emitting
    // a region of guessed length would be worse than emitting none: the bytes
    // fall to `Unmapped` instead, which denies. Safe but blunt -- tracked as #7.
    #[test]
    fn a_bloom_filter_with_no_length_is_left_unmapped() {
        let bytes = doctored("tests/fixtures/dict.parquet", |row_groups| {
            let column = &mut row_groups[0].columns_mut()[1];
            *column = column
                .clone()
                .into_builder()
                .set_bloom_filter_length(None)
                .build()
                .unwrap();
        });
        let idx = build_index(&bytes, bytes.len() as u64).unwrap();
        assert!(idx
            .regions()
            .iter()
            .all(|r| !matches!(r.kind, RegionKind::BloomFilter { .. })));
        // 40921 is where that bloom filter starts. Nothing claims it, so it is
        // unmapped -- and unmapped answers to no policy anyone can write.
        let at = idx.resolve(&(40921..40922));
        assert_eq!(at.len(), 1);
        assert!(matches!(at[0].kind, RegionKind::Unmapped));
    }

    // ---- malformed input fails closed rather than panicking ----------------

    // Every one of these is a footer an attacker can serve. The assertion is
    // `is_err()`, but the property being defended is that the call RETURNS:
    // a panic here aborts the wasm module instance, and a test that panicked
    // would fail rather than pass.
    #[test]
    fn a_truncated_or_corrupt_footer_fails_closed() {
        let whole = read("tests/fixtures/dict.parquet");
        let size = whole.len() as u64;

        // Truncated objects: the object really is `n` bytes long.
        for n in [0, 1, 4, 7, 8, 11, 12, 100, 20804, 40968, 41340, 41348] {
            let bytes = &whole[..n];
            assert!(build_index(bytes, n as u64).is_err(), "truncated to {n}");
        }
        // Whole object, but the buffer handed in stops short of the footer.
        for n in [1, 8, 9, 100, 373, 380] {
            let bytes = &whole[whole.len() - n..];
            let result = build_index(bytes, size);
            assert!(result.is_err(), "tail of {n} bytes: {result:?}");
        }
        // A footer length that lies, in both directions.
        for lie in [0u32, 1, 7, 372, 374, 40_000, u32::MAX, u32::MAX - 8] {
            let mut bytes = whole.clone();
            let at = bytes.len() - 8;
            bytes[at..at + 4].copy_from_slice(&lie.to_le_bytes());
            assert!(build_index(&bytes, size).is_err(), "footer length {lie}");
        }
        // A trailer that is not a Parquet trailer at all.
        for magic in [b"PAR2", b"par1", b"\0\0\0\0"] {
            let mut bytes = whole.clone();
            let at = bytes.len() - 4;
            bytes[at..].copy_from_slice(magic);
            assert!(build_index(&bytes, size).is_err(), "{magic:?}");
        }
        // Thrift the decoder has to refuse: one byte of the footer body
        // flipped, at a spread of positions.
        let (prefix, body) = split_footer(&whole);
        for at in [0, 1, 7, 32, 77, 150, body.len() - 2, body.len() - 1] {
            let mut bytes = whole.clone();
            bytes[prefix.len() + at] ^= 0xff;
            // Corrupting a byte may leave a decodable footer; what it must
            // never do is panic, and it must never widen coverage.
            if let Ok(idx) = build_index(&bytes, size) {
                assert_eq!(idx.size(), size);
            }
        }
    }

    // The buffer must be a suffix of the object it describes. A caller that
    // passed the head of the file, or an object size smaller than the buffer,
    // has an index describing bytes that are not there.
    #[test]
    fn a_buffer_that_is_not_a_suffix_of_the_object_is_rejected() {
        let whole = read("tests/fixtures/dict.parquet");
        let size = whole.len() as u64;
        assert!(build_index(&whole, size - 1).is_err());
        assert!(build_index(&whole, 0).is_err());
        // The head of a Parquet file ends in data, not in a trailer.
        assert!(build_index(&whole[..1024], size).is_err());
    }

    // ---- end to end, against a real file -----------------------------------

    // The whole stack -- footer, index, policy, decision -- over a 8.4 MB file
    // from the NYC TLC. A policy that denies one real column must deny a range
    // over that column's chunk and authorize one over a permitted column's.
    #[test]
    fn a_real_file_denies_the_denied_column_and_authorizes_the_others() {
        let bytes = read("data/nyc-taxi-8rg.parquet");
        let idx = index(&bytes);
        let policy = Policy::load(
            "allow:\n  - \"region.kind = 'metadata'\"\n  \
             - \"region.kind = 'column_chunk' AND region.column <> 'total_amount'\"",
            QUERYABLES,
        )
        .unwrap();
        let user = json!({"role": "analyst"});

        let header = |(start, end): (u64, u64)| format!("bytes={start}-{}", end - 1);
        let denied = Decision::Denied {
            reason: DenyReason::NotPermitted,
        };

        // Every one of the eight row groups holds a chunk of the protected
        // column, and every one of them is denied.
        for group in 0..8 {
            let secret = chunk_in(&idx, "total_amount", group);
            assert_eq!(
                check(&idx, &policy, &user, Some(&header(secret))),
                denied,
                "row group {group}"
            );
        }
        let secret = chunk_in(&idx, "total_amount", 0);

        let public = chunk_in(&idx, "trip_distance", 0);
        assert_eq!(
            check(&idx, &policy, &user, Some(&header(public))),
            Decision::Authorized {
                canonical: public.0..public.1
            }
        );

        // A range that reaches ONE byte into the protected chunk is denied,
        // however much of it was permitted: the decision is conjunctive. This
        // is the coalesced read a real reader issues, and it is the range the
        // whole design exists to answer.
        assert_eq!(
            check(
                &idx,
                &policy,
                &user,
                Some(&format!("bytes={}-{}", secret.0 - 1, secret.0))
            ),
            denied
        );
        // The bloom filter for the protected column is NOT a column chunk and
        // NOT metadata, so the metadata rule does not reach it either.
        let bloom = idx
            .regions()
            .iter()
            .find(|r| {
                matches!(&r.kind, RegionKind::BloomFilter { column } if column == "total_amount")
            })
            .unwrap();
        assert_eq!(
            check(
                &idx,
                &policy,
                &user,
                Some(&header((bloom.start, bloom.end())))
            ),
            denied
        );
        // And the whole object, which is the retry a reader makes after a 403.
        assert_eq!(check(&idx, &policy, &user, None), denied);
    }
}
