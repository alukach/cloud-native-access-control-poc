//! The sorted, gap-free map from byte extents to logical regions.
//!
//! # Why coverage is total by construction
//!
//! The decision rule this index feeds is conjunctive: *every region overlapping
//! the requested range must satisfy the policy*. In Rust that is
//! `regions.iter().all(..)` -- and `[].iter().all(..)` is `true`. So a byte
//! that belongs to no region is not "unauthorized by default", it is
//! **authorized**, silently, by the empty-set convention.
//!
//! Bytes that belong to nothing are the normal case, not a corner case. A
//! Parquet file has the 4-byte `PAR1` magic at each end, the footer length
//! trailer, inter-chunk padding, page index structures and bloom filter pages,
//! none of which a column-chunk resolver claims. A COG has the GDAL ghost area
//! and out-of-line tag arrays. A *striped* (non-tiled) GeoTIFF has no
//! `TileOffsets` tag at all, so a tile resolver claims nothing whatsoever and
//! the entire image would be readable by an `all()` over an empty set.
//!
//! Rather than assert total coverage in a test and hope every future resolver
//! upholds it, [`LayoutIndex::try_new`] *fills every gap* with
//! [`RegionKind::Unmapped`]. The invariant is then a property of the only
//! constructor rather than a property of each caller: the `regions` field is
//! private, nothing else writes it, so every `LayoutIndex` in existence covers
//! `[0, size)` exactly once.
//!
//! `Unmapped` is deliberately its own kind and not `Metadata { name: "other" }`.
//! A blanket `region.kind = 'metadata'` allow is a policy people really write;
//! if unrecognized bytes classified as metadata, that rule would become a
//! wildcard over everything the resolver failed to understand -- which is
//! exactly the set of bytes we understand least.
//!
//! # The empty range is the same bug wearing a different hat
//!
//! Total coverage removes empty results for every *non-empty* range. It cannot
//! remove them for an empty one: `0..0` overlaps no bytes, so it honestly
//! resolves to no regions, and `all()` over that is `true` again. Task 2's
//! parser returns exactly `0..0` for `parse(None, 0)` -- a zero-byte object
//! with no `Range` header -- so this value is reachable from the wire.
//! [`LayoutIndex::resolve`] is the raw geometric query and returns the empty
//! slice for it; [`LayoutIndex::try_resolve`] refuses it, and refuses ranges
//! reaching past `size`, so that a decision path can be written without an
//! emptiness check the author must remember to add.

use serde_json::{json, Value};
use std::ops::Range;

/// What a byte extent *is*. Kinds are the vocabulary policies match on, so
/// every variant is a promise about what bytes it can name.
#[derive(Debug, Clone, PartialEq)]
pub enum RegionKind {
    /// A named, specific metadata extent. NEVER a fallback: a blanket
    /// `region.kind = 'metadata'` allow plus a catch-all classification is a
    /// wildcard. Unrecognized bytes are [`RegionKind::Unmapped`], not
    /// `Metadata`.
    Metadata { name: String },
    /// Bytes belonging to nothing known. No policy can match this: its props
    /// carry no column, no coordinates, no name -- nothing to write a rule
    /// against. Under a conjunctive decision that makes any range touching
    /// unclassified bytes a denial, which is the entire point.
    Unmapped,
    ColumnChunk { column: String, row_group: usize },
    ColumnIndex { column: String },
    BloomFilter { column: String },
    Tile {
        overview_level: u32,
        x: u32,
        y: u32,
        bbox: [f64; 4],
        crs: Option<u32>,
    },
}

/// A half-open byte extent `[start, start + len)` with a meaning attached.
///
/// `PartialEq` and not `Eq` because `Tile` holds `f64`. That is not merely a
/// derive technicality: with a NaN in the bbox a `Region` is not equal to
/// itself, which would quietly break any dedup or `assert_eq!` written against
/// it. [`LayoutIndex::try_new`] rejects non-finite bboxes, so equality is
/// reflexive for every region that reaches an index; regions built by hand and
/// never indexed are the caller's problem.
#[derive(Debug, Clone, PartialEq)]
pub struct Region {
    pub start: u64,
    pub len: u64,
    pub kind: RegionKind,
}

impl Region {
    /// The exclusive end, saturating at `u64::MAX`.
    ///
    /// `start + len` would panic in debug and *wrap* in release, and both
    /// operands come from a file footer an attacker may control. A wrapped end
    /// is the dangerous outcome: a region at `start = u64::MAX - 1` with
    /// `len = 4` would report `end() == 2`, which passes an `end() <= size`
    /// bounds check, sorts as if it were at the front of the object, and turns
    /// the sorted/non-overlapping invariant that [`LayoutIndex::resolve`]'s
    /// binary searches rely on into a lie. Saturating keeps `end()` monotone in
    /// `len` so a bounds check on it always fails closed; `try_new` still
    /// rejects the overflow outright, because saturation alone would let such a
    /// region through when `size == u64::MAX`.
    pub fn end(&self) -> u64 {
        self.start.saturating_add(self.len)
    }

    pub fn column(&self) -> Option<&str> {
        match &self.kind {
            RegionKind::ColumnChunk { column, .. }
            | RegionKind::ColumnIndex { column }
            | RegionKind::BloomFilter { column } => Some(column),
            _ => None,
        }
    }

    /// The CQL2 evaluation context for this region, built lazily -- only for
    /// the regions a request actually overlaps, never for the whole index.
    ///
    /// Scalars plus one whitelisted geometry, never nested file-derived JSON:
    /// cql2's `Expr::try_from` is untagged, so a props value shaped like
    /// `{"property": ...}` or `{"op": ...}` becomes an AST node rather than
    /// data. A file whose column was named `op` could otherwise smuggle
    /// structure into the expression tree.
    ///
    /// Never emit `null`. Absent and null are indistinguishable to cql2, and
    /// comparing against a present null errors rather than evaluating to false,
    /// so a null turns a policy that should deny into a policy that fails --
    /// and how a caller maps a failure is one refactor away from an allow.
    pub fn props(&self) -> Value {
        match &self.kind {
            RegionKind::Metadata { name } => json!({"kind":"metadata","name":name}),
            RegionKind::Unmapped => json!({"kind":"unmapped"}),
            RegionKind::ColumnChunk { column, row_group } => {
                json!({"kind":"column_chunk","column":column,"row_group":row_group})
            }
            RegionKind::ColumnIndex { column } => {
                json!({"kind":"column_index","column":column})
            }
            RegionKind::BloomFilter { column } => {
                json!({"kind":"bloom_filter","column":column})
            }
            RegionKind::Tile {
                overview_level,
                x,
                y,
                bbox,
                crs,
            } => {
                let mut v = json!({
                    "kind":"tile","overview_level":overview_level,"x":x,"y":y,
                });
                // Non-finite coordinates are rejected at construction, so this
                // is unreachable for an indexed region; `Region` is publicly
                // constructible, though, and serde_json serializes NaN and
                // infinity as `null`. A geometry whose coordinates are nulls is
                // strictly worse than no geometry: it violates the no-null rule
                // from inside a nested array where a reviewer will not see it.
                // Omitting both spatial keys leaves a spatial policy unable to
                // match, which under a conjunctive decision is a denial.
                if bbox.iter().all(|c| c.is_finite()) {
                    // Normalize before emitting. A north-up raster's geo
                    // transform has a negative y pixel size, so a resolver that
                    // computes `ymin` from the top edge hands us ymin > ymax.
                    // The point set of the rectangle is the same either way,
                    // but the emitted `bbox` object would be invalid per the
                    // CQL2 bbox form and the ring would wind backwards.
                    let (xmin, xmax) = (bbox[0].min(bbox[2]), bbox[0].max(bbox[2]));
                    let (ymin, ymax) = (bbox[1].min(bbox[3]), bbox[1].max(bbox[3]));
                    // A bare array is NOT a CQL2 spatial operand: untagged
                    // deserialization matches it as Array and S_INTERSECTS
                    // silently fails to reduce. Emit a geometry and the object
                    // bbox form. The ring is counter-clockwise and closed --
                    // first point repeated last -- because an unclosed ring is
                    // not a valid GeoJSON polygon and parsers disagree about
                    // whether to reject it or to close it for you.
                    v["geom"] = json!({"type":"Polygon","coordinates":[[
                        [xmin,ymin],[xmax,ymin],[xmax,ymax],[xmin,ymax],[xmin,ymin]]]});
                    v["bbox"] = json!({ "bbox": [xmin, ymin, xmax, ymax] });
                }
                // Absent, not null: see the no-null rule above.
                if let Some(c) = crs {
                    v["crs"] = json!(c);
                }
                v
            }
        }
    }
}

/// A malformed region set. Every variant means the resolver that produced the
/// regions has a bug, or the file it read was crafted to give it one -- there
/// is no input a correct resolver can produce that lands here.
#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum IndexError {
    /// Two regions claim the same byte. Not merged, not tolerated: overlapping
    /// regions mean one of them is wrong about what it is, and a byte carrying
    /// two contradictory classifications cannot be authorized honestly.
    #[error("regions overlap at byte {0}")]
    Overlap(u64),
    #[error("region ends at {end}, past the end of the {size}-byte object")]
    PastEof { end: u64, size: u64 },
    /// `start + len` does not fit in a `u64`. Kept distinct from `PastEof`
    /// because `PastEof` cannot catch it when `size == u64::MAX`.
    #[error("region at {start} with length {len} overflows a u64")]
    Overflow { start: u64, len: u64 },
    /// A tile bbox containing NaN or an infinity. serde_json renders those as
    /// `null`, and the no-null rule on [`Region::props`] is load-bearing.
    ///
    /// The offending region is named by its `start` rather than by its bbox on
    /// purpose. An error carrying the `[f64; 4]` cannot derive `Eq`, and worse,
    /// its derived `PartialEq` would compare NaN against NaN and answer
    /// `false` -- so the error would not equal itself, and every test or
    /// dedup written against it would silently never match.
    #[error("tile bbox at byte {start} is not finite")]
    NonFiniteBbox { start: u64 },
}

/// Why a range could not be resolved into a set of regions to authorize.
#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum ResolveError {
    /// The range covers no bytes, so there is nothing to authorize and the
    /// conjunctive decision would be vacuously true. Reachable from the wire:
    /// `range::parse(None, 0)` returns `0..0` for a zero-byte object.
    #[error("range is empty or inverted")]
    EmptyRange,
    /// The range reaches past the object the index was built for. Task 2's
    /// parser clamps to the size it was given, so this means the size used to
    /// parse and the size used to index disagree -- and bytes past the indexed
    /// end are covered by no region at all.
    #[error("range ends at {end}, past the end of the {size}-byte object")]
    PastEof { end: u64, size: u64 },
}

/// The regions of one object, sorted, non-overlapping, and covering
/// `[0, size)` with no holes.
#[derive(Debug, Clone)]
pub struct LayoutIndex {
    regions: Vec<Region>,
    size: u64,
}

impl LayoutIndex {
    /// Panics on a malformed region set.
    ///
    /// For tests and for region sets that are correct by inspection at the call
    /// site. **Every path that begins with parsed file bytes must use
    /// [`LayoutIndex::try_new`]**, and not out of style preference: this crate
    /// compiles to wasm32, where the panic runtime aborts. There is no unwind
    /// to catch, the module instance is poisoned, and a gateway that hosts one
    /// instance per worker turns a malformed footer into an availability bug
    /// for every request that worker would have served. A `Result` at the parse
    /// boundary costs one `?`.
    #[track_caller]
    #[must_use]
    pub fn new(regions: Vec<Region>, size: u64) -> Self {
        Self::try_new(regions, size).expect("resolver produced a malformed region set")
    }

    /// Sorts, rejects malformed input, and fills every gap with
    /// [`RegionKind::Unmapped`] so that coverage of `[0, size)` is total BY
    /// CONSTRUCTION.
    pub fn try_new(mut regions: Vec<Region>, size: u64) -> Result<Self, IndexError> {
        // Zero-length regions are dropped rather than rejected, because they
        // are legitimate: a sparse tiled GeoTIFF (GDAL's SPARSE_OK) records an
        // undefined tile as offset 0, byte count 0. Dropping is also the safer
        // reading of them. Kept, such a tile would sort to the front and be
        // returned by `resolve` for any range starting at byte 0, attaching
        // that tile's coordinates -- and any policy written about them -- to
        // the first byte of the file header. A tile that occupies no bytes can
        // never be requested, so it has nothing to say about authorization.
        regions.retain(|r| r.len > 0);
        // Stable sort: equal starts keep the resolver's order, so the byte
        // reported by `Overlap` is deterministic across runs and platforms.
        // Two regions sharing a start are caught whichever order they land in,
        // since the second one's start is then strictly below the cursor the
        // first one advanced.
        regions.sort_by_key(|r| r.start);

        let mut out = Vec::with_capacity(regions.len() * 2 + 1);
        let mut cursor = 0u64;
        for r in regions {
            // Checked, not `end()`: saturation would let a region through when
            // `size == u64::MAX`, and every later invariant -- sortedness,
            // non-overlap, the monotonicity the binary searches need -- assumes
            // the extent is real.
            let end = r.start.checked_add(r.len).ok_or(IndexError::Overflow {
                start: r.start,
                len: r.len,
            })?;
            if end > size {
                return Err(IndexError::PastEof { end, size });
            }
            if let RegionKind::Tile { bbox, .. } = &r.kind {
                if !bbox.iter().all(|c| c.is_finite()) {
                    return Err(IndexError::NonFiniteBbox(*bbox));
                }
            }
            if r.start < cursor {
                return Err(IndexError::Overlap(r.start));
            }
            if r.start > cursor {
                out.push(Region {
                    start: cursor,
                    len: r.start - cursor,
                    kind: RegionKind::Unmapped,
                });
            }
            cursor = end;
            out.push(r);
        }
        // The trailing gap, and the whole object when the resolver produced
        // nothing at all -- a striped GeoTIFF handed to a tile resolver.
        if cursor < size {
            out.push(Region {
                start: cursor,
                len: size - cursor,
                kind: RegionKind::Unmapped,
            });
        }
        Ok(Self { regions: out, size })
    }

    /// Every region, in order, covering `[0, size)` exactly once.
    pub fn regions(&self) -> &[Region] {
        &self.regions
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    /// Every region overlapping the half-open `range`.
    ///
    /// The raw geometric query, with no opinion about whether the answer is
    /// usable. **An empty result is not an allow.** For any non-empty range
    /// within `[0, size)` the result is non-empty by construction, so the two
    /// ways to get an empty slice back are an empty range and a range entirely
    /// past `size` -- and a decision written as `resolve(r).iter().all(..)`
    /// answers `true` for both. Use [`LayoutIndex::try_resolve`] anywhere the
    /// result feeds an authorization decision; use this one for diagnostics,
    /// or after checking the range yourself.
    ///
    /// Both binary searches need their predicate to hold on a prefix of the
    /// slice and nowhere after it. `try_new` leaves `start` strictly increasing
    /// and `end()` strictly increasing (regions are contiguous, non-empty and
    /// non-overlapping), so `r.end() <= range.start` and `r.start < range.end`
    /// are each a threshold on a strictly increasing sequence. Zero-length
    /// regions -- the one thing that could make either sequence merely
    /// non-decreasing -- were dropped before the scan.
    #[must_use]
    pub fn resolve(&self, range: &Range<u64>) -> &[Region] {
        if range.start >= range.end {
            return &[];
        }
        // First region whose end is strictly past range.start: a region ending
        // exactly at range.start shares no byte with it. This is the
        // off-by-one the `boundaries_are_exact` test exists to pin -- widen it
        // by one and a range ending at a boundary starts dragging in the next
        // region; narrow it and the last byte of a request goes unauthorized.
        let first = self.regions.partition_point(|r| r.end() <= range.start);
        // One past the last region starting strictly before range.end.
        let last = self.regions.partition_point(|r| r.start < range.end);
        &self.regions[first..last]
    }

    /// [`LayoutIndex::resolve`], refusing the ranges whose answer would be
    /// vacuous.
    ///
    /// A successful result is always non-empty, so `all()` over it is a real
    /// quantification rather than an empty-set convention. The refusals are
    /// denials, not errors to paper over: an empty range authorizes nothing
    /// because it *asks* for nothing, and a range past the indexed end asks for
    /// bytes this index cannot classify.
    #[must_use = "an unchecked resolve result is the empty-set allow this method exists to prevent"]
    pub fn try_resolve(&self, range: &Range<u64>) -> Result<&[Region], ResolveError> {
        if range.start >= range.end {
            return Err(ResolveError::EmptyRange);
        }
        if range.end > self.size {
            return Err(ResolveError::PastEof {
                end: range.end,
                size: self.size,
            });
        }
        Ok(self.resolve(range))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chunk(start: u64, len: u64, col: &str) -> Region {
        Region {
            start,
            len,
            kind: RegionKind::ColumnChunk {
                column: col.into(),
                row_group: 0,
            },
        }
    }

    fn tile(bbox: [f64; 4]) -> Region {
        Region {
            start: 0,
            len: 10,
            kind: RegionKind::Tile {
                overview_level: 0,
                x: 1,
                y: 2,
                bbox,
                crs: Some(4326),
            },
        }
    }

    #[test]
    fn gaps_are_filled_with_unmapped() {
        // 0..10 chunk, 10..20 hole, 20..30 chunk, 30..100 hole
        let idx = LayoutIndex::new(vec![chunk(0, 10, "a"), chunk(20, 10, "b")], 100);
        assert_eq!(idx.regions().len(), 4);
        assert!(matches!(idx.regions()[1].kind, RegionKind::Unmapped));
        assert_eq!(idx.regions()[1].start..idx.regions()[1].end(), 10..20);
        assert!(matches!(idx.regions()[3].kind, RegionKind::Unmapped));
        assert_eq!(idx.regions()[3].start..idx.regions()[3].end(), 30..100);
    }

    #[test]
    fn coverage_is_total() {
        let idx = LayoutIndex::new(vec![chunk(5, 10, "a"), chunk(40, 10, "b")], 100);
        let mut cursor = 0;
        for r in idx.regions() {
            assert_eq!(r.start, cursor, "hole before {}", r.start);
            cursor = r.end();
        }
        assert_eq!(cursor, 100);
    }

    #[test]
    fn resolve_returns_every_overlapped_region() {
        let idx = LayoutIndex::new(vec![chunk(0, 10, "a"), chunk(10, 10, "b")], 20);
        assert_eq!(idx.resolve(&(0..10)).len(), 1);
        assert_eq!(idx.resolve(&(5..15)).len(), 2); // straddles
        assert_eq!(idx.resolve(&(0..20)).len(), 2);
    }

    // The exfiltration primitive from the security review. A range ending
    // exactly at a region boundary must NOT touch the next region, and one
    // starting one byte before must touch both.
    #[test]
    fn boundaries_are_exact() {
        let idx = LayoutIndex::new(vec![chunk(0, 10, "a"), chunk(10, 10, "secret")], 20);
        assert_eq!(idx.resolve(&(0..10)).len(), 1);
        assert_eq!(idx.resolve(&(9..10)).len(), 1);
        assert_eq!(idx.resolve(&(9..11)).len(), 2);
        assert_eq!(idx.resolve(&(10..11))[0].column(), Some("secret"));
    }

    #[test]
    fn resolve_never_returns_empty_for_a_valid_range() {
        let idx = LayoutIndex::new(vec![chunk(50, 10, "a")], 100);
        for r in [0..1, 0..100, 99..100, 49..51] {
            assert!(!idx.resolve(&r).is_empty(), "empty for {r:?}");
        }
    }

    #[test]
    fn overlapping_input_regions_are_rejected() {
        // A resolver bug that double-claims bytes must be caught loudly.
        let res = LayoutIndex::try_new(vec![chunk(0, 10, "a"), chunk(5, 10, "b")], 100);
        assert!(res.is_err());
    }

    // Coverage is total for a resolver that claims nothing -- a striped
    // (non-tiled) GeoTIFF handed to a tile resolver, where the alternative is
    // an index of zero regions and a readable image.
    #[test]
    fn an_object_no_resolver_understood_is_entirely_unmapped() {
        let idx = LayoutIndex::new(vec![], 100);
        assert_eq!(idx.regions().len(), 1);
        assert!(matches!(idx.regions()[0].kind, RegionKind::Unmapped));
        assert_eq!(idx.regions()[0].start..idx.regions()[0].end(), 0..100);
        assert_eq!(idx.resolve(&(0..100)).len(), 1);
    }

    // Two regions claiming the same start byte differ from the plain overlap
    // case: the sort leaves them adjacent in an order the comparator does not
    // pin down, so the check must catch them from either side.
    #[test]
    fn regions_sharing_a_start_are_an_overlap_in_either_order() {
        let long_first = LayoutIndex::try_new(vec![chunk(0, 10, "a"), chunk(0, 5, "b")], 100);
        let short_first = LayoutIndex::try_new(vec![chunk(0, 5, "b"), chunk(0, 10, "a")], 100);
        assert_eq!(long_first.unwrap_err(), IndexError::Overlap(0));
        assert_eq!(short_first.unwrap_err(), IndexError::Overlap(0));
    }

    // `start + len` comes from a footer an attacker may control. In release
    // the sum wraps, and a wrapped end is worse than a panic: it passes an
    // `end <= size` bounds check, sorts to the front of the object, and breaks
    // the sortedness that `resolve`'s binary searches assume.
    #[test]
    fn an_overflowing_extent_is_rejected_rather_than_wrapped() {
        let r = Region {
            start: u64::MAX - 1,
            len: 4,
            kind: RegionKind::Unmapped,
        };
        // Saturating, so the naive `end() <= size` check fails closed too.
        assert_eq!(r.end(), u64::MAX);
        assert_eq!(
            LayoutIndex::try_new(vec![r.clone()], 100).unwrap_err(),
            IndexError::Overflow {
                start: u64::MAX - 1,
                len: 4
            }
        );
        // The case saturation alone would miss: with `size == u64::MAX` the
        // saturated end is not past EOF, so only the checked add catches it.
        assert_eq!(
            LayoutIndex::try_new(vec![r], u64::MAX).unwrap_err(),
            IndexError::Overflow {
                start: u64::MAX - 1,
                len: 4
            }
        );
    }

    #[test]
    fn regions_past_the_end_of_the_object_are_rejected() {
        assert_eq!(
            LayoutIndex::try_new(vec![chunk(95, 10, "a")], 100).unwrap_err(),
            IndexError::PastEof { end: 105, size: 100 }
        );
        // Nothing fits in a zero-byte object.
        assert!(LayoutIndex::try_new(vec![chunk(0, 1, "a")], 0).is_err());
    }

    // A sparse tiled GeoTIFF (GDAL SPARSE_OK) records an undefined tile as
    // offset 0, byte count 0. Such a tile owns no bytes, so it is dropped
    // rather than rejected -- and dropping is also what keeps it from
    // attaching its coordinates to byte 0 of the file header.
    #[test]
    fn zero_length_regions_are_dropped_not_indexed() {
        let sparse = Region {
            start: 0,
            len: 0,
            kind: RegionKind::Tile {
                overview_level: 0,
                x: 7,
                y: 7,
                bbox: [0.0, 0.0, 1.0, 1.0],
                crs: None,
            },
        };
        let idx = LayoutIndex::new(vec![sparse, chunk(0, 10, "a")], 100);
        assert_eq!(idx.regions().len(), 2);
        assert_eq!(idx.resolve(&(0..1)).len(), 1);
        assert_eq!(idx.resolve(&(0..1))[0].column(), Some("a"));
    }

    // The hazard this module exists to contain, written out as an executable
    // fact rather than a warning in a doc comment: a conjunctive decision over
    // an empty resolve result is `true`.
    #[test]
    fn a_conjunctive_decision_over_an_empty_result_is_vacuously_true() {
        let idx = LayoutIndex::new(vec![chunk(0, 10, "a")], 10);
        let deny_everything = |_: &Region| false;
        assert!(idx.resolve(&(0..0)).iter().all(deny_everything));
        // ...and the checked entry point refuses to hand that slice over.
        assert_eq!(
            idx.try_resolve(&(0..0)).unwrap_err(),
            ResolveError::EmptyRange
        );
    }

    // Task 2 documents that `parse(None, 0)` yields `0..0` on a zero-byte
    // object and that `check()` denies it. This pins the mechanism that claim
    // rests on, instead of leaving it to a comment in another module.
    #[test]
    fn the_empty_range_from_the_parser_is_refused() {
        let range = crate::range::parse(None, 0).unwrap();
        assert_eq!(range, 0..0);
        let idx = LayoutIndex::new(vec![], 0);
        assert!(idx.regions().is_empty());
        assert!(idx.resolve(&range).is_empty());
        assert_eq!(
            idx.try_resolve(&range).unwrap_err(),
            ResolveError::EmptyRange
        );
    }

    // A range reaching past the indexed size means the size used to parse the
    // Range header and the size used to build the index disagree. The bytes
    // beyond `size` are covered by no region, so `resolve` answers about the
    // prefix only -- silently authorizing the rest.
    #[test]
    fn a_range_past_the_indexed_size_is_refused() {
        let idx = LayoutIndex::new(vec![chunk(0, 100, "a")], 100);
        assert_eq!(idx.resolve(&(50..200)).len(), 1); // says nothing about 100..200
        assert_eq!(
            idx.try_resolve(&(50..200)).unwrap_err(),
            ResolveError::PastEof { end: 200, size: 100 }
        );
        assert_eq!(idx.try_resolve(&(50..100)).unwrap().len(), 1);
    }

    #[test]
    fn new_panics_on_a_malformed_region_set() {
        let overlapping = vec![chunk(0, 10, "a"), chunk(5, 10, "b")];
        assert!(std::panic::catch_unwind(|| LayoutIndex::new(overlapping, 100)).is_err());
    }

    // Absent and null are indistinguishable to cql2, and comparing against a
    // present null errors rather than evaluating to false. Nested arrays are
    // included in the walk because that is where a NaN coordinate would hide.
    #[test]
    fn props_never_contain_null() {
        fn walk(v: &Value, path: &str) {
            match v {
                Value::Null => panic!("null at {path}"),
                Value::Object(m) => m.iter().for_each(|(k, v)| walk(v, &format!("{path}.{k}"))),
                Value::Array(a) => a.iter().for_each(|v| walk(v, &format!("{path}[]"))),
                _ => {}
            }
        }
        let kinds = [
            RegionKind::Metadata {
                name: "footer".into(),
            },
            RegionKind::Unmapped,
            RegionKind::ColumnChunk {
                column: "ssn".into(),
                row_group: 3,
            },
            RegionKind::ColumnIndex { column: "ssn".into() },
            RegionKind::BloomFilter { column: "ssn".into() },
            RegionKind::Tile {
                overview_level: 2,
                x: 1,
                y: 2,
                bbox: [0.0, 0.0, 1.0, 1.0],
                crs: None,
            },
            RegionKind::Tile {
                overview_level: 2,
                x: 1,
                y: 2,
                bbox: [f64::NAN, 0.0, f64::INFINITY, 1.0],
                crs: Some(3857),
            },
        ];
        for kind in kinds {
            let r = Region {
                start: 0,
                len: 1,
                kind,
            };
            walk(&r.props(), "props");
        }
    }

    // A NaN bbox is rejected at construction, so no indexed region can carry
    // one. `props()` still refuses to emit the geometry if one arrives by
    // another route: a polygon whose coordinates are nulls breaks the no-null
    // rule from inside a nested array, and no spatial policy can match a
    // region with no geometry -- which is a denial under a conjunctive rule.
    #[test]
    fn non_finite_bboxes_are_rejected_and_never_emitted() {
        for bad in [
            [f64::NAN, 0.0, 1.0, 1.0],
            [0.0, f64::INFINITY, 1.0, 1.0],
            [0.0, 0.0, f64::NEG_INFINITY, 1.0],
        ] {
            assert_eq!(
                LayoutIndex::try_new(vec![tile(bad)], 100).unwrap_err(),
                IndexError::NonFiniteBbox(bad)
            );
            let props = tile(bad).props();
            assert!(props.get("geom").is_none(), "emitted geom for {bad:?}");
            assert!(props.get("bbox").is_none(), "emitted bbox for {bad:?}");
            assert_eq!(props["kind"], "tile");
        }
    }

    // A north-up raster's geo transform has a negative y pixel size, so a
    // resolver that reads the top edge as `ymin` hands us an inverted bbox.
    // The ring must still come out closed, counter-clockwise, and describing
    // the same rectangle.
    #[test]
    fn the_tile_ring_is_closed_and_normalized() {
        let upright = tile([0.0, 0.0, 10.0, 20.0]).props();
        let inverted = tile([10.0, 20.0, 0.0, 0.0]).props();
        assert_eq!(upright["geom"], inverted["geom"]);
        assert_eq!(upright["bbox"], json!({"bbox":[0.0,0.0,10.0,20.0]}));
        let ring = upright["geom"]["coordinates"][0].as_array().unwrap().clone();
        assert_eq!(ring.len(), 5, "ring must repeat its first point");
        assert_eq!(ring[0], ring[4]);
        assert_eq!(
            ring,
            vec![
                json!([0.0, 0.0]),
                json!([10.0, 0.0]),
                json!([10.0, 20.0]),
                json!([0.0, 20.0]),
                json!([0.0, 0.0])
            ]
        );
    }

    // The claim in `props()` that a bare array is not a CQL2 spatial operand
    // is only worth making if the geometry we emit instead really does reduce.
    // Both directions: a regression that made `matches` fail open would pass
    // the positive assertion alone.
    #[test]
    fn tile_props_are_a_working_cql2_spatial_operand() {
        let props = tile([0.0, 0.0, 10.0, 10.0]).props();
        let inside: cql2::Expr = "S_INTERSECTS(geom, POINT(5 5))".parse().unwrap();
        let outside: cql2::Expr = "S_INTERSECTS(geom, POINT(50 50))".parse().unwrap();
        assert!(inside.matches(Some(&props)).unwrap());
        assert!(!outside.matches(Some(&props)).unwrap());
    }

    // Unmapped bytes must not answer to the vocabulary policies are written
    // in. If a rule about columns could match them, filling gaps would have
    // moved the hole rather than closed it.
    #[test]
    fn unmapped_regions_match_no_column_or_metadata_policy() {
        let props = Region {
            start: 0,
            len: 1,
            kind: RegionKind::Unmapped,
        }
        .props();
        assert_eq!(props, json!({"kind":"unmapped"}));
        for rule in ["kind = 'metadata'", "kind = 'column_chunk'"] {
            let expr: cql2::Expr = rule.parse().unwrap();
            assert!(!expr.matches(Some(&props)).unwrap(), "matched: {rule}");
        }
    }
}
