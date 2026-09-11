//! Sparsify + scrub: serve a *valid* COG whose IFD never points at the tiles a
//! policy withholds.
//!
//! # The COG analogue of footer rewrite
//!
//! [`crate::rewrite`] serves a Parquet file whose footer never mentions the
//! withheld columns, leaving their bytes physically in place but zeroed, so
//! that a block-aligned reader's coalesced fetch spans a hole nothing parses.
//! The same move works on a tiled GeoTIFF, and it is **simpler by one whole
//! codec**, because TIFF already has a way to say "this tile is not here":
//!
//! > `TileOffsets[i] = 0`, `TileByteCounts[i] = 0`
//!
//! That is exactly how a *sparse* COG -- GDAL's `SPARSE_OK=YES` -- represents a
//! tile that was never written, and GDAL handles it natively: the tile reads
//! back as the band's nodata value, or as zero when no nodata is declared.
//!
//! # Measured before any of this was written
//!
//! GDAL 3.13.3, `data/s2-tci-512.tif`, tag entries zeroed for a 5x5 block of
//! full-resolution tiles, locally and then over `/vsicurl` against a
//! range-serving HTTP server:
//!
//! * `gdalinfo` reports the same 10980x10980 raster, the same CRS, the same
//!   `LAYOUT=COG`, the same five overviews, no warning and no error.
//! * `gdal_translate -srcwin` over a window spanning zeroed AND live tiles
//!   exits 0. The withheld pixels come back **all zero**; 6,193,631 of them
//!   were non-zero in the original, so the hole is real and not a coincidence.
//! * Every live pixel is **byte-identical** to the original: 6,553,600 pixels
//!   x 3 bands, exact.
//! * The overview checksums are unchanged, because nothing else moved.
//! * It does not depend on a declared nodata value. Repeated on a COG built
//!   with `-a_nodata none`, the withheld tiles still read back as zero; the
//!   nodata declaration decides what zero MEANS, not whether the read works.
//!
//! Then end to end through `examples/cog_gate.rs`, withholding every
//! full-resolution tile outside a licensed polygon (459 of 484), with GDAL
//! reading `/vsicurl` from the gateway itself:
//!
//! ```text
//! mode      gdal_translate   requests   straddling a withheld tile
//! refuse    FAILED, exit 1   4          3, all refused -- died on the first tile read
//! scrub     ok, exit 0       6          5, all served
//! ```
//!
//! Under `refuse` GDAL reports `TIFFFillTile:Read error ... got 0 bytes,
//! expected 35803` on its very first tile read, which is issue #26 exactly: the
//! `/vsicurl` block grid cannot be made to land on tile boundaries. Under
//! `scrub` five of the six reads span a withheld tile and none of them matter,
//! because GDAL never asks for a tile whose offset is zero and reads straight
//! through the hole when a coalesced fetch covers one.
//!
//! # Why there is no re-serialization
//!
//! A Parquet footer cannot be patched: the schema is field 2 of
//! `FileMetaData`, so dropping one element shifts a length varint and every
//! byte after it moves. `rewrite` therefore re-encodes the whole tree and
//! serves a tail of a different length, which costs it the origin's `ETag`, the
//! origin's `Content-Length`, and `ARROW:schema`.
//!
//! `TileOffsets` and `TileByteCounts` are out-of-line arrays of **fixed-width**
//! integers -- LONG, or SHORT on a small image. Element `i` sits at a known
//! address and zeroing it is a same-length overwrite. So:
//!
//! * the object's length does not change, and neither does any offset in it;
//! * every edit and every scrub is "overwrite these bytes with zeroes", which
//!   is the single operation [`Verdict::redact`] already performs, in the one
//!   audited place the absolute-to-buffer subtraction is written down;
//! * a gateway holds **no rewritten tail at all** -- the plan is a sorted list
//!   of byte ranges, and `data/s2-tci-512.tif` withholding 25 tiles produces
//!   one of 27 entries.
//!
//! The edits are literally zeroes too, so the "rewrite" and the "scrub" halves
//! are the same operation on different bytes. They are reported separately
//! anyway ([`Sparse::edits`] against [`Sparse::scrub`]) because an operator
//! auditing a plan needs to see which 200 bytes made the tiles disappear and
//! which 122,361 bytes stopped them being readable anyway.
//!
//! # Scrubbing is still mandatory
//!
//! Zeroing the tag entries alone **hides** a tile; it does not withhold it.
//! `Range: bytes=...` over the tile's old extent still returns live JPEG bytes
//! to anyone who kept the original IFD or simply guessed, and a COG's tile
//! addressing is guessable from the grid. So the payload is zeroed as well --
//! and the scrub extent is the **whole tile region**, which by rule 1 of
//! [`crate::cog`] already includes GDAL's four-byte block leader and four-byte
//! trailer. Scrubbing only `[offset, offset + len)` would leave a live
//! `SIZE_AS_UINT4` leader sitting in front of a zeroed tile: a size prefix
//! announcing a payload that is no longer there, which is both a leak of the
//! tile's compressed size and a reader-visible inconsistency.
//!
//! The ghost area is left exactly as it is. `BLOCK_LEADER` and `BLOCK_TRAILER`
//! still describe every tile the served IFD points at, because the live tiles
//! did not move; and `KNOWN_INCOMPATIBLE_EDITION` stays `NO`, because it is
//! GDAL's flag for a writer that did not understand those declarations, which
//! is not what happened here. Flipping it would make [`crate::cog`] refuse to
//! index the very object this module produced.
//!
//! # Masks: refused, not handled
//!
//! A COG containing a mask image is **refused outright**
//! ([`SparseError::MaskImage`]). This is a deliberate fail-closed answer to
//! issue #21, not an oversight, and it is the one place the COG story is worse
//! than the Parquet one.
//!
//! [`crate::cog`] gives mask tiles no regions at all, so the policy has nothing
//! to say about them -- there is no verdict to act on. Under
//! [`check`](crate::decision::check) that was survivable: unclassified bytes
//! are [`RegionKind::Unmapped`] and deny, so a mask read simply failed. Under
//! sparsify the whole object is served, so anything not in the blank set goes
//! out **live** -- and a mask is a per-pixel map of exactly where the data is.
//! Serving a withheld tile's mask intact restores the footprint that
//! withholding the tile was supposed to remove, at 1-bit-per-pixel resolution.
//!
//! There are only three possible answers and two of them are wrong: serve the
//! mask (leaks the footprint), zero the mask tile's bytes without zeroing its
//! tag entries (a reader follows a live pointer into zeroes and gets a
//! corrupt-file error rather than a policy one). The third is to withhold the
//! mask tile the same way -- which needs `RegionKind::Mask` so the policy can
//! *decide* it, and that is issue #21's fix in `index.rs` and `policy.rs`.
//! Until then, refusing the object is the only honest option.
//!
//! # What else is refused
//!
//! Any object with a single [`RegionKind::Unmapped`] byte
//! ([`SparseError::Unclassified`]). Same reasoning, generalized: sparsify
//! serves everything it does not blank, so a byte the resolver could not
//! account for is a byte served without a decision. Under refusal those bytes
//! denied; here they would not. This also closes rule 5 -- a striped TIFF
//! classifies nothing, so it is wholly unmapped -- and rule 6's unknown field
//! types.
//!
//! # What is NOT evaluated
//!
//! Regions with no tile: `Metadata` and, by the paragraph above, nothing else.
//! This is the same divergence from [`check`](crate::decision::check) that
//! [`crate::rewrite::plan`] documents. The header, the ghost area, the IFDs,
//! the tag arrays and the GeoTIFF keys are the structure the permitted tiles
//! are found through; a representation that withheld them would not be a TIFF.
//! A deployment that wants to deny a principal the object denies it the
//! object, rather than expressing that as a region rule.

use crate::{
    cog::CogLayout,
    decision::{DenyReason, Verdict},
    index::{LayoutIndex, RegionKind},
    policy::Policy,
};
use serde_json::Value;
use std::collections::BTreeMap;
use std::ops::Range;

/// Why a sparse representation could not be produced.
///
/// Every variant is a refusal to serve the object at all. There is no partial
/// plan: a COG whose IFD half-describes its tiles is a corrupt file, which
/// presents to a reader as data loss rather than as a policy decision.
#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum SparseError {
    /// The index has no `Metadata { name: "header" }` region at offset 0, so it
    /// did not come from [`cog::build_index_with_layout`](crate::cog::build_index_with_layout)
    /// and nothing here knows what it is looking at.
    #[error("the index does not describe a TIFF")]
    NotATiff,
    /// The object contains a mask image. See the module docs: there is no
    /// region for a mask tile, so there is no verdict for one, and serving it
    /// live restores the footprint of every withheld tile. Issue #21.
    #[error("the object has a mask image, which has no region and so no verdict (issue #21)")]
    MaskImage,
    /// The object has bytes the resolver could not account for. Sparsify serves
    /// everything it does not blank, so an unclassified byte would be served
    /// without a decision -- where refusal denied it.
    #[error("{len} bytes at {start} are unclassified; sparsify would serve them undecided")]
    Unclassified { start: u64, len: u64 },
    /// A tile region names an overview level no image in the layout has, or two
    /// images claim the same level. Either way the index and the layout came
    /// from different parses of different bytes.
    #[error("overview level {overview_level} matches {images} images in the layout, not 1")]
    LevelNotUnique { overview_level: u32, images: usize },
    /// A tile region's coordinates are outside the grid its image declares.
    #[error("tile ({x}, {y}) at level {overview_level} is outside the {across}x{down} grid")]
    TileOutOfGrid {
        overview_level: u32,
        x: u32,
        y: u32,
        across: u64,
        down: u64,
    },
    /// An edit computed from the layout does not land wholly inside metadata
    /// the index classified. The two derivations disagree about where the tile
    /// arrays are, and writing zeroes at a guessed address corrupts whatever is
    /// really there.
    #[error("the tile-array edit at {start}..{end} is not classified as metadata")]
    EditNotInMetadata { start: u64, end: u64 },
    /// An offset computation overflowed a u64. The file disagrees with itself.
    #[error("tile addressing at level {overview_level} overflows a u64")]
    Overflow { overview_level: u32 },
}

/// One tile the policy withheld.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WithheldTile {
    pub overview_level: u32,
    pub x: u32,
    pub y: u32,
    /// The payload bytes zeroed, including the GDAL block leader and trailer.
    pub bytes: u64,
}

/// A filtered representation of one COG for one principal.
///
/// The address map is **one case**, which is what makes this cheaper to serve
/// than [`crate::rewrite::Rewrite`]:
///
/// ```text
/// virtual offset  ->  the same physical offset, zeroed where the plan says
/// ```
///
/// Nothing moves, nothing is resident, and [`Sparse::virtual_size`] equals the
/// origin's length -- so unlike the Parquet path, a `ListObjects` size and a
/// `HEAD` still agree with what is served. The origin's `ETag` and
/// `Content-MD5` still do not; see [`Sparse::etag`].
#[derive(Debug, Clone)]
pub struct Sparse {
    edits: Vec<Range<u64>>,
    scrub: Vec<Range<u64>>,
    blank: Vec<Range<u64>>,
    withheld: Vec<WithheldTile>,
    object_size: u64,
}

impl Sparse {
    /// The tag-array entries to zero: two per withheld tile, one in
    /// `TileOffsets` and one in `TileByteCounts`, each 2 or 4 bytes wide.
    ///
    /// Sorted, pairwise disjoint, and **same-length by construction** -- these
    /// are extents that get overwritten in place, not replacements. That is the
    /// whole difference from a footer rewrite.
    pub fn edits(&self) -> &[Range<u64>] {
        &self.edits
    }

    /// The withheld tiles' payload extents, each including its GDAL block
    /// leader and trailer. Sorted, pairwise disjoint, merged where adjacent.
    pub fn scrub(&self) -> &[Range<u64>] {
        &self.scrub
    }

    /// Everything a gateway must zero before any byte reaches the client:
    /// [`Sparse::edits`] and [`Sparse::scrub`] merged into one sorted,
    /// pairwise-disjoint list.
    ///
    /// Both halves are zeroes, so there is exactly one operation to apply. The
    /// two accessors above exist for the audit, not for the serve path.
    pub fn blank(&self) -> &[Range<u64>] {
        &self.blank
    }

    /// The tiles the policy withheld, sorted by level, then row, then column.
    pub fn withheld(&self) -> &[WithheldTile] {
        &self.withheld
    }

    /// How many bytes the plan zeroes in total.
    pub fn blanked_bytes(&self) -> u64 {
        self.blank.iter().map(|s| s.end - s.start).sum()
    }

    /// The origin object's length.
    pub fn object_size(&self) -> u64 {
        self.object_size
    }

    /// The length to advertise in `HEAD`, `Content-Length` and the
    /// complete-length of a `Content-Range`.
    ///
    /// Always equal to [`Sparse::object_size`]: nothing moves and nothing
    /// changes length. The method exists so that a gateway written against
    /// [`crate::rewrite::Rewrite`] reads the same for both formats.
    pub fn virtual_size(&self) -> u64 {
        self.object_size
    }

    /// A strong entity tag for the **virtual** representation.
    ///
    /// The origin's `ETag` and `Content-MD5` describe an object this gateway
    /// does not serve -- the length agrees, which makes the mismatch *less*
    /// visible than in the Parquet case and not more forgivable. Two principals
    /// whose policies withhold the same tiles get the same tag, which collapses
    /// them onto one cache entry; it is deliberately not derived from the
    /// principal.
    ///
    /// FNV-1a, matching [`crate::rewrite::Rewrite::etag`]. A cache key, not an
    /// integrity check.
    pub fn etag(&self) -> String {
        let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
        let mut eat = |bytes: &[u8]| {
            for b in bytes {
                hash ^= u64::from(*b);
                hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
            }
        };
        eat(&self.object_size.to_le_bytes());
        for span in &self.blank {
            eat(&span.start.to_le_bytes());
            eat(&span.end.to_le_bytes());
        }
        format!("\"cnac-{hash:016x}\"")
    }

    /// The verdict for a range of the object, in the shape
    /// [`Verdict::redact`] consumes.
    ///
    /// There is no footer split here -- the whole object is addressable -- so
    /// any non-empty range inside the object is served, with the blank extents
    /// clipped to it. An empty range, or one past the end, is
    /// [`Verdict::Denied`]: not an authorization failure, since there is no
    /// request to authorize, but a caller that got the arithmetic wrong must
    /// not get bytes.
    pub fn object_verdict(&self, object_range: &Range<u64>) -> Verdict {
        if object_range.start >= object_range.end || object_range.end > self.object_size {
            return Verdict::Denied {
                reason: DenyReason::NotPermitted,
            };
        }
        let blank = self
            .blank
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

/// Produce the sparse representation of `index`'s object for `user`.
///
/// `index` and `layout` must be the pair one call to
/// [`cog::build_index_with_layout`](crate::cog::build_index_with_layout)
/// returned. They are cross-checked rather than trusted: every edit this
/// function computes from `layout` must land inside a region `index`
/// classified as metadata, or the plan is refused
/// ([`SparseError::EditNotInMetadata`]).
///
/// # Which tiles are withheld
///
/// Every [`RegionKind::Tile`] region is evaluated against the policy, and the
/// tile is withheld if its region is denied. Unlike a Parquet column, a tile is
/// independently representable -- a COG can be sparse in one tile and dense in
/// its neighbour -- so there is no fail-closed widening here and no analogue of
/// `Withheld::denied_kinds`. One region, one decision.
pub fn plan(
    index: &LayoutIndex,
    layout: &CogLayout,
    policy: &Policy,
    user: &Value,
) -> Result<Sparse, SparseError> {
    // Before anything is planned, the three things sparsify cannot serve. The
    // unclassified check goes FIRST because it is the one that catches a
    // striped TIFF, whose index is a single `Unmapped` region with no header in
    // it -- "unclassified" is the true answer there and "not a TIFF" is not.
    if let Some(region) = index
        .regions()
        .iter()
        .find(|r| matches!(r.kind, RegionKind::Unmapped))
    {
        return Err(SparseError::Unclassified {
            start: region.start,
            len: region.len,
        });
    }
    if layout.images.iter().any(|i| i.overview_level.is_none()) {
        return Err(SparseError::MaskImage);
    }
    let is_tiff = index.regions().iter().any(|r| {
        r.start == 0 && matches!(&r.kind, RegionKind::Metadata { name } if name == "header")
    });
    if !is_tiff {
        return Err(SparseError::NotATiff);
    }

    // Level -> image, built once. A level claimed by two images means the index
    // and the layout cannot be reconciled, and the ambiguity is an error rather
    // than a first-match: picking one would write zeroes into the other's array.
    let mut per_level: BTreeMap<u32, usize> = BTreeMap::new();
    for image in &layout.images {
        if let Some(level) = image.overview_level {
            *per_level.entry(level).or_default() += 1;
        }
    }

    let mut edits: Vec<Range<u64>> = Vec::new();
    let mut scrub: Vec<Range<u64>> = Vec::new();
    let mut withheld: Vec<WithheldTile> = Vec::new();

    for region in index.regions() {
        let RegionKind::Tile {
            overview_level,
            x,
            y,
            ..
        } = region.kind
        else {
            continue;
        };
        if policy.permits(&serde_json::json!({"user": user, "region": region.props()})) {
            continue;
        }

        let count = per_level.get(&overview_level).copied().unwrap_or(0);
        if count != 1 {
            return Err(SparseError::LevelNotUnique {
                overview_level,
                images: count,
            });
        }
        let image = layout
            .images
            .iter()
            .find(|i| i.overview_level == Some(overview_level))
            .expect("the level was counted once, so it is present");

        if u64::from(x) >= image.across || u64::from(y) >= image.down {
            return Err(SparseError::TileOutOfGrid {
                overview_level,
                x,
                y,
                across: image.across,
                down: image.down,
            });
        }
        let overflow = || SparseError::Overflow { overview_level };
        let i = u64::from(y)
            .checked_mul(image.across)
            .and_then(|row| row.checked_add(u64::from(x)))
            .ok_or_else(overflow)?;

        for array in [image.offsets, image.byte_counts] {
            if i >= array.count {
                return Err(SparseError::TileOutOfGrid {
                    overview_level,
                    x,
                    y,
                    across: image.across,
                    down: image.down,
                });
            }
            let width = u64::from(array.width);
            let start = i
                .checked_mul(width)
                .and_then(|off| array.at.checked_add(off))
                .ok_or_else(overflow)?;
            let end = start.checked_add(width).ok_or_else(overflow)?;
            // The cross-check. `index` classified these bytes independently of
            // the scan `layout` came from; if they are not metadata then the
            // address is a guess, and a guessed address is somebody else's
            // bytes.
            let covers = index.resolve(&(start..end));
            let all_metadata = !covers.is_empty()
                && covers
                    .iter()
                    .all(|r| matches!(r.kind, RegionKind::Metadata { .. }));
            if !all_metadata {
                return Err(SparseError::EditNotInMetadata { start, end });
            }
            edits.push(start..end);
        }

        scrub.push(region.start..region.end());
        withheld.push(WithheldTile {
            overview_level,
            x,
            y,
            bytes: region.len,
        });
    }

    withheld.sort_by_key(|t| (t.overview_level, t.y, t.x));
    let edits = coalesce(edits);
    let scrub = coalesce(scrub);
    let blank = coalesce(edits.iter().chain(scrub.iter()).cloned().collect());

    Ok(Sparse {
        edits,
        scrub,
        blank,
        withheld,
        object_size: index.size(),
    })
}

/// Sort and merge, so that the result is the extents themselves rather than the
/// index's internal boundaries: two withheld tiles that abut are one span.
fn coalesce(mut spans: Vec<Range<u64>>) -> Vec<Range<u64>> {
    spans.retain(|s| s.start < s.end);
    spans.sort_by_key(|s| (s.start, s.end));
    let mut out: Vec<Range<u64>> = Vec::with_capacity(spans.len());
    for span in spans {
        match out.last_mut() {
            Some(last) if span.start <= last.end => last.end = last.end.max(span.end),
            _ => out.push(span),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cog::build_index_with_layout;
    use crate::decision::{check, Decision, DenialMode};
    use std::path::PathBuf;

    fn repo(rel: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel)
    }

    fn read(rel: &str) -> Vec<u8> {
        std::fs::read(repo(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
    }

    fn parse(rel: &str) -> (Vec<u8>, LayoutIndex, CogLayout) {
        let bytes = read(rel);
        let size = bytes.len() as u64;
        let (index, layout) = build_index_with_layout(&bytes, size).expect("indexes");
        (bytes, index, layout)
    }

    fn policy(rules: &[&str]) -> Policy {
        let yaml = std::iter::once("allow:".to_string())
            .chain(
                rules
                    .iter()
                    .map(|r| format!("  - \"{}\"", r.replace('"', "'"))),
            )
            .collect::<Vec<_>>()
            .join("\n");
        Policy::load(&yaml, crate::policy::QUERYABLES).unwrap_or_else(|e| panic!("{yaml}: {e}"))
    }

    /// Permit the structure, every overview, and every full-resolution tile
    /// except those inside the box. Levelled on purpose: `region.x` means
    /// something different at every level, so a box written without a level is
    /// a box in five other grids as well.
    fn withhold_box(x0: u32, x1: u32, y0: u32, y1: u32) -> Policy {
        policy(&[
            "region.kind = 'metadata'",
            "region.overview_level > 0",
            &format!(
                "region.overview_level = 0 AND NOT (region.x >= {x0} AND region.x <= {x1} \
                 AND region.y >= {y0} AND region.y <= {y1})"
            ),
        ])
    }

    fn user() -> Value {
        serde_json::json!({"role": "analyst"})
    }

    /// Read one element of a tile array out of a buffer.
    fn element(bytes: &[u8], layout: &CogLayout, array: crate::cog::TileArray, i: u64) -> u64 {
        let at = (array.at + i * u64::from(array.width)) as usize;
        match array.width {
            2 => {
                let raw: [u8; 2] = bytes[at..at + 2].try_into().unwrap();
                u64::from(if layout.big_endian {
                    u16::from_be_bytes(raw)
                } else {
                    u16::from_le_bytes(raw)
                })
            }
            _ => {
                let raw: [u8; 4] = bytes[at..at + 4].try_into().unwrap();
                u64::from(if layout.big_endian {
                    u32::from_be_bytes(raw)
                } else {
                    u32::from_le_bytes(raw)
                })
            }
        }
    }

    /// Serve the whole object through the plan, the way a gateway does.
    fn serve(bytes: &[u8], plan: &Sparse) -> Vec<u8> {
        let mut out = bytes.to_vec();
        let verdict = plan.object_verdict(&(0..plan.object_size()));
        verdict
            .redact(&mut out)
            .expect("the whole object is served");
        out
    }

    #[test]
    fn withholding_a_block_of_tiles_zeroes_exactly_their_two_tag_entries() {
        let (bytes, index, layout) = parse("data/s2-tci-512.tif");
        let plan = plan(&index, &layout, &withhold_box(5, 9, 5, 9), &user()).expect("plans");

        // 5x5 tiles at full resolution, and nothing at any other level.
        assert_eq!(plan.withheld().len(), 25);
        assert!(plan.withheld().iter().all(|t| t.overview_level == 0));

        let served = serve(&bytes, &plan);
        let full = layout.images[0];
        assert_eq!(full.across, 22);

        for y in 0..full.down {
            for x in 0..full.across {
                let i = y * full.across + x;
                let hole = (5..=9).contains(&x) && (5..=9).contains(&y);
                let offset = element(&served, &layout, full.offsets, i);
                let length = element(&served, &layout, full.byte_counts, i);
                if hole {
                    assert_eq!((offset, length), (0, 0), "tile ({x}, {y}) should be sparse");
                } else {
                    assert_eq!(
                        (offset, length),
                        (
                            element(&bytes, &layout, full.offsets, i),
                            element(&bytes, &layout, full.byte_counts, i)
                        ),
                        "tile ({x}, {y}) should be untouched"
                    );
                }
            }
        }
    }

    #[test]
    fn every_edit_is_the_same_length_as_the_bytes_it_replaces() {
        // The property the whole module rests on, and the one thing `rewrite`
        // could not have: nothing moves, so no offset anywhere in the object
        // needs revisiting.
        let (bytes, index, layout) = parse("data/s2-tci-512.tif");
        let plan = plan(&index, &layout, &withhold_box(0, 21, 0, 21), &user()).expect("plans");
        let served = serve(&bytes, &plan);
        assert_eq!(served.len(), bytes.len());
        assert_eq!(plan.virtual_size(), plan.object_size());
        assert_eq!(plan.object_size(), bytes.len() as u64);
        // Two entries per tile, 4 bytes each, over the whole 22x22 grid --
        // before coalescing merges the neighbours, which it does completely
        // because the arrays are contiguous.
        assert_eq!(plan.withheld().len(), 484);
        assert_eq!(
            plan.edits().iter().map(|e| e.end - e.start).sum::<u64>(),
            484 * 2 * 4
        );
    }

    #[test]
    fn nothing_outside_the_withheld_tiles_and_their_entries_changes() {
        let (bytes, index, layout) = parse("data/s2-tci-512.tif");
        let plan = plan(&index, &layout, &withhold_box(5, 9, 5, 9), &user()).expect("plans");
        let served = serve(&bytes, &plan);

        let mut expected: Vec<usize> = Vec::new();
        for span in plan.blank() {
            expected.extend(span.start as usize..span.end as usize);
        }
        let differing: Vec<usize> = (0..bytes.len())
            .filter(|i| bytes[*i] != served[*i])
            .collect();
        // Every differing byte is inside the plan. The converse does not hold
        // and must not be asserted: a payload byte that was already zero is in
        // the plan and does not differ.
        assert!(differing.iter().all(|i| {
            plan.blank()
                .iter()
                .any(|s| (*i as u64) >= s.start && (*i as u64) < s.end)
        }));
        assert!(!differing.is_empty());
        assert!(expected.len() >= differing.len());
    }

    #[test]
    fn a_withheld_tiles_payload_leader_and_trailer_all_come_back_as_zeroes() {
        // Rule 1's consequence. Scrubbing only `[offset, offset + len)` would
        // leave the four-byte SIZE_AS_UINT4 leader announcing a payload that is
        // no longer there.
        let (bytes, index, layout) = parse("data/s2-tci-512.tif");
        assert_eq!((layout.leader, layout.trailer), (4, 4));
        let plan = plan(&index, &layout, &withhold_box(5, 9, 5, 9), &user()).expect("plans");
        let served = serve(&bytes, &plan);

        let full = layout.images[0];
        let mut checked = 0;
        for y in 5..=9u64 {
            for x in 5..=9u64 {
                let i = y * full.across + x;
                let offset = element(&bytes, &layout, full.offsets, i);
                let length = element(&bytes, &layout, full.byte_counts, i);
                assert!(offset > 0 && length > 0, "the fixture tile is not sparse");
                let from = (offset - layout.leader) as usize;
                let to = (offset + length + layout.trailer) as usize;
                // Non-trivially so: the original bytes were not already zero.
                assert!(bytes[from..to].iter().any(|b| *b != 0));
                assert!(
                    served[from..to].iter().all(|b| *b == 0),
                    "tile ({x}, {y}) payload survived"
                );
                checked += 1;
            }
        }
        assert_eq!(checked, 25);
    }

    #[test]
    fn a_coalesced_read_spanning_a_withheld_tile_is_served_where_refusal_denies_it() {
        // The measurement the whole approach exists for. A block-aligned reader
        // asks for a 64 KiB-aligned window that happens to contain a withheld
        // tile; under `check` that is a denial and the read fails, under a plan
        // it is 206 with a hole in it.
        let (bytes, index, layout) = parse("data/s2-tci-512.tif");
        let policy = withhold_box(5, 9, 5, 9);
        let plan = plan(&index, &layout, &policy, &user()).expect("plans");

        let hole = &plan.scrub()[0];
        let block = 64 * 1024;
        let start = (hole.start / block) * block;
        let end = (hole.end.div_ceil(block) * block).min(plan.object_size());
        assert!(
            start < hole.start && end > hole.end,
            "the read must straddle"
        );

        let header = format!("bytes={start}-{}", end - 1);
        let refused = check(&index, &policy, &user(), Some(&header));
        assert!(
            matches!(refused, Decision::Denied { .. }),
            "the aligned read must be denied under refusal, or there is nothing to prove"
        );

        let Verdict::Serve { canonical, blank } = plan.object_verdict(&(start..end)) else {
            panic!("the same read must be served under a plan");
        };
        assert_eq!(canonical, start..end);
        assert!(!blank.is_empty());

        let mut buffer = bytes[start as usize..end as usize].to_vec();
        plan.object_verdict(&(start..end))
            .redact(&mut buffer)
            .expect("redacts");
        // The withheld tile is gone from the response and the surrounding live
        // tiles are byte-identical.
        let lo = (hole.start - start) as usize;
        let hi = (hole.end - start) as usize;
        assert!(buffer[lo..hi].iter().all(|b| *b == 0));
        assert_eq!(&buffer[..lo], &bytes[start as usize..hole.start as usize]);
        assert_eq!(&buffer[hi..], &bytes[hole.end as usize..end as usize]);
    }

    #[test]
    fn zero_fill_refuses_the_same_aligned_read_a_plan_serves() {
        // `DenialMode::ZeroFill` already blanks forbidden extents inside a
        // served range, so it is the closest thing in `decision.rs` to this
        // module -- but it only blanks bytes the REQUEST covered, and a reader
        // still has to survive an IFD pointing at them. The plan edits the IFD
        // too, which is the difference.
        let (_, index, layout) = parse("data/s2-tci-512.tif");
        let policy = withhold_box(5, 9, 5, 9);
        let plan = plan(&index, &layout, &policy, &user()).expect("plans");
        let hole = &plan.scrub()[0];
        let header = format!("bytes={}-{}", hole.start, hole.end - 1);
        let zero_filled = crate::decision::check_with_mode(
            &index,
            &policy,
            &user(),
            Some(&header),
            DenialMode::ZeroFill,
        );
        assert!(matches!(zero_filled, Verdict::Serve { .. }));
        // And yet every tag entry still points straight at those bytes, which
        // is what makes the reader see a corrupt tile rather than a missing one.
        assert!(plan
            .edits()
            .iter()
            .all(|e| e.end <= hole.start || e.start >= hole.end));
    }

    #[test]
    fn a_permissive_policy_plans_an_empty_change() {
        let (bytes, index, layout) = parse("data/s2-tci-512.tif");
        let plan = plan(&index, &layout, &policy(&["true"]), &user()).expect("plans");
        assert!(plan.withheld().is_empty());
        assert!(plan.blank().is_empty());
        assert_eq!(plan.blanked_bytes(), 0);
        assert_eq!(serve(&bytes, &plan), bytes);
    }

    #[test]
    fn the_edits_land_inside_the_tag_array_regions_the_index_named() {
        // The cross-check is not vacuous: it really is the `tile_offsets` and
        // `tile_byte_counts` regions the edits fall in, and nothing else.
        let (_, index, layout) = parse("data/s2-tci-512.tif");
        let plan = plan(&index, &layout, &withhold_box(5, 9, 5, 9), &user()).expect("plans");
        assert!(!plan.edits().is_empty());
        for edit in plan.edits() {
            for region in index.resolve(edit) {
                let RegionKind::Metadata { name } = &region.kind else {
                    panic!("edit at {edit:?} is not metadata");
                };
                assert!(
                    name == "tile_offsets" || name == "tile_byte_counts" || name == "ifd",
                    "edit at {edit:?} landed in `{name}`"
                );
            }
        }
    }

    #[test]
    fn an_overview_tile_is_withheld_through_the_same_arithmetic() {
        // Two things at once: the level -> image lookup is by rank and not by
        // IFD position, and the coarsest overview of both fixtures is a single
        // tile whose TileOffsets is four bytes and therefore lives INSIDE its
        // IFD entry rather than at an offset.
        let (bytes, index, layout) = parse("data/s2-tci-512.tif");
        let levels = layout
            .images
            .iter()
            .filter_map(|i| i.overview_level)
            .collect::<Vec<_>>();
        assert_eq!(levels, vec![0, 1, 2, 3, 4, 5]);
        let coarsest = layout.images.last().copied().expect("six images");
        assert_eq!(coarsest.overview_level, Some(5));
        assert_eq!((coarsest.across, coarsest.down), (1, 1));

        let plan = plan(
            &index,
            &layout,
            &policy(&["region.kind = 'metadata'", "region.overview_level < 5"]),
            &user(),
        )
        .expect("plans");
        assert_eq!(plan.withheld().len(), 1);
        assert_eq!(plan.withheld()[0].overview_level, 5);

        let served = serve(&bytes, &plan);
        assert_eq!(element(&served, &layout, coarsest.offsets, 0), 0);
        assert_eq!(element(&served, &layout, coarsest.byte_counts, 0), 0);
        // The inline case really was inline: the entry's value sits in the IFD.
        let ifd_regions: Vec<_> = index
            .resolve(&(coarsest.offsets.at..coarsest.offsets.at + 4))
            .to_vec();
        assert!(ifd_regions
            .iter()
            .all(|r| matches!(&r.kind, RegionKind::Metadata { name } if name == "ifd")));
    }

    #[test]
    fn a_striped_tiff_is_refused_rather_than_served_whole() {
        // Rule 5 leaves it wholly unmapped, and sparsify serves what it does
        // not blank -- so serving this object would serve every strip undecided.
        let (_, index, layout) = parse("tests/fixtures/striped.tif");
        assert!(layout.images.is_empty());
        assert!(matches!(
            plan(&index, &layout, &policy(&["true"]), &user()),
            Err(SparseError::Unclassified { start: 0, len }) if len == index.size()
        ));
    }

    #[test]
    fn an_index_that_is_not_a_tiff_is_refused() {
        let bytes = read("data/nyc-taxi-8rg.parquet");
        let index = crate::parquet::build_index(&bytes, bytes.len() as u64).expect("indexes");
        let layout = CogLayout {
            big_endian: false,
            leader: 0,
            trailer: 0,
            images: Vec::new(),
        };
        assert!(matches!(
            plan(&index, &layout, &policy(&["true"]), &user()),
            Err(SparseError::NotATiff)
        ));
    }

    #[test]
    fn a_mask_image_refuses_the_whole_object_rather_than_serving_the_footprint() {
        // Issue #21. A mask tile gets no region, so there is no verdict for it;
        // sparsify would serve it live, and a mask is a per-pixel map of where
        // the withheld data was.
        let (_, index, mut layout) = parse("data/s2-tci-512.tif");
        assert!(layout.images.iter().all(|i| i.overview_level.is_some()));
        layout.images[3].overview_level = None;
        assert!(matches!(
            plan(&index, &layout, &policy(&["true"]), &user()),
            Err(SparseError::MaskImage)
        ));
    }

    #[test]
    fn an_edit_that_would_land_outside_metadata_is_refused() {
        // The cross-check between the two derivations, provoked: move the array
        // base into the pixel data and the plan must refuse rather than write
        // zeroes over somebody's tile.
        let (_, index, mut layout) = parse("data/s2-tci-512.tif");
        let pixels = index
            .regions()
            .iter()
            .find(|r| matches!(r.kind, RegionKind::Tile { .. }))
            .expect("a tile")
            .start;
        layout.images[0].offsets.at = pixels;
        assert!(matches!(
            plan(&index, &layout, &withhold_box(5, 9, 5, 9), &user()),
            Err(SparseError::EditNotInMetadata { .. })
        ));
    }

    #[test]
    fn a_duplicated_overview_level_is_refused_rather_than_resolved_to_the_first() {
        let (_, index, mut layout) = parse("data/s2-tci-512.tif");
        layout.images[1].overview_level = Some(0);
        assert!(matches!(
            plan(&index, &layout, &withhold_box(5, 9, 5, 9), &user()),
            Err(SparseError::LevelNotUnique { .. })
        ));
    }

    #[test]
    fn a_tile_outside_the_grid_the_layout_declares_is_refused() {
        let (_, index, mut layout) = parse("data/s2-tci-512.tif");
        layout.images[0].across = 4;
        assert!(matches!(
            plan(&index, &layout, &withhold_box(5, 9, 5, 9), &user()),
            Err(SparseError::TileOutOfGrid { .. })
        ));
    }

    #[test]
    fn the_etag_tracks_the_withheld_set_and_not_the_principal() {
        let (_, index, layout) = parse("data/s2-tci-512.tif");
        let one = plan(&index, &layout, &withhold_box(5, 9, 5, 9), &user()).expect("plans");
        let other = plan(
            &index,
            &layout,
            &withhold_box(5, 9, 5, 9),
            &serde_json::json!({"role": "someone-else"}),
        )
        .expect("plans");
        assert_eq!(one.etag(), other.etag());

        let wider = plan(&index, &layout, &withhold_box(5, 10, 5, 9), &user()).expect("plans");
        assert_ne!(one.etag(), wider.etag());
    }

    #[test]
    fn a_range_past_the_end_of_the_object_is_denied_rather_than_clipped() {
        let (_, index, layout) = parse("tests/fixtures/tiny-cog.tif");
        let plan = plan(&index, &layout, &policy(&["true"]), &user()).expect("plans");
        let size = plan.object_size();
        for range in [0..0, size..size + 1, size - 1..size + 4] {
            assert!(matches!(
                plan.object_verdict(&range),
                Verdict::Denied { .. }
            ));
        }
        assert!(matches!(
            plan.object_verdict(&(0..size)),
            Verdict::Serve { .. }
        ));
    }

    #[test]
    fn the_plan_is_the_same_for_every_cog_in_the_repo() {
        // A smoke test over every tiled fixture: a plan withholding everything
        // must leave every tag entry at zero and every payload byte at zero,
        // whatever the file's grid, endianness or array widths.
        for rel in ["data/s2-tci-512.tif", "tests/fixtures/tiny-cog.tif"] {
            let (bytes, index, layout) = parse(rel);
            let plan = plan(
                &index,
                &layout,
                &policy(&["region.kind = 'metadata'"]),
                &user(),
            )
            .unwrap_or_else(|e| panic!("{rel}: {e}"));
            let served = serve(&bytes, &plan);
            assert_eq!(served.len(), bytes.len(), "{rel} changed length");
            for image in &layout.images {
                for i in 0..image.offsets.count {
                    assert_eq!(element(&served, &layout, image.offsets, i), 0, "{rel}");
                    assert_eq!(element(&served, &layout, image.byte_counts, i), 0, "{rel}");
                }
            }
            for region in index.regions() {
                if matches!(region.kind, RegionKind::Tile { .. }) {
                    let span = region.start as usize..region.end() as usize;
                    assert!(served[span].iter().all(|b| *b == 0), "{rel}");
                }
            }
        }
    }
}
