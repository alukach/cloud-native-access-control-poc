//! The COG resolver: a prefix of a tiled GeoTIFF in, a [`LayoutIndex`] out.
//!
//! [`build_index`] is synchronous and pure, like [`crate::parquet::build_index`]
//! and for the same reason: the caller reads the bytes and hands them over,
//! because the reader in a gateway already has a cache, a credential and a
//! retry policy, and this crate should have none of the three.
//!
//! # A prefix, not a suffix
//!
//! Parquet puts its footer at the end; TIFF puts everything at the front. The
//! header, GDAL's ghost area, every IFD and every tag value too large to sit
//! inside its IFD entry all precede the first pixel byte in a COG -- that is
//! what `LAYOUT=IFDS_BEFORE_DATA` in the ghost area declares. So `bytes` is a
//! contiguous **prefix** of the object, and the whole object is always a valid
//! argument because an object is a prefix of itself.
//!
//! How long a prefix is not knowable in advance -- it is a property of the file
//! -- so a buffer that stops short is refused with [`CogError::Truncated`],
//! which names the number of bytes **from the start** that would have reached
//! the structure the parse stopped at. A caller that guessed too small widens
//! its read and retries; following that advice terminates, because every answer
//! is strictly larger than the buffer that provoked it. Measured on the two
//! committed COGs: `tiny-cog.tif` needs its first 1,956 bytes of 18,907, and
//! the 5 MB `data/s2-tci-512.tif` needs its first 8,264. A 16 KiB speculative
//! prefix covers both in one read.
//!
//! This is a *prefix*, not "the metadata", and the distinction is rule 6's. A
//! plain GeoTIFF is free to put its IFD at the end of the file or to interleave
//! tag arrays with pixel data; such a file simply needs a longer prefix, up to
//! the whole object, and says so.
//!
//! # The format rules, each from a specification review
//!
//! 1. **A tile's bytes include GDAL's block leader and trailer.** A COG's ghost
//!    area declares `BLOCK_LEADER=SIZE_AS_UINT4` and
//!    `BLOCK_TRAILER=LAST_4_BYTES_REPEATED`, and `TileOffsets[i]` points at the
//!    PAYLOAD -- so a COG-aware reader fetches `offset - 4 .. offset + len + 4`.
//!    A resolver mapping only `[offset, offset + len)` makes every legitimate
//!    tile request overlap eight unclassified bytes and, under default-deny,
//!    denies all of them. The leader and trailer are therefore part of the tile
//!    region.
//!
//!    The sizes come from what the ghost area DECLARES, never from a constant:
//!    a TIFF without a ghost area must not have its tiles widened, or the first
//!    tile's region eats four bytes of somebody's tag array and every other one
//!    overlaps its neighbour. A declaration this resolver cannot size --
//!    anything but `SIZE_AS_UINT4` / `LAST_4_BYTES_REPEATED`, or
//!    `KNOWN_INCOMPATIBLE_EDITION=YES`, which is GDAL recording that a
//!    non-COG-aware writer has edited the file and the declarations may no
//!    longer hold -- is an error rather than a guess.
//!
//!    The leader's four bytes are never READ. They sit in the pixel data, which
//!    is outside the metadata prefix and attacker-controlled; the extent comes
//!    from `TileByteCounts` and from the declared leader and trailer sizes,
//!    both of which are in the prefix. A file whose leader lies is indexed
//!    exactly as one whose leader tells the truth.
//!
//!    The ghost area itself is a named metadata region, because unrecognized
//!    bytes deny and a reader must fetch the head of the file to find anything.
//!
//! 2. **`overview_level` is NOT the IFD index.** It is the rank of the image's
//!    `ImageWidth` among the distinct widths in the file, widest first, so that
//!    level 0 is full resolution and a higher level is always a COARSER image.
//!    The direction is the whole point: a policy meaning "overviews only" is
//!    written `region.overview_level >= N`, and an inverted scale grants full
//!    resolution. Rank rather than a computed ratio because the OGC COG
//!    standard permits 2-10x decimation per level, so the ratio is not
//!    necessarily a power of two or even integral -- `data/s2-tci-512.tif`
//!    steps 10980 / 5490 / 2745 / 1372 / 686 / 343, where three of the five
//!    steps are not exactly 2.
//!
//!    `NewSubfileType` (254) bit 0 marks a reduced-resolution image and bit 2 a
//!    mask; both set is a mask of an overview. Bit 0 is not used for numbering
//!    -- the width is the ground truth and the tag is only a claim -- but bit 2
//!    is honoured, because a mask is not a resolution level at all. See
//!    "Masks" below for how they are represented.
//!
//! 3. **`SubIFDs` (tag 330) is followed.** GDAL >= 3.2 hangs overviews and
//!    masks there rather than on the main next-IFD chain, and a resolver
//!    walking only the chain leaves all their tile bytes unmapped and therefore
//!    denied. Every SubIFD pointer is treated as the head of its own chain. The
//!    walk is an explicit queue rather than recursion (this crate compiles to
//!    wasm32, where a stack overflow aborts the module instance rather than
//!    unwinding), it refuses to visit an offset twice, and it is capped at
//!    [`MAX_IMAGES`].
//!
//! 4. **`PlanarConfiguration` (284) = 2 is refused.** The tile count becomes
//!    `SamplesPerPixel x TilesPerImage`, band-major, and
//!    [`RegionKind::Tile`] has no band component -- so every band past the
//!    first would be attributed to the wrong pixels, silently, with no gap for
//!    `Unmapped` to catch.
//!
//! 5. **A striped TIFF is classified as nothing at all.** A non-tiled image has
//!    no `TileOffsets`, so a tile resolver maps nothing -- and a conjunctive
//!    `all()` over an empty region set is vacuously TRUE. `LayoutIndex::try_new`
//!    closes that by filling the object with `Unmapped`, and this resolver
//!    leans on it: if ANY image in the file lacks tiles, NO regions at all are
//!    emitted, not even the metadata ones, and the whole object comes back
//!    unmapped and unreadable. Adding strip support is a separate decision;
//!    half-classifying such a file would leave the strips unmapped while
//!    granting a `region.kind = 'metadata'` rule over the header.
//!
//! 6. **The tag arrays are their own metadata regions.** A tag value over four
//!    bytes does not fit in its IFD entry, so `TileOffsets`, `TileByteCounts`
//!    and the GeoTIFF key arrays live between the IFDs and the pixel data.
//!    "The first N bytes are metadata" is wrong even for a well-formed COG, and
//!    these are bytes a reader MUST fetch to find the tiles at all -- unmapped
//!    metadata is a denial on the first read a reader makes.
//!
//!    `tiff` 0.11 resolves those values internally and its `Entry::offset` is
//!    crate-private, so where they live is recovered by scanning the 12-byte
//!    IFD entries directly out of `bytes`. The two parses are cross-checked:
//!    every tag `tiff` decoded must appear in the scan with the same field type
//!    and count, or the file is refused. The one gap is a tag whose TYPE this
//!    resolver does not know a size for: its value cannot be located, so it
//!    falls to `Unmapped`. No file measured so far reaches that path.
//!
//!    **A value's extent is its word-aligned slot, not its length.** TIFF 6.0
//!    requires every value to begin on a word boundary, so a value of ODD
//!    length is followed by one filler byte that belongs to no structure at
//!    all. GDAL writes `GDAL_METADATA` (42112) as ASCII of whatever length the
//!    metadata happens to be, and in a real Sentinel-2 COG
//!    (`sentinel-cogs.s3.us-west-2.amazonaws.com`,
//!    `S2A_10SEG_20240923_0_L2A/TCI.tif`) that value is 81 bytes ending at
//!    1303: one `Unmapped` byte in the middle of the metadata prefix, which
//!    denies EVERY read of the header -- the first read any reader makes. That
//!    is issue #23's COG half, and it is the harm this rule exists to prevent
//!    arriving one byte at a time.
//!
//!    So a gap of exactly one byte at an odd offset immediately after an
//!    out-of-line value is folded into that value's region. The word-aligned
//!    slot IS the value's footprint, and a filler byte is not a vocabulary
//!    word a policy author should have to write a rule about -- which is also
//!    why it gets no metadata name of its own. One byte and an odd offset are
//!    the only gap the alignment rule can produce; anything wider is something
//!    else and stays `Unmapped`. `tests/fixtures/odd-tag.tif` is the same file
//!    shape in 19 KB.
//!
//! 7. **Georeferencing is refused rather than guessed.** `ModelPixelScale`
//!    (33550) plus `ModelTiepoint` (33922), or `ModelTransformation` (34264),
//!    give the affine transform. A rotated or sheared one is an ERROR: a
//!    rotated tile is not an axis-aligned rectangle, its axis-aligned envelope
//!    covers ground the tile does not show, and a rule written
//!    `S_INTERSECTS(region.geom, <allowed area>)` would then grant tiles whose
//!    pixels are outside the allowed area. So is a GCP-only file (several
//!    tiepoints, no pixel scale), which has no affine transform to find. So is
//!    a file with no georeferencing at all -- a tile carrying pixel
//!    coordinates dressed as ground coordinates answers spatial rules wrongly.
//!
//!    Overview IFDs generally do NOT repeat the georeferencing tags, so the
//!    full-resolution transform is scaled per level by the width and height
//!    ratios. Every level then covers exactly the same ground, which is what an
//!    overview IS.
//!
//! 8. **The CRS is read** from `GeoKeyDirectory` (34735) -- the projected
//!    (3072) key, falling back to the geographic (2048) one -- and carried on
//!    every tile. `geo` is planar and CRS-agnostic, so a policy polygon in the
//!    wrong CRS silently matches everything (issue #5); this populates the
//!    field so that a later CRS check has something to check. A user-defined or
//!    absent code is left absent rather than null, per the no-null rule on
//!    [`Region::props`].
//!
//! 9. **BigTIFF is refused.** Every offset in one is eight bytes wide, so a
//!    classic-TIFF parse reads halves of offsets as whole ones. Out of scope
//!    has to mean an error rather than a partial classification; tracked as
//!    issue #6.
//!
//! # Masks
//!
//! A mask image's tiles are classified as **nothing**: they fall to `Unmapped`
//! and deny. [`RegionKind`] has no mask variant, and giving masks an
//! `overview_level` is the very mislabelling rule 2 exists to prevent -- a rule
//! meaning "coarse imagery only" would grant a full-resolution validity mask,
//! which is a per-pixel map of where the data is. Classifying them as
//! `Metadata` is worse: a blanket `region.kind = 'metadata'` allow is a policy
//! people really write, and pixel-derived bytes must never answer to it.
//!
//! The cost is real and is stated rather than hidden: a reader that fetches a
//! mask is denied, and GDAL fetches masks on its own initiative. The fix is a
//! `RegionKind::Mask { overview_level, x, y, bbox, crs }` plus a
//! `region.kind = 'mask'` vocabulary entry in `QUERYABLES`, which is a change
//! to `index.rs` and `policy.rs` that this task deliberately did not make
//! unannounced.
//!
//! # What is NOT classified
//!
//! Strips (rule 5), mask tiles (above), and the value of any tag whose field
//! type has no known size (rule 6). Every one of them is `Unmapped`, which
//! denies.

use crate::index::{IndexError, LayoutIndex, Region, RegionKind};
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::Cursor;
use tiff::decoder::Decoder;
use tiff::tags::{IfdPointer, Tag};

/// `II`/`MM`, the version, and the offset of the first IFD.
const HEADER_LEN: u64 = 8;
/// The first bytes of a GDAL ghost area, immediately after the header.
const GHOST_MARKER: &[u8] = b"GDAL_STRUCTURAL_METADATA_SIZE=";
/// What follows the decimal size in the ghost area's first line.
const GHOST_UNITS: &[u8] = b" bytes\n";
/// How much slack between the end of the declared ghost area and the first IFD
/// is read as GDAL's alignment padding and folded into the ghost region. More
/// than this and the slack is left to `Unmapped`: a large gap is not padding,
/// it is bytes this resolver has no account of.
const GHOST_PADDING_MAX: u64 = 16;
/// The cap on how many images one object may declare. A TIFF chain is a linked
/// list an attacker writes, and while the visited set already makes the walk
/// terminate, the cap bounds the work before it does.
const MAX_IMAGES: usize = 4096;

const NEW_SUBFILE_TYPE: u16 = 254;
const IMAGE_WIDTH: u16 = 256;
const IMAGE_LENGTH: u16 = 257;
const PLANAR_CONFIGURATION: u16 = 284;
const TILE_WIDTH: u16 = 322;
const TILE_LENGTH: u16 = 323;
const TILE_OFFSETS: u16 = 324;
const TILE_BYTE_COUNTS: u16 = 325;
const SUB_IFDS: u16 = 330;
const MODEL_PIXEL_SCALE: u16 = 33550;
const MODEL_TIEPOINT: u16 = 33922;
const MODEL_TRANSFORMATION: u16 = 34264;
const GEO_KEY_DIRECTORY: u16 = 34735;
const GEO_DOUBLE_PARAMS: u16 = 34736;
const GEO_ASCII_PARAMS: u16 = 34737;

/// `NewSubfileType` bit 2: this image is a transparency mask.
const SUBFILE_MASK: u64 = 0b100;
/// The GeoTIFF key whose value is the projected CRS's EPSG code.
const PROJECTED_CS_TYPE: u64 = 3072;
/// ...and the geographic one, used when there is no projected CRS.
const GEOGRAPHIC_TYPE: u64 = 2048;
/// Both of the above use this to mean "described by other keys, not by a code".
const USER_DEFINED: u64 = 32767;

/// Why a TIFF could not be turned into a layout index.
///
/// Every variant is a refusal to classify, and a refusal to classify is a
/// refusal to serve: there is no partial index. These are build-time errors on
/// a trusted path -- the object's owner is indexing their own object -- so
/// unlike [`DenyReason`](crate::decision::DenyReason) they may name the offset
/// that caused them.
///
/// A *striped* TIFF is deliberately not among them; see rule 5.
#[derive(Debug, thiserror::Error)]
pub enum CogError {
    /// Smaller than a TIFF header, so it cannot be a TIFF.
    #[error("object is {size} bytes, too small to be a TIFF")]
    TooSmall { size: u64 },
    /// The buffer is longer than the object it claims to describe, so it is not
    /// a prefix of it and every offset derived from it would be a guess.
    #[error("buffer is {buffer} bytes of a {size}-byte object")]
    NotAPrefix { buffer: u64, size: u64 },
    /// The buffer stops short of a structure the parse needed. `needed` is the
    /// number of bytes from the START of the object that would have reached it,
    /// and is always strictly more than the buffer that produced the error, so
    /// a caller that keeps widening its read terminates.
    #[error("metadata needs the first {needed} bytes of the object")]
    Truncated { needed: u64 },
    /// No `II`/`MM`, or a version that is not 42.
    #[error("not a TIFF: {0}")]
    NotTiff(String),
    /// Version 43. Out of scope; see rule 9 and issue #6.
    #[error("BigTIFF (version 43) is not supported")]
    BigTiff,
    /// Rule 4: band-major tiles, which region props cannot express.
    #[error("PlanarConfiguration = {planar} stores tiles band-major")]
    PlanarBandMajor { planar: u64 },
    /// Rule 1: a ghost area whose block leader or trailer this resolver cannot
    /// size, or one GDAL has flagged as edited by a non-COG-aware writer.
    #[error("ghost area is not one this resolver understands: {0}")]
    UnsupportedGhostArea(String),
    /// Rule 7: a rotated or sheared raster, whose tiles are not axis-aligned
    /// rectangles and whose envelopes would over-cover.
    #[error("raster is rotated or sheared, so a tile is not an axis-aligned rectangle")]
    RotatedTransform,
    /// Rule 7: georeferenced by ground control points, with no affine
    /// transform to derive a tile's coordinates from.
    #[error("georeferencing is {tiepoints} ground control points with no pixel scale")]
    GroundControlPoints { tiepoints: usize },
    /// Rule 7: no usable georeferencing tags at all.
    #[error("no georeferencing: a tile has no coordinates to answer a spatial rule with")]
    MissingGeoreferencing,
    /// The TIFF did not decode, or decoded into something self-contradictory.
    #[error("TIFF did not decode: {0}")]
    Malformed(String),
    /// Rule 3: the IFD walk hit its cap.
    #[error("object declares more than {limit} images")]
    TooManyImages { limit: usize },
    /// The regions this resolver produced are not a valid layout: they overlap,
    /// they run past the end of the object, or an extent overflows. Each means
    /// the file disagrees with itself or with the object size the caller
    /// supplied, and the whole index is refused rather than the offending
    /// region dropped -- a dropped region is a hole, and a hole hides that the
    /// file was lying even though `Unmapped` would deny it.
    #[error("TIFF does not describe a valid layout: {0}")]
    Layout(#[from] IndexError),
}

/// Where one out-of-line array of fixed-width integers physically lives.
///
/// This is the address [`crate::sparse`] writes zeroes at, and the reason the
/// COG analogue of footer rewrite needs no codec: `TileOffsets` and
/// `TileByteCounts` are arrays of fixed-width values, so withholding a tile is
/// a **same-length overwrite** rather than a re-serialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TileArray {
    /// Object offset of element 0.
    ///
    /// A value of four bytes or fewer -- a single-tile overview's `TileOffsets`
    /// -- lives INSIDE its twelve-byte IFD entry rather than at an offset, and
    /// this is the right address in both cases. Both committed COGs have such
    /// an image, so the inline case is not hypothetical.
    pub at: u64,
    /// The width of one element in bytes: 2 for SHORT, 4 for LONG.
    pub width: u8,
    /// How many elements, which is the image's tile count.
    pub count: u64,
}

/// One image's tile addressing: the grid, and where the two arrays that
/// address it live.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImageArrays {
    /// The `overview_level` this image's [`RegionKind::Tile`] regions carry, or
    /// `None` for a mask image -- which gets no tile regions at all, so there
    /// is no level to name (issue #21).
    pub overview_level: Option<u32>,
    /// Tiles across the image, so tile `(x, y)` is element `y * across + x`.
    pub across: u64,
    /// Tiles down the image.
    pub down: u64,
    pub offsets: TileArray,
    pub byte_counts: TileArray,
}

/// The physical addressing [`build_index`] computes and discards.
///
/// Emitted by [`build_index_with_layout`] rather than re-derived, for the
/// reason [`crate::rewrite`] gives about Parquet: a second offset derivation is
/// a second place to get the offsets wrong.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CogLayout {
    /// `MM` rather than `II`. Zeroes are endian-agnostic, so nothing in
    /// [`crate::sparse`] needs this; a caller reading the arrays back -- a test
    /// asserting an entry really did become zero -- does.
    pub big_endian: bool,
    /// The GDAL block leader width the ghost area declared, or 0.
    pub leader: u64,
    /// The GDAL block trailer width the ghost area declared, or 0.
    pub trailer: u64,
    /// One entry per IFD, in walk order. Empty for a striped TIFF, which
    /// classifies nothing (rule 5).
    pub images: Vec<ImageArrays>,
}

/// Parse a TIFF's metadata prefix into the layout index of the object it
/// belongs to.
///
/// `bytes` is a contiguous prefix of the object (the whole object is one) that
/// reaches the end of every structure the parse needs; `object_size` is the
/// object's full length, which is what a `Content-Length` or a HEAD gives the
/// caller. See the module docs for what "every structure" means and for how
/// [`CogError::Truncated`] lets a caller that guessed too small retry.
///
/// Coverage of `[0, object_size)` is total, because [`LayoutIndex::try_new`]
/// fills whatever this resolver did not claim with [`RegionKind::Unmapped`].
pub fn build_index(bytes: &[u8], object_size: u64) -> Result<LayoutIndex, CogError> {
    build_index_with_layout(bytes, object_size).map(|(index, _)| index)
}

/// [`build_index`], plus the physical addressing of every tile array.
///
/// The extra return value is what [`crate::sparse::plan`] needs and the index
/// cannot carry: a [`RegionKind::Tile`] says which tile it is and which bytes
/// it owns, but not where the two integers that point at it live.
pub fn build_index_with_layout(
    bytes: &[u8],
    object_size: u64,
) -> Result<(LayoutIndex, CogLayout), CogError> {
    let buffer = bytes.len() as u64;
    if buffer > object_size {
        return Err(CogError::NotAPrefix {
            buffer,
            size: object_size,
        });
    }
    if object_size < HEADER_LEN {
        return Err(CogError::TooSmall { size: object_size });
    }
    if buffer < HEADER_LEN {
        return Err(CogError::Truncated { needed: HEADER_LEN });
    }

    let big_endian = match &bytes[..2] {
        b"II" => false,
        b"MM" => true,
        other => {
            return Err(CogError::NotTiff(format!(
                "byte order is {other:?}, not II or MM"
            )))
        }
    };
    match read_u16(bytes, 2, big_endian) {
        Some(42) => {}
        // Rule 9. Detected before anything else is believed, because a
        // BigTIFF's 8-byte offsets would all be misread from here on.
        Some(43) => return Err(CogError::BigTiff),
        other => return Err(CogError::NotTiff(format!("version {other:?}, not 42"))),
    }
    let first_ifd = read_u32(bytes, 4, big_endian)
        .map(u64::from)
        .ok_or_else(|| CogError::NotTiff("no first IFD offset".into()))?;

    let ghost = Ghost::parse(bytes, first_ifd)?;
    let ifds = walk(bytes, big_endian, first_ifd, object_size)?;
    if ifds.is_empty() {
        return Err(CogError::NotTiff("no image file directory".into()));
    }

    // The values, read by `tiff` rather than by the scan above: coercing a
    // SHORT `TileOffsets` array to u64, or a RATIONAL to f64, is exactly the
    // work a TIFF library exists to do. The scan supplies what a library
    // cannot: where each value physically lives.
    let mut decoder =
        Decoder::new(Cursor::new(bytes)).map_err(|e| CogError::Malformed(e.to_string()))?;
    let mut images = Vec::with_capacity(ifds.len());
    let mut georeferencing = None;
    for raw in &ifds {
        let dir = decoder
            .read_directory(IfdPointer(raw.offset))
            .map_err(|e| CogError::Malformed(e.to_string()))?;
        // Rule 6's cross-check, in the only direction that is sound: `tiff`
        // silently skips an entry whose field type it does not know, so the
        // scan is a superset of the directory, and every tag the directory DID
        // decode must agree with the scan about its type and count. They read
        // the same twelve bytes, so a disagreement means the scan is looking in
        // the wrong place -- and every offset it recovered is then a guess.
        //
        // Through a map and not a linear search per tag: an IFD may declare
        // 65,535 entries, and a quadratic walk over an attacker-chosen count is
        // a way to spend four billion comparisons on one small file.
        let scanned: HashMap<u16, &RawEntry> = raw.entries.iter().map(|e| (e.tag, e)).collect();
        for (tag, entry) in dir.iter() {
            let number = tag.to_u16();
            let agrees = scanned.get(&number).is_some_and(|e| {
                e.field_type == entry.field_type().to_u16() && e.count == entry.count()
            });
            if !agrees {
                return Err(CogError::Malformed(format!(
                    "IFD at {} disagrees with itself about tag {number}",
                    raw.offset
                )));
            }
        }
        let mut tags = decoder.read_directory_tags(&dir);

        let scalar = |tags: &mut tiff::decoder::IfdDecoder<'_>, tag: u16| {
            tags.find_tag_unsigned::<u64>(known(tag))
                .map_err(|e| CogError::Malformed(e.to_string()))
        };
        let vector = |tags: &mut tiff::decoder::IfdDecoder<'_>, tag: u16| {
            tags.find_tag_unsigned_vec::<u64>(known(tag))
                .map_err(|e| CogError::Malformed(e.to_string()))
        };
        let doubles = |tags: &mut tiff::decoder::IfdDecoder<'_>, tag: u16| {
            tags.find_tag(known(tag))
                .map_err(|e| CogError::Malformed(e.to_string()))?
                .map(|value| value.into_f64_vec())
                .transpose()
                .map_err(|e| CogError::Malformed(e.to_string()))
        };

        // Rule 4, checked before any tile offset is believed: with band-major
        // tiles the array below means something this resolver cannot express.
        match scalar(&mut tags, PLANAR_CONFIGURATION)? {
            None | Some(1) => {}
            Some(planar) => return Err(CogError::PlanarBandMajor { planar }),
        }

        let offsets = vector(&mut tags, TILE_OFFSETS)?;
        let Some(offsets) = offsets else {
            // Rule 5: a striped image. Nothing in this object is classified --
            // and an empty layout is the honest companion to an empty index,
            // because there is no tile array to address.
            return Ok((
                LayoutIndex::try_new(Vec::new(), object_size)?,
                CogLayout {
                    big_endian,
                    leader: 0,
                    trailer: 0,
                    images: Vec::new(),
                },
            ));
        };
        let lengths = vector(&mut tags, TILE_BYTE_COUNTS)?.unwrap_or_default();
        if offsets.len() != lengths.len() {
            return Err(CogError::Malformed(format!(
                "IFD at {}: {} tile offsets but {} byte counts",
                raw.offset,
                offsets.len(),
                lengths.len()
            )));
        }

        // Where the two arrays physically are. From the SCAN, which is the only
        // parse that knows: `tiff` 0.11 resolves a value and forgets its
        // address. An array of four bytes or fewer never left its IFD entry, so
        // its base is the entry's own value field.
        let placement = |tag: u16| -> Result<TileArray, CogError> {
            let entry = scanned.get(&tag).ok_or_else(|| {
                CogError::Malformed(format!("IFD at {}: no tag {tag}", raw.offset))
            })?;
            let width = match type_size(entry.field_type) {
                2 => 2u8,
                4 => 4u8,
                other => {
                    return Err(CogError::Malformed(format!(
                        "IFD at {}: tag {tag} has {other}-byte elements, not SHORT or LONG",
                        raw.offset
                    )))
                }
            };
            Ok(TileArray {
                at: entry.value.map_or(entry.at + 8, |(start, _)| start),
                width,
                count: entry.count,
            })
        };
        let arrays = (placement(TILE_OFFSETS)?, placement(TILE_BYTE_COUNTS)?);
        if arrays.0.count != offsets.len() as u64 || arrays.1.count != lengths.len() as u64 {
            return Err(CogError::Malformed(format!(
                "IFD at {}: the tile array scan and the decoded values disagree about length",
                raw.offset
            )));
        }

        let require = |value: Option<u64>, tag: u16| {
            value
                .filter(|v| *v > 0)
                .ok_or_else(|| CogError::Malformed(format!("IFD at {}: no tag {tag}", raw.offset)))
        };
        let image = ImageLayout {
            arrays,
            width: require(scalar(&mut tags, IMAGE_WIDTH)?, IMAGE_WIDTH)?,
            height: require(scalar(&mut tags, IMAGE_LENGTH)?, IMAGE_LENGTH)?,
            tile_width: require(scalar(&mut tags, TILE_WIDTH)?, TILE_WIDTH)?,
            tile_height: require(scalar(&mut tags, TILE_LENGTH)?, TILE_LENGTH)?,
            is_mask: scalar(&mut tags, NEW_SUBFILE_TYPE)?.unwrap_or(0) & SUBFILE_MASK != 0,
            tiles: offsets.into_iter().zip(lengths).collect(),
        };

        if georeferencing.is_none() {
            // Rule 7: from the first image, which is the full-resolution one.
            // Overviews do not repeat these tags.
            georeferencing = Some(Georeferencing {
                transform: Transform::build(
                    doubles(&mut tags, MODEL_PIXEL_SCALE)?,
                    doubles(&mut tags, MODEL_TIEPOINT)?,
                    doubles(&mut tags, MODEL_TRANSFORMATION)?,
                )?,
                crs: vector(&mut tags, GEO_KEY_DIRECTORY)?
                    .as_deref()
                    .and_then(crs_from_geokeys),
            });
        }
        images.push(image);
    }

    let geo = georeferencing.expect("at least one IFD, so georeferencing was read");

    // Rule 2: the levels, widest first, so that level 0 is full resolution.
    let mut widths: Vec<u64> = images
        .iter()
        .filter(|i| !i.is_mask)
        .map(|i| i.width)
        .collect();
    widths.sort_unstable();
    widths.dedup();
    widths.reverse();
    let full = *widths
        .first()
        .ok_or_else(|| CogError::Malformed("every image in the object is a mask".into()))?;
    if images[0].is_mask || images[0].width != full {
        return Err(CogError::Malformed(
            "the first IFD is not the full-resolution image".into(),
        ));
    }
    let full_height = images[0].height;

    let mut regions = vec![Region {
        start: 0,
        len: HEADER_LEN,
        kind: named("header"),
    }];
    if let Some(ghost) = &ghost {
        regions.push(Region {
            start: HEADER_LEN,
            len: ghost.end - HEADER_LEN,
            kind: named("ghost_area"),
        });
    }
    // Rule 6. A value extent claimed twice -- two tags sharing one buffer -- is
    // emitted once; a PARTIAL overlap is left for `try_new` to refuse, because
    // it means the two tags disagree about where their values end.
    let mut claimed = HashSet::new();
    for raw in &ifds {
        regions.push(Region {
            start: raw.offset,
            len: raw.len,
            kind: named("ifd"),
        });
        for entry in &raw.entries {
            if let Some((start, len)) = entry.value {
                if claimed.insert((start, len)) {
                    regions.push(Region {
                        start,
                        len,
                        kind: named(value_region_name(entry.tag)),
                    });
                }
            }
        }
    }

    let (leader, trailer) = ghost.map_or((0, 0), |g| (g.leader, g.trailer));
    let mut layout_images = Vec::with_capacity(images.len());
    for image in &images {
        let across = image.width.div_ceil(image.tile_width);
        let down = image.height.div_ceil(image.tile_height);
        // Masks get no tile regions; see the module docs. They DO get a layout
        // entry, carrying no level, so that a caller can see the object has a
        // mask it cannot reason about rather than silently not find one --
        // which is what `sparse::plan` refuses on.
        let level = (!image.is_mask).then(|| {
            widths
                .iter()
                .position(|w| *w == image.width)
                .expect("every non-mask width is in the list") as u32
        });
        layout_images.push(ImageArrays {
            overview_level: level,
            across,
            down,
            offsets: image.arrays.0,
            byte_counts: image.arrays.1,
        });
        let Some(level) = level else {
            continue;
        };
        if across.checked_mul(down) != Some(image.tiles.len() as u64) {
            return Err(CogError::Malformed(format!(
                "a {across}x{down} tile grid but {} tile offsets",
                image.tiles.len()
            )));
        }
        // Rule 7: the full-resolution transform, resampled to this level. Every
        // level covers the same ground, so the origin does not move and only
        // the pixel size changes.
        let sx = geo.transform.sx * full as f64 / image.width as f64;
        let sy = geo.transform.sy * full_height as f64 / image.height as f64;

        for (i, (offset, len)) in image.tiles.iter().enumerate() {
            // A sparse tile (GDAL's SPARSE_OK) is offset 0, length 0. It owns
            // no bytes, so it has nothing to say about authorization, and
            // widening it by the leader would underflow.
            if *len == 0 {
                continue;
            }
            let i = i as u64;
            let (x, y) = (i % across, i / across);
            let left = x * image.tile_width;
            let top = y * image.tile_height;
            // Clipped to the image: the edge tiles are padded out to a full
            // tile in the file, and the padding shows no ground.
            let right = (left + image.tile_width).min(image.width);
            let bottom = (top + image.tile_height).min(image.height);
            let bbox = [
                geo.transform.origin_x + left as f64 * sx,
                geo.transform.origin_y + top as f64 * sy,
                geo.transform.origin_x + right as f64 * sx,
                geo.transform.origin_y + bottom as f64 * sy,
            ];
            // Rule 1: the payload plus its leader and trailer.
            let start = offset.checked_sub(leader).ok_or_else(|| {
                CogError::Malformed(format!(
                    "tile at {offset} starts inside its {leader}-byte block leader"
                ))
            })?;
            let len = len
                .checked_add(leader + trailer)
                .ok_or_else(|| CogError::Malformed(format!("tile at {offset} overflows a u64")))?;
            regions.push(Region {
                start,
                len,
                kind: RegionKind::Tile {
                    overview_level: level,
                    x: u32::try_from(x).map_err(|_| CogError::Malformed("tile x".into()))?,
                    y: u32::try_from(y).map_err(|_| CogError::Malformed("tile y".into()))?,
                    bbox,
                    crs: geo.crs,
                },
            });
        }
    }

    pad_word_aligned_values(&mut regions);

    Ok((
        LayoutIndex::try_new(regions, object_size)?,
        CogLayout {
            big_endian,
            leader,
            trailer,
            images: layout_images,
        },
    ))
}

fn named(name: &str) -> RegionKind {
    RegionKind::Metadata { name: name.into() }
}

/// The metadata name for an out-of-line tag value. The set is CLOSED: `tiff`'s
/// `Tag` enum is open and a name derived from it would be a new vocabulary word
/// for every private tag any writer ever invents, which is not a vocabulary a
/// policy author can be expected to enumerate.
fn value_region_name(tag: u16) -> &'static str {
    match tag {
        TILE_OFFSETS => "tile_offsets",
        TILE_BYTE_COUNTS => "tile_byte_counts",
        GEO_KEY_DIRECTORY | GEO_DOUBLE_PARAMS | GEO_ASCII_PARAMS => "geo_keys",
        _ => "tag_values",
    }
}

/// Every name [`value_region_name`] can return, which is exactly the set of
/// regions [`pad_word_aligned_values`] may extend.
const VALUE_REGION_NAMES: [&str; 4] =
    ["tile_offsets", "tile_byte_counts", "geo_keys", "tag_values"];

/// Rule 6, the alignment half: fold TIFF's word-alignment pad byte into the
/// value it follows.
///
/// A value of odd length is followed by one filler byte that belongs to no
/// structure, because the next value has to start on a word boundary. Left
/// alone it is an `Unmapped` byte inside the metadata prefix, and unmapped
/// metadata denies the first read a reader makes -- which for a Sentinel-2 COG
/// it did, at byte 1303. See rule 6 in the module docs.
///
/// A gap is bytes no region holds, so extending a region into one can neither
/// take a byte from another region nor create the overlap
/// [`LayoutIndex::try_new`] refuses. Nothing else is claimed: not a wider gap,
/// not a gap at an even offset, and not a gap after a region that is not a tag
/// value.
fn pad_word_aligned_values(regions: &mut [Region]) {
    let mut order: Vec<usize> = (0..regions.len()).collect();
    order.sort_by_key(|i| regions[*i].start);
    for pair in order.windows(2) {
        let (before, after) = (pair[0], pair[1]);
        let end = regions[before].end();
        // An even end is already on a word boundary, so whatever follows it is
        // not alignment padding.
        if end.is_multiple_of(2) || Some(regions[after].start) != end.checked_add(1) {
            continue;
        }
        let is_value = matches!(&regions[before].kind,
            RegionKind::Metadata { name } if VALUE_REGION_NAMES.contains(&name.as_str()));
        if is_value {
            regions[before].len += 1;
        }
    }
}

/// `tiff`'s `Tag` for a raw tag number. `from_u16_exhaustive` rather than
/// `Tag::Unknown`, so a tag the library has a name for is spelled the way the
/// library spells it and the `BTreeMap` lookup cannot miss.
fn known(tag: u16) -> Tag {
    Tag::from_u16_exhaustive(tag)
}

/// What one image contributes: its grid, and where its tiles are.
struct ImageLayout {
    width: u64,
    height: u64,
    tile_width: u64,
    tile_height: u64,
    is_mask: bool,
    /// Where `TileOffsets` and `TileByteCounts` physically live.
    arrays: (TileArray, TileArray),
    /// `(offset, byte count)` per tile, in row-major order.
    tiles: Vec<(u64, u64)>,
}

struct Georeferencing {
    transform: Transform,
    crs: Option<u32>,
}

/// An axis-aligned affine transform: `x = origin_x + column * sx`, and
/// `y = origin_y + row * sy` with `sy` negative for a north-up raster.
struct Transform {
    origin_x: f64,
    origin_y: f64,
    sx: f64,
    sy: f64,
}

impl Transform {
    fn build(
        scale: Option<Vec<f64>>,
        tiepoint: Option<Vec<f64>>,
        matrix: Option<Vec<f64>>,
    ) -> Result<Self, CogError> {
        // `ModelTransformation` wins where both are present, which is what GDAL
        // does and what the GeoTIFF specification's precedence implies.
        if let Some(m) = matrix {
            if m.len() < 16 {
                return Err(CogError::Malformed(format!(
                    "ModelTransformation has {} values, not 16",
                    m.len()
                )));
            }
            // The two off-diagonal terms of the 2x2 block: column -> northing
            // and row -> easting. Either one non-zero and the tile is a rotated
            // rectangle whose envelope over-covers. See rule 7.
            if m[1] != 0.0 || m[4] != 0.0 {
                return Err(CogError::RotatedTransform);
            }
            return Self::finite(m[3], m[7], m[0], m[5]);
        }
        match (scale, tiepoint) {
            // More than one tiepoint is a GCP list, not an origin, whether or
            // not a pixel scale came with it.
            (_, Some(t)) if t.len() > 6 && t.len() % 6 == 0 => Err(CogError::GroundControlPoints {
                tiepoints: t.len() / 6,
            }),
            (Some(s), Some(t)) if s.len() >= 3 && t.len() >= 6 => {
                let (sx, sy) = (s[0], -s[1]);
                // The tiepoint ties raster point (t0, t1) to model point
                // (t3, t4); it is (0, 0) in every file GDAL writes, but a file
                // that ties a different pixel must not be read as if it tied
                // the origin.
                Self::finite(t[3] - t[0] * sx, t[4] - t[1] * sy, sx, sy)
            }
            _ => Err(CogError::MissingGeoreferencing),
        }
    }

    fn finite(origin_x: f64, origin_y: f64, sx: f64, sy: f64) -> Result<Self, CogError> {
        // A NaN or an infinity here becomes a NaN bbox, which `try_new` refuses
        // anyway -- but it would refuse it as a layout error, naming a byte
        // offset, rather than as the georeferencing problem it is. A zero pixel
        // size collapses every tile to a line, so no tile intersects anything
        // and a spatial policy quietly denies the whole object.
        if ![origin_x, origin_y, sx, sy].iter().all(|v| v.is_finite()) {
            return Err(CogError::Malformed(
                "georeferencing contains a non-finite value".into(),
            ));
        }
        if sx == 0.0 || sy == 0.0 {
            return Err(CogError::Malformed("pixel size is zero".into()));
        }
        Ok(Self {
            origin_x,
            origin_y,
            sx,
            sy,
        })
    }
}

/// The EPSG code a GeoTIFF key directory names, if it names one.
///
/// The directory is a flat `u16` array: four header values -- version,
/// revision, minor revision, and the number of keys -- then four per key:
/// the key's id, the tag its value lives in (0 meaning "the value is right
/// here"), a count, and the value or an index into that tag.
fn crs_from_geokeys(keys: &[u64]) -> Option<u32> {
    let count = *keys.get(3)? as usize;
    let mut projected = None;
    let mut geographic = None;
    for i in 0..count {
        let key = keys.get(4 + i * 4..8 + i * 4)?;
        // A key whose value lives in another tag is a `double` or a string, and
        // neither is an EPSG code.
        if key[1] != 0 {
            continue;
        }
        match key[0] {
            PROJECTED_CS_TYPE => projected = Some(key[3]),
            GEOGRAPHIC_TYPE => geographic = Some(key[3]),
            _ => {}
        }
    }
    projected
        .or(geographic)
        .filter(|code| *code != 0 && *code != USER_DEFINED)
        .and_then(|code| u32::try_from(code).ok())
}

/// GDAL's ghost area: the block layout it declares, and where it ends.
struct Ghost {
    /// One past the last byte the `ghost_area` region covers.
    end: u64,
    leader: u64,
    trailer: u64,
}

impl Ghost {
    /// `Ok(None)` when the object has no ghost area, which is the normal case
    /// for a TIFF that is not a GDAL COG and must NOT be read as a declaration
    /// of a zero-length leader on a file that has one.
    fn parse(bytes: &[u8], first_ifd: u64) -> Result<Option<Self>, CogError> {
        let at = HEADER_LEN as usize;
        if bytes.len() < at + GHOST_MARKER.len() || !bytes[at..].starts_with(GHOST_MARKER) {
            return Ok(None);
        }
        let rest = &bytes[at + GHOST_MARKER.len()..];
        let digits = rest.iter().take_while(|b| b.is_ascii_digit()).count();
        let unsized_header = || {
            CogError::UnsupportedGhostArea(
                "first line is not `GDAL_STRUCTURAL_METADATA_SIZE=<n> bytes`".into(),
            )
        };
        if digits == 0 || digits > 12 || !rest[digits..].starts_with(GHOST_UNITS) {
            return Err(unsized_header());
        }
        let declared: u64 = std::str::from_utf8(&rest[..digits])
            .map_err(|_| unsized_header())?
            .parse()
            .map_err(|_| unsized_header())?;
        let start = HEADER_LEN + (GHOST_MARKER.len() + digits + GHOST_UNITS.len()) as u64;
        let end = start
            .checked_add(declared)
            .ok_or_else(|| CogError::UnsupportedGhostArea("declared size overflows".into()))?;
        if end > first_ifd {
            return Err(CogError::UnsupportedGhostArea(format!(
                "declares {declared} bytes, running past the first IFD at {first_ifd}"
            )));
        }
        if end > bytes.len() as u64 {
            return Err(CogError::Truncated { needed: end });
        }

        let mut leader = 0;
        let mut trailer = 0;
        let body = String::from_utf8_lossy(&bytes[start as usize..end as usize]);
        for line in body.split('\n') {
            // GDAL pads the declared area with spaces and NULs.
            let Some((key, value)) = line.trim_matches(['\0', ' ', '\r']).split_once('=') else {
                continue;
            };
            let refuse = || {
                Err(CogError::UnsupportedGhostArea(format!(
                    "{key}={value} is not a block layout this resolver can size"
                )))
            };
            match key {
                // Rule 1: sized from the declaration, never from a constant.
                "BLOCK_LEADER" if value == "SIZE_AS_UINT4" => leader = 4,
                "BLOCK_TRAILER" if value == "LAST_4_BYTES_REPEATED" => trailer = 4,
                "BLOCK_LEADER" | "BLOCK_TRAILER" => return refuse(),
                // GDAL sets this when a writer that does not understand the
                // ghost area has edited the file -- which is exactly when the
                // declarations above stop being true of the bytes.
                "KNOWN_INCOMPATIBLE_EDITION" if value != "NO" => return refuse(),
                _ => {}
            }
        }
        // Fold GDAL's alignment padding into the region rather than leaving a
        // handful of bytes unmapped between the ghost area and the first IFD:
        // a reader fetching the head of the file reads straight through them,
        // and one unmapped byte in that span denies the whole read.
        let end = if first_ifd - end <= GHOST_PADDING_MAX {
            first_ifd
        } else {
            end
        };
        Ok(Some(Ghost {
            end,
            leader,
            trailer,
        }))
    }
}

/// One IFD's physical layout: where it is, and where each of its out-of-line
/// tag values is.
struct RawIfd {
    offset: u64,
    /// The entry array and its terminating next-IFD pointer.
    len: u64,
    entries: Vec<RawEntry>,
    next: u64,
}

struct RawEntry {
    /// The entry's own twelve bytes, needed because a value that fits in four
    /// bytes is stored right here rather than at an offset.
    at: u64,
    tag: u16,
    field_type: u16,
    count: u64,
    /// `(start, len)` when the value did not fit in the entry. `None` for an
    /// inline value, an empty one, and one whose field type has no known size
    /// -- see rule 6 for the last of those.
    value: Option<(u64, u64)>,
}

/// Every IFD reachable from `first`, along the next-IFD chain and through
/// `SubIFDs`, in the order they were discovered.
fn walk(
    bytes: &[u8],
    big_endian: bool,
    first: u64,
    object_size: u64,
) -> Result<Vec<RawIfd>, CogError> {
    let mut queue = VecDeque::from([first]);
    let mut seen = HashSet::new();
    let mut out: Vec<RawIfd> = Vec::new();
    while let Some(mut offset) = queue.pop_front() {
        // An offset of zero terminates a chain, and an offset already visited
        // is a cycle: stop this chain rather than the whole walk, so a file
        // that loops one overview back on itself still classifies the rest.
        while offset != 0 && seen.insert(offset) {
            if out.len() >= MAX_IMAGES {
                return Err(CogError::TooManyImages { limit: MAX_IMAGES });
            }
            let ifd = scan_ifd(bytes, big_endian, offset, object_size)?;
            // Rule 3. Each pointer is the head of its own chain.
            if let Some(entry) = ifd.entries.iter().find(|e| e.tag == SUB_IFDS) {
                queue.extend(entry_integers(bytes, big_endian, entry));
            }
            offset = ifd.next;
            out.push(ifd);
        }
    }
    Ok(out)
}

/// The byte width of a TIFF field type, or zero for one this resolver does not
/// know -- which is the same answer the specification gives a reader: skip it.
fn type_size(field_type: u16) -> u64 {
    match field_type {
        1 | 2 | 6 | 7 => 1,              // BYTE, ASCII, SBYTE, UNDEFINED
        3 | 8 => 2,                      // SHORT, SSHORT
        4 | 9 | 11 | 13 => 4,            // LONG, SLONG, FLOAT, IFD
        5 | 10 | 12 | 16 | 17 | 18 => 8, // RATIONAL, SRATIONAL, DOUBLE, LONG8, SLONG8, IFD8
        _ => 0,
    }
}

fn scan_ifd(
    bytes: &[u8],
    big_endian: bool,
    offset: u64,
    object_size: u64,
) -> Result<RawIfd, CogError> {
    // A structure past the end of the OBJECT is a lie the file told; one past
    // the end of the BUFFER is a prefix the caller cut too short. The two are
    // different answers and only the second is worth retrying.
    let reach = |end: u64| -> Result<(), CogError> {
        if end > object_size {
            return Err(CogError::Malformed(format!(
                "a structure ends at {end}, past the end of the {object_size}-byte object"
            )));
        }
        if end > bytes.len() as u64 {
            return Err(CogError::Truncated { needed: end });
        }
        Ok(())
    };
    let overflow = || CogError::Malformed(format!("IFD at {offset} overflows a u64"));

    reach(offset.checked_add(2).ok_or_else(overflow)?)?;
    let count = u64::from(read_u16(bytes, offset, big_endian).ok_or_else(overflow)?);
    let len = 2 + count * 12 + 4; // at most 2 + 65535 * 12 + 4
    let end = offset.checked_add(len).ok_or_else(overflow)?;
    reach(end)?;

    let mut entries = Vec::with_capacity(count as usize);
    for i in 0..count {
        let at = offset + 2 + i * 12;
        let tag = read_u16(bytes, at, big_endian).ok_or_else(overflow)?;
        let field_type = read_u16(bytes, at + 2, big_endian).ok_or_else(overflow)?;
        let values = u64::from(read_u32(bytes, at + 4, big_endian).ok_or_else(overflow)?);
        let size = type_size(field_type)
            .checked_mul(values)
            .ok_or_else(overflow)?;
        // Four bytes or fewer live in the entry itself; a size of zero is
        // either an empty value or a field type with no known width, and in
        // neither case is there an extent to claim.
        let value = if size == 0 || size <= 4 {
            None
        } else {
            let start = u64::from(read_u32(bytes, at + 8, big_endian).ok_or_else(overflow)?);
            reach(start.checked_add(size).ok_or_else(overflow)?)?;
            Some((start, size))
        };
        entries.push(RawEntry {
            at,
            tag,
            field_type,
            count: values,
            value,
        });
    }
    let next =
        u64::from(read_u32(bytes, offset + 2 + count * 12, big_endian).ok_or_else(overflow)?);
    Ok(RawIfd {
        offset,
        len,
        entries,
        next,
    })
}

/// An entry's values, read as integers. Only used for `SubIFDs`, which has to
/// be read during the scan -- before there is a `Directory` to ask -- because
/// it is what decides which directories exist.
fn entry_integers(bytes: &[u8], big_endian: bool, entry: &RawEntry) -> Vec<u64> {
    let size = type_size(entry.field_type);
    if !matches!(entry.field_type, 3 | 4 | 13) {
        return Vec::new();
    }
    let base = entry.value.map_or(entry.at + 8, |(start, _)| start);
    (0..entry.count)
        .filter_map(|i| {
            let at = base + i * size;
            match size {
                2 => read_u16(bytes, at, big_endian).map(u64::from),
                _ => read_u32(bytes, at, big_endian).map(u64::from),
            }
        })
        .collect()
}

/// Bounds-checked, endianness-aware reads. `Option` rather than an index, so
/// that a crafted offset is an error and not a panic: this crate compiles to
/// wasm32, where the panic runtime aborts the module instance.
fn read_u16(bytes: &[u8], at: u64, big_endian: bool) -> Option<u16> {
    let raw: [u8; 2] = bytes
        .get(usize::try_from(at).ok()?..)?
        .get(..2)?
        .try_into()
        .ok()?;
    Some(if big_endian {
        u16::from_be_bytes(raw)
    } else {
        u16::from_le_bytes(raw)
    })
}

fn read_u32(bytes: &[u8], at: u64, big_endian: bool) -> Option<u32> {
    let raw: [u8; 4] = bytes
        .get(usize::try_from(at).ok()?..)?
        .get(..4)?
        .try_into()
        .ok()?;
    Some(if big_endian {
        u32::from_be_bytes(raw)
    } else {
        u32::from_le_bytes(raw)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::{check, Decision, DenyReason};
    use crate::index::{Region, RegionKind};
    use crate::policy::{Policy, QUERYABLES};
    use serde_json::json;
    use std::path::{Path, PathBuf};

    // ---- fixtures ----------------------------------------------------------

    fn repo(rel: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join(rel)
    }

    fn read(rel: &str) -> Vec<u8> {
        std::fs::read(repo(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
    }

    /// Every TIFF committed to this repository, found by walking the
    /// directories rather than by listing names, so a fixture added later is
    /// covered by the invariant tests without anyone remembering to add it.
    fn every_tiff_file() -> Vec<(String, Vec<u8>)> {
        let mut found = Vec::new();
        for dir in ["data", "tests/fixtures"] {
            for entry in std::fs::read_dir(repo(dir)).unwrap() {
                let path = entry.unwrap().path();
                if path.extension().is_some_and(|e| e == "tif") {
                    let bytes = std::fs::read(&path).unwrap();
                    found.push((path.file_name().unwrap().to_string_lossy().into(), bytes));
                }
            }
        }
        found.sort_by(|a: &(String, Vec<u8>), b| a.0.cmp(&b.0));
        // The loop is only an invariant test while it really loops over
        // something: an empty `read_dir` would make every assertion pass.
        assert!(
            found.len() >= 4,
            "expected the committed fixtures: {found:?}"
        );
        found
    }

    /// The whole object is a valid `bytes` argument -- it is a prefix of
    /// itself -- and it is what a test has in hand.
    fn index(bytes: &[u8]) -> LayoutIndex {
        build_index(bytes, bytes.len() as u64).expect("build_index")
    }

    fn tiles(idx: &LayoutIndex) -> Vec<&Region> {
        idx.regions()
            .iter()
            .filter(|r| matches!(r.kind, RegionKind::Tile { .. }))
            .collect()
    }

    /// The tile region for `(level, x, y)`, as `(start, end)`.
    fn tile_at(idx: &LayoutIndex, level: u32, x: u32, y: u32) -> (u64, u64) {
        let found: Vec<_> = idx
            .regions()
            .iter()
            .filter(|r| {
                matches!(&r.kind, RegionKind::Tile { overview_level, x: tx, y: ty, .. }
                    if *overview_level == level && *tx == x && *ty == y)
            })
            .collect();
        assert_eq!(found.len(), 1, "tile {level}/{x}/{y}: {found:?}");
        (found[0].start, found[0].end())
    }

    fn levels(idx: &LayoutIndex) -> Vec<u32> {
        let mut seen: Vec<u32> = tiles(idx)
            .iter()
            .filter_map(|r| match r.kind {
                RegionKind::Tile { overview_level, .. } => Some(overview_level),
                _ => None,
            })
            .collect();
        seen.sort_unstable();
        seen.dedup();
        seen
    }

    fn tiles_at_level(idx: &LayoutIndex, level: u32) -> usize {
        tiles(idx)
            .iter()
            .filter(|r| matches!(r.kind, RegionKind::Tile { overview_level, .. } if overview_level == level))
            .count()
    }

    fn metadata_named<'a>(idx: &'a LayoutIndex, name: &str) -> Vec<&'a Region> {
        idx.regions()
            .iter()
            .filter(|r| matches!(&r.kind, RegionKind::Metadata { name: n } if n == name))
            .collect()
    }

    fn unmapped_bytes(idx: &LayoutIndex) -> u64 {
        idx.regions()
            .iter()
            .filter(|r| matches!(r.kind, RegionKind::Unmapped))
            .map(|r| r.len)
            .sum()
    }

    fn header(start: u64, end: u64) -> String {
        format!("bytes={start}-{}", end - 1)
    }

    fn denied() -> Decision {
        Decision::Denied {
            reason: DenyReason::NotPermitted,
        }
    }

    // ---- a synthetic, genuinely formatted TIFF ------------------------------

    /// A tag value for [`synth`].
    #[derive(Clone)]
    enum V {
        Short(Vec<u16>),
        Long(Vec<u32>),
        Double(Vec<f64>),
    }

    impl V {
        fn field_type(&self) -> u16 {
            match self {
                V::Short(_) => 3,
                V::Long(_) => 4,
                V::Double(_) => 12,
            }
        }
        fn count(&self) -> u32 {
            match self {
                V::Short(v) => v.len() as u32,
                V::Long(v) => v.len() as u32,
                V::Double(v) => v.len() as u32,
            }
        }
        fn bytes(&self) -> Vec<u8> {
            match self {
                V::Short(v) => v.iter().flat_map(|n| n.to_le_bytes()).collect(),
                V::Long(v) => v.iter().flat_map(|n| n.to_le_bytes()).collect(),
                V::Double(v) => v.iter().flat_map(|n| n.to_le_bytes()).collect(),
            }
        }
    }

    /// A real, minimal, single-IFD tiled TIFF: 128x64 pixels in a 2x1 grid of
    /// 64x64 uncompressed 8-bit tiles.
    ///
    /// The committed fixtures cover every case a real GDAL writer produces.
    /// This covers the ones it does not: a `ModelTransformation`, a rotated
    /// raster, a GCP-only file, no georeferencing at all, and a tiled TIFF with
    /// no ghost area. Building those by doctoring `tiny-cog.tif` would mean
    /// resizing an IFD entry array and re-deriving every offset after it, which
    /// is a TIFF writer wearing a disguise. This is the writer, undisguised,
    /// and every offset a test asserts against is one it computed here.
    ///
    /// `ghost` is the BODY of the GDAL ghost area; the size-declaring first
    /// line is written for you. The tile data is laid out with the block leader
    /// and trailer that body declares, so the fixture agrees with its own
    /// declaration.
    fn synth(ghost: Option<&str>, geo: &[(u16, V)]) -> Vec<u8> {
        const TILE_BYTES: u32 = 4096;

        let (ghost_text, leader, trailer) = match ghost {
            None => (String::new(), 0u32, 0u32),
            Some(body) => (
                format!(
                    "GDAL_STRUCTURAL_METADATA_SIZE={:06} bytes\n{body}",
                    body.len()
                ),
                if body.contains("BLOCK_LEADER=SIZE_AS_UINT4") {
                    4
                } else {
                    0
                },
                if body.contains("BLOCK_TRAILER=LAST_4_BYTES_REPEATED") {
                    4
                } else {
                    0
                },
            ),
        };

        let mut entries: Vec<(u16, V)> = vec![
            (256, V::Short(vec![128])),
            (257, V::Short(vec![64])),
            (258, V::Short(vec![8])),
            (259, V::Short(vec![1])),
            (262, V::Short(vec![1])),
            (277, V::Short(vec![1])),
            (284, V::Short(vec![1])),
            (322, V::Short(vec![64])),
            (323, V::Short(vec![64])),
            (324, V::Long(vec![0, 0])),
            (325, V::Long(vec![TILE_BYTES, TILE_BYTES])),
        ];
        entries.extend(geo.iter().cloned());
        entries.sort_by_key(|(tag, _)| *tag);

        let ifd_start = 8 + ghost_text.len() as u32;
        let ifd_len = 2 + 12 * entries.len() as u32 + 4;
        let mut cursor = ifd_start + ifd_len;
        let mut blob: Vec<u8> = Vec::new();
        // Where each entry's value lives: `None` when it fits in the entry.
        let mut placed: Vec<Option<u32>> = Vec::new();
        for (_, value) in &entries {
            let raw = value.bytes();
            if raw.len() <= 4 {
                placed.push(None);
            } else {
                placed.push(Some(cursor));
                cursor += raw.len() as u32;
                blob.extend_from_slice(&raw);
            }
        }

        let data_start = cursor;
        let tile0 = data_start + leader;
        let tile1 = tile0 + TILE_BYTES + trailer + leader;
        let size = tile1 + TILE_BYTES + trailer;

        // Patch TileOffsets now that the data layout is known. It is a two-LONG
        // value, so it was placed out of line and its extent has not moved.
        let tile_offsets_at = entries.iter().position(|(t, _)| *t == 324).unwrap();
        let at = placed[tile_offsets_at].unwrap() - (ifd_start + ifd_len);
        blob[at as usize..at as usize + 8]
            .copy_from_slice(&[tile0.to_le_bytes(), tile1.to_le_bytes()].concat());

        let mut out: Vec<u8> = Vec::with_capacity(size as usize);
        out.extend_from_slice(b"II");
        out.extend_from_slice(&42u16.to_le_bytes());
        out.extend_from_slice(&ifd_start.to_le_bytes());
        out.extend_from_slice(ghost_text.as_bytes());
        out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        for (i, (tag, value)) in entries.iter().enumerate() {
            out.extend_from_slice(&tag.to_le_bytes());
            out.extend_from_slice(&value.field_type().to_le_bytes());
            out.extend_from_slice(&value.count().to_le_bytes());
            match placed[i] {
                Some(offset) => out.extend_from_slice(&offset.to_le_bytes()),
                None => {
                    let mut raw = value.bytes();
                    raw.resize(4, 0);
                    out.extend_from_slice(&raw);
                }
            }
        }
        out.extend_from_slice(&0u32.to_le_bytes()); // no next IFD
        out.extend_from_slice(&blob);
        for _ in 0..2 {
            let body = vec![0xABu8; TILE_BYTES as usize];
            if leader > 0 {
                out.extend_from_slice(&TILE_BYTES.to_le_bytes());
            }
            out.extend_from_slice(&body);
            if trailer > 0 {
                out.extend_from_slice(&body[body.len() - 4..]);
            }
        }
        assert_eq!(out.len(), size as usize, "synth: size mismatch");
        out
    }

    /// The ghost area GDAL writes for a COG.
    const COG_GHOST: &str = "LAYOUT=IFDS_BEFORE_DATA\nBLOCK_ORDER=ROW_MAJOR\n\
        BLOCK_LEADER=SIZE_AS_UINT4\nBLOCK_TRAILER=LAST_4_BYTES_REPEATED\n\
        KNOWN_INCOMPATIBLE_EDITION=NO\n";

    /// North-up 10 m pixels with their origin at (1000, 2000), in EPSG:32610.
    fn north_up() -> Vec<(u16, V)> {
        vec![
            (33550, V::Double(vec![10.0, 10.0, 0.0])),
            (33922, V::Double(vec![0.0, 0.0, 0.0, 1000.0, 2000.0, 0.0])),
            (34735, V::Short(vec![1, 1, 0, 1, 3072, 0, 1, 32610])),
        ]
    }

    // ---- rule 1: the GDAL block leader and trailer --------------------------

    // A COG-aware reader fetches `offset - 4 .. offset + len + 4`, because
    // GDAL's ghost area declares a 4-byte size leader before each tile and a
    // repeat of its last 4 bytes after it, and `TileOffsets` points at the
    // PAYLOAD. A resolver that maps only `[offset, offset + len)` leaves those
    // 8 bytes to `Unmapped` and denies EVERY legitimate tile request.
    #[test]
    fn a_tile_region_includes_its_gdal_block_leader_and_trailer() {
        let bytes = read("tests/fixtures/tiny-cog.tif");
        let idx = index(&bytes);
        // Tile 0 of the full-resolution image: offset 6898, length 740, so the
        // leader is at 6894 and the trailer ends at 7642.
        assert_eq!(tile_at(&idx, 0, 0, 0), (6894, 7642));
        // ...and the read a COG-aware reader actually issues resolves to that
        // ONE region, which is the property the widening exists for.
        let fetched = idx.resolve(&(6894..7642));
        assert_eq!(fetched.len(), 1);
        assert_eq!((fetched[0].start, fetched[0].end()), (6894, 7642));
    }

    // The other half: the leader and the trailer are only there when the ghost
    // area says they are. Widening unconditionally would overlap the
    // neighbouring tile's bytes in a plain tiled TIFF -- or, at the first tile,
    // claim four bytes of somebody else's tag array.
    #[test]
    fn a_tiff_without_a_ghost_area_does_not_get_widened_tiles() {
        let plain = synth(None, &north_up());
        let idx = index(&plain);
        let (start, end) = tile_at(&idx, 0, 0, 0);
        assert_eq!(end - start, 4096, "a bare tile is its byte count, exactly");

        // Same image, same tile bytes, with the ghost area GDAL writes: now the
        // region is eight bytes wider and starts four bytes earlier.
        let cog = synth(Some(COG_GHOST), &north_up());
        let idx = index(&cog);
        let (start, end) = tile_at(&idx, 0, 0, 0);
        assert_eq!(end - start, 4096 + 8);
    }

    // The ghost area is real bytes, and unrecognized real bytes deny. It is
    // emitted as a named metadata region rather than left to `Unmapped`.
    #[test]
    fn the_ghost_area_is_a_named_metadata_region() {
        let idx = index(&read("tests/fixtures/tiny-cog.tif"));
        let ghost = metadata_named(&idx, "ghost_area");
        assert_eq!(ghost.len(), 1);
        // It starts immediately after the 8-byte header and runs to the first
        // IFD, which tiny-cog puts at 192.
        assert_eq!((ghost[0].start, ghost[0].end()), (8, 192));

        // A TIFF without one has no such region and nothing pretends otherwise.
        let plain = index(&synth(None, &north_up()));
        assert!(metadata_named(&plain, "ghost_area").is_empty());
    }

    // The leader is never READ. Its four bytes are an attacker-controlled
    // length sitting in the pixel data; the extent comes from `TileByteCounts`
    // and from the size the ghost area declares, both of which are in the
    // metadata prefix. So a file whose leader lies is still indexed correctly.
    #[test]
    fn a_lying_block_leader_does_not_move_a_tile_boundary() {
        let honest = synth(Some(COG_GHOST), &north_up());
        let mut lying = honest.clone();
        // The first tile's leader: four bytes before the first tile payload.
        let (start, _) = tile_at(&index(&honest), 0, 0, 0);
        lying[start as usize..start as usize + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(index(&lying).regions(), index(&honest).regions());
    }

    // A ghost area declaring a leader or trailer this resolver does not know
    // how to size is a refusal, not a guess: guessing four bytes is how every
    // tile boundary moves by the amount of the guess.
    #[test]
    fn an_unrecognized_ghost_declaration_is_refused() {
        for body in [
            "BLOCK_LEADER=SIZE_AS_UINT8\n",
            "BLOCK_TRAILER=LAST_8_BYTES_REPEATED\n",
            // GDAL sets this when a non-COG-aware writer has edited the file,
            // which is exactly when the declarations above stop being true.
            "BLOCK_LEADER=SIZE_AS_UINT4\nKNOWN_INCOMPATIBLE_EDITION=YES\n",
        ] {
            let bytes = synth(Some(body), &north_up());
            let result = build_index(&bytes, bytes.len() as u64);
            assert!(
                matches!(result, Err(CogError::UnsupportedGhostArea(_))),
                "{body}: {result:?}"
            );
        }
    }

    // ---- rule 2: overview_level is not the IFD index ------------------------

    // `tiny-cog.tif` is 256 / 128 / 64. The levels must come out 0 / 1 / 2 --
    // and the direction matters more than the numbering: a policy meaning
    // "overviews only" is written `region.overview_level >= N`, so an inverted
    // scale grants full resolution. The assertion is therefore on the GROUND
    // FOOTPRINT of a tile, not on its position in the chain.
    #[test]
    fn overview_level_is_derived_from_the_image_width_not_the_ifd_position() {
        let idx = index(&read("tests/fixtures/tiny-cog.tif"));
        assert_eq!(levels(&idx), vec![0, 1, 2]);
        // 64-pixel tiles over 256 / 128 / 64 pixels: 4x4, 2x2, 1x1.
        assert_eq!(tiles_at_level(&idx, 0), 16);
        assert_eq!(tiles_at_level(&idx, 1), 4);
        assert_eq!(tiles_at_level(&idx, 2), 1);

        // The full-resolution pixel is 10 m, so a 64-pixel tile is 640 m
        // across; each level doubles it. A higher `overview_level` is a
        // COARSER image, which is what every rule written against it assumes.
        let width_of = |level: u32| {
            let region = idx
                .regions()
                .iter()
                .find(|r| {
                    matches!(&r.kind, RegionKind::Tile { overview_level, x: 0, y: 0, .. }
                        if *overview_level == level)
                })
                .unwrap();
            match &region.kind {
                RegionKind::Tile { bbox, .. } => bbox[2] - bbox[0],
                _ => unreachable!(),
            }
        };
        assert_eq!(width_of(0), 640.0);
        assert_eq!(width_of(1), 1280.0);
        assert_eq!(width_of(2), 2560.0);
    }

    // Every level covers the SAME ground: an overview is the whole image at a
    // coarser sampling, so a resolver that forgot to rescale the transform per
    // level would leave the coarse levels covering a quarter of the scene --
    // and a spatial rule would then grant coarse tiles for ground they do not
    // show.
    #[test]
    fn every_overview_level_covers_the_same_ground_as_the_full_resolution_image() {
        for file in ["tests/fixtures/tiny-cog.tif", "data/s2-tci-512.tif"] {
            let idx = index(&read(file));
            let envelope = |level: u32| {
                let mut env = [f64::MAX, f64::MAX, f64::MIN, f64::MIN];
                for region in tiles(&idx) {
                    if let RegionKind::Tile {
                        overview_level,
                        bbox,
                        ..
                    } = &region.kind
                    {
                        if *overview_level != level {
                            continue;
                        }
                        env[0] = env[0].min(bbox[0]).min(bbox[2]);
                        env[1] = env[1].min(bbox[1]).min(bbox[3]);
                        env[2] = env[2].max(bbox[0]).max(bbox[2]);
                        env[3] = env[3].max(bbox[1]).max(bbox[3]);
                    }
                }
                env
            };
            let full = envelope(0);
            for level in levels(&idx) {
                let this = envelope(level);
                for axis in 0..4 {
                    assert!(
                        (this[axis] - full[axis]).abs() < 1e-6,
                        "{file} level {level}: {this:?} vs {full:?}"
                    );
                }
            }
        }
    }

    // GDAL >= 3.2 hangs overviews and masks off SubIFDs (tag 330) rather than
    // off the main next-IFD chain. A resolver walking only the main chain
    // leaves every one of their tile bytes unmapped, and unmapped denies -- so
    // the overviews of a perfectly ordinary COG become unreadable.
    //
    // No committed fixture uses SubIFDs, so this one is `tiny-cog.tif` with its
    // first IFD's `next` pointer cut and the second IFD re-hung off a SubIFDs
    // entry. Nothing moves: the resulting region set must be IDENTICAL to the
    // one the chain-linked original produces.
    #[test]
    fn overviews_hung_off_sub_ifds_are_followed() {
        let original = read("tests/fixtures/tiny-cog.tif");
        let mut doctored = original.clone();
        // IFD 0 is at 192 with 21 entries; the last of them is tag 42113
        // (GDAL_NODATA), an inline value nothing here reads. Repurpose its
        // 12-byte slot as `SubIFDs = [972]`, and cut the chain.
        let entry = 192 + 2 + 20 * 12;
        doctored[entry..entry + 2].copy_from_slice(&330u16.to_le_bytes()); // tag
        doctored[entry + 2..entry + 4].copy_from_slice(&4u16.to_le_bytes()); // LONG
        doctored[entry + 4..entry + 8].copy_from_slice(&1u32.to_le_bytes()); // count
        doctored[entry + 8..entry + 12].copy_from_slice(&972u32.to_le_bytes());
        let next = 192 + 2 + 21 * 12;
        doctored[next..next + 4].copy_from_slice(&0u32.to_le_bytes());

        // The doctoring is only evidence if it really cut the chain: a resolver
        // that follows `next` alone now sees one image instead of three.
        let idx = index(&doctored);
        assert_eq!(levels(&idx), vec![0, 1, 2]);
        assert_eq!(idx.regions(), index(&original).regions());
    }

    // `NewSubfileType` bit 2 marks a MASK, and a mask is not a resolution
    // level: numbering by chain position labels it as one, and a rule meaning
    // "coarse imagery only" then grants a full-resolution validity mask.
    //
    // `index.rs` has no mask region kind and this task does not add one, so a
    // mask's tiles are classified as nothing at all and fall to `Unmapped`,
    // which denies. See the module docs for why that is the honest option and
    // what the alternative would cost.
    #[test]
    fn a_mask_image_is_not_given_an_overview_level() {
        let original = read("tests/fixtures/tiny-cog.tif");
        let mut doctored = original.clone();
        // IFD 2 is at 1384 and its first entry is NewSubfileType = 1 (reduced
        // resolution). Set bit 2 as well: a mask of an overview.
        let value = 1384 + 2 + 8;
        doctored[value..value + 4].copy_from_slice(&5u32.to_le_bytes());

        let idx = index(&doctored);
        assert_eq!(levels(&idx), vec![0, 1], "the mask must not become level 2");
        // Its tile really is the 1960..3101 extent the undoctored file maps as
        // level 2, and it is now unclassified.
        assert_eq!(tile_at(&index(&original), 2, 0, 0), (1956, 3101));
        let at = idx.resolve(&(1956..3101));
        assert!(
            at.iter().all(|r| matches!(r.kind, RegionKind::Unmapped)),
            "{at:?}"
        );
    }

    // ---- rule 4: band-major planar configuration ----------------------------

    // With `PlanarConfiguration = 2` the tile count is `samples x grid`,
    // band-major, and a region's props have no band component -- so every band
    // past the first is attributed to the wrong pixels, silently, with no gap
    // for `Unmapped` to catch. `planar2.tif` is 3 samples over a 4x4 grid with
    // 48 TileOffsets entries.
    #[test]
    fn a_band_major_planar_configuration_is_rejected() {
        let bytes = read("tests/fixtures/planar2.tif");
        let result = build_index(&bytes, bytes.len() as u64);
        assert!(
            matches!(result, Err(CogError::PlanarBandMajor { planar: 2 })),
            "{result:?}"
        );
    }

    // ---- rule 5: a striped TIFF has no tiles at all -------------------------

    // The dangerous case. `striped.tif` has `StripOffsets` and no tag 324, so a
    // tile resolver maps NOTHING -- and a conjunctive `all()` over an empty
    // region set is vacuously TRUE. The file must come back wholly `Unmapped`,
    // and a read of it must be denied even under a policy that permits every
    // tile there is.
    #[test]
    fn a_striped_tiff_is_wholly_unmapped_and_every_read_of_it_is_denied() {
        let bytes = read("tests/fixtures/striped.tif");
        let size = bytes.len() as u64;
        let idx = index(&bytes);
        assert_eq!(idx.regions().len(), 1);
        assert!(matches!(idx.regions()[0].kind, RegionKind::Unmapped));
        assert_eq!((idx.regions()[0].start, idx.regions()[0].end()), (0, size));
        assert_eq!(unmapped_bytes(&idx), size);

        let permissive = Policy::load(
            "allow:\n  - \"region.kind = 'tile'\"\n  - \"region.kind = 'metadata'\"",
            QUERYABLES,
        )
        .unwrap();
        let user = json!({"role": "analyst"});
        for range in [
            None,
            Some("bytes=0-7"),
            Some("bytes=768-2102"),
            Some(&*format!("bytes={}-{}", size - 1, size - 1)),
        ] {
            assert_eq!(
                check(&idx, &permissive, &user, range),
                denied(),
                "{range:?}"
            );
        }
    }

    // ---- rule 6: the tag arrays live outside the IFD ------------------------

    // A value over four bytes does not fit in its IFD entry, so `TileOffsets`,
    // `TileByteCounts` and the GeoTIFF key arrays sit in their own extents
    // between the IFDs and the pixel data. "The first N bytes are metadata" is
    // wrong even for a well-formed COG, and bytes a reader must fetch to find
    // the tiles at all cannot be left to `Unmapped`.
    #[test]
    fn out_of_line_tag_arrays_are_their_own_metadata_regions() {
        let idx = index(&read("tests/fixtures/tiny-cog.tif"));
        // IFD 0's TileOffsets: 16 LONGs at 1796, then its TileByteCounts.
        let offsets = metadata_named(&idx, "tile_offsets");
        let counts = metadata_named(&idx, "tile_byte_counts");
        // Two of the three images, not three: the coarsest level holds a single
        // tile, so its one-LONG arrays fit inside their IFD entries and have no
        // extent of their own. That is rule 6 in both directions -- a value is
        // out of line only when it does not fit.
        assert_eq!(offsets.len(), 2, "{offsets:?}");
        assert_eq!(counts.len(), 2, "{counts:?}");
        let extents: Vec<_> = offsets.iter().map(|r| (r.start, r.end())).collect();
        assert!(extents.contains(&(1796, 1860)), "{extents:?}");
        let extents: Vec<_> = counts.iter().map(|r| (r.start, r.end())).collect();
        assert!(extents.contains(&(1860, 1924)), "{extents:?}");

        // The GeoTIFF key directory and the IFDs themselves, likewise.
        let keys = metadata_named(&idx, "geo_keys");
        let extents: Vec<_> = keys.iter().map(|r| (r.start, r.end())).collect();
        assert!(extents.contains(&(878, 942)), "{extents:?}");
        let ifds = metadata_named(&idx, "ifd");
        assert_eq!(ifds.len(), 3);
        // 21 entries: 2 + 21 * 12 + 4.
        assert_eq!((ifds[0].start, ifds[0].end()), (192, 450));
    }

    // Rule 6, the alignment half. `odd-tag.tif` carries a 185-byte
    // `GDAL_METADATA` (42112) ending at the odd offset 837, and the next value
    // -- `ModelPixelScale` -- starts at 838. The byte between them is TIFF's
    // word-alignment padding and belongs to no structure.
    //
    // This is not a synthetic shape. Every COG on
    // `sentinel-cogs.s3.us-west-2.amazonaws.com` is written the same way;
    // `S2A_10SEG_20240923_0_L2A/TCI.tif` has an 81-byte `GDAL_METADATA` ending
    // at 1303 and used to index with exactly one unmapped byte, sitting in the
    // middle of the metadata prefix. One unmapped byte there is not a rounding
    // error: it denies the header read that every reader makes first.
    #[test]
    fn the_word_alignment_pad_after_an_odd_length_tag_value_is_not_unmapped() {
        let bytes = read("tests/fixtures/odd-tag.tif");
        let idx = index(&bytes);
        assert_eq!(unmapped_bytes(&idx), 0);

        // Folded into the value it follows rather than given a name of its own.
        let at = idx.resolve(&(837..838));
        assert_eq!(at.len(), 1, "{at:?}");
        assert_eq!((at[0].start, at[0].end()), (652, 838), "{at:?}");
        assert_eq!(
            at[0].kind,
            RegionKind::Metadata {
                name: "tag_values".into()
            }
        );

        // The property that matters: a reader fetching the metadata prefix in
        // one range is no longer denied by a single byte inside it.
        let policy = Policy::load(
            "allow:\n  - \"region.kind = 'metadata'\"",
            crate::policy::QUERYABLES,
        )
        .unwrap();
        let user = json!({});
        assert!(idx
            .try_resolve(&(0..1828))
            .unwrap()
            .iter()
            .all(|r| policy.permits(&json!({"user": &user, "region": r.props()}))));
    }

    // Only the alignment pad, and only when it IS one. Shortening the ASCII
    // value by a byte makes it end EVEN, so the two bytes before the next value
    // are not padding and must stay `Unmapped` -- a resolver that simply
    // absorbed any following gap would swallow them.
    #[test]
    fn a_gap_that_is_not_a_single_word_alignment_pad_stays_unmapped() {
        let mut bytes = read("tests/fixtures/odd-tag.tif");
        // Find tag 42112's entry in IFD 0 and shorten its count by one.
        let ifd = u32::from_le_bytes(bytes[4..8].try_into().unwrap()) as usize;
        let n = u16::from_le_bytes(bytes[ifd..ifd + 2].try_into().unwrap()) as usize;
        let entry = (0..n)
            .map(|i| ifd + 2 + i * 12)
            .find(|at| u16::from_le_bytes(bytes[*at..*at + 2].try_into().unwrap()) == 42112)
            .expect("odd-tag.tif has a GDAL_METADATA tag");
        let count = u32::from_le_bytes(bytes[entry + 4..entry + 8].try_into().unwrap());
        assert_eq!(count, 185);
        bytes[entry + 4..entry + 8].copy_from_slice(&(count - 1).to_le_bytes());

        let idx = index(&bytes);
        assert_eq!(unmapped_bytes(&idx), 2, "{:?}", idx.resolve(&(830..840)));
        let at = idx.resolve(&(836..838));
        assert!(
            at.iter().all(|r| matches!(r.kind, RegionKind::Unmapped)),
            "{at:?}"
        );
    }

    // `Metadata` must never be a fallback classification: a blanket
    // `region.kind = 'metadata'` allow plus a catch-all is a wildcard over the
    // bytes the resolver understood least. The set of names is closed.
    #[test]
    fn metadata_names_are_a_closed_set() {
        let known = [
            "header",
            "ghost_area",
            "ifd",
            "tile_offsets",
            "tile_byte_counts",
            "geo_keys",
            "tag_values",
        ];
        for (file, bytes) in every_tiff_file() {
            let Ok(idx) = build_index(&bytes, bytes.len() as u64) else {
                continue;
            };
            for region in idx.regions() {
                if let RegionKind::Metadata { name } = &region.kind {
                    assert!(known.contains(&name.as_str()), "{file}: {name}");
                }
            }
        }
    }

    // ---- rules 7 and 8: georeferencing and the CRS --------------------------

    // A rotated or sheared raster's tile is not an axis-aligned rectangle, and
    // the axis-aligned ENVELOPE of one covers ground the tile does not show.
    // A spatial rule is written `S_INTERSECTS(region.geom, <allowed area>)`, so
    // an over-large geometry GRANTS tiles whose pixels are outside the allowed
    // area. Fail closed.
    #[test]
    fn a_rotated_model_transformation_is_refused() {
        // A 4x4 row-major matrix with non-zero shear in the two off-diagonal
        // terms that map pixel column to northing and pixel row to easting.
        #[rustfmt::skip]
        let matrix = vec![
            10.0,  1.0, 0.0, 1000.0,
             1.0, -10.0, 0.0, 2000.0,
             0.0,  0.0, 0.0,    0.0,
             0.0,  0.0, 0.0,    1.0,
        ];
        let rotated = vec![
            (34264, V::Double(matrix)),
            (34735, V::Short(vec![1, 1, 0, 1, 3072, 0, 1, 32610])),
        ];
        let bytes = synth(Some(COG_GHOST), &rotated);
        let result = build_index(&bytes, bytes.len() as u64);
        assert!(
            matches!(result, Err(CogError::RotatedTransform)),
            "{result:?}"
        );
    }

    // The same tag without rotation is an ordinary north-up transform and must
    // be honoured, or the assertion above would be passing for the wrong
    // reason -- "we reject tag 34264" rather than "we reject rotation".
    #[test]
    fn an_axis_aligned_model_transformation_is_honoured() {
        #[rustfmt::skip]
        let matrix = vec![
            10.0,   0.0, 0.0, 1000.0,
             0.0, -10.0, 0.0, 2000.0,
             0.0,   0.0, 0.0,    0.0,
             0.0,   0.0, 0.0,    1.0,
        ];
        let upright = vec![
            (34264, V::Double(matrix)),
            (34735, V::Short(vec![1, 1, 0, 1, 3072, 0, 1, 32610])),
        ];
        let by_matrix = index(&synth(Some(COG_GHOST), &upright));
        // The same geometry written as a pixel scale plus a tiepoint. The two
        // files differ in their tag values, so only the TILES can be compared
        // -- which is the whole claim: two spellings of one transform place
        // the same pixels on the same ground.
        let by_scale = index(&synth(Some(COG_GHOST), &north_up()));
        let kinds = |idx: &LayoutIndex| {
            tiles(idx)
                .iter()
                .map(|r| r.kind.clone())
                .collect::<Vec<_>>()
        };
        assert_eq!(kinds(&by_matrix), kinds(&by_scale));
        // ...and it really is the transform the tags describe: a 64-pixel tile
        // of 10 m pixels, with its top-left corner at the tiepoint. Asserted
        // through `props`, which is the normalized form a policy sees -- a
        // north-up transform has a negative y pixel size, so the resolver hands
        // the index a bbox whose y runs downwards and `Region::props` puts it
        // the right way up.
        assert_eq!(
            tiles(&by_matrix)[0].props()["bbox"],
            json!({"bbox": [1000.0, 1360.0, 1640.0, 2000.0]})
        );
    }

    // A file georeferenced only by ground control points has no affine
    // transform at all: `ModelTiepoint` holds 6 values per GCP and there is no
    // pixel scale to turn a pixel into a coordinate. Inventing one would put
    // every tile's polygon somewhere plausible and wrong.
    #[test]
    fn a_gcp_only_file_is_refused() {
        // Three tiepoints, six values each, and no `ModelPixelScale`.
        #[rustfmt::skip]
        let tiepoints = vec![
              0.0,  0.0, 0.0, 1000.0, 2000.0, 0.0,
            128.0,  0.0, 0.0, 2280.0, 2000.0, 0.0,
              0.0, 64.0, 0.0, 1000.0, 1360.0, 0.0,
        ];
        let gcps = vec![
            (33922, V::Double(tiepoints)),
            (34735, V::Short(vec![1, 1, 0, 1, 3072, 0, 1, 32610])),
        ];
        let bytes = synth(Some(COG_GHOST), &gcps);
        let result = build_index(&bytes, bytes.len() as u64);
        assert!(
            matches!(result, Err(CogError::GroundControlPoints { tiepoints: 3 })),
            "{result:?}"
        );
    }

    // No georeferencing at all is a refusal too. A tile with no geometry
    // answers no spatial rule, and a tile carrying PIXEL coordinates dressed as
    // ground coordinates answers them wrongly.
    #[test]
    fn a_tiff_with_no_georeferencing_is_refused() {
        let bytes = synth(Some(COG_GHOST), &[]);
        let result = build_index(&bytes, bytes.len() as u64);
        assert!(
            matches!(result, Err(CogError::MissingGeoreferencing)),
            "{result:?}"
        );
    }

    // `geo` is planar and CRS-agnostic, so a policy polygon written in the
    // wrong CRS silently matches everything (issue #5). The CRS is read from
    // the GeoTIFF key directory so that a later check has something to check --
    // and overview IFDs do NOT repeat the georeferencing tags, so every level
    // has to inherit it.
    #[test]
    fn every_tile_carries_the_crs_from_the_geokey_directory() {
        for file in ["tests/fixtures/tiny-cog.tif", "data/s2-tci-512.tif"] {
            let idx = index(&read(file));
            let seen: Vec<_> = tiles(&idx)
                .iter()
                .filter_map(|r| match r.kind {
                    RegionKind::Tile { crs, .. } => Some(crs),
                    _ => None,
                })
                .collect();
            assert!(!seen.is_empty(), "{file}");
            assert!(seen.iter().all(|c| *c == Some(32610)), "{file}");
            assert_eq!(tiles(&idx)[0].props()["crs"], json!(32610));
        }
    }

    // ---- rule 9: BigTIFF ----------------------------------------------------

    // Out of scope has to mean an error rather than a partial classification:
    // every offset in a BigTIFF is eight bytes wide, so a classic-TIFF parse of
    // one reads halves of offsets as whole ones. Tracked as issue #6.
    #[test]
    fn a_bigtiff_is_refused_rather_than_misparsed() {
        let mut bytes = read("tests/fixtures/tiny-cog.tif");
        bytes[2..4].copy_from_slice(&43u16.to_le_bytes());
        assert!(matches!(
            build_index(&bytes, bytes.len() as u64),
            Err(CogError::BigTiff)
        ));
    }

    // ---- the invariant that closes the unmapped-range bypass ----------------

    #[test]
    fn coverage_is_total_for_every_tiff_in_the_repo() {
        for (file, bytes) in every_tiff_file() {
            let size = bytes.len() as u64;
            let Ok(idx) = build_index(&bytes, size) else {
                // A refusal is also total coverage: there is no index to read.
                continue;
            };
            let mut cursor = 0u64;
            for region in idx.regions() {
                assert_eq!(region.start, cursor, "{file}: hole before {}", region.start);
                cursor = region.end();
            }
            assert_eq!(cursor, size, "{file}: coverage stops short");
            assert_eq!(idx.size(), size, "{file}");
        }
    }

    // Total coverage is satisfied by classifying NOTHING -- which is exactly
    // what `striped.tif` does on purpose -- so the number that matters for a
    // file this resolver claims to understand is how many bytes it left
    // unclassified. Unmapped metadata is a reader DENIED on the very read it
    // must make to find the tiles, so for the two real COGs the answer is zero.
    #[test]
    fn a_cog_this_resolver_understands_has_no_unmapped_bytes_at_all() {
        for (file, tiles_expected, regions_expected) in [
            ("tests/fixtures/tiny-cog.tif", 21, 47),
            ("data/s2-tci-512.tif", 655, 702),
        ] {
            let idx = index(&read(file));
            assert_eq!(unmapped_bytes(&idx), 0, "{file}");
            assert_eq!(tiles(&idx).len(), tiles_expected, "{file}");
            assert_eq!(idx.regions().len(), regions_expected, "{file}");
        }
    }

    // ---- one read, and how much of it -------------------------------------
    //
    // Unlike Parquet, TIFF metadata is at the FRONT, so `bytes` is a prefix.
    // A caller that guessed its prefix read too small must be told how much
    // would have been enough, or it has to fall back to fetching the object.

    #[test]
    fn a_prefix_shorter_than_the_metadata_asks_for_the_bytes_it_needs() {
        // The two numbers the module docs quote, measured rather than assumed.
        for (file, enough) in [
            ("tests/fixtures/tiny-cog.tif", 1956u64),
            ("data/s2-tci-512.tif", 8264),
        ] {
            let bytes = read(file);
            let size = bytes.len() as u64;
            // Start far too small and follow the resolver's own advice until it
            // stops asking. Every step must ask for MORE than it was given, or
            // the caller loops forever.
            let mut prefix = 16u64;
            let mut asked = Vec::new();
            loop {
                match build_index(&bytes[..prefix as usize], size) {
                    Err(CogError::Truncated { needed }) => {
                        assert!(
                            needed > prefix,
                            "{file}: asked for {needed} having been given {prefix}"
                        );
                        asked.push(needed);
                        prefix = needed;
                    }
                    Ok(_) => break,
                    other => panic!("{file} prefix {prefix}: {other:?}"),
                }
            }
            assert!(asked.len() > 1, "{file}: one guess proves no convergence");
            // One byte less is not enough, so the number is exact rather than a
            // round-up -- and the whole metadata of a 5 MB COG is under 9 KB.
            assert_eq!(prefix, enough, "{file}");
            assert!(
                build_index(&bytes[..enough as usize - 1], size).is_err(),
                "{file}"
            );
            // The index built from the prefix is the one the whole object gives.
            assert_eq!(
                build_index(&bytes[..enough as usize], size)
                    .unwrap()
                    .regions(),
                index(&bytes).regions(),
                "{file}"
            );
        }
    }

    #[test]
    fn a_buffer_that_is_not_a_prefix_of_the_object_is_refused() {
        let whole = read("tests/fixtures/tiny-cog.tif");
        let size = whole.len() as u64;
        assert!(matches!(
            build_index(&whole, size - 1),
            Err(CogError::NotAPrefix { .. })
        ));
        assert!(build_index(&whole, 0).is_err());
        // The TAIL of a TIFF is pixel data, not a header.
        assert!(build_index(&whole[1024..], size).is_err());
    }

    // ---- malformed input fails closed rather than panicking -----------------

    // Every one of these is a file an attacker can serve. The assertion is
    // `is_err()` or a coverage check, but the property being defended is that
    // the call RETURNS: a panic aborts the wasm module instance, and a test
    // that panicked would fail rather than pass.
    #[test]
    fn a_truncated_or_corrupt_tiff_fails_closed() {
        for (file, whole) in every_tiff_file() {
            // Truncated objects: the object really is `n` bytes long.
            for n in [
                0usize, 1, 2, 4, 7, 8, 9, 16, 100, 192, 450, 1000, 1956, 8264,
            ] {
                if n > whole.len() {
                    continue;
                }
                let bytes = &whole[..n];
                if let Ok(idx) = build_index(bytes, n as u64) {
                    assert_eq!(idx.size(), n as u64, "{file} truncated to {n}");
                }
            }
            // A whole object with a prefix that stops short.
            for n in [1usize, 8, 200, 1000, 5000] {
                if n > whole.len() {
                    continue;
                }
                let result = build_index(&whole[..n], whole.len() as u64);
                if let Ok(idx) = result {
                    assert_eq!(idx.size(), whole.len() as u64, "{file} prefix {n}");
                }
            }
            // One byte of the metadata flipped, at a spread of positions. A
            // flip may leave a parseable file; what it must never do is panic,
            // and it must never widen coverage.
            for at in [0usize, 1, 2, 3, 4, 5, 8, 40, 100, 193, 200, 400, 900, 1800] {
                if at >= whole.len() {
                    continue;
                }
                let mut bytes = whole.clone();
                bytes[at] ^= 0xff;
                if let Ok(idx) = build_index(&bytes, bytes.len() as u64) {
                    assert_eq!(idx.size(), bytes.len() as u64, "{file} flipped at {at}");
                }
            }
        }
    }

    // An IFD chain that points at itself must not be walked forever, and a
    // SubIFD pointing back at its parent is the same bug reached another way.
    #[test]
    fn a_cyclic_ifd_chain_terminates() {
        let mut bytes = read("tests/fixtures/tiny-cog.tif");
        // IFD 0's `next` pointer, made to point at IFD 0.
        let next = 192 + 2 + 21 * 12;
        bytes[next..next + 4].copy_from_slice(&192u32.to_le_bytes());
        let result = build_index(&bytes, bytes.len() as u64);
        // Whatever it decides, it decides it in finite time.
        if let Ok(idx) = result {
            assert_eq!(idx.size(), bytes.len() as u64);
        }
    }

    // ---- tile props as a spatial operand ------------------------------------

    // A bare bbox array is NOT a valid CQL2 spatial operand -- untagged
    // deserialization matches it as `Array` and `S_INTERSECTS` silently fails
    // to reduce -- so this is a real risk and not a formality. The polygon is
    // in the file's own CRS (EPSG:32610, metres), because `geo` is planar and
    // CRS-agnostic and a polygon in degrees would match nothing at all.
    #[test]
    fn tile_props_are_a_working_cql2_spatial_operand() {
        let idx = index(&read("data/s2-tci-512.tif"));

        // `Expr::matches` consumes the expression, so it is re-parsed per
        // region. That is the cost `decision.rs` already documents for a
        // spatial rule, not an accident of this test.
        let selected = |wkt: &str| {
            let filter = format!("S_INTERSECTS(region.geom, {wkt})");
            let mut hit = Vec::new();
            for region in tiles(&idx) {
                let props = json!({ "region": region.props() });
                let expr: cql2::Expr = filter.parse().unwrap();
                if expr.matches(Some(&props)).unwrap() {
                    match &region.kind {
                        RegionKind::Tile {
                            overview_level,
                            x,
                            y,
                            ..
                        } => hit.push((*overview_level, *x, *y)),
                        _ => unreachable!(),
                    }
                }
            }
            hit.sort_unstable();
            hit
        };

        // A 2 km square in the north-west corner of the scene, whose origin is
        // (499980, 4200000). It sits strictly inside the corner tile of every
        // level: the finest tile is 512 px x 10 m = 5120 m across. So the
        // answer is exactly the (0, 0) tile of each of the six levels.
        assert_eq!(
            selected(
                "POLYGON((500000 4198000, 502000 4198000, 502000 4200000, \
                 500000 4200000, 500000 4198000))"
            ),
            vec![
                (0, 0, 0),
                (1, 0, 0),
                (2, 0, 0),
                (3, 0, 0),
                (4, 0, 0),
                (5, 0, 0)
            ]
        );

        // The other direction, which a regression that made `matches` fail open
        // would pass the assertion above without: a square in the south-east
        // corner selects the far corner tile of each level and NOT (0, 0).
        assert_eq!(
            selected(
                "POLYGON((608000 4091000, 609000 4091000, 609000 4092000, \
                 608000 4092000, 608000 4091000))"
            ),
            vec![
                (0, 21, 21),
                (1, 10, 10),
                (2, 5, 5),
                (3, 2, 2),
                (4, 1, 1),
                (5, 0, 0)
            ]
        );
    }

    // ---- end to end, against a real file ------------------------------------

    // The whole stack -- TIFF, index, policy, decision -- over a 5 MB COG. The
    // policy a deployment writes to serve a low-resolution preview and withhold
    // the imagery: `region.overview_level >= 2`.
    #[test]
    fn a_policy_allowing_only_coarse_overviews_denies_the_full_resolution_tiles() {
        let bytes = read("data/s2-tci-512.tif");
        let idx = index(&bytes);
        let policy = Policy::load(
            "allow:\n  - \"region.kind = 'tile' AND region.overview_level >= 2\"",
            QUERYABLES,
        )
        .unwrap();
        let user = json!({"role": "analyst"});

        // The single tile of the coarsest level, and a tile of level 2.
        for level in [2u32, 3, 4, 5] {
            let (start, end) = tile_at(&idx, level, 0, 0);
            assert_eq!(
                check(&idx, &policy, &user, Some(&header(start, end))),
                Decision::Authorized {
                    canonical: start..end
                },
                "level {level}"
            );
        }
        // Full resolution, and the first overview, are denied.
        for level in [0u32, 1] {
            let (start, end) = tile_at(&idx, level, 0, 0);
            assert_eq!(
                check(&idx, &policy, &user, Some(&header(start, end))),
                denied(),
                "level {level}"
            );
        }

        // The metadata a reader must fetch to find any of it is denied too --
        // the policy names tiles and nothing else, and `region.kind` really
        // does distinguish them.
        let ifd = metadata_named(&idx, "ifd")[0];
        assert_eq!(
            check(&idx, &policy, &user, Some(&header(ifd.start, ifd.end()))),
            denied()
        );
        // And the whole-object retry a reader makes after a 403.
        assert_eq!(check(&idx, &policy, &user, None), denied());
    }

    // A coalesced read is the request this design exists to answer: a client
    // block that straddles a permitted region and a denied one must be denied,
    // however much of it was allowed. The boundary is FOUND rather than
    // hard-coded, so the test cannot rot into asserting about two regions that
    // the policy happens to decide the same way.
    #[test]
    fn a_read_straddling_a_permitted_and_a_denied_region_is_denied() {
        let bytes = read("data/s2-tci-512.tif");
        let idx = index(&bytes);
        let policy = Policy::load(
            "allow:\n  - \"region.kind = 'tile' AND region.overview_level >= 2\"",
            QUERYABLES,
        )
        .unwrap();
        let user = json!({"role": "analyst"});
        let permits =
            |region: &Region| policy.permits(&json!({"user": user, "region": region.props()}));

        let pair = idx
            .regions()
            .windows(2)
            .find(|w| permits(&w[0]) != permits(&w[1]))
            .expect("the policy must decide some two neighbours differently");
        let (left, right) = (&pair[0], &pair[1]);
        // Each side alone decides as the policy says, so the straddle below is
        // denied by the conjunction and not because both halves were denied.
        let alone = |region: &Region| {
            check(
                &idx,
                &policy,
                &user,
                Some(&header(region.start, region.end())),
            )
        };
        assert_ne!(alone(left), alone(right));
        // One byte either side of the boundary: the smallest straddle there is.
        assert_eq!(
            check(
                &idx,
                &policy,
                &user,
                Some(&header(right.start - 1, right.start + 1))
            ),
            denied()
        );
    }
}
