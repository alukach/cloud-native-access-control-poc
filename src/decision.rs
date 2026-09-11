//! The decision function: may this principal read these bytes?
//!
//! [`check`] is the only entry point a gateway needs. It parses the client's
//! `Range` header, resolves the requested extent into the regions it overlaps,
//! and evaluates the policy against every one of them.
//!
//! # The four rules, each a bypass when guessed wrong
//!
//! 1. **Conjunctive.** EVERY overlapped region must satisfy the policy --
//!    `all`, not `any`. Under `any`, `bytes=<footer start>-<salary chunk end>`
//!    matches a metadata rule and the response carries the salary column with
//!    it. The quantifier short-circuits on the first denial, which is a
//!    latency property and not a security one: the answer is the same either
//!    way.
//! 2. **Total coverage.** `all()` over an EMPTY set is `true`, so an empty
//!    region set is an *allow* unless something refuses it.
//!    [`LayoutIndex`](crate::index::LayoutIndex) already guarantees its regions
//!    partition `[0, size)` and that unmapped bytes carry a
//!    [`RegionKind::Unmapped`] no policy can match -- but this function does
//!    not lean on that invariant holding somewhere else. It calls
//!    [`try_resolve`](crate::index::LayoutIndex::try_resolve), which refuses an
//!    empty range and a range past `size` with a typed error, and it *also*
//!    checks the returned slice for emptiness. See [`check`] for why the
//!    belt and the braces are both worth their line.
//! 3. **An absent `Range` means the whole object.** A reader that gets 403 on
//!    a coalesced range commonly retries as a full-object GET; that retry must
//!    be decided as a request for `0..size`, not waved through as "no range to
//!    check". [`range::parse`] normalizes it.
//! 4. **Half-open internally, inclusive on the wire.** `bytes=0-9` is ten
//!    bytes, `0..10`. [`range::parse`] converts; nothing downstream re-derives
//!    it.
//!
//! # The two denial modes
//!
//! [`check`] refuses any range covering a forbidden byte. That is the only
//! honest answer for a client this crate knows nothing about, and it is also
//! unusable for a whole class of real readers: a reader that projects columns
//! but fetches *aligned blocks* -- DuckDB reads 16 KiB and 64 KiB power-of-two
//! blocks, not chunk extents -- puts a forbidden byte in nearly every request
//! it makes, whether or not its query ever touched that column.
//!
//! [`check_with_mode`] takes a [`DenialMode`] and can answer with a third
//! outcome: serve the range, with the forbidden bytes listed for the caller to
//! blank ([`Verdict::Serve`]). [`DenialMode`] carries the measurement that
//! motivated it and [`DenialMode::ZeroFill`] carries the reader it breaks.
//! Two properties hold across both modes and are pinned by test:
//!
//! * **Zero-fill never widens access.** Every byte a serve returns lies in a
//!   region the policy permits, because every region it does not permit is
//!   either blanked or refused.
//! * **Zero-fill relaxes nothing else.** A bad header, a bad principal, an
//!   empty or unsatisfiable range, and a forbidden region that cannot be
//!   blanked without corrupting the object are refused identically in both.
//!
//! # Why the answer is a byte extent and not a boolean
//!
//! See [`Decision::Authorized`]. In short: a gateway that authorizes a client's
//! `Range` header and then *forwards that header* has authorized one thing and
//! fetched another, because RFC 9110 §14.2 requires an origin server to ignore
//! a `Range` it cannot parse and answer `200` with the entire representation.
//! Returning the extent to fetch, rather than permission to fetch, removes the
//! opportunity to make that mistake.

use crate::{
    index::{LayoutIndex, RegionKind},
    policy::Policy,
    range,
};
use serde_json::{json, Value};
use std::ops::Range;

/// Why a request was refused.
///
/// The two variants exist so a caller can tell a client error from an
/// authorization failure -- but see [`DenyReason::BadRange`] before mapping
/// either one onto a status code, because the choice between them is the one
/// place a denial can still say something about the object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyReason {
    /// The `Range` header did not parse.
    ///
    /// **This is a function of the header text and nothing else.** It is safe
    /// to map onto `400`, and safe to report to any principal, because the
    /// answer would have been the same for every object in the store --
    /// including objects that do not exist.
    ///
    /// Keeping it that way is deliberate and is the reason
    /// [`RangeError::NotSatisfiable`](crate::range::RangeError::NotSatisfiable)
    /// does *not* land here. `range.rs` documents that every `NotSatisfiable`
    /// is a function of `size` and no `Unparseable` ever is; a caller that
    /// answered `400` for one and `403` for the other would hand an attacker
    /// the monotone predicate `N >= size` and with it the object's exact size
    /// in 64 probes. Collapsing the two `RangeError` kinds into a single
    /// `BadRange` is *not* enough to close that, because `BadRange` versus
    /// `NotPermitted` would then carry the same bit. So an unsatisfiable range
    /// is reported as [`DenyReason::NotPermitted`]: it is a denial, and it is
    /// indistinguishable from every other denial.
    BadRange,
    /// The principal may not read the bytes it asked for.
    ///
    /// Everything whose answer could depend on the object arrives here: a
    /// region the policy denied, an unsatisfiable range, an empty range, a
    /// range past the indexed end, and a principal whose shape `check` refused.
    /// Callers must render all of them identically -- same status, same body,
    /// same headers, and in particular **never** `Content-Range: bytes */SIZE`,
    /// which states the size outright.
    ///
    /// The variant carries no regions and no offsets on purpose: a 403 that
    /// echoes the resolved regions hands back the protected column's name and
    /// its byte extent, which is what the policy was withholding.
    NotPermitted,
}

/// The verdict on one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Permission to fetch **exactly** `canonical`, and nothing else.
    ///
    /// # The caller's obligations, all three load-bearing
    ///
    /// 1. **Fetch `canonical`.** Send `Range: bytes={start}-{end - 1}` built
    ///    from this value. Do **not** forward the client's original `Range`
    ///    header. RFC 9110 §14.2 requires an origin server to IGNORE a `Range`
    ///    header it cannot parse and return `200` with the *entire
    ///    representation*, so a gateway that forwards the client's header can
    ///    authorize one byte and deliver the whole object. This crate parses
    ///    strictly; a backend need not parse the same way, and every header
    ///    the two disagree about is a full-object disclosure. `canonical` is
    ///    already clamped to the object, already half-open, and already
    ///    normalized from a suffix or open-ended form, so it re-serializes to
    ///    a spelling no backend can misread.
    /// 2. **Verify the response against `canonical`.** Reject any response
    ///    whose `Content-Range` names a different extent. A `206` must carry
    ///    `Content-Range: bytes {start}-{end - 1}/{complete}`; a `200` is
    ///    acceptable only when `canonical` covers the whole object and the body
    ///    length matches. Anything else -- a `200` for a partial extent above
    ///    all -- is bytes that were never authorized and must not be relayed.
    /// 3. **Check `complete` against the index, and pin the object version.**
    ///    A `Content-Range` whose complete-length differs from
    ///    [`LayoutIndex::size`](crate::index::LayoutIndex::size) proves the
    ///    index describes a different object than the one that answered, and
    ///    the decision above was made against the wrong layout. Size equality
    ///    is necessary and not sufficient -- an object rewritten to the same
    ///    length moves every column while the check passes -- so bind the
    ///    fetch to the exact version the index was built from: an S3
    ///    `versionId`, or `If-Match` with the ETag the index was built from.
    ///    See [`check`] for why this is a caller obligation and not a
    ///    parameter.
    Authorized { canonical: Range<u64> },
    /// The request is refused. See [`DenyReason`] for what a caller may say
    /// about which kind of refusal it was.
    Denied { reason: DenyReason },
}

/// What to do about bytes inside the requested range that the policy forbids.
///
/// **Selected by the caller, never inferred.** The two modes have different
/// failure modes on the client side and only the caller knows which client it
/// is serving; see [`DenialMode::ZeroFill`] for the reader it breaks.
///
/// # Why a second mode exists at all
///
/// Measured against `data/nyc-taxi-8rg.parquet`: DuckDB pushes projection down
/// (2 of 19 columns, 11.9% of the object) and prunes row groups by footer
/// statistics, but its physical reads are **16 KiB / 64 KiB power-of-two
/// aligned blocks, not chunk extents**. 27 of its 27 content requests straddle
/// a column chunk it never projected. Deny `extra` and `SELECT fare_amount`
/// is refused because `extra` is physically adjacent; deny `extra` and
/// `SELECT VendorID` succeeds. *Adjacency in the file decides, not the query.*
///
/// So [`DenialMode::Refuse`] cannot serve DuckDB at all under any policy that
/// withholds a column sitting within 64 KiB of a permitted one, and that is
/// not a client misconfiguration a deployment can fix. Zero-fill is therefore
/// not a degraded fallback: for a projecting reader it is lossless, because
/// the blanked bytes are never parsed -- they are only along for the ride
/// inside the block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DenialMode {
    /// Refuse any range covering a forbidden byte.
    ///
    /// The default, and the only mode that is safe for a reader this crate
    /// knows nothing about: a client either gets the bytes it asked for or a
    /// clean refusal, never something in between.
    #[default]
    Refuse,
    /// Serve the range, with the forbidden bytes blanked.
    ///
    /// # Not safe for every reader, and the caller is the one who knows
    ///
    /// Zero-fill trades a clean refusal for a *corrupt read* in any client
    /// that actually parses the blanked bytes. hyparquet with no column
    /// projection reads all 19 columns of the file above and would decode
    /// zeroes as data. A reader that projects -- DuckDB, pyarrow with
    /// `columns=`, arrow-rs with a projection mask -- never touches them, and
    /// for it the response is byte-identical to an unrestricted one over every
    /// byte it reads.
    ///
    /// Nothing in this crate can tell the two apart: the reader's projection
    /// is not visible in a `Range` header. That is why the mode is a
    /// parameter. Choosing it is a statement about the client, made by whoever
    /// deployed the gateway.
    ZeroFill,
}

/// The verdict on one request, in the form both [`DenialMode`]s answer in.
///
/// [`check`] keeps the older [`Decision`] shape, which cannot express a
/// partial serve; [`check_with_mode`] answers with this.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Fetch `canonical`, then blank `blank` before any byte reaches the
    /// client.
    ///
    /// Every obligation on [`Decision::Authorized`] applies to `canonical`
    /// unchanged -- fetch exactly it, verify the response against it, pin the
    /// object version -- plus one more, which is the whole of this variant:
    ///
    /// 4. **Blank every extent in `blank` before returning any byte.** Not
    ///    after, not lazily, not only on the paths that felt risky. A response
    ///    that leaves the buffer in flight is a response that serves the bytes
    ///    the policy withheld. [`Verdict::redact`] does it, and does the
    ///    offset arithmetic in one audited place.
    Serve {
        canonical: Range<u64>,
        /// The extents of `canonical` that must be overwritten with zeroes,
        /// as **ABSOLUTE FILE OFFSETS** -- the same coordinate system as
        /// `canonical`, *not* offsets into the buffer the fetch returns.
        /// Subtract `canonical.start` to index that buffer, or call
        /// [`Verdict::redact`] and do not write the subtraction again: an
        /// off-by-one here serves protected bytes.
        ///
        /// Each span is non-empty and lies within `canonical`; the list is
        /// sorted, pairwise disjoint, and never merely abutting -- two
        /// forbidden regions that touch are one span, so these are extents
        /// and not the index's internal boundaries. The list itself is empty
        /// whenever the range covered no forbidden byte, which is every serve
        /// under [`DenialMode::Refuse`].
        blank: Vec<Range<u64>>,
    },
    /// The request is refused, identically in both modes and for every reason.
    /// See [`DenyReason`].
    Denied { reason: DenyReason },
}

/// Why a buffer could not be redacted. Both variants mean the caller broke an
/// obligation on [`Verdict::Serve`], and in both the buffer is left zeroed.
#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum RedactError {
    /// There is no authorized extent, so there is nothing to serve and nothing
    /// to redact against.
    #[error("the request was denied; there is nothing to serve")]
    NotServed,
    /// The buffer is not the canonical extent. Blank offsets computed against
    /// it would land on the wrong bytes, so nothing is blanked selectively and
    /// the whole buffer is zeroed instead.
    #[error("buffer holds {got} bytes; the authorized extent is {want}")]
    WrongLength { got: u64, want: u64 },
}

impl Verdict {
    /// Blank the protected extents in a buffer holding **exactly**
    /// `canonical`.
    ///
    /// This is the only place the absolute-to-buffer offset subtraction is
    /// written down, and it is written down once on purpose.
    ///
    /// The length check is not a convenience. Obligation 2 on
    /// [`Decision::Authorized`] requires a caller to reject a response whose
    /// extent is not `canonical`; a buffer of the wrong length *is* that
    /// response, arriving at the last function that can still catch it. On
    /// failure the buffer is zeroed rather than left alone, so that a caller
    /// which ignores the `Result` -- the failure this whole crate is written
    /// against -- serves zeroes and not the object.
    pub fn redact(&self, buffer: &mut [u8]) -> Result<(), RedactError> {
        let Verdict::Serve { canonical, blank } = self else {
            buffer.fill(0);
            return Err(RedactError::NotServed);
        };
        let want = canonical.end - canonical.start;
        if buffer.len() as u64 != want {
            buffer.fill(0);
            return Err(RedactError::WrongLength {
                got: buffer.len() as u64,
                want,
            });
        }
        for span in blank {
            // Exact, not merely lossless-looking: every span lies within
            // `canonical` (asserted by the construction in `check_with_mode`
            // and by test), and `canonical`'s length was just proved equal to
            // `buffer.len()`, which is a `usize`. So both differences are at
            // most `buffer.len()` and the casts cannot truncate.
            let lo = (span.start - canonical.start) as usize;
            let hi = (span.end - canonical.start) as usize;
            let Some(slice) = buffer.get_mut(lo..hi) else {
                // Unreachable given the paragraph above. Reachable only from a
                // hand-built `Verdict`, and the safe answer to a span we
                // cannot place is to blank everything.
                buffer.fill(0);
                return Err(RedactError::WrongLength {
                    got: buffer.len() as u64,
                    want,
                });
            };
            slice.fill(0);
        }
        Ok(())
    }
}

/// May a forbidden region be blanked in place instead of refusing the request?
///
/// The line is not "is this important" -- every region a policy denies is
/// important. It is **what finds what**: blank only bytes a reader locates by
/// an offset it read somewhere else, and never the somewhere else.
///
/// * [`RegionKind::Metadata`] is the somewhere else. Blanking a Parquet footer
///   or a TIFF IFD produces a corrupt file rather than a restricted one: the
///   reader cannot even find the bytes it is still allowed to read, so the
///   failure is total instead of partial, and it presents as file corruption
///   rather than as a policy decision. Refuse.
/// * [`RegionKind::Unmapped`] is bytes no resolver claimed -- by definition
///   the set we understand least, and in practice the Parquet `PAR1` magic,
///   the footer-length trailer, inter-chunk padding and a COG's GDAL ghost
///   area. Zero-filling asserts that the blanked bytes are never parsed, and
///   that assertion cannot be made about bytes whose meaning is unknown.
///   `index.rs` already refuses to classify unrecognized bytes as metadata for
///   the mirror-image reason; treating them as blankable here would be the
///   same mistake in the other direction, giving the least-understood bytes
///   the most permissive handling. Refuse.
/// * Column chunks, column indexes, bloom filter pages and tiles are all
///   located by an offset in the footer or the IFD. A reader that did not
///   project the column, or did not request the tile, never parses them -- and
///   a reader that did is being denied on purpose. Blank.
///
/// Exhaustive, with no catch-all: a new [`RegionKind`] must fail to compile
/// here rather than inherit a default. Defaulting to blankable would serve
/// structure as zeroes; defaulting to refuse would silently make the mode
/// useless for a new format, which at least fails closed -- but a reviewer
/// should have to choose either way.
fn is_blankable(kind: &RegionKind) -> bool {
    match kind {
        RegionKind::Metadata { .. } | RegionKind::Unmapped => false,
        RegionKind::ColumnChunk { .. }
        | RegionKind::ColumnIndex { .. }
        | RegionKind::BloomFilter { .. }
        | RegionKind::Tile { .. } => true,
    }
}

/// Decide whether `user` may read the bytes `header` asks for.
///
/// The result is a byte extent to fetch, not a boolean; see
/// [`Decision::Authorized`] for the obligations that come with it.
///
/// # What this function trusts
///
/// `index` is trusted to describe the object that will answer the fetch.
/// `check` cannot verify that: it never sees the object, so any `expected_size`
/// or `expected_etag` parameter would only compare the caller's belief against
/// the caller's own index and would catch nothing except a caller that already
/// knew the two disagreed. Worse, a size parameter would read as a freshness
/// check while being none -- an object rewritten to the same length passes it
/// with every column in a new place. The check that is both sound and free
/// lives on the response, where the origin states the complete length and the
/// `If-Match`/`versionId` the fetch was pinned with either held or did not.
/// Obligation 3 on [`Decision::Authorized`] spells it out.
///
/// `user` is **not** trusted. It is the one part of the evaluation context that
/// comes from outside this crate, so its shape is checked before it is
/// interpolated; see [`principal_is_addressable`].
///
/// # Cost
///
/// One context and one policy evaluation per overlapped region, and
/// `Policy::permits` clones each rule per call. Measured on a release build,
/// a coalesced COG read of 200 contiguous tiles against a four-rule policy:
///
/// | policy | per check | per region |
/// |---|---|---|
/// | 4 rules, one spatial (matching last) | 7.5 ms | 37.6 us |
/// | 4 rules, none spatial | 3.1 ms | 15.3 us |
/// | any policy, denied on the first region | 3.7 us | -- |
///
/// The spatial rule accounts for ~22 us of each region's cost, matching the
/// ~20.6 us `Policy::permits` documents -- cql2 re-parses the policy's GeoJSON
/// through WKT on every evaluation. Nothing here is optimized: correctness of
/// the per-call clone matters more than the microseconds, and the shape of the
/// fix (evaluate a rule once against a whole region *set*, or hoist the
/// geometry parse into `Policy::load`) belongs in cql2 or in a later task
/// rather than in the decision function. Two things are worth carrying
/// forward, though. Milliseconds of CPU per request is a real gateway budget
/// at 200 tiles, and short-circuiting buys nothing on the allow path, which is
/// the path that runs when the system is working.
pub fn check(index: &LayoutIndex, policy: &Policy, user: &Value, header: Option<&str>) -> Decision {
    match check_with_mode(index, policy, user, header, DenialMode::Refuse) {
        Verdict::Serve { canonical, blank } if blank.is_empty() => {
            Decision::Authorized { canonical }
        }
        // Unreachable: `Refuse` returns at the first forbidden region, so a
        // serve from it has nothing to blank. Guarded rather than asserted
        // because the failure is silent -- a `Decision::Authorized` built here
        // from a partial serve would drop the blank spans on the floor and
        // authorize the protected bytes outright. A regression should cost a
        // denial, not the object.
        Verdict::Serve { .. } => not_permitted(),
        Verdict::Denied { reason } => Decision::Denied { reason },
    }
}

/// [`check`], with the caller choosing what happens to forbidden bytes inside
/// the requested range.
///
/// Under [`DenialMode::Refuse`] this is `check` exactly -- same answers, same
/// short-circuit, same cost -- in the [`Verdict`] shape. Under
/// [`DenialMode::ZeroFill`] a range covering forbidden bytes may still be
/// served, with those bytes listed in [`Verdict::Serve::blank`] for the caller
/// to blank. Read [`DenialMode::ZeroFill`] before selecting it: it is unsafe
/// for a reader that parses the blanked bytes.
///
/// # What zero-fill does not relax
///
/// Everything except the treatment of forbidden bytes. A header that did not
/// parse, a principal of the wrong shape, an unsatisfiable range, an empty
/// range and a range past the indexed end are refused identically in both
/// modes, and a forbidden region that is metadata or unmapped refuses in both
/// too (see [`is_blankable`]). The set of bytes a principal can observe is
/// never larger under `ZeroFill` than under `Refuse`: every byte a serve
/// returns lies in a region the policy permits, because every region it does
/// not permit is either blanked or refused.
///
/// # Cost
///
/// `Refuse` short-circuits on the first forbidden region. `ZeroFill` cannot:
/// it has to know about every forbidden region in the range to blank them all,
/// so a denied request costs one policy evaluation per overlapped region
/// rather than stopping at the first. The allow path -- where nothing is
/// forbidden -- is identical in both, and it is the path that runs when the
/// system is working.
pub fn check_with_mode(
    index: &LayoutIndex,
    policy: &Policy,
    user: &Value,
    header: Option<&str>,
    mode: DenialMode,
) -> Verdict {
    // Only a header that did not parse may be reported as `BadRange`. An
    // unsatisfiable one is a function of `size`, so it joins the denials --
    // see `DenyReason::BadRange`.
    let range = match range::parse(header, index.size()) {
        Ok(range) => range,
        Err(range::RangeError::Unparseable) => {
            return Verdict::Denied {
                reason: DenyReason::BadRange,
            }
        }
        Err(range::RangeError::NotSatisfiable) => return not_served(),
    };

    if !principal_is_addressable(user) {
        return not_served();
    }

    // `try_resolve`, not `resolve` plus a hand-written `is_empty()`. The two
    // are not the same check, and the difference is a fail-open:
    //
    // * An empty range resolves to an empty slice, which `is_empty()` does
    //   catch -- but only for as long as whoever edits this function next
    //   remembers why the line is there.
    // * A range reaching past the indexed end resolves to a NON-empty slice:
    //   `resolve(&(50..200))` on a 100-byte index answers with the one region
    //   covering `50..100` and says nothing at all about `100..200`. An
    //   `is_empty()` check passes, the conjunction passes, and `check` hands
    //   back a `canonical` of `50..200` having authorized half of it. No
    //   emptiness test can see that; only comparing the range against the size
    //   can, which is what `try_resolve` does.
    //
    // That second case is unreachable from here today, because the range came
    // from `range::parse(header, index.size())` and is therefore already
    // clamped to this index. It is guarded anyway: the clamp and the resolve
    // read `size` from the same index in two separate statements, and the day
    // one of them takes a size from somewhere else -- a caller-supplied
    // expected size, a wasm binding that passes the object length in
    // separately -- the failure is silent and the bytes are already out.
    let Ok(regions) = index.try_resolve(&range) else {
        return not_served();
    };

    // Belt and braces, and the braces are cheap. `try_resolve` already
    // guarantees this slice is non-empty; the guarantee is worth one branch
    // because the failure it guards is silent and total -- an empty set makes
    // the conjunction below vacuously true, which authorizes the request rather
    // than failing it. A regression in `try_resolve` should cost a denial, not
    // the object.
    if regions.is_empty() {
        return not_served();
    }

    // Conjunctive: EVERY overlapped region must satisfy the policy. Under
    // `Refuse` the loop returns at the first one that does not, which is the
    // short-circuit the cost table above measures; under `ZeroFill` it keeps
    // going, because a span it never looked at is a forbidden byte it never
    // blanked. `props()` is built here rather than in the index so that only
    // the regions a request actually touches pay for one.
    let mut blank: Vec<Range<u64>> = Vec::new();
    for region in regions {
        if policy.permits(&json!({"user": user, "region": region.props()})) {
            continue;
        }
        if mode == DenialMode::Refuse {
            return not_served();
        }
        // Some forbidden bytes cannot be blanked without corrupting the object
        // for the bytes that WERE permitted. Those still refuse, and the
        // refusal is the same value as every other -- a caller able to tell
        // "would have been served, but the region was metadata" from an
        // ordinary denial would have an oracle for where the footer is.
        if !is_blankable(&region.kind) {
            return not_served();
        }
        // Clipped to the request. `resolve` returns only regions that overlap
        // `range`, so this intersection is non-empty; clipping is what keeps
        // every span inside `canonical`, which `redact` then relies on to index
        // the buffer.
        let span = region.start.max(range.start)..region.end().min(range.end);
        match blank.last_mut() {
            // Regions are sorted and contiguous, so a forbidden region
            // immediately after another one starts exactly where the last span
            // ended. Coalesce, so that the spans describe extents rather than
            // the index's internal boundaries. `>=` rather than `==` because a
            // span set that is merely non-decreasing must still come out
            // disjoint.
            Some(last) if span.start <= last.end => last.end = last.end.max(span.end),
            _ => blank.push(span),
        }
    }

    Verdict::Serve {
        canonical: range,
        blank,
    }
}

fn not_permitted() -> Decision {
    Decision::Denied {
        reason: DenyReason::NotPermitted,
    }
}

fn not_served() -> Verdict {
    Verdict::Denied {
        reason: DenyReason::NotPermitted,
    }
}

/// Is `user` a principal this crate is willing to evaluate a policy against?
///
/// A JSON object whose values are scalars, or arrays of scalars. Nothing
/// nested, and no nulls.
///
/// This is the same discipline
/// [`Region::props`](crate::index::Region::props) applies to file-derived
/// values, applied to the other half of the context for the same reason.
/// cql2 resolves a property by looking its dot-path up in the context and
/// running the value it finds through `Expr::try_from`, which is untagged: a
/// value shaped like `{"property": ..}` or `{"op": ..}` becomes an AST node
/// rather than data. Measured against cql2 0.6, such a node does not escalate
/// -- the converted expression is not reduced again, so it reaches the
/// enclosing operator unfolded and denies -- but that is a property of one
/// version of one dependency's reducer, and it is not a property this crate
/// should be resting on. Refusing the shape costs a walk over a handful of
/// claims and removes the question.
///
/// The nesting limit is not only about AST nodes. `Expr::try_from` recurses
/// through untagged deserialization, and this crate compiles to wasm32, where
/// the panic runtime aborts: a stack overflow there poisons the module
/// instance and takes down every request the worker would have served, so it
/// is an availability bug and not a crash. serde_json's own parser refuses at
/// depth 128, which caps a principal decoded straight from JSON text, but a
/// principal built from a struct or assembled in code has no such cap and the
/// measured abort is around 400 levels of array nesting on a 2 MiB stack.
/// This walk is itself depth-bounded -- object, then value, then array element
/// -- so it cannot be the thing that overflows.
///
/// Nulls are refused rather than tolerated. Absent and null are
/// indistinguishable to cql2, so a policy author cannot write a rule that
/// tells a claim that is missing from one that is present and empty. Both
/// deny; refusing is how the caller finds out.
///
/// The cost is that a rule cannot take a *structured* value from the
/// principal, `S_INTERSECTS(user.area, region.geom)` being the plausible one.
/// That is a feature nothing has asked for yet, and admitting it means
/// validating a GeoJSON geometry specifically rather than reopening the
/// context to arbitrary JSON.
fn principal_is_addressable(user: &Value) -> bool {
    let Some(claims) = user.as_object() else {
        // Not dot-addressable. `policy::permits` would deny a non-object
        // context anyway, but `user` is only one branch of the context, so
        // nothing downstream would have noticed.
        return false;
    };
    let scalar = |v: &Value| matches!(v, Value::String(_) | Value::Number(_) | Value::Bool(_));
    claims.values().all(|claim| match claim {
        Value::Array(items) => items.iter().all(scalar),
        other => scalar(other),
    })
}

// `single_range_in_vec_init` exists to catch a `vec![0..10]` written where
// `(0..10).collect()` was meant. Every range literal in a list below is one
// byte extent, which is the reading the lint assumes is a mistake -- and byte
// extents are what this whole module is about.
#[cfg(test)]
#[allow(clippy::single_range_in_vec_init)]
mod tests {
    use super::*;
    use crate::index::{Region, RegionKind};
    use crate::policy::QUERYABLES;
    use serde_json::json;

    /// metadata `0..10`, column_chunk "public" `10..20`, column_chunk "salary"
    /// `20..30`, and size 40 -- so `30..40` is filled with `Unmapped` by
    /// `LayoutIndex::try_new` and belongs to no rule anyone can write.
    fn index() -> LayoutIndex {
        LayoutIndex::new(
            vec![
                Region {
                    start: 0,
                    len: 10,
                    kind: RegionKind::Metadata {
                        name: "footer".into(),
                    },
                },
                Region {
                    start: 10,
                    len: 10,
                    kind: RegionKind::ColumnChunk {
                        column: "public".into(),
                        row_group: 0,
                    },
                },
                Region {
                    start: 20,
                    len: 10,
                    kind: RegionKind::ColumnChunk {
                        column: "salary".into(),
                        row_group: 0,
                    },
                },
            ],
            40,
        )
    }

    fn policy() -> Policy {
        Policy::load(
            "allow:\n  - \"region.kind = 'metadata'\"\n  \
             - \"region.kind = 'column_chunk' AND region.column <> 'salary'\"",
            QUERYABLES,
        )
        .unwrap()
    }

    fn analyst() -> Value {
        json!({"role": "analyst"})
    }

    fn decide(header: Option<&str>) -> Decision {
        check(&index(), &policy(), &analyst(), header)
    }

    fn denied() -> Decision {
        Decision::Denied {
            reason: DenyReason::NotPermitted,
        }
    }

    fn bad_range() -> Decision {
        Decision::Denied {
            reason: DenyReason::BadRange,
        }
    }

    // ---- The required tests ------------------------------------------------

    #[test]
    fn permitted_range_is_authorized_with_a_canonical_extent() {
        // The canonical extent is half-open: `bytes=0-9` is ten bytes, `0..10`.
        // An off-by-one here is a one-byte-per-request exfiltration primitive.
        for (header, canonical) in [
            ("bytes=0-9", 0..10u64),
            ("bytes=10-19", 10..20),
            ("bytes=0-19", 0..20),
            ("bytes=9-9", 9..10),
            ("bytes=19-19", 19..20),
        ] {
            assert_eq!(
                decide(Some(header)),
                Decision::Authorized { canonical },
                "{header}"
            );
        }
    }

    #[test]
    fn forbidden_range_is_denied() {
        for header in ["bytes=20-29", "bytes=20-20", "bytes=29-29"] {
            assert_eq!(decide(Some(header)), denied(), "{header}");
        }
    }

    // Rule 1, conjunctive: EVERY overlapped region must satisfy the policy.
    // Under `any` this range matches the metadata rule and serves the salary
    // column with it.
    #[test]
    fn a_straddling_range_is_denied_even_though_one_region_is_permitted() {
        for header in [
            "bytes=19-20", // one byte of public, one byte of salary
            "bytes=0-20",  // metadata + public + one byte of salary
            "bytes=0-29",  // everything the resolver classified
            "bytes=9-20",
        ] {
            assert_eq!(decide(Some(header)), denied(), "{header}");
        }
    }

    // Rule 2. `Unmapped` answers to no vocabulary a policy is written in, so a
    // range touching it can never be permitted -- and this must hold because
    // the region denies, not because the region set came back empty.
    #[test]
    fn a_range_over_unmapped_bytes_is_denied() {
        for header in ["bytes=30-39", "bytes=39-39", "bytes=29-30", "bytes=-1"] {
            assert_eq!(decide(Some(header)), denied(), "{header}");
        }
    }

    // Rule 3. A reader that gets 403 on a coalesced range commonly retries as a
    // full-object GET; that retry must not be the way around the policy.
    #[test]
    fn no_range_header_means_the_whole_object_and_is_denied() {
        assert_eq!(decide(None), denied());
    }

    // RFC 9110 requires an origin server to IGNORE a Range header it cannot
    // parse and answer 200 with the entire representation. Authorizing the
    // prefix of a header we parsed loosely is therefore a full-object
    // disclosure, so a header we cannot parse strictly is a denial.
    #[test]
    fn a_malformed_range_is_denied_not_ignored() {
        for header in [
            "bytes=0-9,20-29", // multi-range: prefix is permitted, whole is not
            "bytes=0-0, items=20-29",
            "BYTES=0-9",
            "bytes= 0-9",
            "bytes=5-4",
            "items=0-9",
            "bytes=",
            "",
            "bytes=0-9\n",
        ] {
            assert_eq!(decide(Some(header)), bad_range(), "{header}");
        }
    }

    // A 403 that echoes the resolved regions hands back the protected column's
    // name and its byte extent -- the two things the policy exists to withhold.
    #[test]
    fn denial_does_not_disclose_which_region_was_protected() {
        let salary = decide(Some("bytes=20-29"));
        let unmapped = decide(Some("bytes=30-39"));
        let straddle = decide(Some("bytes=19-20"));
        let whole = decide(None);
        // Denials for different causes are the same value, so no caller can
        // relay a distinction it was never given.
        assert_eq!(salary, unmapped);
        assert_eq!(salary, straddle);
        assert_eq!(salary, whole);
        // ...including through the debug rendering, which is what a structured
        // log line or a `{:?}` in an error body would carry off-box.
        let rendered = format!("{salary:?}");
        for leak in ["salary", "public", "footer", "column", "20", "30", "region"] {
            assert!(!rendered.contains(leak), "`{leak}` disclosed by {rendered}");
        }
    }

    // ---- Contracts left open by earlier tasks ------------------------------

    // `range.rs` documents that `parse(None, 0)` yields `0..0` on a zero-byte
    // object and that `check()` denies it. That claim has lived in a doc
    // comment in another module; this is the end-to-end proof of it.
    #[test]
    fn a_zero_byte_object_with_no_range_header_is_denied() {
        assert_eq!(range::parse(None, 0).unwrap(), 0..0);
        let empty = LayoutIndex::new(vec![], 0);
        // Not merely denied: denied even under a policy that permits every
        // region there is, because there are no regions and `all()` over the
        // empty set is `true`.
        let permissive = Policy::load("allow:\n  - \"true\"", QUERYABLES).unwrap();
        assert_eq!(check(&empty, &permissive, &analyst(), None), denied());
    }

    // The design was criticised for example rules that never mention who is
    // asking. A policy naming `user.role` must actually gate on the principal.
    #[test]
    fn a_policy_naming_the_principal_gates_on_it() {
        let p = Policy::load(
            "allow:\n  - \"region.kind = 'column_chunk' AND user.role = 'auditor'\"",
            QUERYABLES,
        )
        .unwrap();
        let idx = index();
        let auditor = json!({"role": "auditor"});
        assert_eq!(
            check(&idx, &p, &auditor, Some("bytes=20-29")),
            Decision::Authorized { canonical: 20..30 }
        );
        // Same object, same bytes, same policy -- only the principal differs.
        assert_eq!(check(&idx, &p, &analyst(), Some("bytes=20-29")), denied());
        // And the principal alone does not grant: the region still has to
        // match, or the assertion above would pass for the wrong reason.
        assert_eq!(check(&idx, &p, &auditor, Some("bytes=0-9")), denied());
    }

    // ---- The error kinds as a disclosure channel ---------------------------

    // `range.rs`: every `NotSatisfiable` is a function of `size` and no
    // `Unparseable` ever is, and an attacker who can tell them apart binary-
    // searches the object size in 64 probes. Collapsing both into `BadRange`
    // is NOT enough, because `BadRange` vs `NotPermitted` would then carry the
    // same bit. `BadRange` must mean "the header did not parse" and nothing
    // else, so that it is a function of the header alone.
    #[test]
    fn bad_range_is_a_function_of_the_header_alone() {
        let idx = index();
        let p = policy();
        let sizes = [1u64, 40, 1_000, u64::MAX];
        for header in ["BYTES=0-9", "bytes=", "bytes=5-4", "items=0-9", ""] {
            for size in sizes {
                let sized = LayoutIndex::new(vec![], size);
                assert_eq!(
                    check(&sized, &p, &analyst(), Some(header)),
                    bad_range(),
                    "size {size}: {header}"
                );
            }
        }
        // A satisfiability failure is a *denial*, not a bad range: it is a
        // function of the size and must be indistinguishable from any other
        // denial. `bytes=N-` is the probe the range docs single out.
        for header in ["bytes=39-", "bytes=40-", "bytes=41-", "bytes=99999-"] {
            assert_eq!(
                check(&idx, &p, &analyst(), Some(header)),
                denied(),
                "{header}"
            );
        }
        // The boundary the probe would binary-search: N = 39 is inside the
        // object and N = 40 is past its end, and the two are the same answer.
        assert_eq!(
            check(&idx, &p, &analyst(), Some("bytes=39-")),
            check(&idx, &p, &analyst(), Some("bytes=40-"))
        );
        // Same for the one-request "is this object empty?" probe, asked by a
        // principal who could not have read that byte either way: an
        // unsatisfiable range on a zero-byte object and a forbidden byte on a
        // real one are the same answer.
        let empty = LayoutIndex::new(vec![], 0);
        assert_eq!(
            check(&empty, &p, &analyst(), Some("bytes=20-20")),
            check(&idx, &p, &analyst(), Some("bytes=20-20"))
        );
        // The residual channel, stated rather than hidden: a principal who IS
        // permitted the byte does learn the object is non-empty. That is the
        // boundary `range.rs` draws -- size facts may reach a principal
        // already permitted to read the extent, and the backend states the
        // complete length to them in `Content-Range` regardless.
        assert_eq!(
            check(&idx, &p, &analyst(), Some("bytes=0-0")),
            Decision::Authorized { canonical: 0..1 }
        );
        assert_eq!(check(&empty, &p, &analyst(), Some("bytes=0-0")), denied());
    }

    // ---- The principal is externally supplied JSON -------------------------

    // cql2 resolves a property by looking the path up in the context and
    // running the value it finds through `Expr::try_from`, which is untagged:
    // an object shaped like `{"op": ..}` or `{"property": ..}` becomes an AST
    // node rather than data. Region props are scalars by construction; the
    // principal is whatever the caller passes, so `check` holds it to the same
    // rule instead of trusting the evaluator to be safe against it.
    #[test]
    fn a_crafted_principal_is_refused() {
        let idx = index();
        let p = Policy::load(
            "allow:\n  - \"region.kind = 'metadata' AND user.role = 'admin'\"",
            QUERYABLES,
        )
        .unwrap();
        for hostile in [
            json!({"role": {"op": "=", "args": [1, 1]}}),
            json!({"role": {"property": "user.level"}, "level": "admin"}),
            json!({"role": {"op": "lower", "args": ["ADMIN"]}}),
            json!({"role": {"type": "Point", "coordinates": [0, 0]}}),
            json!({"role": [["nested"]]}),
            json!({"role": null}),
            json!({"properties": {"region": {"kind": "metadata"}}, "role": "admin"}),
            // Not an object at all, so nothing about it is dot-addressable.
            json!("admin"),
            json!(["admin"]),
            json!(null),
            json!(7),
        ] {
            assert_eq!(
                check(&idx, &p, &hostile, Some("bytes=0-9")),
                denied(),
                "{hostile}"
            );
        }
        // The same rule, the same bytes, an ordinary principal: permitted.
        // Without this the assertions above would pass for the wrong reason.
        assert_eq!(
            check(&idx, &p, &json!({"role": "admin"}), Some("bytes=0-9")),
            Decision::Authorized { canonical: 0..10 }
        );
    }

    // An ordinary identity token is scalars and lists of scalars -- and an
    // anonymous principal is an empty object, which must still decide rather
    // than fail.
    #[test]
    fn an_ordinary_principal_is_accepted() {
        let idx = index();
        let p = policy();
        for ok in [
            json!({}),
            json!({"role": "analyst"}),
            json!({"role": "analyst", "level": 3, "admin": false}),
            json!({"groups": ["a", "b"], "role": "analyst"}),
        ] {
            assert_eq!(
                check(&idx, &p, &ok, Some("bytes=0-9")),
                Decision::Authorized { canonical: 0..10 },
                "{ok}"
            );
        }
    }

    // `Expr::try_from` recurses through untagged deserialization, and this
    // crate compiles to wasm32 where the panic runtime aborts: a stack
    // overflow poisons the module instance and takes out every request that
    // worker would have served. serde_json's own parser refuses at depth 128,
    // so a principal decoded straight from JSON text cannot reach this -- but
    // one built from a struct or assembled in code has no such limit, and the
    // measured abort is around 400 levels of nesting on a 2 MiB stack.
    #[test]
    fn a_deeply_nested_principal_is_refused_rather_than_overflowing_the_stack() {
        let mut deep = json!(1);
        for _ in 0..1_000 {
            deep = json!([deep]);
        }
        assert_eq!(
            check(
                &index(),
                &policy(),
                &json!({ "role": deep }),
                Some("bytes=0-9")
            ),
            denied()
        );
    }

    // ---- The canonical extent is the API's whole point ---------------------

    // The caller must fetch `canonical` and nothing else. It is derived from
    // the parsed header, never echoed from it, so the clamping and the
    // inclusive-to-half-open conversion are already applied.
    #[test]
    fn the_canonical_extent_is_clamped_and_half_open() {
        let idx = LayoutIndex::new(
            vec![Region {
                start: 0,
                len: 40,
                kind: RegionKind::Metadata {
                    name: "footer".into(),
                },
            }],
            40,
        );
        let p = policy();
        for (header, canonical) in [
            ("bytes=0-9", 0..10u64),
            ("bytes=30-999", 30..40), // clamped to the end of the object
            ("bytes=-5", 35..40),     // suffix, counted back from the end
            ("bytes=-500", 0..40),    // suffix longer than the object
            ("bytes=35-", 35..40),
            ("bytes=0-18446744073709551615", 0..40),
        ] {
            assert_eq!(
                check(&idx, &p, &analyst(), Some(header)),
                Decision::Authorized { canonical },
                "{header}"
            );
        }
    }

    // ---- Zero-fill: the second denial mode ---------------------------------

    fn chunk(start: u64, len: u64, column: &str, row_group: usize) -> Region {
        Region {
            start,
            len,
            kind: RegionKind::ColumnChunk {
                column: column.into(),
                row_group,
            },
        }
    }

    /// The layout zero-fill exists for: permitted and forbidden extents
    /// interleaved, two forbidden ones physically adjacent, a metadata region
    /// at the front and an unmapped tail.
    ///
    /// ```text
    ///  0..10  metadata "footer"
    /// 10..20  column_chunk "public" rg0
    /// 20..30  column_chunk "salary" rg0
    /// 30..40  column_chunk "public" rg1
    /// 40..50  column_chunk "ssn"    rg0
    /// 50..60  column_chunk "bonus"  rg0   <- adjacent to the one above
    /// 60..70  column_chunk "public" rg2
    /// 70..80  unmapped (filled by `try_new`)
    /// ```
    fn zf_index() -> LayoutIndex {
        LayoutIndex::new(
            vec![
                Region {
                    start: 0,
                    len: 10,
                    kind: RegionKind::Metadata {
                        name: "footer".into(),
                    },
                },
                chunk(10, 10, "public", 0),
                chunk(20, 10, "salary", 0),
                chunk(30, 10, "public", 1),
                chunk(40, 10, "ssn", 0),
                chunk(50, 10, "bonus", 0),
                chunk(60, 10, "public", 2),
            ],
            80,
        )
    }

    /// Metadata and the `public` column, nothing else.
    fn zf_policy() -> Policy {
        Policy::load(
            "allow:\n  - \"region.kind = 'metadata'\"\n  \
             - \"region.kind = 'column_chunk' AND region.column = 'public'\"",
            QUERYABLES,
        )
        .unwrap()
    }

    fn zero_fill(index: &LayoutIndex, policy: &Policy, header: &str) -> Verdict {
        check_with_mode(
            index,
            policy,
            &analyst(),
            Some(header),
            DenialMode::ZeroFill,
        )
    }

    fn served(canonical: Range<u64>, blank: Vec<Range<u64>>) -> Verdict {
        Verdict::Serve { canonical, blank }
    }

    fn refused() -> Verdict {
        Verdict::Denied {
            reason: DenyReason::NotPermitted,
        }
    }

    /// Which bytes of `index` this principal could read one byte at a time
    /// under `Refuse` -- the definition of "observable" the no-widening
    /// property is stated against. A single-byte range touches exactly one
    /// region, so this is the policy's verdict per region, obtained through
    /// the real decision function rather than re-derived here.
    fn observable_under_refuse(index: &LayoutIndex, policy: &Policy, user: &Value) -> Vec<bool> {
        (0..index.size())
            .map(|b| {
                let header = format!("bytes={b}-{b}");
                matches!(
                    check(index, policy, user, Some(&header)),
                    Decision::Authorized { .. }
                )
            })
            .collect()
    }

    /// Every region boundary, and one byte either side of it. An off-by-one in
    /// the clipping of a blank span serves a protected byte, so the matrix
    /// tests walk these rather than a coarse grid.
    fn edge_offsets(index: &LayoutIndex) -> Vec<u64> {
        let mut offsets = vec![0u64, index.size()];
        for region in index.regions() {
            for edge in [region.start, region.end()] {
                offsets.extend([edge.saturating_sub(1), edge, (edge + 1).min(index.size())]);
            }
        }
        offsets.sort_unstable();
        offsets.dedup();
        offsets
    }

    // `Refuse` is today's behaviour, unchanged. Not "equivalent": the same
    // answer for every header and every principal the existing tests reach,
    // including the ones `check` refuses before a region is ever resolved.
    #[test]
    fn refuse_mode_answers_exactly_what_check_answers() {
        let (idx, pol) = (zf_index(), zf_policy());
        let users = [
            analyst(),
            json!({"role": "auditor"}),
            json!({}),
            json!({"role": {"op": "=", "args": [1, 1]}}),
            json!(null),
        ];
        let headers = [
            None,
            Some("bytes=0-9"),
            Some("bytes=10-19"),
            Some("bytes=20-29"),
            Some("bytes=19-20"),
            Some("bytes=0-79"),
            Some("bytes=70-79"),
            Some("bytes=-1"),
            Some("bytes=80-"),
            Some("BYTES=0-9"),
            Some("bytes=5-4"),
            Some(""),
        ];
        for user in &users {
            for header in headers {
                let old = check(&idx, &pol, user, header);
                let new = check_with_mode(&idx, &pol, user, header, DenialMode::Refuse);
                let expected = match old {
                    Decision::Authorized { canonical } => served(canonical, vec![]),
                    Decision::Denied { reason } => Verdict::Denied { reason },
                };
                assert_eq!(new, expected, "{header:?} / {user}");
            }
        }
    }

    // The case DuckDB produces: a 16 KiB aligned block that lies wholly inside
    // a column chunk the reader never projected. `Refuse` has nothing to offer
    // it; `ZeroFill` serves the block with every byte of it blanked, which is
    // what the reader was going to ignore anyway.
    #[test]
    fn a_range_wholly_inside_a_forbidden_chunk_is_served_entirely_blank() {
        let (idx, pol) = (zf_index(), zf_policy());
        assert_eq!(
            zero_fill(&idx, &pol, "bytes=20-29"),
            served(20..30, vec![20..30])
        );
        assert_eq!(
            zero_fill(&idx, &pol, "bytes=22-27"),
            served(22..28, vec![22..28])
        );
        assert_eq!(
            zero_fill(&idx, &pol, "bytes=25-25"),
            served(25..26, vec![25..26])
        );
        // ...and `Refuse` still refuses every one of them.
        for header in ["bytes=20-29", "bytes=22-27", "bytes=25-25"] {
            assert_eq!(
                check(&idx, &pol, &analyst(), Some(header)),
                denied(),
                "{header}"
            );
        }
    }

    // permitted / forbidden / permitted / forbidden / permitted in one range:
    // two blank spans, each clipped to the forbidden extent and nothing wider.
    #[test]
    fn a_range_spanning_permitted_and_forbidden_extents_blanks_only_the_forbidden_ones() {
        let (idx, pol) = (zf_index(), zf_policy());
        assert_eq!(
            zero_fill(&idx, &pol, "bytes=10-69"),
            served(10..70, vec![20..30, 40..60])
        );
    }

    // Two forbidden regions that touch are one blank span, not two abutting
    // ones. A caller that walks the spans to build `Content-Range` parts, or
    // that asserts on their count, must see the extents and not the index's
    // internal region boundaries.
    #[test]
    fn adjacent_forbidden_regions_coalesce_into_one_span() {
        let (idx, pol) = (zf_index(), zf_policy());
        assert_eq!(
            zero_fill(&idx, &pol, "bytes=40-59"),
            served(40..60, vec![40..60])
        );
        assert_eq!(
            zero_fill(&idx, &pol, "bytes=45-55"),
            served(45..56, vec![45..56])
        );
        // The `salary` chunk is NOT adjacent to the `ssn`/`bonus` pair -- a
        // permitted chunk sits between them -- so those stay two spans. Without
        // this the assertion above would pass for a coalescer that merged
        // everything.
        assert_eq!(
            zero_fill(&idx, &pol, "bytes=20-59"),
            served(20..60, vec![20..30, 40..60])
        );
    }

    // The boundary arithmetic, one byte either side of every edge a blank span
    // can have. Widen a span by one and a permitted byte is destroyed; narrow
    // it by one and a protected byte is served.
    #[test]
    fn a_blank_span_at_a_range_boundary_is_exact() {
        let (idx, pol) = (zf_index(), zf_policy());
        for (header, canonical, blank) in [
            // The forbidden region starts at 20.
            ("bytes=19-19", 19..20u64, vec![]),
            ("bytes=19-20", 19..21, vec![20..21]),
            ("bytes=20-20", 20..21, vec![20..21]),
            ("bytes=20-21", 20..22, vec![20..22]),
            // ...and ends at 30.
            ("bytes=28-29", 28..30, vec![28..30]),
            ("bytes=29-29", 29..30, vec![29..30]),
            ("bytes=29-30", 29..31, vec![29..30]),
            ("bytes=30-30", 30..31, vec![]),
            ("bytes=29-31", 29..32, vec![29..30]),
            // Clipped at both ends at once.
            ("bytes=25-44", 25..45, vec![25..30, 40..45]),
            // A range that stops exactly where a forbidden region starts
            // touches no forbidden byte at all.
            ("bytes=10-19", 10..20, vec![]),
            ("bytes=30-39", 30..40, vec![]),
        ] {
            assert_eq!(
                zero_fill(&idx, &pol, header),
                served(canonical, blank),
                "{header}"
            );
        }
    }

    // Blanking a Parquet footer or a TIFF IFD produces a CORRUPT file rather
    // than a restricted one: the reader cannot find what it is still allowed
    // to read, so the failure is total instead of partial. `ZeroFill` must
    // refuse there, exactly as `Refuse` would.
    #[test]
    fn zero_fill_still_refuses_a_range_covering_forbidden_metadata() {
        let idx = zf_index();
        // Column chunks are grantable, the footer is not.
        let no_metadata = Policy::load(
            "allow:\n  - \"region.kind = 'column_chunk' AND region.column = 'public'\"",
            QUERYABLES,
        )
        .unwrap();
        for header in [
            "bytes=0-9",  // the footer alone
            "bytes=0-0",  // one byte of it
            "bytes=9-10", // the footer and a permitted chunk
            "bytes=0-19", // ...and the whole of one
            "bytes=0-29", // ...plus a chunk that WOULD have been blankable
        ] {
            assert_eq!(zero_fill(&idx, &no_metadata, header), refused(), "{header}");
        }
        // The same ranges under a policy that grants the footer are served,
        // so the refusals above are about the metadata and not about the range.
        assert_eq!(
            zero_fill(&idx, &zf_policy(), "bytes=0-29"),
            served(0..30, vec![20..30])
        );
    }

    // `Unmapped` is bytes no resolver claimed, which is the set we understand
    // least -- and the set that in practice holds a Parquet `PAR1` magic, a
    // footer-length trailer, inter-chunk padding and a COG's GDAL ghost area.
    // Zero-filling is a claim that the blanked bytes are never parsed, and
    // that claim cannot be made about bytes whose meaning is unknown, so
    // `Unmapped` refuses on the same footing as metadata.
    #[test]
    fn zero_fill_still_refuses_a_range_covering_unmapped_bytes() {
        let (idx, pol) = (zf_index(), zf_policy());
        for header in [
            "bytes=70-79",
            "bytes=79-79",
            "bytes=69-70",
            "bytes=-1",
            "bytes=60-79",
        ] {
            assert_eq!(zero_fill(&idx, &pol, header), refused(), "{header}");
        }
        // ...even under a policy that grants every classified region, which is
        // the case where an `Unmapped` blank would be most tempting.
        let permissive = Policy::load(
            "allow:\n  - \"region.kind = 'metadata'\"\n  \
             - \"region.kind = 'column_chunk'\"",
            QUERYABLES,
        )
        .unwrap();
        assert_eq!(zero_fill(&idx, &permissive, "bytes=60-79"), refused());
    }

    // The property the mode lives or dies by. `ZeroFill` serves requests
    // `Refuse` would have denied, so it cannot be a subset per request -- the
    // statement that has to hold is per BYTE: every byte a `ZeroFill` response
    // returns lies in a region this principal could have read one byte at a
    // time under `Refuse`. That implies the global statement (the union over
    // all requests does not grow) without depending on a quantifier over
    // requests a test cannot enumerate.
    //
    // The converse is asserted in the same walk, because only the pair pins
    // the blank set: every byte of the canonical extent that is NOT observable
    // is inside a blank span. One direction alone is satisfied by blanking
    // everything, the other by blanking nothing.
    #[test]
    fn zero_fill_never_widens_the_bytes_a_principal_can_observe() {
        let idx = zf_index();
        let policies = [
            (
                "everything",
                Policy::load("allow:\n  - \"true\"", QUERYABLES).unwrap(),
            ),
            (
                "nothing",
                Policy::load("allow:\n  - \"false\"", QUERYABLES).unwrap(),
            ),
            ("public", zf_policy()),
            (
                "chunks only",
                Policy::load("allow:\n  - \"region.kind = 'column_chunk'\"", QUERYABLES).unwrap(),
            ),
            (
                "not salary",
                Policy::load(
                    "allow:\n  - \"region.kind = 'metadata'\"\n  \
                     - \"region.kind = 'column_chunk' AND region.column <> 'salary'\"",
                    QUERYABLES,
                )
                .unwrap(),
            ),
            (
                "auditors only",
                Policy::load(
                    "allow:\n  - \"region.kind = 'column_chunk' AND user.role = 'auditor'\"",
                    QUERYABLES,
                )
                .unwrap(),
            ),
        ];
        let users = [
            analyst(),
            json!({"role": "auditor"}),
            json!({}),
            json!(null),
        ];
        let offsets = edge_offsets(&idx);

        for (name, pol) in &policies {
            for user in &users {
                let observable = observable_under_refuse(&idx, pol, user);
                for (i, &start) in offsets.iter().enumerate() {
                    for &end in &offsets[i..] {
                        if start >= end {
                            continue;
                        }
                        let header = format!("bytes={}-{}", start, end - 1);
                        let what = format!("{name} / {user} / {header}");
                        let verdict =
                            check_with_mode(&idx, pol, user, Some(&header), DenialMode::ZeroFill);
                        let Verdict::Serve { canonical, blank } = verdict else {
                            continue; // A denial serves nothing, so it widens nothing.
                        };

                        // The spans themselves: inside the extent, ordered,
                        // non-empty, disjoint and never merely abutting.
                        let mut previous_end = canonical.start;
                        for span in &blank {
                            assert!(span.start < span.end, "empty span in {what}");
                            assert!(
                                span.start >= canonical.start && span.end <= canonical.end,
                                "{span:?} outside {canonical:?} in {what}"
                            );
                            assert!(
                                span.start > previous_end || previous_end == canonical.start,
                                "{span:?} abuts or overlaps the span before it in {what}"
                            );
                            previous_end = span.end;
                        }

                        // The byte-level property, both directions.
                        for byte in canonical.clone() {
                            let blanked = blank.iter().any(|s| s.contains(&byte));
                            let allowed = observable[byte as usize];
                            assert!(
                                blanked || allowed,
                                "byte {byte} served but not observable under Refuse: {what}"
                            );
                            assert!(
                                !blanked || !allowed,
                                "byte {byte} blanked though Refuse would have served it: {what}"
                            );
                        }

                        // And where `Refuse` authorizes, the two modes are the
                        // same answer with nothing blanked.
                        if let Decision::Authorized {
                            canonical: refused_canonical,
                        } = check(&idx, pol, user, Some(&header))
                        {
                            assert_eq!(canonical, refused_canonical, "{what}");
                            assert!(blank.is_empty(), "{what}");
                        }
                    }
                }
            }
        }
    }

    // `ZeroFill` is a policy about *forbidden bytes*, not a relaxation of
    // anything else. A header that did not parse, a principal of the wrong
    // shape, an unsatisfiable range and an empty one are refused identically
    // in both modes -- and a `BadRange` stays a `BadRange`, because it is still
    // a function of the header text alone.
    #[test]
    fn zero_fill_relaxes_nothing_except_forbidden_bytes() {
        let (idx, pol) = (zf_index(), zf_policy());
        for header in [
            "BYTES=0-9",
            "bytes= 0-9",
            "bytes=5-4",
            "bytes=0-9,20-29",
            "bytes=",
            "",
        ] {
            assert_eq!(
                check_with_mode(&idx, &pol, &analyst(), Some(header), DenialMode::ZeroFill),
                Verdict::Denied {
                    reason: DenyReason::BadRange
                },
                "{header}"
            );
        }
        for header in ["bytes=80-", "bytes=999-", "bytes=-0"] {
            assert_eq!(zero_fill(&idx, &pol, header), refused(), "{header}");
        }
        for hostile in [
            json!({"role": {"op": "=", "args": [1, 1]}}),
            json!("analyst"),
            json!(null),
        ] {
            assert_eq!(
                check_with_mode(
                    &idx,
                    &pol,
                    &hostile,
                    Some("bytes=10-19"),
                    DenialMode::ZeroFill
                ),
                refused(),
                "{hostile}"
            );
        }
        // A zero-byte object with no header resolves to no regions, which a
        // conjunction would wave through. `ZeroFill` must not be the way in.
        let empty = LayoutIndex::new(vec![], 0);
        let permissive = Policy::load("allow:\n  - \"true\"", QUERYABLES).unwrap();
        assert_eq!(
            check_with_mode(&empty, &permissive, &analyst(), None, DenialMode::ZeroFill),
            refused()
        );
    }

    // A `ZeroFill` denial must be the same value as every other denial. If a
    // caller could tell "would have been served, but the forbidden region was
    // metadata" from an ordinary refusal, the mode would have turned the
    // denial into an oracle for where the footer is.
    #[test]
    fn a_zero_fill_denial_discloses_no_more_than_any_other_denial() {
        let idx = zf_index();
        let no_metadata = Policy::load(
            "allow:\n  - \"region.kind = 'column_chunk' AND region.column = 'public'\"",
            QUERYABLES,
        )
        .unwrap();
        let metadata = zero_fill(&idx, &no_metadata, "bytes=0-9");
        let unmapped = zero_fill(&idx, &zf_policy(), "bytes=70-79");
        let principal = check_with_mode(
            &idx,
            &zf_policy(),
            &json!(null),
            Some("bytes=10-19"),
            DenialMode::ZeroFill,
        );
        assert_eq!(metadata, unmapped);
        assert_eq!(metadata, principal);
        let rendered = format!("{metadata:?}");
        for leak in [
            "salary", "public", "footer", "column", "metadata", "unmapped", "0", "70",
        ] {
            assert!(!rendered.contains(leak), "`{leak}` disclosed by {rendered}");
        }
    }

    // The blank spans are ABSOLUTE file offsets, and `redact` is the only
    // place the subtraction back to buffer offsets is written down. A caller
    // that does the arithmetic itself and gets it wrong serves protected bytes.
    #[test]
    fn redact_blanks_exactly_the_protected_bytes_of_the_fetched_buffer() {
        let verdict = zero_fill(&zf_index(), &zf_policy(), "bytes=10-69");
        let Verdict::Serve { canonical, .. } = verdict.clone() else {
            panic!("expected a served verdict");
        };
        assert_eq!(canonical, 10..70);
        // Every byte non-zero to start with, so a zero can only come from the
        // redaction.
        let mut buffer: Vec<u8> = (canonical.start..canonical.end)
            .map(|b| (b % 251 + 1) as u8)
            .collect();
        verdict.redact(&mut buffer).unwrap();
        for (i, byte) in buffer.iter().enumerate() {
            let offset = canonical.start + i as u64;
            let protected = (20..30).contains(&offset) || (40..60).contains(&offset);
            assert_eq!(*byte == 0, protected, "byte at {offset}");
        }
    }

    // Obligation 2 on `Decision::Authorized` says a caller must reject a
    // response whose extent is not `canonical`. A buffer of the wrong length
    // is that response, arriving at the one function that can still catch it:
    // the blank offsets would land on the wrong bytes. It refuses -- and it
    // blanks the buffer on the way out, so that a caller which ignores the
    // error still cannot serve what it fetched.
    #[test]
    fn redact_refuses_a_buffer_that_is_not_the_canonical_extent() {
        let verdict = zero_fill(&zf_index(), &zf_policy(), "bytes=10-69");
        for length in [0usize, 59, 61, 80] {
            let mut buffer = vec![0xffu8; length];
            assert!(verdict.redact(&mut buffer).is_err(), "{length} bytes");
            assert!(
                buffer.iter().all(|b| *b == 0),
                "{length} bytes left readable"
            );
        }
        // A denial has no extent to redact against at all.
        let denial = zero_fill(&zf_index(), &zf_policy(), "bytes=70-79");
        let mut buffer = vec![0xffu8; 10];
        assert!(denial.redact(&mut buffer).is_err());
        assert!(buffer.iter().all(|b| *b == 0));
    }

    // The measurement the mode exists for, against the real object rather than
    // the toy index: DuckDB reads `data/nyc-taxi-8rg.parquet` in 16 KiB
    // power-of-two aligned blocks, so a policy withholding one column refuses
    // every block that column happens to share an alignment boundary with --
    // whether or not the query ever projected it.
    //
    // This also pins the thing that decides whether refusing `Unmapped` costs
    // anything in practice: the Parquet resolver claims every byte of this
    // file, magic and footer trailer included, so there are no unmapped bytes
    // for a block to trip over. A resolver that regressed into leaving gaps
    // would silently take zero-fill back to refusing.
    #[test]
    fn zero_fill_serves_the_aligned_block_reads_refuse_cannot() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let bytes = std::fs::read(root.join("data/nyc-taxi-8rg.parquet")).unwrap();
        let size = bytes.len() as u64;
        let idx = crate::parquet::build_index(&bytes, size).unwrap();
        assert!(
            !idx.regions()
                .iter()
                .any(|r| matches!(r.kind, RegionKind::Unmapped)),
            "an unmapped region would refuse under both modes"
        );

        // Everything but the `extra` column, which is what the measurement in
        // `DenialMode` withholds.
        let pol = Policy::load(
            "allow:\n  - \"region.kind = 'metadata'\"\n  \
             - \"region.kind = 'column_index'\"\n  \
             - \"region.kind = 'bloom_filter' AND region.column <> 'extra'\"\n  \
             - \"region.kind = 'column_chunk' AND region.column <> 'extra'\"",
            QUERYABLES,
        )
        .unwrap();

        let (mut refused_blocks, mut zero_filled_blocks) = (0u32, 0u32);
        let mut offset = 0u64;
        while offset < size {
            let end = (offset + 16 * 1024).min(size);
            let header = format!("bytes={}-{}", offset, end - 1);
            let refuse = check(&idx, &pol, &analyst(), Some(&header));
            let fill = check_with_mode(&idx, &pol, &analyst(), Some(&header), DenialMode::ZeroFill);
            // Whatever else happens, zero-fill never refuses a block that
            // `Refuse` would have served.
            if matches!(refuse, Decision::Authorized { .. }) {
                assert_eq!(fill, served(offset..end, vec![]), "{header}");
            } else {
                refused_blocks += 1;
                let Verdict::Serve { canonical, blank } = &fill else {
                    panic!("{header} refused under both modes");
                };
                assert_eq!(*canonical, offset..end, "{header}");
                assert!(!blank.is_empty(), "{header} served nothing blanked");
                zero_filled_blocks += 1;
            }
            offset = end;
        }
        // Measured: 26 of the 515 aligned blocks cover a byte of `extra`, and
        // `Refuse` has nothing to offer any of them. The exact count is not the
        // property -- that every one of them becomes servable is.
        assert!(refused_blocks > 0, "the policy withheld nothing");
        assert_eq!(zero_filled_blocks, refused_blocks);
    }

    // Nothing forbidden in the range means the two modes are one answer: the
    // allow path is where a gateway spends its time, and `ZeroFill` must not
    // quietly change what it hands back there.
    #[test]
    fn a_wholly_permitted_range_is_the_same_answer_in_both_modes() {
        let (idx, pol) = (zf_index(), zf_policy());
        for (header, canonical) in [
            ("bytes=0-19", 0..20u64),
            ("bytes=10-19", 10..20),
            ("bytes=30-39", 30..40),
            ("bytes=60-69", 60..70),
            ("bytes=0-0", 0..1),
        ] {
            assert_eq!(
                zero_fill(&idx, &pol, header),
                served(canonical.clone(), vec![]),
                "{header}"
            );
            assert_eq!(
                check(&idx, &pol, &analyst(), Some(header)),
                Decision::Authorized { canonical },
                "{header}"
            );
        }
    }
}
