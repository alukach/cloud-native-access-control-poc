//! The browser boundary.
//!
//! Two operations, as small as they can be: build an index from bytes, and
//! check a byte range against an index, a policy and a principal.
//!
//! # Why this module is not `#[cfg(target_arch = "wasm32")]` in its entirety
//!
//! `#[wasm_bindgen]` exports cannot be called from a native test, so a binding
//! that carries logic is a binding that is never tested. Everything here is
//! therefore split in two: plain functions that hold the whole of the
//! behaviour and compile on every target, and -- behind
//! `#[cfg(target_arch = "wasm32")]` -- wrappers that do nothing but convert
//! types. The tests at the bottom run natively against the plain half.
//!
//! # Why the handles are opaque
//!
//! A COG index is hundreds of regions and a policy costs a parse plus static
//! validation ([`Policy::load`]). Both are built once and held by the JS side
//! as handles, because the demo measures the per-request cost of a *check* and
//! rebuilding either one per request would bury that measurement under work a
//! real gateway does at startup.
//!
//! # Where the decision actually comes from
//!
//! Nowhere in this module is an allow or a deny computed. Every verdict --
//! the request's, and each individual region's for the grid colouring -- is
//! [`decision::check`]'s answer, reached through the same range parse, the
//! same principal validation and the same conjunction. This module resolves
//! regions for *display* only. A binding that re-derived the rule would be a
//! second implementation of it, and the second implementation is the one
//! nobody audits.
//!
//! # Offsets cross the boundary as `f64`
//!
//! JavaScript byte offsets are `Number`s: `File.size`, `AsyncBuffer.slice`'s
//! arguments and geotiff's `{offset, length}` are all doubles. Taking `u64`
//! would force every call site to wrap in `BigInt`, and taking `f64` blindly
//! would silently round a large offset into a different one -- in an
//! authorization path. [`offset_from_f64`] refuses anything that is not an
//! exact non-negative integer at or below 2^53, so a value either survives the
//! crossing unchanged or does not cross.

use crate::{
    cog,
    decision::{self, Decision, DenyReason},
    index::LayoutIndex,
    parquet,
    policy::{Policy, QUERYABLES},
};
use serde_json::{json, Value};

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

/// The largest integer a JS `Number` represents exactly.
const MAX_SAFE_INTEGER: f64 = 9_007_199_254_740_991.0;

/// Which resolver to hand the bytes to.
///
/// The two have **different input contracts** and getting them the wrong way
/// round produces a confident index of the wrong object:
///
/// * [`Format::Parquet`] wants a contiguous **suffix** -- the footer lives at
///   the end.
/// * [`Format::Cog`] wants a contiguous **prefix** -- the IFD chain starts at
///   byte 0.
///
/// Both also accept the whole object, which is what the demo passes for the
/// small committed samples.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Parquet,
    Cog,
}

impl Format {
    /// The JS-facing spelling. Unknown strings are refused rather than
    /// defaulted: defaulting would index a COG with the Parquet resolver and
    /// report the failure as "not a Parquet file".
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "parquet" => Some(Self::Parquet),
            "cog" | "tiff" | "geotiff" => Some(Self::Cog),
            _ => None,
        }
    }
}

/// A refusal to index, in the shape a caller that guessed its read window too
/// small can retry from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildError {
    pub message: String,
    /// The number of bytes that would have been enough, or `None` when the
    /// failure is not about the window. Counted **from the end** of the object
    /// for [`Format::Parquet`] and **from the start** for [`Format::Cog`],
    /// matching each resolver's input contract -- the caller knows which
    /// format it asked for.
    pub needed: Option<u64>,
}

impl BuildError {
    fn msg(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            needed: None,
        }
    }
}

/// Why a check answered as it did, as a stable string for the UI.
///
/// These are [`DenyReason`]'s variants plus the authorized case. The mapping
/// is total and exhaustive on purpose: a new variant in `decision.rs` must
/// fail to compile here rather than fall into a catch-all that reads as
/// "denied for some reason".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    Authorized,
    BadRange,
    NotPermitted,
}

impl Reason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Authorized => "authorized",
            Self::BadRange => "bad_range",
            Self::NotPermitted => "not_permitted",
        }
    }
}

/// One check, with the extra detail the demo renders.
///
/// # `regions` is a demo-only affordance
///
/// [`DenyReason::NotPermitted`] carries no regions and no offsets, and
/// `decision.rs` is explicit about why: a 403 that echoes the resolved regions
/// hands the client the protected column's name and its exact byte extent,
/// which is the pair the policy exists to withhold.
///
/// **This struct exposes them on denial anyway, and a gateway must not copy
/// that.** The reasoning above is void in this one setting and nowhere else:
/// the browser already holds the object, the policy text and this module, so
/// the denied region's identity is not a secret being disclosed -- it is an
/// input the user supplied. The demo's entire subject is *which bytes were
/// refused and why*, which cannot be shown without naming them. Across a
/// network, to a principal who holds none of those three things, every field
/// below except `allowed` and `reason` is a disclosure, and `reason` itself is
/// only safe because `BadRange` is a function of the header text alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub allowed: bool,
    pub reason: Reason,
    /// The extent the caller is authorized to fetch -- and, per
    /// [`Decision::Authorized`], the extent it must fetch instead of echoing
    /// the range it asked for. `None` on any denial.
    pub canonical: Option<std::ops::Range<u64>>,
    /// Indices into [`LayoutIndex::regions`] of every region the *requested*
    /// range overlapped, in order. Empty when the range never parsed.
    pub regions: Vec<u32>,
    /// How many of `regions` the policy permits on their own, and how many it
    /// does not. `permitted + denied == regions.len()`.
    pub permitted: u32,
    pub denied: u32,
}

impl Outcome {
    /// Did this request cross a policy boundary?
    ///
    /// The demo's headline number. True when the requested range overlapped
    /// more than one region and the policy answers differently for at least
    /// two of them -- one permitted, one not. That is the case a conjunctive
    /// decision turns into a denial of the whole request, and the case a
    /// reader that coalesces nearby reads produces by accident.
    ///
    /// `permitted > 0 && denied > 0` already implies more than one region;
    /// the length check is spelled out anyway because the definition is
    /// stated in terms of it.
    pub fn straddles(&self) -> bool {
        self.regions.len() > 1 && self.permitted > 0 && self.denied > 0
    }
}

/// Convert a JS byte offset, refusing anything that did not survive the
/// crossing exactly.
///
/// `as u64` on an out-of-range or NaN float saturates rather than panicking,
/// so this guard is about *silence*, not about crashes: an offset of 2^53 + 1
/// arrives as 2^53, and authorizing a range the caller did not ask for is the
/// whole failure mode this crate is written against.
pub fn offset_from_f64(value: f64) -> Result<u64, String> {
    if !value.is_finite() || value < 0.0 || value.fract() != 0.0 || value > MAX_SAFE_INTEGER {
        return Err(format!(
            "{value} is not an exact byte offset (want an integer in 0..=2^53-1)"
        ));
    }
    Ok(value as u64)
}

/// Build an index from a window of an object.
///
/// `bytes` must satisfy the resolver's contract for `format` -- see
/// [`Format`]. `object_size` is the object's *full* length, which is not
/// `bytes.len()` unless the window is the whole object.
pub fn build_index(
    format: Format,
    bytes: &[u8],
    object_size: u64,
) -> Result<LayoutIndex, BuildError> {
    let index = match format {
        Format::Parquet => parquet::build_index(bytes, object_size).map_err(|e| BuildError {
            message: e.to_string(),
            needed: match e {
                parquet::ParquetError::Truncated { needed } => Some(needed),
                _ => None,
            },
        })?,
        Format::Cog => cog::build_index(bytes, object_size).map_err(|e| BuildError {
            message: e.to_string(),
            needed: match e {
                cog::CogError::Truncated { needed } => Some(needed),
                _ => None,
            },
        })?,
    };
    // Region indices cross to JS as `u32`. Unreachable for any real object --
    // it would need four billion regions -- but the alternative to checking is
    // a truncating cast that renumbers regions, and a renumbered region is the
    // wrong cell highlighted.
    if u32::try_from(index.regions().len()).is_err() {
        return Err(BuildError::msg(
            "object has more regions than a u32 can index",
        ));
    }
    Ok(index)
}

/// Every region, in order, as the JSON the demo builds its grids from.
///
/// One entry per region with `i` (its index, the same one [`Outcome::regions`]
/// reports), `start`, `end` and the region's own properties -- the very
/// properties a policy is written against, so a cell's tooltip and the rule
/// that decided it cannot disagree.
///
/// Two departures from [`Region::props`](crate::index::Region::props), both
/// for the renderer's benefit and neither affecting a decision:
///
/// * `geom` is dropped. It is the same rectangle as `bbox` in the form cql2
///   needs, and at one closed ring per region it is most of the payload.
/// * `bbox` is flattened from the CQL2 `{"bbox": [..]}` operand form to the
///   bare `[xmin, ymin, xmax, ymax]` array.
pub fn regions_json(index: &LayoutIndex) -> String {
    let regions: Vec<Value> = index
        .regions()
        .iter()
        .enumerate()
        .map(|(i, region)| {
            let mut value = region.props();
            if let Some(object) = value.as_object_mut() {
                object.remove("geom");
                if let Some(bbox) = object.get("bbox").and_then(|b| b.get("bbox")).cloned() {
                    object.insert("bbox".into(), bbox);
                }
                object.insert("i".into(), json!(i));
                object.insert("start".into(), json!(region.start));
                object.insert("end".into(), json!(region.end()));
            }
            value
        })
        .collect();
    Value::Array(regions).to_string()
}

/// Would a request for exactly this region's bytes be authorized?
///
/// This is how the demo colours a cell without inventing a byte range: the
/// range *is* the region, so the answer is [`decision::check`]'s, reached
/// through the real range parse and the real principal validation rather than
/// through a policy evaluation this module assembled by hand.
///
/// `false` for an index that has no such region, which is a caller bug and
/// still not a panic.
fn region_is_permitted(index: &LayoutIndex, policy: &Policy, user: &Value, i: usize) -> bool {
    let Some(region) = index.regions().get(i) else {
        return false;
    };
    // Regions in an index are non-empty (`try_new` drops zero-length ones), so
    // `end() - 1` cannot underflow and the inclusive spelling is exact.
    let header = format!("bytes={}-{}", region.start, region.end().saturating_sub(1));
    matches!(
        decision::check(index, policy, user, Some(&header)),
        Decision::Authorized { .. }
    )
}

/// [`region_is_permitted`] for every region, as one byte each: 1 permitted,
/// 0 denied.
///
/// One call rather than one per cell: a COG index is hundreds of regions, and
/// a spatial rule costs tens of microseconds each. The demo re-runs this when
/// the policy or the principal changes, not per frame.
pub fn verdicts(index: &LayoutIndex, policy: &Policy, user: &Value) -> Vec<u8> {
    (0..index.regions().len())
        .map(|i| u8::from(region_is_permitted(index, policy, user, i)))
        .collect()
}

/// Check a `Range` header, exactly as a gateway would.
///
/// The header path exists alongside [`check_offsets`] because it is the one
/// that exercises [`range::parse`](crate::range::parse), where the RFC 9110
/// strictness lives. `None` means no header at all, which is a request for
/// the whole object and is decided as one.
pub fn check_header(
    index: &LayoutIndex,
    policy: &Policy,
    user: &Value,
    header: Option<&str>,
) -> Outcome {
    // The verdict, and only the verdict, comes from here.
    let (allowed, reason, canonical) = match decision::check(index, policy, user, header) {
        Decision::Authorized { canonical } => (true, Reason::Authorized, Some(canonical)),
        Decision::Denied {
            reason: DenyReason::BadRange,
        } => (false, Reason::BadRange, None),
        Decision::Denied {
            reason: DenyReason::NotPermitted,
        } => (false, Reason::NotPermitted, None),
    };

    // Detail for the UI. Re-parsing the header is not a second decision: it is
    // the same pure function on the same input, and its result is used only to
    // name regions. A range that did not parse names none.
    let mut regions = Vec::new();
    let (mut permitted, mut denied) = (0u32, 0u32);
    if let Ok(requested) = crate::range::parse(header, index.size()) {
        for (i, region) in index.regions().iter().enumerate() {
            if region.start >= requested.end {
                break;
            }
            if region.end() <= requested.start {
                continue;
            }
            // Every region in an index fits a u32 index; `build_index` refuses
            // one that does not, and a hand-built index that big is not
            // reachable from the boundary.
            let Ok(i) = u32::try_from(i) else { break };
            regions.push(i);
        }

        if allowed {
            // Derived, not re-evaluated, and the derivation is the decision
            // rule itself: `Authorized` is a conjunction over *exactly* these
            // regions, so every one of them is permitted. Re-running the
            // policy here could only ever disagree with the answer already
            // given -- and it would cost a second evaluation per region on the
            // path that runs when the system is working, which is the path the
            // demo times.
            permitted = u32::try_from(regions.len()).unwrap_or(u32::MAX);
        } else {
            // The explanation is only assembled on a denial, which is the case
            // the demo is about and the case `decision::check` short-circuits
            // -- so this is the one place the binding costs more than a
            // gateway would pay. One policy evaluation per overlapped region.
            for i in &regions {
                if region_is_permitted(index, policy, user, *i as usize) {
                    permitted += 1;
                } else {
                    denied += 1;
                }
            }
        }
    }

    Outcome {
        allowed,
        reason,
        canonical,
        regions,
        permitted,
        denied,
    }
}

/// Check a half-open byte range given as offsets.
///
/// The shape both JS readers hand over: hyparquet's `AsyncBuffer.slice(start,
/// end)` and geotiff's `{offset, length}` are already offsets, so the demo's
/// interceptors do not have to assemble a header and get the inclusive/
/// half-open conversion wrong on the way.
///
/// The range is spelled as a header and decided by [`check_header`], so the
/// two entry points cannot drift: clamping, suffix normalization and the
/// satisfiability rules are applied once, in `range::parse`.
pub fn check_offsets(
    index: &LayoutIndex,
    policy: &Policy,
    user: &Value,
    start: u64,
    end: u64,
) -> Outcome {
    if end <= start {
        // An empty or inverted extent. `decision::check` reaches the same
        // verdict for an empty range (`try_resolve` refuses it), and it is a
        // `NotPermitted` rather than a `BadRange` because no header was
        // malformed -- there was no header. Spelling it `bytes=5-4` and
        // letting the parser refuse it would report the caller's arithmetic
        // as a client syntax error.
        return Outcome {
            allowed: false,
            reason: Reason::NotPermitted,
            canonical: None,
            regions: Vec::new(),
            permitted: 0,
            denied: 0,
        };
    }
    // Inclusive on the wire: `end - 1`, and `end > start >= 0` so it cannot
    // underflow.
    let header = format!("bytes={}-{}", start, end - 1);
    check_header(index, policy, user, Some(&header))
}

/// Parse a principal from JSON text.
///
/// Kept fallible and kept here rather than inside a check: a principal that is
/// not JSON is a caller bug worth reporting, whereas a principal that is valid
/// JSON of the wrong *shape* is a denial that `decision::check` is already
/// responsible for making.
pub fn parse_user(json_text: &str) -> Result<Value, String> {
    serde_json::from_str(json_text).map_err(|e| format!("principal is not valid JSON: {e}"))
}

/// The property names a policy may mention, as JSON.
///
/// Exported so the demo's editor and the loader cannot drift into two
/// different schemas -- the reason [`QUERYABLES`] is a constant in the first
/// place.
pub fn queryables_json() -> String {
    Value::Array(QUERYABLES.iter().map(|q| json!(q)).collect()).to_string()
}

// ---- The boundary itself -------------------------------------------------
//
// Thin by construction: every function below converts types and delegates.
// Nothing here decides anything, so nothing here is untested logic.

/// A parsed, statically validated policy. Build once; hold it.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = Policy)]
pub struct WasmPolicy {
    inner: Policy,
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_class = Policy)]
impl WasmPolicy {
    /// Parse and validate a policy document. Throws on a rule that does not
    /// parse or names a property outside the queryables schema -- which is the
    /// point of loading it ahead of time rather than at evaluation.
    #[wasm_bindgen(constructor)]
    pub fn new(yaml: &str) -> Result<WasmPolicy, JsValue> {
        Policy::load(yaml, QUERYABLES)
            .map(|inner| WasmPolicy { inner })
            .map_err(|e| js_error(&e.to_string()))
    }
}

/// One object's layout. Build once per object; hold it across every check.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = LayoutIndex)]
pub struct WasmIndex {
    inner: LayoutIndex,
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_class = LayoutIndex)]
impl WasmIndex {
    /// Build from a window of the object. `format` is `"parquet"` or `"cog"`;
    /// see [`Format`] for which end of the object each one wants.
    ///
    /// Throws an `Error` whose `needed` property, when present, is the window
    /// size that would have worked -- counted from the end for Parquet and
    /// from the start for a COG.
    pub fn build(format: &str, bytes: &[u8], object_size: f64) -> Result<WasmIndex, JsValue> {
        let format =
            Format::parse(format).ok_or_else(|| js_error(&format!("unknown format `{format}`")))?;
        let object_size = offset_from_f64(object_size).map_err(|e| js_error(&e))?;
        build_index(format, bytes, object_size)
            .map(|inner| WasmIndex { inner })
            .map_err(build_error_to_js)
    }

    /// The object's full length in bytes.
    #[wasm_bindgen(getter)]
    pub fn size(&self) -> f64 {
        // Every index was built from an `object_size` that came through
        // `offset_from_f64`, so this is exact.
        self.inner.size() as f64
    }

    #[wasm_bindgen(getter, js_name = regionCount)]
    pub fn region_count(&self) -> u32 {
        // `build` refuses an index whose region count does not fit.
        u32::try_from(self.inner.regions().len()).unwrap_or(u32::MAX)
    }

    /// Every region as JSON: `[{i, start, end, kind, ...props}]`.
    pub fn regions(&self) -> String {
        regions_json(&self.inner)
    }

    /// One byte per region: 1 if a request for exactly that region's bytes
    /// would be authorized, 0 otherwise. This is how a grid is coloured.
    pub fn verdicts(&self, policy: &WasmPolicy, user: &str) -> Result<Vec<u8>, JsValue> {
        let user = parse_user(user).map_err(|e| js_error(&e))?;
        Ok(verdicts(&self.inner, &policy.inner, &user))
    }

    /// Check a half-open byte range, the shape hyparquet and geotiff hand over.
    pub fn check(
        &self,
        policy: &WasmPolicy,
        user: &str,
        start: f64,
        end: f64,
    ) -> Result<WasmOutcome, JsValue> {
        let user = parse_user(user).map_err(|e| js_error(&e))?;
        let start = offset_from_f64(start).map_err(|e| js_error(&e))?;
        let end = offset_from_f64(end).map_err(|e| js_error(&e))?;
        Ok(WasmOutcome {
            inner: check_offsets(&self.inner, &policy.inner, &user, start, end),
        })
    }

    /// Check a `Range` header. `undefined` means no header, which is a request
    /// for the whole object.
    #[wasm_bindgen(js_name = checkHeader)]
    pub fn check_header(
        &self,
        policy: &WasmPolicy,
        user: &str,
        header: Option<String>,
    ) -> Result<WasmOutcome, JsValue> {
        let user = parse_user(user).map_err(|e| js_error(&e))?;
        Ok(WasmOutcome {
            inner: check_header(&self.inner, &policy.inner, &user, header.as_deref()),
        })
    }
}

/// The verdict on one check. See [`Outcome`] for why `regions` is exposed on a
/// denial here and must not be by a gateway.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = CheckResult)]
pub struct WasmOutcome {
    inner: Outcome,
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_class = CheckResult)]
impl WasmOutcome {
    #[wasm_bindgen(getter)]
    pub fn allowed(&self) -> bool {
        self.inner.allowed
    }

    /// `"authorized"`, `"bad_range"` or `"not_permitted"`.
    #[wasm_bindgen(getter)]
    pub fn reason(&self) -> String {
        self.inner.reason.as_str().to_string()
    }

    /// The extent to fetch -- not the extent that was asked for. `undefined`
    /// on a denial.
    #[wasm_bindgen(getter)]
    pub fn start(&self) -> Option<f64> {
        self.inner.canonical.as_ref().map(|r| r.start as f64)
    }

    #[wasm_bindgen(getter)]
    pub fn end(&self) -> Option<f64> {
        self.inner.canonical.as_ref().map(|r| r.end as f64)
    }

    /// Indices into `LayoutIndex.regions()` of every region the request
    /// overlapped.
    #[wasm_bindgen(getter)]
    pub fn regions(&self) -> Vec<u32> {
        self.inner.regions.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn permitted(&self) -> u32 {
        self.inner.permitted
    }

    #[wasm_bindgen(getter)]
    pub fn denied(&self) -> u32 {
        self.inner.denied
    }

    /// Did this request cross a policy boundary? See [`Outcome::straddles`].
    #[wasm_bindgen(getter)]
    pub fn straddles(&self) -> bool {
        self.inner.straddles()
    }
}

/// Every refusal crosses as a real JS `Error`.
///
/// Uniformly, including the ones that are a caller mistake rather than a
/// property of the object: `throw "a string"` leaves `e.message` undefined, so
/// a demo that logs `e.message` would show `undefined` for exactly the errors
/// it is most likely to hit while being written.
#[cfg(target_arch = "wasm32")]
fn js_error(message: &str) -> JsValue {
    js_sys::Error::new(message).into()
}

/// A [`BuildError`] as a JS `Error`, with `needed` attached when the failure
/// was only that the read window was too small.
#[cfg(target_arch = "wasm32")]
fn build_error_to_js(error: BuildError) -> JsValue {
    let js = js_sys::Error::new(&error.message);
    if let Some(needed) = error.needed {
        // Ignored on failure rather than unwrapped: a `Reflect::set` that does
        // not take costs the caller a retry hint, and throwing from the error
        // path would replace a useful message with a useless one.
        let _ = js_sys::Reflect::set(
            &js,
            &JsValue::from_str("needed"),
            &JsValue::from_f64(needed as f64),
        );
    }
    js.into()
}

/// The crate version, so the demo can show what it is running.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub fn version() -> String {
    crate::version().to_string()
}

/// The property names a policy may mention, as a JSON array.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub fn queryables() -> String {
    queryables_json()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::{Region, RegionKind};
    use serde_json::json;

    /// metadata `0..10`, column_chunk "public" `10..20`, column_chunk "salary"
    /// `20..30`, and size 40, so `30..40` is `Unmapped`. The same shape
    /// `decision.rs` tests against, on purpose: these tests are about the
    /// binding agreeing with that module, so they should be readable beside it.
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

    /// Every header the decision tests exercise, plus the ones only a binding
    /// can reach.
    const HEADERS: &[Option<&str>] = &[
        None,
        Some("bytes=0-9"),
        Some("bytes=10-19"),
        Some("bytes=20-29"),
        Some("bytes=0-19"),
        Some("bytes=19-20"),
        Some("bytes=0-29"),
        Some("bytes=30-39"),
        Some("bytes=29-30"),
        Some("bytes=-1"),
        Some("bytes=-500"),
        Some("bytes=35-"),
        Some("bytes=40-"),
        Some("bytes=0-18446744073709551615"),
        Some("bytes=5-4"),
        Some("BYTES=0-9"),
        Some("bytes= 0-9"),
        Some("bytes=0-9,20-29"),
        Some(""),
        Some("bytes="),
    ];

    // ---- The required test: the binding is `decision::check` ---------------

    #[test]
    fn the_binding_answers_exactly_what_check_answers() {
        let (idx, pol) = (index(), policy());
        let users = [
            analyst(),
            json!({"role": "auditor"}),
            json!({}),
            // Shapes `check` refuses outright, which must not become an allow
            // on the way through a binding.
            json!({"role": {"op": "=", "args": [1, 1]}}),
            json!("admin"),
            json!(null),
        ];
        for user in &users {
            for header in HEADERS {
                let direct = decision::check(&idx, &pol, user, *header);
                let bound = check_header(&idx, &pol, user, *header);
                match direct {
                    Decision::Authorized { canonical } => {
                        assert!(bound.allowed, "{header:?} / {user}");
                        assert_eq!(bound.reason, Reason::Authorized);
                        assert_eq!(bound.canonical, Some(canonical), "{header:?} / {user}");
                    }
                    Decision::Denied { reason } => {
                        assert!(!bound.allowed, "{header:?} / {user}");
                        assert_eq!(bound.canonical, None, "{header:?} / {user}");
                        let expected = match reason {
                            DenyReason::BadRange => Reason::BadRange,
                            DenyReason::NotPermitted => Reason::NotPermitted,
                        };
                        assert_eq!(bound.reason, expected, "{header:?} / {user}");
                    }
                }
            }
        }
    }

    // The offsets path must not be a second parser. Every extent the header
    // path accepts, spelled the other way, must decide identically.
    #[test]
    fn the_offset_path_and_the_header_path_agree() {
        let (idx, pol) = (index(), policy());
        for (start, end) in [
            (0u64, 10u64),
            (10, 20),
            (20, 30),
            (0, 20),
            (19, 21),
            (30, 40),
            (0, 40),
            (9, 10),
            (39, 40),
            // Past the end of the object: `range::parse` clamps, so the
            // canonical extent is shorter than the request.
            (30, 100),
        ] {
            let header = format!("bytes={}-{}", start, end - 1);
            assert_eq!(
                check_offsets(&idx, &pol, &analyst(), start, end),
                check_header(&idx, &pol, &analyst(), Some(&header)),
                "{start}..{end}"
            );
        }
    }

    // An empty or inverted extent is a denial, and specifically not a
    // `BadRange`: there was no header to be malformed. It must never be an
    // allow -- an empty region set makes a conjunctive decision vacuously true,
    // which is the failure `index.rs` exists to prevent.
    #[test]
    fn an_empty_or_inverted_offset_range_is_denied() {
        let (idx, pol) = (index(), policy());
        for (start, end) in [(0u64, 0u64), (10, 10), (20, 5), (40, 40), (100, 0)] {
            let out = check_offsets(&idx, &pol, &analyst(), start, end);
            assert!(!out.allowed, "{start}..{end}");
            assert_eq!(out.reason, Reason::NotPermitted, "{start}..{end}");
            assert_eq!(out.canonical, None);
            assert!(out.regions.is_empty());
            assert!(!out.straddles());
        }
    }

    // ---- The detail the demo renders ---------------------------------------

    #[test]
    fn a_check_names_every_region_the_request_overlapped() {
        let (idx, pol) = (index(), policy());
        for (header, expected) in [
            ("bytes=0-9", vec![0u32]),
            ("bytes=0-10", vec![0, 1]),
            ("bytes=9-10", vec![0, 1]),
            ("bytes=0-29", vec![0, 1, 2]),
            ("bytes=0-39", vec![0, 1, 2, 3]),
            ("bytes=30-39", vec![3]),
            ("bytes=19-19", vec![1]),
        ] {
            let out = check_header(&idx, &pol, &analyst(), Some(header));
            assert_eq!(out.regions, expected, "{header}");
            assert_eq!(
                out.permitted + out.denied,
                out.regions.len() as u32,
                "{header}"
            );
        }
        // A header that never parsed resolves nothing, so there is nothing to
        // name -- and nothing that could be mistaken for a region set.
        let bad = check_header(&idx, &pol, &analyst(), Some("BYTES=0-9"));
        assert_eq!(bad.reason, Reason::BadRange);
        assert!(bad.regions.is_empty());
    }

    // The region indices are indices into `regions_json`, which is how the
    // demo maps a check back onto a cell. An off-by-one here highlights the
    // wrong column.
    #[test]
    fn reported_indices_address_the_rendered_regions() {
        let idx = index();
        let listed: Value = serde_json::from_str(&regions_json(&idx)).unwrap();
        let listed = listed.as_array().unwrap();
        assert_eq!(listed.len(), idx.regions().len());
        for (i, entry) in listed.iter().enumerate() {
            assert_eq!(entry["i"], json!(i));
            assert_eq!(entry["start"], json!(idx.regions()[i].start));
            assert_eq!(entry["end"], json!(idx.regions()[i].end()));
        }
        let out = check_header(&idx, &policy(), &analyst(), Some("bytes=20-29"));
        assert_eq!(out.regions, vec![2]);
        assert_eq!(listed[2]["column"], json!("salary"));
    }

    // The straddle definition, stated as the demo will state it: more than one
    // region, at least one permitted, at least one denied.
    #[test]
    fn straddles_is_a_mixed_verdict_over_more_than_one_region() {
        let (idx, pol) = (index(), policy());
        let straddling = check_header(&idx, &pol, &analyst(), Some("bytes=19-20"));
        assert!(straddling.straddles());
        assert_eq!((straddling.permitted, straddling.denied), (1, 1));
        assert!(!straddling.allowed, "a straddle is denied, conjunctively");

        // One region, permitted: not a straddle.
        assert!(!check_header(&idx, &pol, &analyst(), Some("bytes=0-9")).straddles());
        // One region, denied: not a straddle either.
        assert!(!check_header(&idx, &pol, &analyst(), Some("bytes=20-29")).straddles());
        // Two regions, both permitted: a coalesced read that crossed no
        // boundary. Denied count is zero, so not a straddle.
        let both_ok = check_header(&idx, &pol, &analyst(), Some("bytes=0-19"));
        assert!(both_ok.allowed);
        assert_eq!((both_ok.permitted, both_ok.denied), (2, 0));
        assert!(!both_ok.straddles());
        // Two regions, both denied: still not a straddle -- no boundary was
        // crossed, the whole request was in forbidden territory.
        let both_denied = check_header(&idx, &pol, &analyst(), Some("bytes=20-39"));
        assert_eq!((both_denied.permitted, both_denied.denied), (0, 2));
        assert!(!both_denied.straddles());
    }

    // On the allow path the counts are DERIVED from the conjunctive rule
    // rather than evaluated, so that a permitted request costs what a gateway
    // pays and no more. The derivation has to hold for every permitted range,
    // or the demo's straddle tally is built on an assumption.
    #[test]
    fn derived_counts_on_the_allow_path_match_an_explicit_evaluation() {
        let (idx, pol) = (index(), policy());
        for user in [analyst(), json!({"role": "auditor"}), json!({})] {
            for header in HEADERS {
                let out = check_header(&idx, &pol, &user, *header);
                if !out.allowed {
                    continue;
                }
                let explicit = out
                    .regions
                    .iter()
                    .filter(|i| region_is_permitted(&idx, &pol, &user, **i as usize))
                    .count();
                assert_eq!(out.permitted as usize, explicit, "{header:?} / {user}");
                assert_eq!(out.denied, 0, "{header:?} / {user}");
                assert_eq!(out.permitted as usize, out.regions.len());
                assert!(!out.straddles());
            }
        }
    }

    // The grid colours must be the same function as the check, or a cell shown
    // green would refuse the read it invites.
    #[test]
    fn verdicts_agree_with_a_check_for_the_region_itself() {
        let (idx, pol) = (index(), policy());
        for user in [analyst(), json!({}), json!("not-an-object")] {
            let v = verdicts(&idx, &pol, &user);
            assert_eq!(v.len(), idx.regions().len());
            for (i, region) in idx.regions().iter().enumerate() {
                let header = format!("bytes={}-{}", region.start, region.end() - 1);
                let direct = decision::check(&idx, &pol, &user, Some(&header));
                assert_eq!(
                    v[i] == 1,
                    matches!(direct, Decision::Authorized { .. }),
                    "region {i} / {user}"
                );
            }
        }
        // Concretely, for the policy under test: metadata and `public` yes,
        // `salary` and the unmapped tail no.
        assert_eq!(verdicts(&idx, &pol, &analyst()), vec![1, 1, 0, 0]);
        // A principal `check` refuses outright colours the whole grid denied.
        assert_eq!(verdicts(&idx, &pol, &json!(null)), vec![0, 0, 0, 0]);
    }

    // The affordance the module doc warns about, pinned as a test so that
    // removing it is a deliberate act rather than an accident: this struct
    // says what `decision::check` refuses to say.
    #[test]
    fn a_denial_names_regions_here_and_nowhere_else() {
        let (idx, pol) = (index(), policy());
        let denied = check_header(&idx, &pol, &analyst(), Some("bytes=20-29"));
        assert!(!denied.allowed);
        assert_eq!(denied.regions, vec![2]);
        // `decision::check`'s own denial is indistinguishable from every other
        // denial, including through its debug rendering. That is the property
        // a gateway relies on, and it is untouched by anything in this module.
        let rendered = format!(
            "{:?}",
            decision::check(&idx, &pol, &analyst(), Some("bytes=20-29"))
        );
        for leak in ["salary", "20", "region"] {
            assert!(!rendered.contains(leak), "`{leak}` disclosed by {rendered}");
        }
    }

    #[test]
    fn regions_json_carries_the_props_a_policy_is_written_against() {
        let idx = LayoutIndex::new(
            vec![Region {
                start: 0,
                len: 10,
                kind: RegionKind::Tile {
                    overview_level: 2,
                    x: 3,
                    y: 4,
                    bbox: [10.0, 20.0, 0.0, 0.0],
                    crs: Some(32633),
                },
            }],
            20,
        );
        let listed: Value = serde_json::from_str(&regions_json(&idx)).unwrap();
        let tile = &listed[0];
        assert_eq!(tile["kind"], json!("tile"));
        assert_eq!(tile["overview_level"], json!(2));
        assert_eq!((tile["x"].clone(), tile["y"].clone()), (json!(3), json!(4)));
        assert_eq!(tile["crs"], json!(32633));
        // Flattened out of the CQL2 operand form, and normalized by `props`
        // even though the resolver handed it a north-up (inverted) bbox.
        assert_eq!(tile["bbox"], json!([0.0, 0.0, 10.0, 20.0]));
        // Dropped: the same rectangle again, and most of the payload.
        assert!(tile.get("geom").is_none());
        // The `Unmapped` tail is listed too -- the demo must be able to show
        // the bytes nothing claimed, which are the ones that always deny.
        assert_eq!(listed[1]["kind"], json!("unmapped"));
        assert_eq!(listed[1]["start"], json!(10));
    }

    // ---- Nothing crosses the boundary that could not have -------------------

    #[test]
    fn a_js_number_that_is_not_an_exact_byte_offset_is_refused() {
        assert_eq!(offset_from_f64(0.0), Ok(0));
        assert_eq!(offset_from_f64(42.0), Ok(42));
        assert_eq!(offset_from_f64(MAX_SAFE_INTEGER), Ok(9_007_199_254_740_991));
        for bad in [
            -1.0,
            0.5,
            f64::NAN,
            f64::INFINITY,
            f64::NEG_INFINITY,
            // Past 2^53-1: `as u64` would accept it silently, and the value
            // the caller meant is not the value that arrived.
            MAX_SAFE_INTEGER + 2.0,
            1e300,
        ] {
            assert!(offset_from_f64(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn format_strings_are_a_closed_set() {
        assert_eq!(Format::parse("parquet"), Some(Format::Parquet));
        assert_eq!(Format::parse("cog"), Some(Format::Cog));
        assert_eq!(Format::parse("geotiff"), Some(Format::Cog));
        for unknown in ["", "PARQUET", "par1", "zarr", "cog "] {
            assert_eq!(Format::parse(unknown), None, "{unknown}");
        }
    }

    // A panic on wasm32 aborts the module instance and every later call fails,
    // so an input the demo can produce must never reach one. These are the
    // shapes a file picker and a wrong format choice produce.
    #[test]
    fn malformed_input_is_an_error_and_never_a_panic() {
        for format in [Format::Parquet, Format::Cog] {
            for (bytes, size) in [
                (vec![], 0u64),
                (vec![], 100),
                (vec![0u8; 4], 4),
                (b"PAR1".to_vec(), 4),
                (vec![0xff; 64], 64),
                // A buffer longer than the object it claims to describe.
                (vec![0u8; 100], 10),
                (b"II\x2a\x00\xff\xff\xff\xff".to_vec(), 8),
            ] {
                assert!(
                    build_index(format, &bytes, size).is_err(),
                    "{format:?} accepted {} bytes of a {size}-byte object",
                    bytes.len()
                );
            }
        }
        // ...and the right bytes handed to the wrong resolver.
        let cog = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/tiny-cog.tif"),
        )
        .unwrap();
        let size = cog.len() as u64;
        assert!(build_index(Format::Parquet, &cog, size).is_err());
        assert!(build_index(Format::Cog, &cog, size).is_ok());
    }

    // A caller that guessed its read window too small has to be able to widen
    // it without parsing an error message, and the two formats count from
    // opposite ends.
    #[test]
    fn a_window_too_small_reports_how_many_bytes_would_do() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let parquet = std::fs::read(root.join("data/nyc-taxi-8rg.parquet")).unwrap();
        let size = parquet.len() as u64;
        // The last 8 bytes are the trailer, which declares a footer far longer
        // than that, so this is the retry case rather than a corrupt file.
        let err = build_index(Format::Parquet, &parquet[parquet.len() - 8..], size).unwrap_err();
        let needed = err.needed.expect("a truncated footer must say how much");
        assert!(needed > 8 && needed <= size, "{needed} of {size}");
        // Counted from the END for Parquet: the suffix of that length works.
        let start = (size - needed) as usize;
        assert!(build_index(Format::Parquet, &parquet[start..], size).is_ok());

        let cog = std::fs::read(root.join("data/s2-tci-512.tif")).unwrap();
        let size = cog.len() as u64;
        let err = build_index(Format::Cog, &cog[..8], size).unwrap_err();
        let needed = err.needed.expect("a truncated prefix must say how much");
        assert!(needed > 8 && needed <= size, "{needed} of {size}");
        // Counted from the START for a COG -- and one widening is NOT enough.
        // `needed` is the next structure the IFD walk could not reach, not the
        // total the parse will end up wanting, so a caller that reads exactly
        // `needed` each time walks the file a few bytes at a time: this object
        // takes fourteen round trips to converge that way, the last few adding
        // sixteen bytes each. Doubling instead converges in a handful, and the
        // demo should do what `cog.rs` recommends -- read speculatively (16 KiB
        // covers this 5 MB object's 8,264) and treat `needed` as a floor.
        let mut window = needed as usize;
        let mut widenings = 0;
        while build_index(Format::Cog, &cog[..window], size).is_err() {
            let Some(needed) = build_index(Format::Cog, &cog[..window], size)
                .err()
                .and_then(|e| e.needed)
            else {
                panic!("widening stopped reporting a byte count at {window}");
            };
            // The termination guarantee `CogError::Truncated` documents: the
            // count is always strictly more than the window that produced it,
            // so a caller that keeps widening cannot loop forever.
            assert!(
                needed as usize > window,
                "{needed} did not advance {window}"
            );
            window = (needed as usize).max(window * 2);
            widenings += 1;
            assert!(widenings < 12, "still truncated at {window} bytes");
        }
        // The speculative read `cog.rs` recommends needs no widening at all.
        assert!(build_index(Format::Cog, &cog[..16 * 1024], size).is_ok());
    }

    // The whole point of the handles: an index built once decides many
    // requests, and the answers do not depend on how many came before.
    #[test]
    fn a_held_index_decides_repeatedly_and_identically() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let bytes = std::fs::read(root.join("data/nyc-taxi-8rg.parquet")).unwrap();
        let size = bytes.len() as u64;
        let idx = build_index(Format::Parquet, &bytes, size).unwrap();
        let pol = policy();
        let first = check_offsets(&idx, &pol, &analyst(), 0, 4);
        for _ in 0..100 {
            assert_eq!(check_offsets(&idx, &pol, &analyst(), 0, 4), first);
        }
        // And every region of a real file is addressable through the JSON the
        // demo renders, with the verdicts lining up one for one.
        let listed: Value = serde_json::from_str(&regions_json(&idx)).unwrap();
        let v = verdicts(&idx, &pol, &analyst());
        assert_eq!(listed.as_array().unwrap().len(), v.len());
    }

    #[test]
    fn a_principal_that_is_not_json_is_reported_rather_than_guessed() {
        assert!(parse_user("{\"role\":\"analyst\"}").is_ok());
        // Valid JSON of a shape `check` will refuse: that refusal is a denial,
        // not a parse error, so it must load.
        assert!(parse_user("null").is_ok());
        assert!(parse_user("{role: analyst}").is_err());
        assert!(parse_user("").is_err());
    }

    #[test]
    fn the_exported_queryables_are_the_crate_schema() {
        let listed: Value = serde_json::from_str(&queryables_json()).unwrap();
        let listed: Vec<&str> = listed
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(listed, QUERYABLES);
    }
}
