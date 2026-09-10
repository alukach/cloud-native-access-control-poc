# Cloud-Native Access Control Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a Rust crate that maps HTTP byte ranges to logical regions of Parquet and COG files, authorizes them with CQL2 policies, and a GitHub Pages demo that measures how often real readers straddle a policy boundary.

**Architecture:** Two pure stages. `build_index(footer_bytes, object_size, format) -> LayoutIndex` parses a format's metadata into byte-range regions that provably cover `[0, size)`. `check(index, policy, ctx, request) -> Decision` returns the canonical ranges a caller is authorized to fetch, or a denial. No async, no I/O in the crate — callers fetch. The same crate compiles to WASM for the browser demo, where interception happens at hyparquet's `AsyncBuffer` and geotiff.js's `BaseSource`.

**Tech Stack:** Rust, `cql2` 0.6, `parquet` 59.3 (`default-features = false`), `tiff` 0.11, `geo` 0.33, `wasm-bindgen`, vanilla JS + hyparquet + geotiff.js, GitHub Pages.

**Read first:** [the design document](2026-09-10-cloud-native-access-control-design.md). Every non-obvious decision below is justified there. In particular, do not "simplify" the four decision rules in §Decision semantics — each is a bypass when guessed wrong.

---

## Task 1: Scaffold and prove the WASM toolchain

De-risks the toolchain before any logic exists. Every pin here was verified; do not float them.

**Files:**
- Create: `Cargo.toml`, `src/lib.rs`, `.gitignore`, `rust-toolchain.toml`

**Step 1: Create the manifest**

```toml
[package]
name = "cnac"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib", "rlib"]

[dependencies]
cql2 = "0.6"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
serde_yaml = "0.9"
thiserror = "2"
parquet = { version = "59.3", default-features = false }
tiff = "0.11"
# Direct dependency: a transitive dep cannot have this feature enabled for it.
getrandom = { version = "0.3", features = ["wasm_js"] }

[target.'cfg(target_arch = "wasm32")'.dependencies]
wasm-bindgen = "0.2"

[profile.release]
opt-level = "z"
lto = true
codegen-units = 1
```

`parquet` needs no codec features: footer thrift is never compressed.

**Step 2: Minimal lib and a smoke test**

```rust
// src/lib.rs
pub fn version() -> &'static str { env!("CARGO_PKG_VERSION") }

#[cfg(test)]
mod tests {
    #[test]
    fn cql2_evaluates_a_spatial_predicate() {
        let e: cql2::Expr = "S_INTERSECTS(geom, POINT(5 5))".parse().unwrap();
        let ctx = serde_json::json!({
            "geom": {"type":"Polygon","coordinates":[[[0,0],[10,0],[10,10],[0,10],[0,0]]]}
        });
        assert!(e.matches(Some(&ctx)).unwrap());
    }
}
```

This test exists to prove that spatial predicates are genuinely computed in-process, and that `matches` takes `self` by value — clone per evaluation.

**Step 3: Run native tests**

Run: `cargo test`
Expected: PASS.

**Step 4: Prove the wasm32 build**

Run:
```bash
rustup target add wasm32-unknown-unknown
cargo build --release --target wasm32-unknown-unknown
```
Expected: builds clean. If `jsonschema` errors with `Features 'resolve-http' and 'resolve-file' are not supported on WASM`, something in the graph pulled it with default features — find it with `cargo tree -i jsonschema` and disable them.

**Step 5: Record the bundle size**

Run: `ls -l target/wasm32-unknown-unknown/release/cnac.wasm`
Expect roughly 900 KB. Note it in the commit message — `cql2` is ~82% of it and feature-gating it upstream is the only lever that will ever move this number.

**Step 6: Commit**

```bash
git add Cargo.toml Cargo.lock src/lib.rs .gitignore rust-toolchain.toml
git commit -m "feat: scaffold crate, prove wasm32 build and in-process spatial predicates"
```

---

## Task 2: Range request parsing

Pure, self-contained, and the site of two documented bypasses. Do this before anything touches a file format.

**Files:**
- Create: `src/range.rs`, Modify: `src/lib.rs`

**Step 1: Write the failing tests**

```rust
// src/range.rs
#[cfg(test)]
mod tests {
    use super::*;

    // HTTP bytes=a-b INCLUDES b. Regions are half-open. Off-by-one here is a
    // one-byte-per-request exfiltration primitive.
    #[test]
    fn inclusive_end_becomes_exclusive() {
        assert_eq!(parse(Some("bytes=0-9"), 100).unwrap(), 0..10);
    }

    #[test]
    fn absent_header_is_the_whole_object() {
        assert_eq!(parse(None, 100).unwrap(), 0..100);
    }

    #[test]
    fn open_ended_runs_to_end() {
        assert_eq!(parse(Some("bytes=90-"), 100).unwrap(), 90..100);
    }

    #[test]
    fn suffix_counts_back_from_end() {
        assert_eq!(parse(Some("bytes=-20"), 100).unwrap(), 80..100);
    }

    #[test]
    fn suffix_larger_than_object_clamps() {
        assert_eq!(parse(Some("bytes=-500"), 100).unwrap(), 0..100);
    }

    #[test]
    fn end_past_eof_clamps() {
        assert_eq!(parse(Some("bytes=90-999"), 100).unwrap(), 90..100);
    }

    // Every one of these must be an error, never a permissive fallback.
    #[test]
    fn hostile_forms_are_rejected() {
        for h in [
            "bytes=0-0, items=100-200", // lenient parse + strict backend = RFC 9110 200 full body
            "bytes=0-19,40-59",         // multi-range: response is multipart, unverifiable
            "bytes=+0-5",
            "bytes=5-4",                // start > end
            "bytes=999999-",            // start past EOF -> 416, not an allow
            "items=0-5",
            "bytes=",
            "bytes=-",
            "",
        ] {
            assert!(parse(Some(h), 100).is_err(), "should reject: {h}");
        }
    }

    #[test]
    fn zero_length_object_has_no_satisfiable_range() {
        assert!(parse(Some("bytes=0-0"), 0).is_err());
    }
}
```

**Step 2: Run to verify failure**

Run: `cargo test range`
Expected: FAIL, `parse` not found.

**Step 3: Implement**

```rust
use std::ops::Range;

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum RangeError {
    #[error("unparseable or unsupported Range header")]
    Unparseable,
    #[error("range not satisfiable")]
    NotSatisfiable,
}

/// Parse a Range header into a single half-open range clamped to `size`.
///
/// Deliberately strict. A lenient parser here is a bypass: RFC 9110 requires
/// an origin server to IGNORE a Range header it cannot understand and return
/// 200 with the entire representation, so any header we accept but a backend
/// rejects becomes a full-object disclosure. Multi-range is rejected rather
/// than supported because a multipart/byteranges response cannot be verified
/// against a single authorized extent.
pub fn parse(header: Option<&str>, size: u64) -> Result<Range<u64>, RangeError> {
    if size == 0 {
        return Err(RangeError::NotSatisfiable);
    }
    let Some(h) = header else { return Ok(0..size) };

    let spec = h.strip_prefix("bytes=").ok_or(RangeError::Unparseable)?;
    if spec.contains(',') {
        return Err(RangeError::Unparseable);
    }
    let (start_s, end_s) = spec.split_once('-').ok_or(RangeError::Unparseable)?;
    let digits = |s: &str| -> Result<u64, RangeError> {
        if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
            return Err(RangeError::Unparseable);
        }
        s.parse().map_err(|_| RangeError::Unparseable)
    };

    match (start_s.trim().is_empty(), end_s.trim().is_empty()) {
        // bytes=-N : the last N bytes
        (true, false) => {
            let n = digits(end_s.trim())?;
            if n == 0 {
                return Err(RangeError::NotSatisfiable);
            }
            Ok(size.saturating_sub(n)..size)
        }
        // bytes=N- : from N to the end
        (false, true) => {
            let start = digits(start_s.trim())?;
            if start >= size {
                return Err(RangeError::NotSatisfiable);
            }
            Ok(start..size)
        }
        // bytes=A-B : inclusive of B on the wire, exclusive here
        (false, false) => {
            let start = digits(start_s.trim())?;
            let end_incl = digits(end_s.trim())?;
            if start > end_incl || start >= size {
                return Err(RangeError::NotSatisfiable);
            }
            Ok(start..(end_incl + 1).min(size))
        }
        (true, true) => Err(RangeError::Unparseable),
    }
}
```

**Step 4: Run to verify pass**

Run: `cargo test range`
Expected: PASS, 8 tests.

**Step 5: Commit**

```bash
git add src/range.rs src/lib.rs
git commit -m "feat: strict Range header parsing, half-open internally

Rejects multi-range and malformed forms rather than parsing leniently:
RFC 9110 requires an origin to ignore a Range it cannot parse and return
200 with the whole object, so a lenient gateway parser plus a strict
backend is a full-object disclosure."
```

---

## Task 3: LayoutIndex with coverage guaranteed by construction

The design requires regions to cover `[0, size)` with no holes, because `all` over an empty set is `true` and any unmapped range would be authorized. Rather than asserting this in a test and hoping, **the constructor fills gaps**, so it cannot be got wrong.

**Files:**
- Create: `src/index.rs`, Modify: `src/lib.rs`

**Step 1: Write the failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn chunk(start: u64, len: u64, col: &str) -> Region {
        Region { start, len, kind: RegionKind::ColumnChunk {
            column: col.into(), row_group: 0 } }
    }

    #[test]
    fn gaps_are_filled_with_unmapped() {
        // 0..10 chunk, 10..20 hole, 20..30 chunk, 30..100 hole
        let idx = LayoutIndex::new(vec![chunk(0,10,"a"), chunk(20,10,"b")], 100);
        assert_eq!(idx.regions().len(), 4);
        assert!(matches!(idx.regions()[1].kind, RegionKind::Unmapped));
        assert_eq!(idx.regions()[1].start..idx.regions()[1].end(), 10..20);
        assert!(matches!(idx.regions()[3].kind, RegionKind::Unmapped));
        assert_eq!(idx.regions()[3].start..idx.regions()[3].end(), 30..100);
    }

    #[test]
    fn coverage_is_total() {
        let idx = LayoutIndex::new(vec![chunk(5,10,"a"), chunk(40,10,"b")], 100);
        let mut cursor = 0;
        for r in idx.regions() {
            assert_eq!(r.start, cursor, "hole before {}", r.start);
            cursor = r.end();
        }
        assert_eq!(cursor, 100);
    }

    #[test]
    fn resolve_returns_every_overlapped_region() {
        let idx = LayoutIndex::new(vec![chunk(0,10,"a"), chunk(10,10,"b")], 20);
        assert_eq!(idx.resolve(&(0..10)).len(), 1);
        assert_eq!(idx.resolve(&(5..15)).len(), 2);   // straddles
        assert_eq!(idx.resolve(&(0..20)).len(), 2);
    }

    // The exfiltration primitive from the security review. A range ending
    // exactly at a region boundary must NOT touch the next region, and one
    // starting one byte before must touch both.
    #[test]
    fn boundaries_are_exact() {
        let idx = LayoutIndex::new(vec![chunk(0,10,"a"), chunk(10,10,"secret")], 20);
        assert_eq!(idx.resolve(&(0..10)).len(), 1);
        assert_eq!(idx.resolve(&(9..10)).len(), 1);
        assert_eq!(idx.resolve(&(9..11)).len(), 2);
        assert_eq!(idx.resolve(&(10..11))[0].column(), Some("secret"));
    }

    #[test]
    fn resolve_never_returns_empty_for_a_valid_range() {
        let idx = LayoutIndex::new(vec![chunk(50,10,"a")], 100);
        for r in [0..1, 0..100, 99..100, 49..51] {
            assert!(!idx.resolve(&r).is_empty(), "empty for {r:?}");
        }
    }

    #[test]
    fn overlapping_input_regions_are_rejected() {
        // A resolver bug that double-claims bytes must be caught loudly.
        let res = LayoutIndex::try_new(vec![chunk(0,10,"a"), chunk(5,10,"b")], 100);
        assert!(res.is_err());
    }
}
```

**Step 2: Run to verify failure**

Run: `cargo test index`
Expected: FAIL.

**Step 3: Implement**

```rust
use serde_json::{json, Value};
use std::ops::Range;

#[derive(Debug, Clone, PartialEq)]
pub enum RegionKind {
    /// A named, specific metadata extent. NEVER a fallback: a blanket
    /// `region.kind = 'metadata'` allow plus a catch-all classification is a
    /// wildcard. Unrecognized bytes are Unmapped, not Metadata.
    Metadata { name: String },
    /// Bytes belonging to nothing known. No policy can match this.
    Unmapped,
    ColumnChunk { column: String, row_group: usize },
    ColumnIndex { column: String },
    BloomFilter { column: String },
    Tile { overview_level: u32, x: u32, y: u32, bbox: [f64; 4], crs: Option<u32> },
}

#[derive(Debug, Clone, PartialEq)]
pub struct Region { pub start: u64, pub len: u64, pub kind: RegionKind }

impl Region {
    pub fn end(&self) -> u64 { self.start + self.len }

    pub fn column(&self) -> Option<&str> {
        match &self.kind {
            RegionKind::ColumnChunk { column, .. }
            | RegionKind::ColumnIndex { column }
            | RegionKind::BloomFilter { column } => Some(column),
            _ => None,
        }
    }

    /// Built lazily, only for regions a request actually overlaps.
    ///
    /// Scalars plus one whitelisted geometry, never nested file-derived JSON:
    /// cql2's `Expr::try_from` is untagged, so a props value shaped like
    /// {"property": ...} or {"op": ...} becomes an AST node rather than data.
    /// Never emit null - absent and null are indistinguishable to cql2 and
    /// comparing against a present null errors.
    pub fn props(&self) -> Value {
        match &self.kind {
            RegionKind::Metadata { name } => json!({"kind":"metadata","name":name}),
            RegionKind::Unmapped => json!({"kind":"unmapped"}),
            RegionKind::ColumnChunk { column, row_group } =>
                json!({"kind":"column_chunk","column":column,"row_group":row_group}),
            RegionKind::ColumnIndex { column } =>
                json!({"kind":"column_index","column":column}),
            RegionKind::BloomFilter { column } =>
                json!({"kind":"bloom_filter","column":column}),
            RegionKind::Tile { overview_level, x, y, bbox, crs } => {
                let mut v = json!({
                    "kind":"tile","overview_level":overview_level,"x":x,"y":y,
                    // A bare array is NOT a CQL2 spatial operand: untagged
                    // deserialization matches it as Array and S_INTERSECTS
                    // silently fails to reduce. Emit a geometry and the
                    // object bbox form.
                    "geom": {"type":"Polygon","coordinates":[[
                        [bbox[0],bbox[1]],[bbox[2],bbox[1]],
                        [bbox[2],bbox[3]],[bbox[0],bbox[3]],[bbox[0],bbox[1]]]]},
                    "bbox": {"bbox": bbox},
                });
                if let Some(c) = crs { v["crs"] = json!(c); }
                v
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum IndexError {
    #[error("regions overlap at byte {0}")]
    Overlap(u64),
    #[error("region extends past end of object")]
    PastEof,
}

pub struct LayoutIndex { regions: Vec<Region>, size: u64 }

impl LayoutIndex {
    /// Panics on a malformed region set. Use `try_new` where input is untrusted.
    pub fn new(regions: Vec<Region>, size: u64) -> Self {
        Self::try_new(regions, size).expect("resolver produced overlapping regions")
    }

    /// Sorts, rejects overlaps, and fills every gap with `Unmapped` so that
    /// coverage of [0, size) is total BY CONSTRUCTION. This is load-bearing:
    /// the decision rule is "every overlapped region satisfies the policy",
    /// and `all` over an empty set is `true`, so any uncovered byte would be
    /// authorized.
    pub fn try_new(mut regions: Vec<Region>, size: u64) -> Result<Self, IndexError> {
        regions.retain(|r| r.len > 0);
        regions.sort_by_key(|r| r.start);

        let mut out = Vec::with_capacity(regions.len() * 2 + 1);
        let mut cursor = 0u64;
        for r in regions {
            if r.end() > size { return Err(IndexError::PastEof); }
            if r.start < cursor { return Err(IndexError::Overlap(r.start)); }
            if r.start > cursor {
                out.push(Region { start: cursor, len: r.start - cursor,
                                  kind: RegionKind::Unmapped });
            }
            cursor = r.end();
            out.push(r);
        }
        if cursor < size {
            out.push(Region { start: cursor, len: size - cursor,
                              kind: RegionKind::Unmapped });
        }
        Ok(Self { regions: out, size })
    }

    pub fn regions(&self) -> &[Region] { &self.regions }
    pub fn size(&self) -> u64 { self.size }

    /// Every region overlapping the half-open `range`.
    pub fn resolve(&self, range: &Range<u64>) -> &[Region] {
        if range.start >= range.end { return &[]; }
        let first = self.regions.partition_point(|r| r.end() <= range.start);
        let last  = self.regions.partition_point(|r| r.start < range.end);
        &self.regions[first..last]
    }
}
```

**Step 4: Run to verify pass**

Run: `cargo test index`
Expected: PASS, 6 tests.

**Step 5: Commit**

```bash
git add src/index.rs src/lib.rs
git commit -m "feat: LayoutIndex with total coverage guaranteed by construction

Gaps are filled with Unmapped regions in the constructor rather than
asserted in a test: the decision rule is 'every overlapped region satisfies
the policy', and all() over an empty set is true, so any uncovered byte
would otherwise be authorized."
```

---

## Task 4: Policy loading with static property validation

The critical finding from the cql2-rs review: **property typos cannot be caught at evaluation time.** `region.knid IS NULL` returns `Ok(true)`, and boolean absorption swallows a typo'd operand whenever a sibling decides the result. The only reliable defence is walking the AST at load time.

**Files:**
- Create: `src/policy.rs`, Modify: `src/lib.rs`

**Step 1: Write the failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const QUERYABLES: &[&str] = &[
        "user.role", "region.kind", "region.column", "region.row_group",
        "region.overview_level", "region.x", "region.y", "region.geom",
        "region.bbox", "region.crs", "region.name",
    ];

    fn load(yaml: &str) -> Result<Policy, PolicyError> { Policy::load(yaml, QUERYABLES) }

    #[test]
    fn a_typo_is_rejected_at_load_not_at_evaluation() {
        // Each of these evaluates to Ok(true) or hides the typo at runtime.
        for f in [
            "region.knid = 'metadata'",
            "region.knid IS NULL",
            "region.knid = 'x' OR region.kind = 'metadata'",
        ] {
            let err = load(&format!("allow:\n  - \"{f}\"")).unwrap_err();
            assert!(matches!(err, PolicyError::UnknownProperty(_)), "{f}");
        }
    }

    #[test]
    fn is_null_is_banned_outright() {
        // cql2 folds an absent property to true for isNull: a guard written
        // this way grants on a typo the validator might not otherwise see.
        let err = load("allow:\n  - \"region.column IS NULL\"").unwrap_err();
        assert!(matches!(err, PolicyError::BannedOperator(_)));
    }

    #[test]
    fn valid_policy_loads() {
        assert!(load("allow:\n  - \"region.kind = 'metadata'\"").is_ok());
    }

    #[test]
    fn rules_are_disjunctive() {
        let p = load("allow:\n  - \"region.kind = 'metadata'\"\n  - \"region.kind = 'tile'\"").unwrap();
        assert!(p.permits(&json!({"region":{"kind":"tile"}})));
        assert!(!p.permits(&json!({"region":{"kind":"unmapped"}})));
    }

    #[test]
    fn evaluation_error_denies() {
        // An unguarded column rule errors against a tile region. It must deny,
        // never leak through as true.
        let p = load("allow:\n  - \"region.column <> 'salary'\"").unwrap();
        assert!(!p.permits(&json!({"region":{"kind":"tile","x":1}})));
    }

    #[test]
    fn empty_allow_list_denies_everything() {
        let p = load("allow: []").unwrap();
        assert!(!p.permits(&json!({"region":{"kind":"metadata"}})));
    }

    #[test]
    fn context_may_not_contain_a_properties_key() {
        // cql2 falls back to `properties.{name}`, so data could shadow a
        // policy property name.
        let p = load("allow:\n  - \"region.kind = 'metadata'\"").unwrap();
        assert!(!p.permits(&json!({"properties":{"region":{"kind":"metadata"}}})));
    }
}
```

**Step 2: Run to verify failure**

Run: `cargo test policy`
Expected: FAIL.

**Step 3: Implement**

```rust
use cql2::Expr;
use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("policy is not valid YAML: {0}")] Yaml(#[from] serde_yaml::Error),
    #[error("filter does not parse as CQL2: {0}")] Parse(String),
    #[error("unknown property `{0}` - not in the queryables schema")] UnknownProperty(String),
    #[error("operator `{0}` is banned in policies")] BannedOperator(String),
}

#[derive(Deserialize)]
struct PolicyFile { allow: Vec<String> }

pub struct Policy { rules: Vec<Expr> }

impl Policy {
    /// Parses and statically validates every filter.
    ///
    /// Validation is not optional. cql2 cannot report an unknown property at
    /// evaluation time: `x IS NULL` folds an absent property to TRUE, and
    /// boolean absorption (FALSE AND _, TRUE OR _) discards a typo'd operand
    /// whenever a sibling decides the result. A typo would therefore silently
    /// widen a policy.
    pub fn load(yaml: &str, queryables: &[&str]) -> Result<Self, PolicyError> {
        let file: PolicyFile = serde_yaml::from_str(yaml)?;
        let mut rules = Vec::with_capacity(file.allow.len());
        for src in file.allow {
            let expr: Expr = src.parse().map_err(|e| PolicyError::Parse(format!("{e}")))?;
            validate(&expr, queryables)?;
            rules.push(expr);
        }
        Ok(Self { rules })
    }

    /// True if ANY rule matches. An evaluation error denies.
    pub fn permits(&self, ctx: &Value) -> bool {
        if ctx.get("properties").is_some() { return false; }
        self.rules.iter().any(|r| r.clone().matches(Some(ctx)).unwrap_or(false))
    }
}

const BANNED_OPS: &[&str] = &["isNull"];

fn validate(expr: &Expr, queryables: &[&str]) -> Result<(), PolicyError> {
    match expr {
        Expr::Property { property } => {
            if queryables.contains(&property.as_str()) { Ok(()) }
            else { Err(PolicyError::UnknownProperty(property.clone())) }
        }
        Expr::Operation { op, args } => {
            if BANNED_OPS.contains(&op.as_str()) {
                return Err(PolicyError::BannedOperator(op.clone()));
            }
            args.iter().try_for_each(|a| validate(a, queryables))
        }
        Expr::Interval { interval } => interval.iter().try_for_each(|a| validate(a, queryables)),
        Expr::Array(items) => items.iter().try_for_each(|a| validate(a, queryables)),
        _ => Ok(()),
    }
}
```

> **Note for the implementer:** `cql2::Expr` variant names and shapes must be
> checked against the installed 0.6 source (`cargo doc --open -p cql2`). If a
> variant is missing from the match, add it — a `_ => Ok(())` arm that silently
> skips a container variant would let a typo through inside it. Add a test with
> a property nested inside every container form you find.

**Step 4: Run to verify pass**

Run: `cargo test policy`
Expected: PASS, 7 tests.

**Step 5: Commit**

```bash
git add src/policy.rs src/lib.rs
git commit -m "feat: policy loading with static property validation

Typos cannot be caught at evaluation time: IS NULL folds an absent property
to true and boolean absorption discards a typo'd operand when a sibling
decides the result. Walk the AST at load and reject unknown properties."
```

---

## Task 5: The decision function

**Files:**
- Create: `src/decide.rs`, Modify: `src/lib.rs`

**Step 1: Write the failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::*;
    use serde_json::json;

    fn idx() -> LayoutIndex {
        LayoutIndex::new(vec![
            Region { start: 0,  len: 10, kind: RegionKind::Metadata { name: "header".into() } },
            Region { start: 10, len: 10, kind: RegionKind::ColumnChunk { column: "public".into(), row_group: 0 } },
            Region { start: 20, len: 10, kind: RegionKind::ColumnChunk { column: "salary".into(), row_group: 0 } },
        ], 40) // 30..40 becomes Unmapped
    }

    fn policy() -> crate::policy::Policy {
        crate::policy::Policy::load(
            "allow:\n  - \"region.kind = 'metadata'\"\n  - \"region.kind = 'column_chunk' AND region.column <> 'salary'\"",
            crate::QUERYABLES).unwrap()
    }

    #[test]
    fn permitted_range_is_authorized_with_a_canonical_extent() {
        match check(&idx(), &policy(), &json!({}), Some("bytes=10-19")) {
            Decision::Authorized { canonical } => assert_eq!(canonical, 10..20),
            d => panic!("{d:?}"),
        }
    }

    #[test]
    fn forbidden_range_is_denied() {
        assert!(matches!(check(&idx(), &policy(), &json!({}), Some("bytes=20-29")),
                         Decision::Denied { .. }));
    }

    // The core of the whole design: `all`, not `any`.
    #[test]
    fn a_straddling_range_is_denied_even_though_one_region_is_permitted() {
        assert!(matches!(check(&idx(), &policy(), &json!({}), Some("bytes=0-29")),
                         Decision::Denied { .. }));
    }

    #[test]
    fn a_range_over_unmapped_bytes_is_denied() {
        assert!(matches!(check(&idx(), &policy(), &json!({}), Some("bytes=30-39")),
                         Decision::Denied { .. }));
    }

    #[test]
    fn no_range_header_means_the_whole_object_and_is_denied() {
        assert!(matches!(check(&idx(), &policy(), &json!({}), None),
                         Decision::Denied { .. }));
    }

    #[test]
    fn a_malformed_range_is_denied_not_ignored() {
        assert!(matches!(check(&idx(), &policy(), &json!({}), Some("bytes=0-0, items=1-2")),
                         Decision::Denied { .. }));
    }

    #[test]
    fn denial_does_not_disclose_which_region_was_protected() {
        let Decision::Denied { reason } = check(&idx(), &policy(), &json!({}), Some("bytes=20-29"))
            else { panic!() };
        let s = format!("{reason:?}");
        assert!(!s.contains("salary"), "denial leaked the column name: {s}");
    }
}
```

**Step 2: Run to verify failure**

Run: `cargo test decide`
Expected: FAIL.

**Step 3: Implement**

```rust
use crate::{index::LayoutIndex, policy::Policy, range};
use serde_json::Value;
use std::ops::Range;

#[derive(Debug)]
pub enum DenyReason { BadRange, NotPermitted }

#[derive(Debug)]
pub enum Decision {
    /// The caller MUST fetch exactly this range, MUST NOT forward the client's
    /// original Range header, and MUST reject any response whose Content-Range
    /// differs. RFC 9110 lets an origin ignore a Range it cannot parse and
    /// answer 200 with the whole object.
    Authorized { canonical: Range<u64> },
    Denied { reason: DenyReason },
}

pub fn check(index: &LayoutIndex, policy: &Policy, user: &Value, header: Option<&str>) -> Decision {
    let Ok(range) = range::parse(header, index.size()) else {
        return Decision::Denied { reason: DenyReason::BadRange };
    };

    let regions = index.resolve(&range);
    // Total coverage makes this unreachable, but `all` over an empty set is
    // `true`, so never rely on that invariant holding elsewhere.
    if regions.is_empty() {
        return Decision::Denied { reason: DenyReason::NotPermitted };
    }

    // Conjunctive: EVERY overlapped region must be permitted.
    let ok = regions.iter().all(|r| {
        let ctx = serde_json::json!({ "user": user, "region": r.props() });
        policy.permits(&ctx)
    });

    if ok { Decision::Authorized { canonical: range } }
    else  { Decision::Denied { reason: DenyReason::NotPermitted } }
}
```

**Step 4: Run to verify pass**

Run: `cargo test decide`
Expected: PASS, 7 tests.

**Step 5: Commit**

```bash
git add src/decide.rs src/lib.rs
git commit -m "feat: conjunctive decision returning canonical authorized ranges

Every overlapped region must be permitted, not any. Returns the range the
caller must fetch rather than a verdict about the client's header, so the
gateway never forwards a header a backend might parse differently."
```

---

## Task 6: Parquet resolver

**Files:**
- Create: `src/parquet.rs`, `tests/fixtures/` (see Task 8 for generation)

**Step 1: Write the failing tests**

```rust
#[test]
fn column_extent_starts_at_the_dictionary_page_not_the_data_page() {
    // For a low-cardinality column the dictionary page IS the set of distinct
    // values. Starting at data_page_offset leaves it outside every region.
    let idx = build_from_fixture("nyc-taxi-8rg.parquet");
    let r = idx.regions().iter()
        .find(|r| r.column() == Some("payment_type")).unwrap();
    let meta = /* read the same chunk's metadata */;
    assert_eq!(r.start, meta.dictionary_page_offset().unwrap() as u64);
}

#[test]
fn nested_columns_use_the_full_dotted_path() {
    let idx = build_from_fixture("nested.parquet");
    assert!(idx.regions().iter().any(|r| r.column() == Some("employee.salary")));
    assert!(!idx.regions().iter().any(|r| r.column() == Some("salary")));
}

#[test]
fn page_index_and_bloom_filters_are_attributed_to_their_column() {
    let idx = build_from_fixture("nyc-taxi-8rg.parquet");
    assert!(idx.regions().iter().any(|r|
        matches!(r.kind, RegionKind::ColumnIndex { .. })));
}

#[test]
fn the_magic_and_footer_are_named_metadata_regions() {
    let idx = build_from_fixture("nyc-taxi-8rg.parquet");
    assert_eq!(idx.resolve(&(0..4))[0].kind,
               RegionKind::Metadata { name: "magic".into() });
}

#[test]
fn coverage_is_total_for_a_real_file() {
    let idx = build_from_fixture("nyc-taxi-8rg.parquet");
    let mut c = 0;
    for r in idx.regions() { assert_eq!(r.start, c); c = r.end(); }
    assert_eq!(c, idx.size());
}
```

**Step 2: Run to verify failure**

Run: `cargo test parquet`

**Step 3: Implement**

Key rules, each from the format review:

- Parse with `ParquetMetaDataReader::new().parse_and_finish(&bytes)`. The footer
  is located by reading the last 8 bytes: `i32` LE length at `[-8..-4]`, magic
  at `[-4..]`, body starts at `len - 8 - footer_len`.
- **Never read `ColumnChunk.file_offset`** — deprecated in `parquet.thrift`,
  which records that implementations disagreed and it is "in many cases wrong".
- Extent is `min(dictionary_page_offset, data_page_offset) .. + total_compressed_size`.
  Do **not** call `ColumnChunkMetaData::byte_range()`: it panics on negative
  offsets, which violates fail-closed. Read the fields and return an error.
- `region.column` is `path_in_schema.join(".")`, not the leaf name.
- Emit `ColumnIndex` / `BloomFilter` regions from `column_index_offset`,
  `column_index_length`, `offset_index_offset`, `offset_index_length`,
  `bloom_filter_offset`, `bloom_filter_length`. **All of these live in the
  footer**, so no second read is needed — we classify where they are, not what
  they contain. If `bloom_filter_offset` is set with no length, emit nothing and
  let the gap become `Unmapped`.
- If `ColumnChunk.file_path` is set, return an error: offsets are not into this
  object.
- Emit named metadata regions for the 4-byte magic, the footer body, and the
  8-byte trailer.

**Step 4: Run to verify pass. Step 5: Commit.**

---

## Task 7: COG resolver

**Files:**
- Create: `src/cog.rs`

**Step 1: Write the failing tests**

```rust
#[test]
fn tile_regions_include_the_gdal_block_leader_and_trailer() {
    // GDAL COGs write a 4-byte size leader before and a 4-byte copy of the
    // last 4 bytes after each tile. TileOffsets points at the PAYLOAD, but
    // readers fetch offset-4 .. offset+len+4. Mapping only the payload makes
    // every legitimate tile request overlap unclassified bytes and be denied.
    let idx = build_from_fixture("s2-tci-512.tif");
    let (off, len) = first_tile_offset_and_len();
    let r = idx.resolve(&(off - 4..off + len + 4));
    assert_eq!(r.len(), 1, "leader/trailer are not part of the tile region");
}

#[test]
fn overview_level_comes_from_the_width_ratio_not_the_ifd_index() {
    // Mask IFDs sit in the chain too. Numbering by position mislabels them,
    // and getting the direction backwards silently inverts every
    // `overview_level >= N` rule.
    let idx = build_from_fixture("s2-tci-512.tif");
    let levels: Vec<u32> = /* distinct overview_level values */;
    assert_eq!(levels, vec![0,1,2,3,4,5]);
}

#[test]
fn tag_arrays_are_their_own_metadata_regions() {
    // TileOffsets/TileByteCounts exceed 4 bytes so they live outside the IFD,
    // between the IFDs and the pixel data.
    let idx = build_from_fixture("s2-tci-512.tif");
    assert!(idx.regions().iter().any(|r|
        matches!(&r.kind, RegionKind::Metadata { name } if name == "tag:TileOffsets")));
}

#[test]
fn planar_configuration_2_fails_closed() {
    assert!(build_from_fixture("planar2.tif").is_err());
}

#[test]
fn a_striped_tiff_produces_no_tiles_and_therefore_no_access() {
    // No TileOffsets at all. Everything must become Unmapped, not open.
    let idx = build_from_fixture("striped.tif").unwrap();
    assert!(idx.regions().iter().all(|r|
        !matches!(r.kind, RegionKind::Tile { .. })));
}

#[test]
fn tile_bbox_carries_its_crs() {
    let idx = build_from_fixture("s2-tci-512.tif");
    let t = idx.regions().iter().find(|r| matches!(r.kind, RegionKind::Tile{..})).unwrap();
    assert!(t.props()["crs"].is_number());
}
```

**Step 2-5:** as above. Implementation rules, each from the format review:

- Use `tiff` 0.11: `seek_to_image` / `next_image` / `more_images` to walk IFDs,
  `get_tag_u64_vec` for `TileOffsets`(324) / `TileByteCounts`(325), and
  `Tag::Unknown(u16)` + `tag_iter()` for `GDAL_METADATA`(42112).
- Detect the ghost area's `BLOCK_LEADER=SIZE_AS_UINT4` /
  `BLOCK_TRAILER=LAST_4_BYTES_REPEATED` and widen every tile region
  accordingly. Emit the ghost area itself as a named metadata region.
- `overview_level` from `ImageWidth_full / ImageWidth_this`, **not** IFD index.
  `NewSubfileType` bit 0 marks a reduced image, bit 2 a mask; both set means a
  mask of an overview. Give masks their own kind, not an overview level.
- Follow `SubIFDs` (tag 330) recursively — GDAL ≥ 3.2 hangs overviews and masks
  there, and a resolver walking only the main chain leaves their tile bytes
  unmapped.
- `PlanarConfiguration`(284) `= 2` → error. Tile count becomes
  `SamplesPerPixel × TilesPerImage` with per-plane grouping and the props have
  no plane component.
- `TilesAcross = ceil(ImageWidth / TileWidth)`; index `= y * TilesAcross + x`.
- BigTIFF: version `0x2B`, 16-byte header, u64 entry count, 20-byte entries,
  inline threshold 8 bytes not 4.
- Georeferencing: `ModelPixelScale`(33550) + `ModelTiepoint`(33922), or
  `ModelTransformation`(34264) for rotated rasters. Fail closed on
  multi-tiepoint GCP-only files. Overview IFDs do not repeat these tags — scale
  the full-resolution transform by the width ratio, which the OGC COG standard
  permits to be 2–10× and not necessarily a power of two.
- Read the CRS from `GeoKeyDirectory`(34735) into `Region::crs`.

---

## Task 8: Sample data and fixtures

**Files:** Create `data/`, `tests/fixtures/`, `scripts/make-fixtures.sh`

Sizes chosen so coalescing actually bites — a file small enough to be fetched in
one range measures zero straddles and reports a false negative.

```bash
# 8.4 MB, 8 row groups x 19 columns. ROW_GROUP_SIZE is mandatory: the 1M-row
# default produces ONE row group. SNAPPY, not ZSTD - hyparquet handles only
# uncompressed and snappy without an extra package.
duckdb -c "COPY (SELECT * FROM read_parquet('yellow_tripdata_2024-01.parquet') LIMIT 400000)
  TO 'data/nyc-taxi-8rg.parquet' (FORMAT PARQUET, COMPRESSION SNAPPY, ROW_GROUP_SIZE 50000);"

# 4.7 MB, 6 overview levels, 512px tiles at ~7KB each
gdal_translate TCI.tif data/s2-tci-512.tif -of COG \
  -co BLOCKSIZE=512 -co COMPRESS=JPEG -co QUALITY=75 -co OVERVIEWS=IGNORE_EXISTING
```

Also generate small negative fixtures: `nested.parquet` (a struct with a
`salary` field), `planar2.tif`, `striped.tif`.

**Commit the binaries directly. Git LFS does not work on GitHub Pages** — it
serves the pointer text, and you will spend an afternoon debugging a 133-byte
"Parquet file".

---

## Task 9: WASM bindings

**Files:** Create `src/wasm.rs`

Two functions, behind `#[cfg(target_arch = "wasm32")]`:

```rust
#[wasm_bindgen]
pub fn build_index(footer: &[u8], size: f64, format: &str) -> Result<JsValue, JsValue>;

#[wasm_bindgen]
pub fn check(index: &JsValue, policy: &str, ctx: &JsValue, range: Option<String>) -> JsValue;
```

Build with `wasm-pack build --target web`. If wasm-opt fails on bulk memory,
either upgrade wasm-pack or set `[package.metadata.wasm-pack.profile.release]
wasm-opt = false`.

---

## Task 10: Web demo

**Files:** Create `web/index.html`, `web/app.js`, `web/policy.js`, `web/grid.css`

Interception at each library's own seam, not a `fetch` shim:

```js
// hyparquet: initialFetchSize ~8KB. The 512KB default tail straddles the last
// row group's chunks, so the demo's own bootstrap read trips the coalescing
// rule and nothing ever loads.
const buf = {
  byteLength: size,
  async slice(start, end) {              // end exclusive
    const d = check(index, policy, ctx, `bytes=${start}-${end - 1}`);
    log.push({ start, end, decision: d });
    if (d.denied) throw new Error(`403 ${d.reason}`);
    return (await fetch(url, { headers: { Range: `bytes=${start}-${end - 1}` } })).arrayBuffer();
  }
};

// geotiff.js: blockSize MUST be `undefined`, not `null`. The docs say null
// disables blocking, but maybeWrapInBlockedSource tests === undefined, so
// null yields NaN block math.
await GeoTIFF.fromSource(new PolicySource(), { blockSize: undefined });
```

UI:
- Row-group × column grid (Parquet) and tile grid per overview level (COG), as
  CSS grid.
- **Alignment toggle**: `columns: [...]` projection on/off, blocking on/off.
- **Counters: ranges issued, ranges straddling a boundary, query outcome.**
  This is the deliverable.
- Two or three preset AOI polygons that paste a `POLYGON(...)` into the policy
  textarea. Not click-to-draw.
- Heatmap as a second colorway on the same grid, from the log live mode emits.

---

## Task 11: Deploy and hosting regression test

**Files:** Create `.github/workflows/pages.yml`

Build WASM, copy `web/` and `data/`, deploy to Pages. Then assert the hosting
assumptions that Live mode depends on:

```bash
# Pages applies Range AFTER gzip. It does not compress octet-stream or tiff
# today, but that is one MIME-database change from silently breaking: a ranged
# request would return a slice of the COMPRESSED stream. Browsers always send
# Accept-Encoding: gzip and it is a Fetch-forbidden header, so this cannot be
# worked around from JS.
curl -sI "$URL/data/nyc-taxi-8rg.parquet" | grep -q 'accept-ranges: bytes'
curl -sI "$URL/data/nyc-taxi-8rg.parquet" | grep -qv 'content-encoding'
curl -s -o /dev/null -w '%{http_code}' -H 'Range: bytes=0-19' "$URL/data/nyc-taxi-8rg.parquet" | grep -q 206
```

---

## Task 12: Write up the measurement

The point of the whole exercise. In `docs/findings.md`, record for each reader,
in both alignment modes: ranges issued, ranges straddling a policy boundary,
whether the query completed, and what a gateway would have to do about clients
it cannot configure. Then answer the adopt/do-not-adopt question from the design
document's §What this proof of concept must decide.
