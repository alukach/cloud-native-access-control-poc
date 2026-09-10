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
//!    [`RegionKind::Unmapped`](crate::index::RegionKind::Unmapped) no policy can
//!    match -- but this function does not lean on that invariant holding
//!    somewhere else. It calls
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
//! # Why the answer is a byte extent and not a boolean
//!
//! See [`Decision::Authorized`]. In short: a gateway that authorizes a client's
//! `Range` header and then *forwards that header* has authorized one thing and
//! fetched another, because RFC 9110 §14.2 requires an origin server to ignore
//! a `Range` it cannot parse and answer `200` with the entire representation.
//! Returning the extent to fetch, rather than permission to fetch, removes the
//! opportunity to make that mistake.

use crate::{index::LayoutIndex, policy::Policy, range};
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
    // Only a header that did not parse may be reported as `BadRange`. An
    // unsatisfiable one is a function of `size`, so it joins the denials --
    // see `DenyReason::BadRange`.
    let range = match range::parse(header, index.size()) {
        Ok(range) => range,
        Err(range::RangeError::Unparseable) => {
            return Decision::Denied {
                reason: DenyReason::BadRange,
            }
        }
        Err(range::RangeError::NotSatisfiable) => return not_permitted(),
    };

    if !principal_is_addressable(user) {
        return not_permitted();
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
        return not_permitted();
    };

    // Belt and braces, and the braces are cheap. `try_resolve` already
    // guarantees this slice is non-empty; the guarantee is worth one branch
    // because the failure it guards is silent and total -- an empty set makes
    // the conjunction below vacuously true, which authorizes the request rather
    // than failing it. A regression in `try_resolve` should cost a denial, not
    // the object.
    if regions.is_empty() {
        return not_permitted();
    }

    // Conjunctive: every overlapped region, short-circuiting on the first
    // denial. `props()` is built here rather than in the index so that only the
    // regions a request actually touches pay for one.
    let permitted = regions
        .iter()
        .all(|region| policy.permits(&json!({"user": user, "region": region.props()})));

    if permitted {
        Decision::Authorized { canonical: range }
    } else {
        not_permitted()
    }
}

fn not_permitted() -> Decision {
    Decision::Denied {
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

#[cfg(test)]
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
}
