//! Strict `Range` header parsing.

use std::ops::Range;

#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
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
///
/// Strictness beyond the obvious, each deliberate:
///
/// * No whitespace is tolerated anywhere. RFC 9110's `byte-range-spec` grammar
///   permits internal whitespace only around the commas of a multi-range list,
///   which we reject wholesale. Trimming would accept `bytes= 0-9`, which a
///   grammar-following backend treats as unparseable -- exactly the
///   accept-here/reject-there gap that yields a 200 full body.
/// * The `bytes=` unit is matched case-sensitively. Range units are formally
///   case-insensitive, so a backend would accept `BYTES=0-9`; rejecting it
///   costs a spec-legal but never-seen-in-practice spelling and fails closed
///   (the caller denies), while accepting it would widen our surface for no
///   gain.
///
/// # Returned range
///
/// The returned range is non-empty, non-inverted and within `0..size`
/// *whenever `size > 0`*. The single exception is a zero-byte object with no
/// `Range` header, which yields the empty `0..0`. Absent header means "not a
/// range request", and zero-byte objects are ordinary (S3 directory markers,
/// empty manifests, `_SUCCESS` files), so answering `NotSatisfiable` there
/// would be wrong; the deliberate consequence is that the downstream `check()`
/// resolves `0..0` to zero regions and denies. That is blunt but correct-by-
/// default for empty objects, and it is a decision rather than an oversight:
/// an empty object carries no bytes to disclose, so denying costs nothing a
/// caller cannot special-case above this layer.
///
/// # Error kinds are a disclosure channel
///
/// `Unparseable` and `NotSatisfiable` are kept distinct so a caller can map
/// them to 400 and 416, but the distinction itself leaks. `NotSatisfiable`
/// depends on `size`; `Unparseable` never does. Concretely,
/// `parse(Some("bytes=N-"), size)` returns `NotSatisfiable` iff `N >= size`.
/// That is a monotone predicate on `N`, so an attacker who can observe the two
/// outcomes binary-searches the exact object size in 64 probes at any
/// magnitude -- object size alone is often enough to fingerprint a file, and
/// it is available before any byte is read.
///
/// The invariant callers must hold: **authorize first, and never let the
/// `NotSatisfiable` vs `Unparseable` distinction reach a principal who could
/// not have read the object.** For an unauthorized principal both kinds must
/// collapse into the identical denial response -- same status, same body, same
/// headers, and in particular no `Content-Range: bytes */SIZE`. Only once the
/// principal is known to be permitted to read the extent may the kinds be
/// reported apart.
pub fn parse(header: Option<&str>, size: u64) -> Result<Range<u64>, RangeError> {
    // Before the size guard: no Range header is not a range request, so there
    // is nothing to find unsatisfiable, not even on a zero-byte object.
    let Some(h) = header else { return Ok(0..size) };

    // ---- Phase 1: syntax. Nothing here may consult `size`. -----------------
    //
    // Validating the grammar in full before looking at `size` is what keeps a
    // header's error kind independent of the object. Short-circuiting on
    // `size == 0` first would answer `NotSatisfiable` for headers that were
    // never syntactically valid (`BYTES=0-9`, `bytes=`, `bytes=٠-٩`), and a
    // caller mapping that to `416 + Content-Range: bytes */0` would hand an
    // attacker a one-request "is this object empty?" oracle keyed on a header
    // the grammar already rejects.
    let spec = h.strip_prefix("bytes=").ok_or(RangeError::Unparseable)?;
    if spec.contains(',') {
        return Err(RangeError::Unparseable);
    }
    let (start_s, end_s) = spec.split_once('-').ok_or(RangeError::Unparseable)?;
    // 1*DIGIT, and nothing else: no sign, no whitespace, no non-ASCII digits,
    // and no value too large to be a u64.
    let digits = |s: &str| -> Result<u64, RangeError> {
        if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
            return Err(RangeError::Unparseable);
        }
        s.parse().map_err(|_| RangeError::Unparseable)
    };

    enum Spec {
        /// `bytes=-N` : the last N bytes
        Suffix(u64),
        /// `bytes=N-` : from N to the end
        From(u64),
        /// `bytes=A-B` : inclusive of B on the wire, exclusive here
        Closed(u64, u64),
    }

    let spec = match (start_s.is_empty(), end_s.is_empty()) {
        (true, false) => Spec::Suffix(digits(end_s)?),
        (false, true) => Spec::From(digits(start_s)?),
        (false, false) => Spec::Closed(digits(start_s)?, digits(end_s)?),
        (true, true) => return Err(RangeError::Unparseable),
    };

    // ---- Phase 2: satisfiability against `size`. ---------------------------
    if size == 0 {
        return Err(RangeError::NotSatisfiable);
    }

    match spec {
        Spec::Suffix(n) => {
            if n == 0 {
                return Err(RangeError::NotSatisfiable);
            }
            Ok(size.saturating_sub(n)..size)
        }
        Spec::From(start) => {
            if start >= size {
                return Err(RangeError::NotSatisfiable);
            }
            Ok(start..size)
        }
        Spec::Closed(start, end_incl) => {
            if start > end_incl || start >= size {
                return Err(RangeError::NotSatisfiable);
            }
            // Clamp the last byte position BEFORE converting to exclusive.
            // `end_incl + 1` first would overflow on `bytes=0-{u64::MAX}`:
            // a panic in debug, and in release a wrap to 0 that `.min(size)`
            // would silently turn into an empty range. `size - 1` cannot
            // underflow -- size == 0 returned above.
            Ok(start..end_incl.min(size - 1) + 1)
        }
    }
}

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
            "bytes=5-4",     // start > end
            "bytes=999999-", // start past EOF -> 416, not an allow
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

    // A request with no Range header is not a range request, so there is
    // nothing to find unsatisfiable -- not even on a zero-byte object, which
    // is an ordinary thing to store (directory markers, empty manifests,
    // `_SUCCESS` files). The empty range that comes back is the documented
    // exception to "always non-empty"; `check()` resolves it to zero regions
    // and denies.
    #[test]
    fn absent_header_on_an_empty_object_is_the_empty_range() {
        assert_eq!(parse(None, 0).unwrap(), 0..0);
    }

    // The error kind must depend only on the header, never on the object.
    // Answering `NotSatisfiable` for a syntactically invalid header just
    // because the object happens to be empty gives a caller that emits
    // `416 + Content-Range: bytes */0` a one-request "is this object empty?"
    // oracle -- reachable with a header the grammar rejects outright.
    #[test]
    fn syntax_errors_do_not_depend_on_object_size() {
        for h in [
            "BYTES=0-9",
            "bytes=",
            "bytes=-",
            "bytes=٠-٩",
            "not-a-range-header-at-all",
            "",
            " bytes=0-9",
            "bytes=0-19,40-59",
            "bytes= 0-9",
            "bytes=1--5",
            "bytes=0-99999999999999999999999",
        ] {
            let empty = parse(Some(h), 0);
            let sized = parse(Some(h), 100);
            assert_eq!(empty, Err(RangeError::Unparseable), "size 0: {h}");
            assert_eq!(sized, Err(RangeError::Unparseable), "size 100: {h}");
            assert_eq!(empty, sized, "size-dependent error kind: {h}");
        }
    }

    // A last-byte-pos of u64::MAX must clamp like any other past-EOF end, not
    // overflow: `end_incl + 1` panics in debug and wraps to an empty 0..0 in
    // release, and an empty authorized extent that the backend answers with
    // the whole object is the disclosure this module exists to prevent.
    #[test]
    fn end_at_u64_max_clamps_instead_of_overflowing() {
        assert_eq!(
            parse(Some("bytes=0-18446744073709551615"), 100).unwrap(),
            0..100
        );
        assert_eq!(
            parse(Some("bytes=90-18446744073709551615"), 100).unwrap(),
            90..100
        );
    }

    // Numerically valid per the grammar but not representable. Rejecting fails
    // closed; a backend confronted with these either clamps or ignores the
    // header, and "ignores" means 200 with the entire representation.
    #[test]
    fn literals_too_large_for_u64_are_rejected() {
        for h in [
            "bytes=0-99999999999999999999999",
            "bytes=99999999999999999999999-",
            "bytes=-99999999999999999999999",
        ] {
            assert_eq!(parse(Some(h), 100), Err(RangeError::Unparseable), "{h}");
        }
    }

    // Whitespace is not trimmed: RFC 9110's byte-range-spec grammar has no
    // room for it, so tolerating it would accept headers a compliant backend
    // rejects -- and a rejected Range header is served as 200, whole object.
    #[test]
    fn whitespace_is_rejected_not_trimmed() {
        for h in [
            "bytes= 0-9",
            "bytes=0 -9",
            "bytes=0- 9",
            "bytes=0-9 ",
            "bytes= -20",
            "bytes=-20 ",
            "bytes= 90-",
            "bytes=\t0-9",
            "bytes=0-\r\n9",
        ] {
            assert_eq!(parse(Some(h), 100), Err(RangeError::Unparseable), "{h}");
        }
    }

    // Range units are case-insensitive per RFC 9110, so this is stricter than
    // the spec. It fails closed (the caller denies) and keeps exactly one
    // accepted spelling.
    #[test]
    fn the_bytes_unit_is_matched_case_sensitively() {
        for h in ["BYTES=0-9", "Bytes=0-9", "bYtEs=0-9"] {
            assert_eq!(parse(Some(h), 100), Err(RangeError::Unparseable), "{h}");
        }
    }

    // A zero-length suffix selects nothing and is unsatisfiable (RFC 9110
    // §14.1.2), rather than silently meaning "the whole object".
    #[test]
    fn zero_length_suffix_is_unsatisfiable() {
        assert_eq!(
            parse(Some("bytes=-0"), 100),
            Err(RangeError::NotSatisfiable)
        );
    }

    // Forms a real backend rejects that a looser split could let through.
    #[test]
    fn malformed_specs_are_rejected() {
        for h in [
            "bytes=0-9-20",    // three-part spec
            "bytes=bytes=0-5", // repeated unit
            "bytes=0-5;q=1",   // trailing parameter
            "bytes=0-5,",      // trailing comma: a one-element list, still a list
            "bytes=٠-٩",       // non-ASCII digits
            "bytes=0x0-0xff",  // hex
            "bytes=-1.5",      // non-integer
            "bytes=1--5",      // negative end
            " bytes=0-9",      // leading whitespace before the unit
            "bytes=0-9\n",     // header smuggling probe
        ] {
            assert_eq!(parse(Some(h), 100), Err(RangeError::Unparseable), "{h}");
        }
    }

    // The two error kinds are distinct so a caller can map them to 400 and 416
    // respectively; neither may ever be silently downgraded to an allow.
    #[test]
    fn error_kinds_separate_syntax_from_satisfiability() {
        assert_eq!(parse(Some("items=0-5"), 100), Err(RangeError::Unparseable));
        assert_eq!(
            parse(Some("bytes=999999-"), 100),
            Err(RangeError::NotSatisfiable)
        );
        assert_eq!(
            parse(Some("bytes=5-4"), 100),
            Err(RangeError::NotSatisfiable)
        );
        assert_eq!(parse(Some("bytes=0-0"), 0), Err(RangeError::NotSatisfiable));
    }

    // The exfiltration primitive from the task, pinned directly: a range that
    // ends one byte into a protected region must report that byte as covered.
    #[test]
    fn single_byte_ranges_are_exact() {
        assert_eq!(parse(Some("bytes=0-0"), 100).unwrap(), 0..1);
        assert_eq!(parse(Some("bytes=41-42"), 100).unwrap(), 41..43);
        assert_eq!(parse(Some("bytes=99-99"), 100).unwrap(), 99..100);
    }
}
