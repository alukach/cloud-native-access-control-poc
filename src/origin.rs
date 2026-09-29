//! Verify an origin's response against what was authorized.
//!
//! [`Decision::Authorized`](crate::decision::Decision::Authorized) states three
//! caller obligations, and until now they were only prose. A gateway that
//! authorizes `canonical` and relays whatever the origin sends back has not
//! enforced anything: RFC 9110 §14.2 requires an origin server to **ignore** a
//! `Range` header it cannot parse and answer `200` with the *entire
//! representation*, so the single most likely failure of this whole design is a
//! backend that disagrees with our parser and hands back the object.
//!
//! This module is the judgment, not the transport. It takes no socket, opens no
//! connection and knows no HTTP library, because the gateway that adopts this
//! crate already has one and its choice is not ours to make. What it cannot be
//! trusted to have is the rule, so the rule ships here as code.
//!
//! # What it does not do
//!
//! Nothing about caching, revalidation or `Vary`. A rewritten view disagrees
//! with the origin's own `ETag`, `Content-MD5` and `ListObjects` size by
//! construction, and keeping a client from revalidating against the origin is
//! a deployment property (issue tracking it in the repo). Passing [`verify`]
//! does not make a response cacheable.
//!
//! Multi-range is absent on purpose: [`range::parse`](crate::range::parse)
//! refuses a multi-range request, so no authorized fetch is ever multi-range
//! and a `multipart/byteranges` response is always a disagreement. It is
//! caught here by its missing `Content-Range`.

use std::ops::Range;

use thiserror::Error;

/// What was authorized, and the object it was authorized against.
///
/// Built from a [`Decision::Authorized`](crate::decision::Decision::Authorized)
/// plus the two facts the index carries: the object's size and the validator it
/// was built from.
#[derive(Debug, Clone)]
pub struct Authorized<'a> {
    /// Exactly the extent [`check`](crate::decision::check) permitted.
    pub canonical: Range<u64>,
    /// [`LayoutIndex::size`](crate::index::LayoutIndex::size) — the length of
    /// the object the layout describes.
    pub object_size: u64,
    /// The validator the index was built from, if the caller pinned one.
    ///
    /// `None` means the caller chose not to pin a version, which obligation 3
    /// permits only when something else does (an S3 `versionId` in the request
    /// path, say). When it is `Some`, a response carrying a *different*
    /// validator is rejected: the layout describes an object that is no longer
    /// the one answering.
    pub etag: Option<&'a str>,
}

/// A response that must not be relayed.
///
/// Every variant is a refusal to serve. There is no partial acceptance and no
/// repair: the bytes in hand were not the bytes authorized, and the only safe
/// answer to the client is an error.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum OriginError {
    /// `200` with a body longer than the authorized extent.
    ///
    /// **The RFC 9110 §14.2 case, and the reason this module exists.** The
    /// origin did not understand the range and answered with the whole
    /// representation. A gateway that streams this on has authorized a slice
    /// and delivered the object.
    #[error("origin ignored the range: 200 with {body} bytes for an authorized {authorized}")]
    RangeIgnored { authorized: u64, body: u64 },

    /// A status that is neither `206` nor an acceptable whole-object `200`.
    #[error("origin answered {status}, which authorizes nothing")]
    Status { status: u16 },

    /// `206` with no `Content-Range` to check it against.
    ///
    /// Also how a `multipart/byteranges` response is caught: it carries its
    /// extents in the body parts, not in a header, and this crate never
    /// authorizes a multi-range fetch.
    #[error("206 without a Content-Range header")]
    MissingContentRange,

    /// A `Content-Range` this crate will not interpret.
    ///
    /// Strict for the same reason [`range::parse`](crate::range::parse) is:
    /// a lenient reading here is a disagreement with the origin about which
    /// bytes arrived, and that disagreement is the vulnerability.
    #[error("Content-Range is not a single satisfied byte range: {0:?}")]
    MalformedContentRange(String),

    /// The origin served a different extent than the one authorized.
    #[error(
        "origin served {served_start}-{served_end} for an authorized \
         {authorized_start}-{authorized_end}"
    )]
    WrongExtent {
        authorized_start: u64,
        authorized_end: u64,
        served_start: u64,
        served_end: u64,
    },

    /// The complete-length disagrees with the size the layout was built from.
    ///
    /// Obligation 3: this proves the index describes a different object than
    /// the one that answered, so the authorization was computed against the
    /// wrong layout. Size equality is necessary and not sufficient — an object
    /// rewritten to the same length moves every column — which is why
    /// [`Authorized::etag`] exists beside it.
    #[error("origin reports a complete length of {origin}; the layout describes {index}")]
    SizeChanged { index: u64, origin: u64 },

    /// The body is not the length the `Content-Range` promised.
    #[error("Content-Range names {expected} bytes; the body is {body}")]
    BodyLengthMismatch { expected: u64, body: u64 },

    /// `Content-Length` disagrees with the extent served.
    #[error("Content-Length is {header}; the served extent is {expected} bytes")]
    ContentLengthMismatch { expected: u64, header: u64 },

    /// The object changed between building the index and fetching the bytes.
    #[error(
        "validator changed: the layout was built from {index:?}, the origin answered {origin:?}"
    )]
    ValidatorChanged { index: String, origin: String },
}

/// One origin response, as the fields this rule needs.
///
/// A struct rather than eight positional arguments, because a caller that
/// transposes `content_length` and `body_len` would still compile.
#[derive(Debug, Clone, Default)]
pub struct Response<'a> {
    pub status: u16,
    pub content_range: Option<&'a str>,
    pub content_length: Option<u64>,
    pub etag: Option<&'a str>,
    /// The bytes actually in hand. For a streaming body, the count after the
    /// stream ends — a check that runs before the body is complete has checked
    /// nothing.
    pub body_len: u64,
}

/// Is this response the one that was authorized?
///
/// `Ok(())` means every obligation in
/// [`Decision::Authorized`](crate::decision::Decision::Authorized) holds and the
/// body may be relayed. Any `Err` means it may not, and the error names which
/// obligation failed rather than collapsing to a boolean — a gateway wants
/// `RangeIgnored` in its logs, loudly, because it means the backend and this
/// crate disagree about range syntax and every other request is suspect too.
pub fn verify(authorized: &Authorized<'_>, response: &Response<'_>) -> Result<(), OriginError> {
    let want = &authorized.canonical;
    // `check` never authorizes an empty range, so the length is non-zero and
    // the subtraction cannot underflow.
    let want_len = want.end - want.start;

    // Obligation 2's one exception: a `200` is acceptable when `canonical`
    // covers the whole object and the body matches. Anything else answered
    // `200` is either the RFC 9110 full-representation case or a body of the
    // wrong length, and both are bytes that were never authorized.
    if response.status == 200 {
        let whole_object = want.start == 0 && want.end == authorized.object_size;
        if whole_object && response.body_len == want_len {
            return check_validator(authorized, response);
        }
        return Err(OriginError::RangeIgnored {
            authorized: want_len,
            body: response.body_len,
        });
    }

    if response.status != 206 {
        return Err(OriginError::Status {
            status: response.status,
        });
    }

    let header = response
        .content_range
        .ok_or(OriginError::MissingContentRange)?;
    let (served, complete) = parse_content_range(header)
        .ok_or_else(|| OriginError::MalformedContentRange(header.to_string()))?;

    if served != *want {
        return Err(OriginError::WrongExtent {
            authorized_start: want.start,
            authorized_end: want.end,
            served_start: served.start,
            served_end: served.end,
        });
    }

    // `*` is permitted by RFC 9110 and carries no claim, so there is nothing to
    // disagree with. A stated length that differs is obligation 3 failing.
    if let Some(complete) = complete {
        if complete != authorized.object_size {
            return Err(OriginError::SizeChanged {
                index: authorized.object_size,
                origin: complete,
            });
        }
    }

    let served_len = served.end - served.start;
    if response.body_len != served_len {
        return Err(OriginError::BodyLengthMismatch {
            expected: served_len,
            body: response.body_len,
        });
    }
    if let Some(len) = response.content_length {
        if len != served_len {
            return Err(OriginError::ContentLengthMismatch {
                expected: served_len,
                header: len,
            });
        }
    }

    check_validator(authorized, response)
}

/// Obligation 3's second half: the bytes came from the object the layout
/// describes.
///
/// Compared as opaque strings, per RFC 9110 §8.8.3 strong comparison. A weak
/// validator (`W/"..."`) is not equal to its strong spelling and is rejected,
/// which is correct here: weak means "semantically equivalent", and a layout
/// index is not interested in semantic equivalence.
fn check_validator(
    authorized: &Authorized<'_>,
    response: &Response<'_>,
) -> Result<(), OriginError> {
    let Some(want) = authorized.etag else {
        return Ok(());
    };
    // A caller that pinned a validator and got none back cannot show the
    // object is unchanged, which is the whole purpose of pinning it.
    let got = response.etag.unwrap_or("");
    if got != want {
        return Err(OriginError::ValidatorChanged {
            index: want.to_string(),
            origin: got.to_string(),
        });
    }
    Ok(())
}

/// `bytes 0-99/8000` → `(0..100, Some(8000))`.
///
/// Returns `None` for anything else, including the unsatisfied `bytes */8000`
/// form: it names no extent, so it cannot be the extent that was authorized.
/// No trimming, no case folding of the digits' surroundings, one space after
/// the unit exactly as RFC 9110 §14.4 spells it — the reasons are
/// [`range::parse`](crate::range::parse)'s, unchanged.
fn parse_content_range(header: &str) -> Option<(Range<u64>, Option<u64>)> {
    let rest = header.strip_prefix("bytes ")?;
    let (extent, complete) = rest.split_once('/')?;
    let (first, last) = extent.split_once('-')?;

    let first: u64 = parse_digits(first)?;
    let last: u64 = parse_digits(last)?;
    // Inclusive on the wire, half-open here. `last < first` is not a range,
    // and `last == u64::MAX` cannot be made half-open without overflowing.
    if last < first || last == u64::MAX {
        return None;
    }

    let complete = match complete {
        "*" => None,
        digits => Some(parse_digits(digits)?),
    };
    Some((first..last + 1, complete))
}

/// Digits and nothing else: no sign, no whitespace, no `+`, no underscores.
///
/// `str::parse` accepts a leading `+`, and a header that reaches this crate as
/// `bytes +0-+99/100` should not be read as agreement.
fn parse_digits(text: &str) -> Option<u64> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIZE: u64 = 8_422_357;

    fn authorized() -> Authorized<'static> {
        Authorized {
            canonical: 1000..2000,
            object_size: SIZE,
            etag: Some("\"abc123\""),
        }
    }

    /// The response a correct origin sends.
    fn good() -> Response<'static> {
        Response {
            status: 206,
            content_range: Some("bytes 1000-1999/8422357"),
            content_length: Some(1000),
            etag: Some("\"abc123\""),
            body_len: 1000,
        }
    }

    #[test]
    fn the_response_that_was_authorized_is_accepted() {
        assert_eq!(verify(&authorized(), &good()), Ok(()));
    }

    // The founding case. An origin that does not understand the range answers
    // 200 with the entire representation, and a gateway that relays it has
    // authorized 1000 bytes and delivered 8.4 MB.
    #[test]
    fn a_200_with_the_whole_object_is_refused_not_relayed() {
        let response = Response {
            status: 200,
            content_range: None,
            content_length: Some(SIZE),
            etag: Some("\"abc123\""),
            body_len: SIZE,
        };
        assert_eq!(
            verify(&authorized(), &response),
            Err(OriginError::RangeIgnored {
                authorized: 1000,
                body: SIZE,
            })
        );
    }

    // `python3 -m http.server` is this exact response, and the README warns
    // against it for this exact reason. The warning is now a test.
    #[test]
    fn a_200_is_refused_even_when_the_body_is_short() {
        let response = Response {
            status: 200,
            body_len: 20,
            ..Response::default()
        };
        assert!(matches!(
            verify(&authorized(), &response),
            Err(OriginError::RangeIgnored { .. })
        ));
    }

    // The one case a 200 is honest: the authorization covered everything.
    #[test]
    fn a_200_is_accepted_only_when_the_authorization_was_the_whole_object() {
        let whole = Authorized {
            canonical: 0..SIZE,
            object_size: SIZE,
            etag: None,
        };
        let response = Response {
            status: 200,
            body_len: SIZE,
            ..Response::default()
        };
        assert_eq!(verify(&whole, &response), Ok(()));

        // ...and not when the body is a different length than the object.
        let short = Response {
            status: 200,
            body_len: SIZE - 1,
            ..Response::default()
        };
        assert!(matches!(
            verify(&whole, &short),
            Err(OriginError::RangeIgnored { .. })
        ));
    }

    // A 206 naming any extent other than the authorized one. The origin may
    // have clamped, rounded to a block, or served a neighbouring chunk; all of
    // them are bytes the policy never authorized.
    #[test]
    fn a_206_for_a_different_extent_is_refused() {
        for (header, body) in [
            ("bytes 0-1999/8422357", 2000u64),   // widened at the start
            ("bytes 1000-65535/8422357", 64536), // rounded up to a block
            ("bytes 1000-1998/8422357", 999),    // one byte short
            ("bytes 999-1999/8422357", 1001),    // one byte early
            ("bytes 2000-2999/8422357", 1000),   // a different chunk entirely
        ] {
            let response = Response {
                content_range: Some(header),
                content_length: Some(body),
                body_len: body,
                ..good()
            };
            assert!(
                matches!(
                    verify(&authorized(), &response),
                    Err(OriginError::WrongExtent { .. })
                ),
                "{header} was accepted"
            );
        }
    }

    // Obligation 3: the layout describes an object of a different length, so
    // every offset in it is suspect.
    #[test]
    fn a_complete_length_that_differs_from_the_index_is_refused() {
        let response = Response {
            content_range: Some("bytes 1000-1999/9000000"),
            ..good()
        };
        assert_eq!(
            verify(&authorized(), &response),
            Err(OriginError::SizeChanged {
                index: SIZE,
                origin: 9_000_000,
            })
        );
    }

    // `*` makes no claim about the complete length, so there is nothing to
    // disagree with and the extent check still stands on its own.
    #[test]
    fn an_unknown_complete_length_is_accepted() {
        let response = Response {
            content_range: Some("bytes 1000-1999/*"),
            ..good()
        };
        assert_eq!(verify(&authorized(), &response), Ok(()));
    }

    // The object was replaced between building the index and fetching the
    // bytes. Same length, same extent, different content: the case
    // design.md calls out, where a chosen-prefix MD5 collision relabels the
    // column chunks while the ETag holds. Here the ETag does not even hold.
    #[test]
    fn a_rotated_validator_is_refused() {
        for origin in [Some("\"def456\""), Some("W/\"abc123\""), None] {
            let response = Response {
                etag: origin,
                ..good()
            };
            assert!(
                matches!(
                    verify(&authorized(), &response),
                    Err(OriginError::ValidatorChanged { .. })
                ),
                "{origin:?} was accepted"
            );
        }
    }

    // A caller that pinned nothing gets no validator check. This is not an
    // endorsement -- obligation 3 requires the version be pinned somehow --
    // but it must not be an error, or every `versionId`-pinned fetch fails.
    #[test]
    fn no_pinned_validator_means_no_validator_check() {
        let unpinned = Authorized {
            etag: None,
            ..authorized()
        };
        let response = Response {
            etag: Some("\"anything\""),
            ..good()
        };
        assert_eq!(verify(&unpinned, &response), Ok(()));
    }

    // A truncated stream. The extent was right, the bytes did not all arrive,
    // and a reader handed a short buffer will parse whatever follows it.
    #[test]
    fn a_body_shorter_than_the_extent_is_refused() {
        let response = Response {
            body_len: 999,
            ..good()
        };
        assert_eq!(
            verify(&authorized(), &response),
            Err(OriginError::BodyLengthMismatch {
                expected: 1000,
                body: 999,
            })
        );
    }

    #[test]
    fn a_content_length_disagreeing_with_the_extent_is_refused() {
        let response = Response {
            content_length: Some(2000),
            ..good()
        };
        assert_eq!(
            verify(&authorized(), &response),
            Err(OriginError::ContentLengthMismatch {
                expected: 1000,
                header: 2000,
            })
        );
    }

    // A multipart response carries its extents in the body, not in a header,
    // and this crate never authorizes a multi-range fetch. It arrives here as
    // a 206 with nothing to check.
    #[test]
    fn a_206_without_a_content_range_is_refused() {
        let response = Response {
            content_range: None,
            ..good()
        };
        assert_eq!(
            verify(&authorized(), &response),
            Err(OriginError::MissingContentRange)
        );
    }

    // Every status that is not 206 and not an honest whole-object 200. `416`
    // and `412` matter most: a backend that refuses the canonical range, or
    // whose precondition failed, has served nothing and must not be read as
    // having served something.
    #[test]
    fn no_other_status_authorizes_anything() {
        for status in [301u16, 304, 400, 403, 404, 412, 416, 500, 503] {
            let response = Response {
                status,
                body_len: 0,
                ..good()
            };
            assert_eq!(
                verify(&authorized(), &response),
                Err(OriginError::Status { status }),
                "{status}"
            );
        }
    }

    // The Content-Range parser is as strict as the Range parser, and for the
    // same reason: a lenient reading is a disagreement with the origin about
    // which bytes arrived, and that disagreement is the vulnerability.
    #[test]
    fn a_malformed_content_range_is_refused_not_interpreted() {
        for header in [
            "bytes */8422357",          // unsatisfied: names no extent
            "bytes 1000-1999",          // no complete length
            "bytes=1000-1999/8422357",  // the request spelling, not the response
            "BYTES 1000-1999/8422357",  // case
            "bytes  1000-1999/8422357", // two spaces
            "bytes 1000-1999/8422357 ", // trailing space
            " bytes 1000-1999/8422357", // leading space
            "bytes +1000-1999/8422357", // str::parse would accept the sign
            "bytes 1000-1999/+8422357",
            "bytes 1000 - 1999/8422357", // spaces inside the extent
            "bytes 1999-1000/8422357",   // inverted
            "bytes 1000-/8422357",       // open-ended is a request form
            "bytes -1999/8422357",       // suffix is a request form
            "items 1000-1999/8422357",   // another unit
            "bytes 1000-1999/8422357, bytes 3000-3999/8422357",
            "",
        ] {
            let response = Response {
                content_range: Some(header),
                ..good()
            };
            assert!(
                matches!(
                    verify(&authorized(), &response),
                    Err(OriginError::MalformedContentRange(_))
                ),
                "{header:?} was interpreted"
            );
        }
    }

    // An inclusive `u64::MAX` end cannot be made half-open without
    // overflowing. It wrapped to `0..0` in release once already, in
    // `range.rs`; the same arithmetic appears here and must refuse instead.
    #[test]
    fn an_end_at_u64_max_is_refused_rather_than_wrapped() {
        let response = Response {
            content_range: Some("bytes 0-18446744073709551615/*"),
            ..good()
        };
        assert!(matches!(
            verify(&authorized(), &response),
            Err(OriginError::MalformedContentRange(_))
        ));
    }

    // The same rule against a real origin that really does misbehave.
    //
    // `python3 -m http.server` ignores `Range` and answers `200` with the whole
    // file. The README warns about it in prose and the tests above model it
    // from a struct literal; this one runs it. It is the only test in the crate
    // that opens a socket, so it is `#[ignore]`d -- it needs python3, a free
    // port and ~2 s -- and it is worth having anyway, because "the origin
    // returns 200 with the entire representation" is the assumption this whole
    // module rests on and it should be observed at least once.
    //
    // Run it with:
    //     cargo test --  --ignored a_real_origin_that_ignores_range
    #[test]
    #[ignore = "spawns python3 -m http.server and shells out to curl"]
    fn a_real_origin_that_ignores_range_is_caught_by_verify() {
        use std::process::{Command, Stdio};

        // Bind to 0 to have the OS name a free port, then release it. A racing
        // process could take it in between; that is a flake in a test nobody
        // runs automatically, not a correctness problem.
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();

        let mut origin = Command::new("python3")
            .args([
                "-m",
                "http.server",
                &port.to_string(),
                "--bind",
                "127.0.0.1",
            ])
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("python3 is required for this test");

        // Poll rather than sleep a fixed amount: the server is ready when the
        // port accepts, and that is sooner than any guess.
        let url = format!("http://127.0.0.1:{port}/data/nyc-taxi-8rg.parquet");
        let mut probe = None;
        for _ in 0..100 {
            let out = Command::new("curl")
                .args([
                    "-s",
                    "-o",
                    "/dev/null",
                    // Ask for 1000 bytes, and report what actually arrived.
                    "-H",
                    "Range: bytes=1000-1999",
                    "-w",
                    "%{http_code} %{size_download}",
                    &url,
                ])
                .output()
                .expect("curl is required for this test");
            let text = String::from_utf8_lossy(&out.stdout).to_string();
            if text.starts_with("200") || text.starts_with("206") {
                probe = Some(text);
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let _ = origin.kill();
        let _ = origin.wait();

        let probe = probe.expect("the origin never came up");
        let mut fields = probe.split_whitespace();
        let status: u16 = fields.next().unwrap().parse().unwrap();
        let body_len: u64 = fields.next().unwrap().parse().unwrap();

        let object_size = std::fs::metadata(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("data/nyc-taxi-8rg.parquet"),
        )
        .unwrap()
        .len();

        // The claim under test: it answers 200, with the entire object, to a
        // request for 1000 bytes.
        assert_eq!(
            status, 200,
            "python3 -m http.server started honouring Range"
        );
        assert_eq!(body_len, object_size);

        let authorized = Authorized {
            canonical: 1000..2000,
            object_size,
            etag: None,
        };
        let response = Response {
            status,
            body_len,
            ..Response::default()
        };
        assert_eq!(
            verify(&authorized, &response),
            Err(OriginError::RangeIgnored {
                authorized: 1000,
                body: object_size,
            })
        );
    }

    // The order of checks is itself a property: a response that is wrong in
    // several ways at once must report the most fundamental problem, so an
    // operator reading logs sees "the origin ignored the range" and not "the
    // content length was off by 8 MB".
    #[test]
    fn the_range_ignored_case_is_reported_before_any_other_disagreement() {
        let response = Response {
            status: 200,
            content_range: Some("bytes 0-8422356/8422357"),
            content_length: Some(SIZE),
            etag: Some("\"rotated\""),
            body_len: SIZE,
        };
        assert!(matches!(
            verify(&authorized(), &response),
            Err(OriginError::RangeIgnored { .. })
        ));
    }
}
