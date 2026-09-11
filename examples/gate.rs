//! A gateway that serves a policy-filtered view of a local Parquet file.
//!
//! ```text
//! cargo run --release --example gate -- \
//!     --file data/nyc-taxi-8rg.parquet \
//!     --policy examples/withhold-fares.yaml \
//!     --user '{"role":"analyst"}' \
//!     --port 8899 [--mode scrub|rewrite|refuse]
//! ```
//!
//! Then point a reader at `http://127.0.0.1:8899/f.parquet`.
//!
//! # What it holds
//!
//! One file handle and the rewritten tail -- ~14 KB for the 8.4 MB sample. The
//! object is never materialized: a request is answered by `pread`ing the extent
//! it asked for, in 1 MiB pieces, scrubbing each piece in place as it goes. A
//! full-object `GET` of the 8.4 MB file peaks at one megabyte of buffer.
//!
//! # The three modes, which exist to be compared
//!
//! * `scrub` (default) -- the recommended architecture. The footer never
//!   mentions the withheld columns and their bytes are zeroed in flight.
//! * `rewrite` -- the footer only. Included because it is the mode that *looks*
//!   like it works and is not safe: the columns are invisible to a reader, and
//!   `Range: bytes=863208-863307` still returns live pages of them to anyone
//!   who kept the original footer or simply guessed.
//! * `refuse` -- the original object, with [`cnac::decision::check`] refusing
//!   any range covering a forbidden byte. This is what a block-aligned client
//!   cannot survive, and running the same client against both modes is the
//!   measurement.
//!
//! Deliberately not production code: no TLS, no auth, no concurrency limit, and
//! the principal is a command-line flag rather than a verified token. It exists
//! so that real readers can be pointed at real bytes.

use cnac::{
    decision::{check, Decision, Verdict},
    index::LayoutIndex,
    parquet::build_index,
    policy::{Policy, QUERYABLES},
    range::{self, RangeError},
    rewrite::{self, Rewrite},
};
use serde_json::{json, Value};
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::net::{TcpListener, TcpStream};
use std::ops::Range;
use std::sync::{Arc, Mutex};

/// The first tail read. Wide enough for any footer these fixtures have; a
/// larger one is read on demand when the resolver says so.
const FIRST_TAIL: u64 = 64 * 1024;
/// The most bytes held in memory at once while answering a request.
const PIECE: u64 = 1024 * 1024;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Footer rewrite plus scrub.
    Scrub,
    /// Footer rewrite only -- the unsafe half, kept so it can be demonstrated.
    Rewrite,
    /// The original object, with ranges refused.
    Refuse,
}

struct Gate {
    file: Mutex<File>,
    mode: Mode,
    index: LayoutIndex,
    policy: Policy,
    user: Value,
    plan: Rewrite,
    tail: Vec<u8>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut path = "data/nyc-taxi-8rg.parquet".to_string();
    let mut policy_path = "examples/withhold-fares.yaml".to_string();
    let mut user_json = r#"{"role":"analyst"}"#.to_string();
    let mut port = 8899u16;
    let mut mode = Mode::Scrub;

    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        let value = || -> String {
            args.get(i + 1)
                .unwrap_or_else(|| panic!("{} needs a value", args[i]))
                .clone()
        };
        match args[i].as_str() {
            "--file" => path = value(),
            "--policy" => policy_path = value(),
            "--user" => user_json = value(),
            "--port" => port = value().parse()?,
            "--mode" => {
                mode = match value().as_str() {
                    "scrub" => Mode::Scrub,
                    "rewrite" => Mode::Rewrite,
                    "refuse" => Mode::Refuse,
                    other => return Err(format!("unknown mode `{other}`").into()),
                }
            }
            other => return Err(format!("unknown flag `{other}`").into()),
        }
        i += 2;
    }

    let mut file = File::open(&path)?;
    let size = file.metadata()?.len();
    let policy = Policy::load(&std::fs::read_to_string(&policy_path)?, QUERYABLES)?;
    let user: Value = serde_json::from_str(&user_json)?;

    // One speculative tail read, widened only if the footer says so. This is
    // the flow `cnac::parquet` documents: the resolver names the number of
    // bytes from the end that would have been enough.
    let mut window = FIRST_TAIL.min(size);
    let index = loop {
        let tail = read_at(&mut file, size - window, window as usize)?;
        match build_index(&tail, size) {
            Ok(index) => break index,
            Err(cnac::parquet::ParquetError::Truncated { needed }) if needed > window => {
                window = needed.min(size);
            }
            Err(e) => return Err(e.into()),
        }
    };

    let footer_region = index
        .regions()
        .iter()
        .find(|r| matches!(&r.kind, cnac::index::RegionKind::Metadata { name } if name == "footer"))
        .ok_or("no footer region")?;
    let footer_body = read_at(&mut file, footer_region.start, footer_region.len as usize)?;

    // Timed because it is the per-(object, policy) cost a deployment caches
    // against: one rewrite serves every principal whose policy withholds the
    // same columns, and the artifact is the ~14 KB tail plus a span list.
    let started = std::time::Instant::now();
    let plan = rewrite::plan(&index, &footer_body, &policy, &user)?;
    let plan_micros = started.elapsed().as_micros();
    let tail = plan.tail();

    // To stdout, once, rather than an HTTP endpoint: the report names every
    // withheld column and every withheld extent, which is exactly what the
    // policy is keeping from the client.
    println!(
        "{:#}",
        json!({
            "file": path,
            "mode": match mode { Mode::Scrub => "scrub", Mode::Rewrite => "rewrite", Mode::Refuse => "refuse" },
            "original_size": size,
            "virtual_size": plan.virtual_size(),
            "footer_start": plan.footer_start(),
            "footer_bytes": [footer_region.len, plan.footer().len()],
            "etag": plan.etag(),
            "withheld": plan.withheld().iter().map(|w| json!({
                "column": w.column,
                "denied_kinds": w.denied_kinds,
                "regions": w.regions,
                "bytes": w.bytes,
            })).collect::<Vec<_>>(),
            "scrub_spans": plan.scrub().len(),
            "scrub_bytes": plan.scrub().iter().map(|s| s.end - s.start).sum::<u64>(),
            "groups_pruned": plan.groups_pruned(),
            "key_value_metadata_stripped": plan.stripped_keys(),
            "resident_bytes": tail.len(),
            "plan_micros": plan_micros,
        })
    );

    let gate = Arc::new(Gate {
        file: Mutex::new(file),
        mode,
        index,
        policy,
        user,
        plan,
        tail,
    });

    let listener = TcpListener::bind(("127.0.0.1", port))?;
    eprintln!("gate: http://127.0.0.1:{port}/f.parquet");
    for stream in listener.incoming() {
        let gate = Arc::clone(&gate);
        std::thread::spawn(move || {
            if let Ok(stream) = stream {
                // A client that hangs up mid-response is normal -- readers
                // abandon speculative reads -- so a write failure is logged and
                // dropped rather than propagated.
                if let Err(e) = serve(&gate, stream) {
                    eprintln!("  (connection ended: {e})");
                }
            }
        });
    }
    Ok(())
}

fn read_at(file: &mut File, offset: u64, len: usize) -> std::io::Result<Vec<u8>> {
    file.seek(SeekFrom::Start(offset))?;
    let mut buf = vec![0u8; len];
    file.read_exact(&mut buf)?;
    Ok(buf)
}

fn serve(gate: &Gate, stream: TcpStream) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut line = String::new();
    if reader.read_line(&mut line)? == 0 {
        return Ok(());
    }
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();

    let mut range_header: Option<String> = None;
    loop {
        let mut header = String::new();
        if reader.read_line(&mut header)? == 0 {
            break;
        }
        let header = header.trim_end();
        if header.is_empty() {
            break;
        }
        if let Some((name, value)) = header.split_once(':') {
            if name.eq_ignore_ascii_case("range") {
                range_header = Some(value.trim().to_string());
            }
        }
    }

    let mut out = stream;
    match method.as_str() {
        "HEAD" => head(gate, &mut out),
        "GET" => get(gate, range_header.as_deref(), &mut out),
        _ => write_status(&mut out, 405, "Method Not Allowed", b"", &[]),
    }
}

/// The complete length of whatever this mode serves. Under `refuse` that is the
/// object; under the two rewriting modes it is the virtual representation,
/// which is what a suffix range has to resolve against.
fn complete_length(gate: &Gate) -> u64 {
    match gate.mode {
        Mode::Refuse => gate.index.size(),
        _ => gate.plan.virtual_size(),
    }
}

/// The validator for what this mode serves, or none.
///
/// Under `refuse` the response body is the origin's own bytes, so the origin's
/// validator would be the honest one -- and this example does not have it. An
/// ETag is emitted only for the two rewriting modes, where the representation
/// really is this gateway's to name. Emitting the synthesized tag alongside
/// origin bytes would be worse than emitting none: a shared cache would key the
/// two representations together.
fn etag(gate: &Gate) -> Option<String> {
    match gate.mode {
        Mode::Refuse => None,
        _ => Some(gate.plan.etag()),
    }
}

fn head(gate: &Gate, out: &mut TcpStream) -> std::io::Result<()> {
    let len = complete_length(gate);
    eprintln!("HEAD -> 200, Content-Length: {len}");
    let mut headers = vec![
        ("Accept-Ranges", "bytes".to_string()),
        ("Content-Length", len.to_string()),
        ("Content-Type", "application/octet-stream".to_string()),
    ];
    if let Some(etag) = etag(gate) {
        headers.push(("ETag", etag));
    }
    write_status(out, 200, "OK", b"", &headers)
}

fn get(gate: &Gate, header: Option<&str>, out: &mut TcpStream) -> std::io::Result<()> {
    let complete = complete_length(gate);
    let requested = match range::parse(header, complete) {
        Ok(r) => r,
        Err(RangeError::Unparseable) => {
            eprintln!("GET {header:?} -> 400 (unparseable)");
            return write_status(out, 400, "Bad Request", b"bad range\n", &[]);
        }
        Err(RangeError::NotSatisfiable) => {
            eprintln!("GET {header:?} -> 416");
            return write_status(out, 416, "Range Not Satisfiable", b"", &[]);
        }
    };

    let straddles = gate
        .plan
        .scrub()
        .iter()
        .filter(|s| s.start < requested.end && s.end > requested.start)
        .count();

    if gate.mode == Mode::Refuse {
        // The comparison mode: no rewrite, no scrub, and any range covering a
        // forbidden byte is refused outright.
        match check(&gate.index, &gate.policy, &gate.user, header) {
            Decision::Authorized { canonical } => {
                eprintln!(
                    "GET bytes={}-{} -> 206 ({} scrub spans overlapped, served whole)",
                    canonical.start,
                    canonical.end - 1,
                    straddles
                );
                return body(gate, out, header.is_some(), complete, &canonical, false);
            }
            Decision::Denied { reason } => {
                eprintln!("GET {header:?} -> 403 ({reason:?}, {straddles} scrub spans overlapped)");
                return write_status(out, 403, "Forbidden", b"denied\n", &[]);
            }
        }
    }

    eprintln!(
        "GET bytes={}-{} -> 206 ({} withheld extents inside, served as zeroes)",
        requested.start,
        requested.end - 1,
        straddles
    );
    body(
        gate,
        out,
        header.is_some(),
        complete,
        &requested,
        gate.mode == Mode::Scrub,
    )
}

/// Write the response for `extent`, streaming it in pieces so that a
/// full-object `GET` never allocates the object.
fn body(
    gate: &Gate,
    out: &mut TcpStream,
    ranged: bool,
    complete: u64,
    extent: &Range<u64>,
    scrub: bool,
) -> std::io::Result<()> {
    let len = extent.end - extent.start;
    let mut headers = vec![
        ("Accept-Ranges", "bytes".to_string()),
        ("Content-Length", len.to_string()),
        ("Content-Type", "application/octet-stream".to_string()),
    ];
    if let Some(etag) = etag(gate) {
        headers.push(("ETag", etag));
    }
    let status = if ranged {
        headers.push((
            "Content-Range",
            format!("bytes {}-{}/{}", extent.start, extent.end - 1, complete),
        ));
        (206, "Partial Content")
    } else {
        (200, "OK")
    };
    write_head(out, status.0, status.1, &headers)?;

    let footer_start = gate.plan.footer_start();
    let mut cursor = extent.start;
    while cursor < extent.end {
        let piece = (cursor + PIECE).min(extent.end);
        if cursor < footer_start || gate.mode == Mode::Refuse {
            // Below the footer (or in refuse mode, anywhere): the original
            // object's bytes at their original offsets.
            let stop = if gate.mode == Mode::Refuse {
                piece
            } else {
                piece.min(footer_start)
            };
            let mut buf = {
                let mut file = gate.file.lock().expect("gate file lock");
                read_at(&mut file, cursor, (stop - cursor) as usize)?
            };
            if scrub {
                // The one audited place the absolute-to-buffer subtraction is
                // written. A `Verdict` this function cannot redact leaves the
                // buffer zeroed, which is the safe direction.
                let verdict = gate.plan.object_verdict(&(cursor..stop));
                if verdict.redact(&mut buf).is_err() {
                    buf.fill(0);
                }
                debug_assert!(matches!(verdict, Verdict::Serve { .. }));
            }
            out.write_all(&buf)?;
            cursor = stop;
        } else {
            // At or above the footer: the rewritten tail, which is resident.
            let lo = (cursor - footer_start) as usize;
            let hi = (piece - footer_start) as usize;
            out.write_all(&gate.tail[lo..hi.min(gate.tail.len())])?;
            cursor = piece;
        }
    }
    out.flush()
}

fn write_head(
    out: &mut TcpStream,
    code: u16,
    reason: &str,
    headers: &[(&str, String)],
) -> std::io::Result<()> {
    let mut head = format!("HTTP/1.1 {code} {reason}\r\n");
    for (name, value) in headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    // No keep-alive: one request per connection keeps this example to a single
    // read loop, and every client used to verify it handles `close`.
    head.push_str("Connection: close\r\n\r\n");
    out.write_all(head.as_bytes())
}

fn write_status(
    out: &mut TcpStream,
    code: u16,
    reason: &str,
    body: &[u8],
    extra: &[(&str, String)],
) -> std::io::Result<()> {
    let mut headers = extra.to_vec();
    if !headers.iter().any(|(n, _)| *n == "Content-Length") {
        headers.push(("Content-Length", body.len().to_string()));
    }
    write_head(out, code, reason, &headers)?;
    out.write_all(body)?;
    out.flush()
}
