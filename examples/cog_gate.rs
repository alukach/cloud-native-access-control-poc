//! A gateway that serves a policy-filtered view of a local COG.
//!
//! ```text
//! cargo run --release --example cog_gate -- \
//!     --file data/s2-tci-512.tif \
//!     --policy examples/withhold-tiles.yaml \
//!     --user '{"role":"analyst"}' \
//!     --port 8898 [--mode scrub|sparsify|refuse]
//! ```
//!
//! Then point GDAL at `/vsicurl/http://127.0.0.1:8898/f.tif`.
//!
//! # What it holds
//!
//! One file handle and a list of byte ranges. Nothing else -- and that is the
//! difference from [`gate`](../gate.rs), which also holds the ~14 KB rewritten
//! Parquet footer. `cnac::sparse` changes no lengths and moves no bytes, so
//! there is no resident tail to hold: a request is answered by `pread`ing the
//! extent it asked for, in 1 MiB pieces, zeroing each piece in place as it
//! goes.
//!
//! # The three modes, which exist to be compared
//!
//! * `scrub` (default) -- the recommended architecture. The IFD's `TileOffsets`
//!   and `TileByteCounts` entries for the withheld tiles are zeroed, which is
//!   exactly how a sparse COG says "this tile was never written", and the
//!   tiles' bytes are zeroed too.
//! * `sparsify` -- the tag entries only. Included because it is the mode that
//!   *looks* like it works and is not safe: the tiles are invisible to GDAL,
//!   and `Range: bytes=<old extent>` still returns live JPEG bytes to anyone
//!   who kept the original IFD or simply guessed -- and a COG's tile addressing
//!   is guessable from the grid.
//! * `refuse` -- the original object, with [`cnac::decision::check`] refusing
//!   any range covering a forbidden byte. This is what a block-aligned client
//!   cannot survive: GDAL `/vsicurl` reads on a 16 KiB grid and no
//!   configuration makes that grid land on tile boundaries (issue #26).
//!
//! Deliberately not production code: no TLS, no auth, no concurrency limit, and
//! the principal is a command-line flag rather than a verified token.

use cnac::{
    cog::{build_index_with_layout, CogError},
    decision::{check, Decision, Verdict},
    index::LayoutIndex,
    policy::{Policy, QUERYABLES},
    range::{self, RangeError},
    sparse::{self, Sparse},
};
use serde_json::{json, Value};
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::net::{TcpListener, TcpStream};
use std::ops::Range;
use std::sync::{Arc, Mutex};

/// The first speculative prefix read. Both committed COGs need less than 16 KiB
/// of metadata; a larger one is read on demand when the resolver says so.
const FIRST_PREFIX: u64 = 16 * 1024;
/// The most bytes held in memory at once while answering a request.
const PIECE: u64 = 1024 * 1024;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Sparsify plus scrub.
    Scrub,
    /// Tag entries only -- the unsafe half, kept so it can be demonstrated.
    Sparsify,
    /// The original object, with ranges refused.
    Refuse,
}

impl Mode {
    fn name(self) -> &'static str {
        match self {
            Mode::Scrub => "scrub",
            Mode::Sparsify => "sparsify",
            Mode::Refuse => "refuse",
        }
    }
}

struct Gate {
    file: Mutex<File>,
    mode: Mode,
    index: LayoutIndex,
    policy: Policy,
    user: Value,
    plan: Sparse,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut path = "data/s2-tci-512.tif".to_string();
    let mut policy_path = "examples/withhold-tiles.yaml".to_string();
    let mut user_json = r#"{"role":"analyst"}"#.to_string();
    let mut port = 8898u16;
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
                    "sparsify" => Mode::Sparsify,
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

    // One speculative PREFIX read, widened only if the resolver says so. A
    // TIFF puts its metadata at the front, so this is the mirror image of the
    // Parquet gateway's tail read, and it terminates for the same reason: every
    // answer is strictly larger than the buffer that provoked it.
    let mut window = FIRST_PREFIX.min(size);
    let (index, layout) = loop {
        let prefix = read_at(&mut file, 0, window as usize)?;
        match build_index_with_layout(&prefix, size) {
            Ok(pair) => break pair,
            Err(CogError::Truncated { needed }) if needed > window => window = needed.min(size),
            Err(e) => return Err(e.into()),
        }
    };

    // Timed because it is the per-(object, policy) cost a deployment caches
    // against: one plan serves every principal whose policy withholds the same
    // tiles, and the artifact is a span list and nothing else.
    let started = std::time::Instant::now();
    let plan = sparse::plan(&index, &layout, &policy, &user)?;
    let plan_micros = started.elapsed().as_micros();

    // To stdout, once, rather than an HTTP endpoint: the report names every
    // withheld tile and every withheld extent, which is exactly what the policy
    // is keeping from the client.
    let mut per_level: std::collections::BTreeMap<u32, usize> = Default::default();
    for tile in plan.withheld() {
        *per_level.entry(tile.overview_level).or_default() += 1;
    }
    println!(
        "{:#}",
        json!({
            "file": path,
            "mode": mode.name(),
            "metadata_prefix": window,
            "original_size": size,
            // Equal, always. A COG plan changes no lengths, which is the whole
            // reason it needs no rewritten tail.
            "virtual_size": plan.virtual_size(),
            "etag": plan.etag(),
            "withheld_tiles": plan.withheld().len(),
            "withheld_tiles_by_level": per_level,
            "tag_edits": plan.edits().len(),
            "tag_edit_bytes": plan.edits().iter().map(|e| e.end - e.start).sum::<u64>(),
            "scrub_spans": plan.scrub().len(),
            "scrub_bytes": plan.scrub().iter().map(|s| s.end - s.start).sum::<u64>(),
            "blank_spans": plan.blank().len(),
            "blank_bytes": plan.blanked_bytes(),
            "resident_bytes": std::mem::size_of_val(plan.blank()),
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
    });

    let listener = TcpListener::bind(("127.0.0.1", port))?;
    eprintln!("cog_gate: /vsicurl/http://127.0.0.1:{port}/f.tif");
    for stream in listener.incoming() {
        let gate = Arc::clone(&gate);
        std::thread::spawn(move || {
            if let Ok(stream) = stream {
                // A client that hangs up mid-response is normal -- GDAL
                // abandons speculative reads -- so a write failure is logged
                // and dropped rather than propagated.
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
    let method = line.split_whitespace().next().unwrap_or("").to_string();

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

/// The validator for what this mode serves, or none.
///
/// Under `refuse` the body is the origin's own bytes, so the origin's validator
/// would be the honest one and this example does not have it. The synthesized
/// tag is emitted only for the two rewriting modes -- and it matters more here
/// than in the Parquet gateway, because a COG plan does not change the object's
/// length, so `Content-Length` no longer distinguishes the representations.
fn etag(gate: &Gate) -> Option<String> {
    match gate.mode {
        Mode::Refuse => None,
        _ => Some(gate.plan.etag()),
    }
}

fn head(gate: &Gate, out: &mut TcpStream) -> std::io::Result<()> {
    let len = gate.index.size();
    eprintln!("HEAD -> 200, Content-Length: {len}");
    let mut headers = vec![
        ("Accept-Ranges", "bytes".to_string()),
        ("Content-Length", len.to_string()),
        ("Content-Type", "image/tiff".to_string()),
    ];
    if let Some(etag) = etag(gate) {
        headers.push(("ETag", etag));
    }
    write_status(out, 200, "OK", b"", &headers)
}

fn get(gate: &Gate, header: Option<&str>, out: &mut TcpStream) -> std::io::Result<()> {
    let complete = gate.index.size();
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
        // The comparison mode: no edit, no scrub, and any range covering a
        // forbidden byte is refused outright.
        match check(&gate.index, &gate.policy, &gate.user, header) {
            Decision::Authorized { canonical } => {
                eprintln!(
                    "GET bytes={}-{} -> 206 ({straddles} withheld tiles overlapped, served whole)",
                    canonical.start,
                    canonical.end - 1,
                );
                return body(gate, out, header.is_some(), complete, &canonical);
            }
            Decision::Denied { reason } => {
                eprintln!("GET {header:?} -> 403 ({reason:?}, {straddles} withheld tiles inside)");
                return write_status(out, 403, "Forbidden", b"denied\n", &[]);
            }
        }
    }

    eprintln!(
        "GET bytes={}-{} -> 206 ({straddles} withheld tiles inside, served as zeroes)",
        requested.start,
        requested.end - 1,
    );
    body(gate, out, header.is_some(), complete, &requested)
}

/// The extents of `extent` this mode blanks.
///
/// `scrub` asks the plan, which is the whole of the real API. `sparsify` clips
/// the tag edits alone -- deliberately leaving every withheld tile's bytes live
/// so that the mode can be *shown* to be unsafe rather than described as such.
fn blanks(gate: &Gate, extent: &Range<u64>) -> Verdict {
    match gate.mode {
        Mode::Scrub => gate.plan.object_verdict(extent),
        _ => Verdict::Serve {
            canonical: extent.clone(),
            blank: gate
                .plan
                .edits()
                .iter()
                .filter(|s| s.start < extent.end && s.end > extent.start)
                .map(|s| s.start.max(extent.start)..s.end.min(extent.end))
                .collect(),
        },
    }
}

/// Write the response for `extent`, streaming it in pieces so that a
/// full-object `GET` never allocates the object.
fn body(
    gate: &Gate,
    out: &mut TcpStream,
    ranged: bool,
    complete: u64,
    extent: &Range<u64>,
) -> std::io::Result<()> {
    let len = extent.end - extent.start;
    let mut headers = vec![
        ("Accept-Ranges", "bytes".to_string()),
        ("Content-Length", len.to_string()),
        ("Content-Type", "image/tiff".to_string()),
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

    // One address case, unlike the Parquet gateway's two: every virtual offset
    // is the same physical offset, zeroed where the plan says.
    let mut cursor = extent.start;
    while cursor < extent.end {
        let stop = (cursor + PIECE).min(extent.end);
        let mut buf = {
            let mut file = gate.file.lock().expect("gate file lock");
            read_at(&mut file, cursor, (stop - cursor) as usize)?
        };
        if gate.mode != Mode::Refuse {
            // `redact` is the one audited place the absolute-to-buffer
            // subtraction is written down. A verdict it cannot apply leaves the
            // buffer zeroed, which is the safe direction.
            let verdict = blanks(gate, &(cursor..stop));
            if verdict.redact(&mut buf).is_err() {
                buf.fill(0);
            }
        }
        out.write_all(&buf)?;
        cursor = stop;
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
    // read loop, and GDAL's /vsicurl handles `close`.
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
