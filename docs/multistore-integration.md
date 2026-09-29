# Integrating with multistore

What it would take to put this crate inside
[multistore](https://github.com/developmentseed/multistore), and what breaks.

Read against multistore `0.7.2` at `266c5b6`. Every line reference below is to
that tree; they will drift.

This is the document the proof of concept exists to produce. Everything else
here establishes *that* sub-object authorization can work. This establishes
**where it would go**, and it finds one blocker that is architectural rather
than incidental.

---

## 1. The path a `GetObject` takes today

```
S3 request  →  parse  →  SigV4 / identity  →  bucket resolve  →  middleware chain
                                                                      │
                                              HandlerAction ──────────┘
                                              ├── Response(ProxyResult)    materialized bytes
                                              ├── Forward(ForwardRequest)  presigned, streamed
                                              └── NeedsBody(..)            request body first
```

A `GetObject` becomes `HandlerAction::Forward` — `crates/core/src/proxy.rs:908`.
`build_forward` (`proxy.rs:1110`) presigns a backend URL with a 300-second TTL,
copies a fixed list of client headers onto it, and returns. The runtime executes
it: `examples/server/src/client.rs:54` issues the request with `reqwest`, and
`examples/server/src/server.rs:196` returns `Body::from_stream(...)` straight to
the client.

**Two corrections to assumptions worth stating plainly, because they point in
opposite directions from where you would guess.**

**The presigned URL never reaches the client.** multistore's README advertises
"zero-copy streaming — presigned URLs enable direct streaming between clients
and backends without buffering," which reads like a redirect. It is not one.
There is no `307` and no `Location` anywhere in `crates/core/src` — the presign
is *backend-facing*, minted so the runtime's own HTTP client can fetch without
re-signing. The gateway is in the data path for every byte of every object
today. **Nothing about sub-object filtering conflicts with the presign design.**

**But the client's `Range` header is forwarded verbatim.** `proxy.rs:916` lists
`"range"` among the headers `build_forward` copies, and `proxy.rs:1129` copies
it with `fwd_headers.insert(*name, v.clone())`. That is exactly what
[`Decision::Authorized`](../src/decision.rs)'s first obligation forbids. It is
harmless today, because multistore makes no sub-object decision — it forwards
the whole request or none of it, so there is no authorization for a parser
disagreement to bypass. **It becomes the RFC 9110 §14.2 bypass on the day a
policy check lands**, and it is one line.

---

## 2. Where the policy check goes

`Middleware` (`crates/core/src/middleware.rs:201`) is the right seam and it
fits without modification. It receives `DispatchContext` — the parsed
`S3Operation`, the resolved identity, the bucket config, the original headers
— and returns a `HandlerAction`. A middleware can therefore:

- read the client's `Range` off `ctx.headers`
- build or look up a `LayoutIndex` for `(endpoint, bucket, key, version, etag)`
- call `decision::check`
- return `HandlerAction::Response` with a `403` on a denial

`DispatchContext::extensions` (`middleware.rs:70`, "arbitrary typed data for
middleware to share downstream") is where a resolved index or plan belongs if
two middlewares need it.

`DenyReason` must not cross this boundary into the response body. A `403` that
echoes the resolved regions hands back the withheld column's name and byte
extent — the design doc says so, and `HandlerAction::Response` makes it easy to
do by accident.

**So `DenialMode::Refuse` integrates today.** One middleware, no changes to
multistore. And per this repo's own findings, refuse is the mode that does not
work for real clients.

---

## 3. The blocker: `HandlerAction` cannot transform a response body

Every mode that *serves* something — zero-fill, `rewrite`, `sparsify` — needs to
change the bytes coming back from the backend. `HandlerAction` has three
variants (`crates/core/src/route_handler.rs:43`) and none of them can:

| variant | response body | why it can't carry a filtered view |
| --- | --- | --- |
| `Forward(ForwardRequest)` | streamed by the runtime | documented as "no handler involvement" (`route_handler.rs:47`) |
| `Response(ProxyResult)` | `ProxyResponseBody::{Bytes, Empty}` (`route_handler.rs:24`) | fully materialized in memory |
| `NeedsBody(..)` | — | the *request* body, for multipart |

There is no streaming-transform seam. A middleware either gives up control of
the bytes entirely, or buffers the whole response in memory.

That matters most exactly where multistore is most attractive. On Cloudflare
Workers, buffering a range response is bounded by the isolate's memory, and the
object sizes this project targets — an 8 MB Parquet is the *small* sample —
make `Response(Bytes)` a poor fit and a full-object read impossible.

**This is the single change multistore would need**: a fourth variant, or a
transform hook on `ForwardResponse`, of roughly the shape

```rust
/// Forward, then run each response chunk through `f` before relaying it.
ForwardTransformed(ForwardRequest, Box<dyn ResponseTransform>),
```

It is tractable because **what this crate needs of it is narrow**. Both write
paths are position-keyed and length-preserving:

- `Verdict::redact` (zero-fill) and `Sparse::scrub` zero byte spans **in
  place** — `sparse.rs` guarantees `virtual_size() == object_size()`, so every
  offset is unchanged and a transform needs only the absolute offset of the
  chunk it is handed.
- `Rewrite` changes length only *above* `footer_start`: every byte below it
  keeps its offset, and the replacement tail is ~14 KB and already resident.

So the transform is a pure `(absolute_offset, &mut [u8])` over a stream whose
total length is known before the first byte moves. No look-ahead, no buffering
of more than one chunk. `examples/gate.rs:369` is that loop, written against a
file handle instead of a stream.

---

## 4. Obligation by obligation

From `Decision::Authorized`'s doc comment and the design doc's cache-validity
section.

| obligation | owner in multistore | holds today? |
| --- | --- | --- |
| Fetch exactly `canonical` | `build_forward` (`proxy.rs:1110`) | **No** — client `Range` copied verbatim (`proxy.rs:916`) |
| Never forward the client's `Range` | same | **No**, same line |
| Verify the response against `canonical` | the runtime's `forward` impl (`client.rs:54`) | **No** — no response verification anywhere; `src/origin.rs::verify` is the rule to call |
| Complete-length matches the index | same | **No** |
| Pin the object version (`If-Match`) | `build_forward`'s header list | **Mechanism exists** — `"if-match"` is already forwarded (`proxy.rs:917`) and `ForwardRequest.headers` is constructible. Nothing sets it *from the index*. |
| `Denied` must not leak regions | the policy middleware | new code; easy to get wrong |
| Index cache keyed on the full tuple, not ETag alone | new | new |

The first four are one function. A policy middleware that builds its own
`ForwardRequest` rather than letting `build_forward` copy headers satisfies all
of them, and `verify` is a single call on the way back.

---

## 5. What each mode costs inside multistore

| | refuse | zero-fill | rewrite / sparsify |
| --- | --- | --- | --- |
| multistore changes | none | response transform | response transform |
| works for real clients | **no** (this repo's central finding) | projecting readers only | **yes, all measured** |
| streaming preserved | yes | yes, chunk-at-a-time | yes, chunk-at-a-time |
| Workers-viable | yes | yes | yes, if transformed not buffered |
| per-request cost | index lookup + policy eval | same | same + plan (3–5 ms Parquet, ~19 ms COG, cold) |
| `ListObjects` size | correct | correct | **wrong** — reports the original length, `Rewrite::virtual_size` is smaller |
| `ETag` / `Content-MD5` | correct | correct | **synthesized**; must not revalidate against origin |
| cache fan-out | per object | per object | per *withheld set*, not per principal |

Two notes on the last three rows.

`should_bypass_cache()` (`route_handler.rs:83`) already skips shared caches for
any ranged or `HEAD` forward, with a doc comment about a `206` poisoning a
full-object entry. That instinct is right and it is not sufficient for a
rewritten view: two principals with *different* withheld sets produce different
bytes at the same URL and the same `Range`. `Rewrite::etag` is deliberately
keyed on the withheld set rather than the principal, so principals with equal
entitlements collapse onto one entry — but the cache key has to include it.

The cold-start plan cost lands on every isolate, and multistore's caching
document is explicit that a deploy cools the whole fleet at once. A plan is
pure and derived from the footer, so it caches like the credential cache does;
but it is per `(object, withheld-set)`, which is a larger key space than
`(role)`.

---

## 6. Recommended order

1. **Stop forwarding the client's `Range`** (`proxy.rs:916`) and send a
   canonical one. One line, correct on its own merits, and it closes the §14.2
   bypass before anything depends on it.
2. **Call `origin::verify` in each runtime's `forward`.** Also correct on its
   own merits: today a backend that ignores a range is relayed unexamined.
3. **Set `If-Match` from the ETag the index was built from.** The header is
   already plumbed.
4. **Add the response transform** to `HandlerAction`. This is the decision —
   everything above is worth doing regardless, and nothing that actually works
   for clients can ship without it.
5. **Then** the policy middleware, `refuse` first because it needs no transform,
   and `rewrite`/`sparsify` behind it.

Steps 1–3 are small, independently valuable, and do not commit multistore to
this design at all. Step 4 is the commitment.

---

## 7. What this does not answer

- **No code here has ever spoken to an origin.** `examples/gate.rs` serves from
  a `std::fs::File`; there is no HTTP client in `src/` or `examples/`.
  `src/origin.rs` states the response rule and tests it against a real
  misbehaving server, but the *fetch* side is untested against S3 itself:
  requester-pays, SSE-C, `x-amz-checksum-mode`, and multipart ETags are all
  unexercised.
- **Only `bytes=` is parsed.** `src/range.rs` handles the `Range` header.
  `GetObject?partNumber=N` addresses a part rather than a byte range, and
  `UploadPartCopy`'s `x-amz-copy-source-range` is a range on a different
  header entirely. Both reach object bytes without passing the parser. Neither
  is refused today because neither is recognized.
- **Nothing here measures multistore.** No benchmark, no deployment, no
  Worker. The costs in §5 are this repo's measurements plus multistore's
  documented behaviour, not an integration that was built and timed.
