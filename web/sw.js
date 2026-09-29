// The gate, as a service worker.
//
// This is the part of the demo that is not a visualization. A service worker
// sees every request a page in its scope makes, before the network, and may
// answer it with bytes of its own. So instead of wrapping each reader's own
// I/O seam -- which is reader-specific, and which a reader is free to route
// around -- the policy sits where a gateway sits: in front of the object.
//
// Readers run completely unmodified. hyparquet, geotiff.js and duckdb-wasm all
// just fetch, and what comes back is what a gateway applying this policy would
// have sent. That is the only honest way to claim interoperability.
//
// # The gate URL
//
// A reader is pointed at `./gate/<id>` on this origin, never at the object.
// Two reasons, and the second is the practical one:
//
//  1. It makes the indirection visible. The bytes at that URL are a *view*,
//     and nothing about the URL suggests otherwise.
//  2. CORS stops being the reader's problem. A cross-origin Parquet needs
//     `Access-Control-Allow-Origin`, an `OPTIONS` answer allowing `Range`, and
//     `Content-Range` exposed -- and most buckets fail at the preflight. Only
//     this worker talks to the origin now, so there is one place that can
//     fail and one message to write about it.
//
// # What it does NOT do
//
// It is not an access gate. The object is still public and still reachable
// with curl. This enforces a policy over a representation; it does not keep a
// determined client away from the bytes.

import init, { LayoutIndex, Policy } from './pkg/cnac.js';

/**
 * Configured gates, by id.
 *
 * In memory only, and a service worker is terminated whenever the browser
 * decides it has been idle -- about thirty seconds of no fetches. Everything
 * here is derived from the config, so the config is what gets persisted, and a
 * request for a gate this worker has never heard of rebuilds it from that
 * rather than failing. Without this the demo works until you stop touching it
 * and then every tile 503s, which looks exactly like the policy breaking.
 */
const gates = new Map();

/** Where the configs outlive the worker. */
const STORE = 'cnac-gate-configs-v1';
const configKey = (id) => new Request(`/__cnac_gate_config__/${id}`);

async function rememberConfig(id, config) {
  const cache = await caches.open(STORE);
  await cache.put(configKey(id), new Response(JSON.stringify(config)));
}

async function forgetConfig(id) {
  const cache = await caches.open(STORE);
  await cache.delete(configKey(id));
}

async function recallConfig(id) {
  const cache = await caches.open(STORE);
  const stored = await cache.match(configKey(id));
  return stored ? stored.json() : null;
}

let wasm = null;
const ready = () => (wasm ??= init());

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (event) => event.waitUntil(self.clients.claim()));

self.addEventListener('message', (event) => {
  const { type, id } = event.data || {};
  if (type === 'configure') {
    event.waitUntil(configure(event));
  } else if (type === 'resolve') {
    event.waitUntil(resolve(event));
  } else if (type === 'release') {
    dispose(gates.get(id));
    gates.delete(id);
    event.waitUntil(forgetConfig(id));
  } else if (type === 'ping') {
    event.source?.postMessage({ type: 'pong', ready: true });
  }
});

function dispose(gate) {
  gate?.filtered?.free?.();
  gate?.index?.free?.();
  gate?.policy?.free?.();
}

/**
 * Build everything one gate needs, and report either its shape or why not.
 *
 * Done here rather than in the page so the worker owns its own state: a
 * service worker is restarted whenever the browser feels like it, and a gate
 * that depended on page-side handles would answer the next request with
 * nothing.
 */
async function configure(event) {
  const { id, url, format, policy, user, mode } = event.data;
  const config = { url, format, policy, user, mode };
  await ready();
  dispose(gates.get(id));

  const reply = (message) => event.source?.postMessage({ id, ...message });
  try {
    const gate = await build(config);
    gates.set(id, gate);
    await rememberConfig(id, config);
    reply({
      type: 'configured',
      size: gate.size,
      window: gate.window,
      regionCount: gate.index.regionCount,
      regions: gate.index.regions(),
      virtualSize: gate.filtered ? gate.filtered.virtualSize : gate.size,
      withheld: gate.filtered ? gate.filtered.withheld : null,
      scrub: gate.filtered ? Array.from(gate.filtered.scrub) : [],
      etag: gate.filtered ? gate.filtered.etag : null,
      planError: gate.planError,
    });
  } catch (err) {
    reply({ type: 'failed', message: err?.message || String(err) });
  }
}

/** Everything a gate needs, from nothing but its config. */
async function build(config) {
  const { url, format, policy, user, mode } = config;
  await ready();
  const size = await objectSize(url);
  const { index, window } = await buildIndex(format, url, size);
  const loaded = new Policy(policy);

  let filtered = null;
  let planError = null;
  if (mode === 'filter') {
    try {
      filtered = index.plan(loaded, user);
    } catch (err) {
      // Issue #27: a policy this mode cannot express. Not a failure to hide
      // -- it is the most instructive thing the gate can say.
      planError = err?.message || String(err);
    }
  }
  return { url, format, size, window, index, policy: loaded, user, mode, filtered, planError };
}

/** The gate for `id`, rebuilt from its stored config if this worker restarted. */
async function gateFor(id) {
  const live = gates.get(id);
  if (live) return live;
  const config = await recallConfig(id);
  if (!config) return null;
  const rebuilt = await build(config);
  gates.set(id, rebuilt);
  return rebuilt;
}

/**
 * Answer "what is in this range?" without fetching anything.
 *
 * This is the resolver on its own, which is feature 1: no policy, no verdict,
 * just the regions the range covers. It runs here rather than in the page so
 * there is one wasm instance and one implementation of the overlap — a page
 * that did the interval arithmetic itself would be a second resolver, and the
 * second one is the one nobody audits.
 */
async function resolve(event) {
  const { id, start, end } = event.data;
  const reply = (message) => event.source?.postMessage({ id, ...message });
  try {
    const gate = await gateFor(id);
    if (!gate) {
      reply({ type: 'failed', message: 'this gate is not configured' });
      return;
    }
    const result = gate.index.check(gate.policy, gate.user, start, end);
    const payload = {
      type: 'resolved',
      start,
      end,
      allowed: result.allowed,
      reason: result.reason,
      straddles: result.straddles,
      permitted: result.permitted,
      denied: result.denied,
      regions: Array.from(result.regions),
    };
    result.free();
    reply(payload);
  } catch (err) {
    reply({ type: 'failed', message: err?.message || String(err) });
  }
}

/** The object's length, from a one-byte range probe. */
async function objectSize(url) {
  const res = await fetch(url, { headers: { Range: 'bytes=0-0' } });
  if (!res.ok) throw new Error(`the origin answered ${res.status} for ${url}`);
  const range = res.headers.get('content-range');
  const total = range && Number(range.split('/')[1]);
  if (Number.isFinite(total) && total > 0) return total;
  // No `Content-Range` means the range was ignored -- RFC 9110 §14.2 -- and
  // the body is the whole object. Its length is the answer, and the caller is
  // told separately that this host does not do ranges.
  const body = await res.arrayBuffer();
  if (body.byteLength > 1) throw new Error(
    `${url} ignored the Range header and returned all ${body.byteLength} bytes. `
    + 'A host that does not implement ranges cannot be gated by one.',
  );
  const length = Number(res.headers.get('content-length'));
  if (Number.isFinite(length) && length > 0) return length;
  throw new Error(`could not determine the size of ${url}`);
}

/** Read from the end the format wants, widening until the metadata fits. */
async function buildIndex(format, url, size) {
  const suffix = format === 'parquet';
  let want = 16384;
  for (let attempt = 0; attempt < 24; attempt += 1) {
    const span = Math.min(want, size);
    const [start, end] = suffix ? [size - span, size] : [0, span];
    const bytes = await originRange(url, start, end);
    try {
      return { index: LayoutIndex.build(format, bytes, size), window: span };
    } catch (err) {
      const needed = Number(err?.needed);
      if (!Number.isFinite(needed) || needed <= 0 || span >= size) throw err;
      want = Math.max(needed, want * 2);
    }
  }
  throw new Error('the layout index did not converge');
}

/** One range from the real object. `end` is exclusive. */
async function originRange(url, start, end) {
  if (end <= start) return new Uint8Array(0);
  const res = await fetch(url, {
    cache: 'no-store',
    headers: { Range: `bytes=${start}-${end - 1}` },
  });
  if (!res.ok) throw new Error(`the origin answered ${res.status}`);
  const body = new Uint8Array(await res.arrayBuffer());
  // The §14.2 case again, mid-stream this time: a host that answered 206 for
  // the probe and 200 here has changed behaviour, and the bytes in hand are
  // not the bytes asked for.
  if (res.status === 200 && body.byteLength > end - start) {
    return body.slice(start, end);
  }
  return body;
}

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);
  const match = /\/gate\/([^/]+)/.exec(url.pathname);
  if (!match) return;
  event.respondWith(serve(match[1], event.request));
});

/** RFC 9110 §14.4, and no more of it than a reader actually sends. */
function parseRange(header, size) {
  if (!header) return null;
  const m = /^bytes=(\d*)-(\d*)$/.exec(header);
  if (!m) return 'unparseable';
  const [, first, last] = m;
  if (first === '' && last === '') return 'unparseable';
  if (first === '') {
    const span = Number(last);
    if (!span) return 'unsatisfiable';
    return [Math.max(0, size - span), size];
  }
  const start = Number(first);
  if (start >= size) return 'unsatisfiable';
  const end = last === '' ? size : Math.min(Number(last) + 1, size);
  if (end <= start) return 'unsatisfiable';
  return [start, end];
}

const plain = (status, body, headers = {}) =>
  new Response(body, { status, headers: { 'content-type': 'text/plain', ...headers } });

async function serve(id, request) {
  let gate;
  try {
    gate = await gateFor(id);
  } catch (err) {
    return plain(502, `The gate could not be rebuilt: ${err?.message || err}`);
  }
  if (!gate) return plain(503, 'This gate is not configured. Reload the page.');

  const filtering = gate.mode === 'filter' && gate.filtered;
  if (gate.mode === 'filter' && !gate.filtered) {
    return plain(409, 'The policy cannot be served as a filtered view.');
  }
  const size = filtering ? gate.filtered.virtualSize : gate.size;

  const base = {
    'accept-ranges': 'bytes',
    'cache-control': 'no-store',
    ...(filtering ? { etag: gate.filtered.etag } : {}),
  };

  if (request.method === 'HEAD') {
    return new Response(null, {
      status: 200,
      headers: { ...base, 'content-length': String(size) },
    });
  }
  if (request.method !== 'GET') return plain(405, 'Only GET and HEAD.');

  const header = request.headers.get('range');
  const parsed = parseRange(header, size);
  if (parsed === 'unparseable') {
    // Never fall back to 200 with the whole object. That is the §14.2
    // behaviour this project exists to warn about, and a gate that does it
    // has authorized a slice and delivered everything.
    return plain(400, `Unparseable Range: ${header}`);
  }
  if (parsed === 'unsatisfiable') {
    return plain(416, 'Range not satisfiable', { 'content-range': `bytes */${size}` });
  }
  const [start, end] = parsed || [0, size];

  try {
    const body = filtering
      ? await servedView(gate, start, end)
      : await gatedOriginal(gate, start, end, header);
    if (body instanceof Response) return body;
    const headers = { ...base, 'content-length': String(body.byteLength) };
    if (parsed) headers['content-range'] = `bytes ${start}-${end - 1}/${size}`;
    return new Response(body, { status: parsed ? 206 : 200, headers });
  } catch (err) {
    return plain(502, `The origin could not be read: ${err?.message || err}`);
  }
}

/** Filter mode: assemble the view, fetching only what it needs. */
async function servedView(gate, start, end) {
  const [lo, hi] = gate.filtered.originRange(start, end);
  const origin = await originRange(gate.url, lo, hi);
  return gate.filtered.serve(start, end, origin);
}

/**
 * Refuse mode: the decision is `check`, and a denial is a real 403.
 *
 * The canonical range from the check is what gets fetched, never the client's
 * header -- the first of `Decision::Authorized`'s obligations, and the one a
 * proxy is most likely to skip.
 */
async function gatedOriginal(gate, start, end, header) {
  const result = gate.index.check(gate.policy, gate.user, start, end);
  const allowed = result.allowed;
  const reason = result.reason;
  const canonical = allowed ? [result.start, result.end] : null;
  result.free();

  if (!allowed) {
    // No region detail crosses this boundary. A 403 that echoed the resolved
    // regions would hand back the withheld column's name and byte extent.
    return plain(403, `Refused ${header || 'the whole object'}: ${reason}`, {
      'x-cnac-reason': reason,
    });
  }
  return await originRange(gate.url, canonical[0], canonical[1]);
}
