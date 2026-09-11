// The measurement machinery: build a layout index over HTTP, put the policy
// in front of each reader's own range seam, and count what happens.
//
// Nothing here decides anything. Every verdict is `LayoutIndex.check`, which
// is the same Rust function a gateway would call.

import init, { LayoutIndex, Policy, queryables, version } from './pkg/cnac.js';
import { parquetRead } from 'https://cdn.jsdelivr.net/npm/hyparquet@1.30.0/+esm';
import { GeoTIFF } from 'https://cdn.jsdelivr.net/npm/geotiff@2.1.3/+esm';
import { BlockedSource } from 'https://cdn.jsdelivr.net/npm/geotiff@2.1.3/dist-module/source/blockedsource.js/+esm';

export { LayoutIndex, Policy, queryables, version };

/** geotiff.js's own default, and the reason its reads are not tile-aligned. */
export const BLOCK_SIZE = 65536;

/** hyparquet defaults to a 512 KB tail, which straddles the last row group. */
export const FOOTER_FETCH = 8192;

export async function ready() {
  await init();
}

// ---- HTTP ----------------------------------------------------------------

/**
 * One range request. `end` is exclusive.
 *
 * A CDN that has never seen the object answers the first request with `200`
 * and the whole body; ranges only work once it is cached. That is the CDN, not
 * the reader, so it is reported separately rather than counted as bytes the
 * reader asked for.
 */
async function fetchRange(url, start, end) {
  // `no-store` keeps the browser from revalidating a range it already holds.
  // A `304` carries no body, and a counter that silently reuses a cached slice
  // is not counting range requests any more.
  const res = await fetch(url, {
    cache: 'no-store',
    headers: { Range: `bytes=${start}-${end - 1}` },
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText} for bytes=${start}-${end - 1}`);
  const body = await res.arrayBuffer();
  if (res.status === 200 && body.byteLength > end - start) {
    return { bytes: body.slice(start, end), fullBody: true, transferred: body.byteLength };
  }
  return { bytes: body, fullBody: false, transferred: body.byteLength };
}

/**
 * Size the object and prove the host really does ranges.
 *
 * The one-byte GET is not only a check. A CDN that has never seen the object
 * answers the first request with the whole body and only serves ranges once it
 * is cached, so this is also the warm-up that keeps that first `200` out of
 * the counters the page is about to report.
 */
export async function probe(url) {
  const head = await fetch(url, { method: 'HEAD' });
  if (!head.ok) throw new Error(`${head.status} ${head.statusText} for ${url}`);
  const size = Number(head.headers.get('content-length'));
  if (!Number.isFinite(size) || size <= 0) throw new Error(`no content-length for ${url}`);

  const probeRes = await fetch(url, { cache: 'no-store', headers: { Range: 'bytes=0-0' } });
  const body = await probeRes.arrayBuffer();
  return {
    size,
    rangeStatus: probeRes.status,
    servedWhole: body.byteLength > 1,
    contentEncoding: head.headers.get('content-encoding') || 'identity',
  };
}

// ---- Index ---------------------------------------------------------------

/**
 * Build a layout index by reading speculatively from the end the format wants.
 *
 * `LayoutIndex.build` reports a `needed` on a short read, but for a COG that
 * number is the next structure the IFD walk could not reach, not the total --
 * following it literally converges one structure at a time. It is treated as a
 * floor under a doubling window instead, which reaches this file's 8,264 bytes
 * on the first try.
 */
export async function buildIndex(format, url, size, log = () => {}) {
  const suffix = format === 'parquet';
  let want = 16384;
  for (let attempt = 0; attempt < 24; attempt += 1) {
    const span = Math.min(want, size);
    const [start, end] = suffix ? [size - span, size] : [0, span];
    const { bytes, fullBody } = await fetchRange(url, start, end);
    log({ start, end, span, attempt, fullBody });
    try {
      return { index: LayoutIndex.build(format, new Uint8Array(bytes), size), window: span };
    } catch (err) {
      const needed = Number(err?.needed);
      if (!Number.isFinite(needed) || needed <= 0) throw err;
      if (span >= size) throw err;
      want = Math.max(needed, want * 2);
    }
  }
  throw new Error('layout index did not converge');
}

// ---- The gate ------------------------------------------------------------

const deny = (message) => Object.assign(new Error(message), { cnacDeny: true });

/**
 * Wrap an index, a policy and a principal in the decision point both readers
 * are made to call. Everything the counters report is collected here.
 */
export function makeGate({ index, policy, user, url, labels, onRequest }) {
  const state = {
    issued: 0,
    straddling: 0,
    denied: 0,
    bytes: 0,
    fullBodies: 0,
    transferred: 0,
    checkMs: 0,
    log: [],
  };

  state.read = async (start, end) => {
    const stop = Math.min(end, index.size);
    state.issued += 1;
    const t0 = performance.now();
    const result = index.check(policy, user, start, stop);
    const verdict = {
      allowed: result.allowed,
      reason: result.reason,
      straddles: result.straddles,
      permitted: result.permitted,
      denied: result.denied,
      regions: Array.from(result.regions),
    };
    result.free();
    state.checkMs += performance.now() - t0;
    if (verdict.straddles) state.straddling += 1;

    const entry = {
      n: state.issued,
      start,
      end: stop,
      length: stop - start,
      ...verdict,
      label: labels(verdict.regions),
    };
    state.log.push(entry);
    onRequest?.(entry);

    if (!verdict.allowed) {
      state.denied += 1;
      throw deny(
        verdict.reason === 'bad_range'
          ? `Refused bytes=${start}-${stop - 1}: the range did not parse.`
          : `Refused bytes=${start}-${stop - 1}: ${verdict.denied} of ${verdict.regions.length} regions are not permitted.`,
      );
    }

    const { bytes, fullBody, transferred } = await fetchRange(url, start, stop);
    state.bytes += stop - start;
    state.transferred += transferred;
    if (fullBody) {
      state.fullBodies += 1;
      entry.fullBody = true;
    }
    return bytes;
  };

  return state;
}

// ---- Parquet -------------------------------------------------------------

/**
 * Run a projection query through hyparquet.
 *
 * `aligned` is the whole comparison. hyparquet coalesces column chunks into
 * runs of up to 2 MB unless it is given a column list, at which point it
 * issues one exact fetch per column chunk -- and with ~1 MB row groups, that
 * is the difference between eight fetches that each span all nineteen columns
 * and one fetch per chunk.
 */
export async function runParquet({ gate, size, columns, aligned }) {
  const file = {
    byteLength: size,
    slice: (start, end = size) => gate.read(start, end),
  };
  let rows = 0;
  const sample = new Map();
  await parquetRead({
    file,
    initialFetchSize: FOOTER_FETCH,
    columns: aligned ? columns : undefined,
    onChunk: ({ columnName, columnData }) => {
      if (columnName === columns[0]) rows += columnData.length;
      if (!sample.has(columnName)) {
        sample.set(columnName, Array.from(columnData.slice(0, 4)));
      }
    },
  });
  return { rows, sample };
}

// ---- COG -----------------------------------------------------------------

/** The policy in the seat geotiff.js reserves for its HTTP source. */
class PolicySource {
  constructor(gate, size, wrapped) {
    this.gate = gate;
    this.size = size;
    // `BlockedSource` expects the RemoteSource contract, `{data, offset,
    // length}`; GeoTIFF itself expects the BaseSource contract, a bare
    // ArrayBuffer. The wrapper is the only thing that translates between them.
    this.wrapped = wrapped;
  }

  get fileSize() {
    return this.size;
  }

  async close() {}

  async fetch(slices) {
    return Promise.all(
      slices.map(async ({ offset, length }) => {
        const end = Math.min(offset + length, this.size);
        const data = await this.gate.read(offset, end);
        return this.wrapped ? { data, offset, length: data.byteLength } : data;
      }),
    );
  }
}

/** Pixel window on `image` covering a map-coordinate box of the base image. */
export function windowFor(image, base, bbox) {
  const extent = base.getBoundingBox();
  const w = image.getWidth();
  const h = image.getHeight();
  const sx = w / (extent[2] - extent[0]);
  const sy = h / (extent[3] - extent[1]);
  const x0 = Math.max(0, Math.floor((bbox[0] - extent[0]) * sx));
  const x1 = Math.min(w, Math.ceil((bbox[2] - extent[0]) * sx));
  const y0 = Math.max(0, Math.floor((extent[3] - bbox[3]) * sy));
  const y1 = Math.min(h, Math.ceil((extent[3] - bbox[1]) * sy));
  return [x0, y0, Math.max(x1, x0 + 1), Math.max(y1, y0 + 1)];
}

/**
 * Read one window of one overview level through geotiff.js.
 *
 * `aligned` swaps the 64 KB blocking layer out. It is the same layer
 * `fromUrl` installs by default, wrapped around the policy source instead of
 * around an HTTP source, so both positions of the toggle read the file the way
 * the library really would.
 */
export async function runCog({ gate, size, level, bbox, aligned, maxPixels = Infinity }) {
  const source = aligned
    ? new PolicySource(gate, size, false)
    : new BlockedSource(new PolicySource(gate, size, true), { blockSize: BLOCK_SIZE });

  const tiff = await GeoTIFF.fromSource(source);
  const base = await tiff.getImage(0);
  const image = level === 0 ? base : await tiff.getImage(level);
  const win = windowFor(image, base, bbox);
  const width = win[2] - win[0];
  const height = win[3] - win[1];
  if (width * height > maxPixels) {
    throw new Error(
      `That area is ${(width * height / 1e6).toFixed(1)} megapixels at level ${level}. Choose a coarser overview level or a smaller area.`,
    );
  }
  const rasters = await image.readRasters({ window: win, interleave: true });
  return {
    width,
    height,
    samples: image.getSamplesPerPixel(),
    // This file is JPEG-compressed with photometric 6, and geotiff.js hands
    // back the samples as stored -- YCbCr, not RGB. Painting them straight to
    // a canvas gives a flat teal square.
    ycbcr: image.fileDirectory.PhotometricInterpretation === 6,
    tileSize: [image.getTileWidth(), image.getTileHeight()],
    imageSize: [image.getWidth(), image.getHeight()],
    rasters,
  };
}
