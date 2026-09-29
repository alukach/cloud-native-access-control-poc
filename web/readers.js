// The readers feature 2 queries with.
//
// Every one of these is unmodified and knows nothing about this project. They
// are handed an ordinary URL and they fetch it; the service worker decides what
// comes back. That is the whole reason the gate lives in a worker rather than
// in a wrapper around each reader's I/O: a reader that had to cooperate would
// prove nothing about readers that will not.
//
// Adding one is adding an entry here. It needs `formats`, a `ui` the page knows
// how to draw, and a `run` that takes a URL and returns something renderable.
// Nothing else in the page changes.

/** Loaded lazily and once: duckdb-wasm is ~30 MB and most visits never query. */
let duckdbPromise = null;

async function duckdbConnection(onProgress) {
  if (!duckdbPromise) {
    duckdbPromise = (async () => {
      onProgress?.('fetching duckdb-wasm…');
      const duckdb = await import('https://cdn.jsdelivr.net/npm/@duckdb/duckdb-wasm@1.29.0/+esm');
      const bundle = await duckdb.selectBundle(duckdb.getJsDelivrBundles());
      onProgress?.('starting the engine…');
      // `createWorker` fetches the script and starts a blob-URL worker. A blob
      // worker inherits its creator's service worker, which is why DuckDB's own
      // HTTP layer -- running in that worker, not on this thread -- still comes
      // through the gate. Verified, and the single load-bearing assumption of
      // this whole design.
      const worker = await duckdb.createWorker(bundle.mainWorker);
      const db = new duckdb.AsyncDuckDB(new duckdb.VoidLogger(), worker);
      await db.instantiate(bundle.mainModule, bundle.pthreadWorker);
      return db.connect();
    })().catch((err) => {
      duckdbPromise = null;
      throw err;
    });
  }
  return duckdbPromise;
}

/** Arrow values that `JSON.stringify` refuses, made printable. */
function plainValue(value) {
  if (typeof value === 'bigint') return Number(value);
  if (value === null || value === undefined) return null;
  if (value instanceof Date) return value.toISOString();
  if (typeof value === 'object' && typeof value.toString === 'function') return value.toString();
  return value;
}

export const READERS = [
  {
    id: 'duckdb',
    name: 'DuckDB',
    how: 'SQL, via duckdb-wasm',
    formats: ['parquet'],
    ui: 'sql',
    note: 'The engine most people actually use, and the hardest case: it reads in '
      + 'fixed 64 KiB blocks and cannot be configured out of it, so every one of its '
      + 'content reads crosses a chunk it never asked for.',
    defaultQuery: (table) =>
      `SELECT payment_type,\n       count(*) AS trips,\n       round(avg(trip_distance), 3) AS avg_miles\nFROM ${table}\nGROUP BY 1\nORDER BY 1;`,
    table: (url) => `read_parquet('${url}')`,
    async run({ url, query, onProgress }) {
      const conn = await duckdbConnection(onProgress);
      onProgress?.('running the query…');
      const result = await conn.query(query.replace(/\{table\}/g, `read_parquet('${url}')`));
      const columns = result.schema.fields.map((f) => f.name);
      const rows = result.toArray().slice(0, 200).map((row) => {
        const object = typeof row.toJSON === 'function' ? row.toJSON() : row;
        return columns.map((c) => plainValue(object[c]));
      });
      return { kind: 'table', columns, rows, total: result.numRows };
    },
    /** What the file's own schema looks like from the reader's side. */
    async describe({ url }) {
      const conn = await duckdbConnection();
      const result = await conn.query(`DESCRIBE SELECT * FROM read_parquet('${url}')`);
      return result.toArray().map((r) => {
        const o = typeof r.toJSON === 'function' ? r.toJSON() : r;
        return { name: String(o.column_name), type: String(o.column_type) };
      });
    },
  },
  {
    id: 'deck',
    name: 'Map view',
    how: 'deck.gl, tile by tile',
    formats: ['cog'],
    ui: 'deck',
    note: 'Pan and zoom. Every tile on screen is a separate range request through the '
      + 'gate, at whatever overview level the zoom calls for — so a policy that '
      + 'withholds a location has to withhold it at every level, and you can see '
      + 'immediately when it does not.',
    async mount(container, options) {
      const { mountMap } = await import('./map.js');
      return mountMap(container, options);
    },
  },
  {
    id: 'geotiff',
    name: 'geotiff.js',
    how: 'one read, whole level',
    formats: ['cog'],
    ui: 'map',
    note: 'Block-aligns its reads to 64 KiB unless told otherwise, which is the same '
      + 'shape GDAL /vsicurl has and cannot be talked out of.',
    async run({ url, level, onProgress }) {
      onProgress?.('opening the image…');
      const { fromUrl } = await import('https://cdn.jsdelivr.net/npm/geotiff@2.1.3/+esm');
      const tiff = await fromUrl(url);
      const count = await tiff.getImageCount();
      // Image 0 is full resolution; higher indices are progressively coarser.
      const index = Math.min(level, count - 1);
      const image = await tiff.getImage(index);
      onProgress?.(`decoding level ${index} (${image.getWidth()}×${image.getHeight()})…`);
      const width = image.getWidth();
      const height = image.getHeight();
      // Cap the decode: a full-resolution Sentinel granule is 11k x 11k and the
      // point is what arrives, not how long a browser takes to paint it.
      const scale = Math.min(1, Math.sqrt(1.5e6 / (width * height)));
      const rasters = await image.readRGB({
        width: Math.max(1, Math.round(width * scale)),
        height: Math.max(1, Math.round(height * scale)),
      });
      return {
        kind: 'image',
        width: rasters.width,
        height: rasters.height,
        pixels: rasters,
        level: index,
        levels: count,
        source: `${width}×${height}`,
      };
    },
  },
  // A column picker over hyparquet belongs here: `formats: ['parquet']`,
  // `ui: 'columns'`, and a `run` that calls `parquetRead` with the picked
  // columns. It needs nothing from the gate, because the gate serves bytes.
];

export const readersFor = (format) => READERS.filter((r) => r.formats.includes(format));
export const readerById = (id) => READERS.find((r) => r.id === id);
