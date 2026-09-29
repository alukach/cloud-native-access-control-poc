// What the page offers before you bring your own: two files, a handful of
// policies per format, and the ranges a real reader would actually ask for.

export const SAMPLES = [
  {
    id: 'paris',
    format: 'cog',
    name: 'Paris — landmarks',
    path: '../data/paris-landmarks.tif',
    blurb: 'IGN orthophoto at 0.4 m, 476 tiles of 153 m each. The Eiffel Tower and the '
      + 'Arc de Triomphe are unmistakable, which is the point: when a policy withholds '
      + 'them you can see exactly what left.',
    attribution: '© IGN — Licence Ouverte 2.0',
  },
  {
    id: 'nyc-taxi',
    format: 'parquet',
    name: 'NYC taxi trips',
    path: '../data/nyc-taxi-8rg.parquet',
    blurb: '400,000 rows, 19 columns, 8 row groups. Sized so a 64 KiB block spans '
      + 'more than one column chunk, which is where every interesting problem starts.',
  },
  {
    id: 's2-tci',
    format: 'cog',
    name: 'Sentinel-2 granule',
    path: '../data/s2-tci-512.tif',
    blurb: '5 MB, 6 overview levels, 655 tiles at 10 m. The licensing case rather than '
      + 'the redaction one: an area is granted, not withheld.',
  },
];

export const sampleById = (id) => SAMPLES.find((s) => s.id === id);

// ---- policies -------------------------------------------------------------

/**
 * One CQL2 expression from several branches.
 *
 * The parentheses are not decoration: `a OR b AND c` binds as `a OR (b AND c)`,
 * so joining raw strings would silently reassociate a rule.
 */
const doc = (rules) => rules.map((r) => `(${r})`).join('\n  OR ');

/** Without this, a reader cannot find the data it IS allowed to read. */
const STRUCTURE = "region.kind = 'metadata'";

/**
 * Guard each branch on `region.kind` first.
 *
 * A region carries only the properties its kind has — a tile has
 * `overview_level` and no `column`, a chunk the reverse — and naming one a
 * region lacks leaves the comparison unresolved, which denies. `AND`
 * short-circuits on a false kind check, so a guarded branch never reaches the
 * missing property. Every rule below is written that way.
 */

/**
 * A rule about the COLUMN, never about a region kind.
 *
 * A column owns `column_chunk`, `column_index` and `bloom_filter` regions and
 * a rule has to permit all three, because a column is withheld if any of its
 * regions is denied. Written as `region.kind = 'column_chunk' AND ...` it
 * withholds every column in the file while looking almost right under
 * refusal. Issue #26 is the same mistake from the other side.
 */
const withoutColumns = (columns) =>
  columns.map((c) => `region.column <> '${c}'`).join(' AND ');

/**
 * `S_CONTAINS(<area>, region.geom)`, never `S_INTERSECTS(region.geom, <area>)`.
 *
 * A tile is the unit of service, so an existential predicate grants every tile
 * the area *touches* — 49 where 25 were licensed on this scene, four of them on
 * edge contact with zero overlap. Containment is the monotone-safe spelling and
 * the areas below are snapped to the tile grid so it does not under-serve.
 */
const inside = (wkt) => `region.kind = 'tile' AND S_CONTAINS(${wkt}, region.geom)`;


/** Tile-grid aligned on data/s2-tci-512.tif: 5,120 m from (499980, 4200000). */
export const AREAS = [
  { id: 'coast', name: 'Coast and fields', tiles: '3 × 3', bbox: [520460, 4184640, 535820, 4200000] },
  { id: 'headland', name: 'Headland', tiles: '2 × 2', bbox: [520460, 4189760, 530700, 4200000] },
  { id: 'scene', name: 'The whole scene', tiles: 'all', bbox: [499980, 4090200, 609780, 4200000] },
];

const ring = ([x0, y0, x1, y1]) =>
  `POLYGON((${x0} ${y0},${x1} ${y0},${x1} ${y1},${x0} ${y1},${x0} ${y0}))`;

/**
 * Two landmarks, in the file's own CRS (EPSG:3857 metres).
 *
 * Boxes rather than outlines: a tile is served whole, so a polygon finer than
 * the tile grid buys nothing, and a box is something a reader of the policy
 * can check against a map.
 */
export const LANDMARKS = [
  {
    id: 'eiffel',
    name: 'Eiffel Tower',
    bbox: [255320, 6250770, 255525, 6250975],
  },
  {
    id: 'arc',
    name: 'Arc de Triomphe',
    bbox: [255350, 6253350, 255610, 6253600],
  },
];

/**
 * Withhold every tile that TOUCHES an area.
 *
 * The inverse of `inside`, and the inversion is the whole point. A tile is
 * served whole, so an area that GRANTS access must contain a tile entirely
 * before that tile is served, while an area that DENIES access must withhold
 * a tile that overlaps it at all. Both are the conservative direction; they
 * are opposite predicates.
 *
 * Measured on data/paris-landmarks.tif: `NOT S_INTERSECTS` withholds 21 tiles
 * for these two landmarks. Spelled `NOT S_CONTAINS(<area>, region.geom)` --
 * which reads like the same intent -- it withholds **nothing**, because no
 * 153 m tile sits wholly inside a 205 m box.
 */
const outside = (areas) =>
  areas.map((a) => `NOT S_INTERSECTS(region.geom, ${ring(a.bbox)})`).join('\n     AND ');

export const POLICIES = {
  paris: [
    {
      id: 'hide-landmarks',
      name: 'Hide the landmarks',
      blurb: 'Full resolution everywhere except over the Eiffel Tower and the Arc de '
        + 'Triomphe. Zoom in and they are gone; zoom out and the overviews still show '
        + 'them, coarsely — which the policy says out loud rather than hiding.',
      build: () => doc([
        STRUCTURE,
        'region.overview_level > 0',
        `region.overview_level = 0\n     AND ${outside(LANDMARKS)}`,
      ]),
    },
    {
      id: 'hide-everywhere',
      name: 'Hide them at every zoom',
      blurb: 'The honest version, and what it costs. Overviews average the level below, '
        + 'so hiding a location properly means hiding it in the coarse tiles too — and '
        + 'one level-5 tile covers the whole city.',
      build: () => doc([STRUCTURE, `region.kind = 'tile'\n     AND ${outside(LANDMARKS)}`]),
    },
    {
      id: 'wrong-predicate',
      name: 'The predicate written backwards',
      blurb: 'The same intent with S_CONTAINS instead of S_INTERSECTS. It reads correctly '
        + 'and it protects nothing at all: no 153 m tile fits inside a 205 m box, so every '
        + 'landmark tile is served.',
      build: () => doc([
        STRUCTURE,
        `region.kind = 'tile'\n     AND ${LANDMARKS.map((a) =>
          `NOT S_CONTAINS(${ring(a.bbox)}, region.geom)`).join('\n     AND ')}`,
      ]),
    },
    {
      id: 'open',
      name: 'Publish everything',
      blurb: 'The baseline. Nothing withheld, and the served file is byte-identical to '
        + 'the stored one.',
      build: () => doc([STRUCTURE, "region.kind = 'tile'"]),
    },
  ],
  parquet: [
    {
      id: 'withhold-fares',
      name: 'Withhold two columns',
      blurb: 'The ordinary case. Everything except fare_amount and tip_amount.',
      columns: ['fare_amount', 'tip_amount'],
      build: (ctx) => doc([STRUCTURE, withoutColumns(ctx.columns)]),
    },
    {
      id: 'open',
      name: 'Allow everything',
      blurb: 'The baseline. Every read succeeds, nothing is withheld, and the '
        + 'served file is byte-identical to the stored one.',
      build: () => doc([STRUCTURE, '1 = 1']),
    },
    {
      id: 'kind-not-column',
      name: 'The mistake worth seeing',
      blurb: 'Names a region KIND where it should name a column. Under refusal it '
        + 'looks nearly right; as a filtered view it withholds seventeen of '
        + 'nineteen columns, because nothing permits the page indexes.',
      columns: ['fare_amount', 'tip_amount'],
      build: (ctx) => doc([
        STRUCTURE,
        `region.kind = 'column_chunk' AND region.column NOT IN (${
          ctx.columns.map((c) => `'${c}'`).join(', ')})`,
      ]),
    },
    {
      id: 'no-structure',
      name: 'No metadata rule',
      blurb: 'Permits every column and no structure. Under refusal nothing loads — '
        + 'the reader cannot reach the footer. As a filtered view it is refused '
        + 'outright, because serving the footer anyway would hand out bytes the '
        + 'policy denied (issue #27).',
      build: () => doc(["region.kind IN ('column_chunk', 'column_index', 'bloom_filter', 'column_metadata')"]),
    },
  ],
  cog: [
    {
      id: 'licensed-area',
      name: 'Overviews public, full resolution licensed',
      blurb: 'The imagery licence. Anyone may browse the overviews; full resolution '
        + 'only inside the licensed area.',
      area: 'coast',
      build: (ctx) => doc([STRUCTURE, 'region.overview_level > 0', inside(ring(ctx.bbox))]),
    },
    {
      id: 'overviews-only',
      name: 'Overviews only',
      blurb: 'Browse resolution for everyone, full resolution for nobody.',
      build: () => doc([STRUCTURE, 'region.overview_level > 0']),
    },
    {
      id: 'open',
      name: 'Allow everything',
      blurb: 'The baseline.',
      build: () => doc([STRUCTURE, "region.kind = 'tile'"]),
    },
    {
      id: 'naive-overviews',
      name: 'Overviews only, written naively',
      blurb: 'One rule, exactly as you would first write it. It serves nothing: the '
        + 'IFDs and tag arrays that locate the tiles are metadata, and this '
        + 'permits neither.',
      build: () => doc(['region.overview_level > 0']),
    },
  ],
};

/**
 * The policies offered for a file.
 *
 * Keyed by sample first, because a spatial rule names coordinates in that
 * file's CRS and a polygon over Paris means nothing over a Sentinel granule.
 * A file loaded from a URL gets the format's generic set, which names no
 * coordinates at all.
 */
export const policiesFor = (format, sampleId) =>
  (sampleId && POLICIES[sampleId]) || POLICIES[format] || [];

export function buildPolicy(format, id, ctx = {}) {
  const available = policiesFor(format, ctx.sample);
  const preset = available.find((p) => p.id === id) || available[0];
  const area = AREAS.find((a) => a.id === (ctx.area || preset.area)) || AREAS[0];
  return {
    preset,
    text: preset.build({
      columns: ctx.columns || preset.columns || [],
      bbox: ctx.bbox || area.bbox,
    }),
  };
}

// ---- the ranges a reader actually asks for --------------------------------

/**
 * Suggested ranges, derived from the file's own layout.
 *
 * The point of feature 1 is that a byte range is opaque until something
 * resolves it, so the examples have to be ranges a reader would really issue —
 * a footer probe, one chunk, one tile, and the fixed-size block that a reader
 * widens those into. A hand-typed range demonstrates the resolver; these
 * demonstrate the problem.
 */
export function suggestedRanges(format, regions, size) {
  const out = [];
  const find = (fn) => regions.find(fn);
  const push = (label, why, start, end) => {
    if (!Number.isFinite(start) || !Number.isFinite(end) || end <= start) return;
    out.push({ label, why, start: Math.max(0, start), end: Math.min(size, end) });
  };

  if (format === 'parquet') {
    push(
      'The footer probe',
      'Every Parquet reader starts here: the last few KiB, to find the schema and '
      + 'where each column chunk lives. hyparquet asks for 8 KiB, DuckDB for less.',
      size - 8192, size,
    );
    const chunk = find((r) => r.kind === 'column_chunk');
    if (chunk) {
      push(
        `One column chunk — ${chunk.column}, row group ${chunk.row_group}`,
        'What a projecting reader asks for when it wants exactly this column of this '
        + 'row group. Chunk-exact: nothing else is in it.',
        chunk.start, chunk.end,
      );
      const block = Math.floor(chunk.start / 65536) * 65536;
      push(
        'The 64 KiB block that chunk falls in',
        'What duckdb-wasm and GDAL /vsicurl actually issue. Same intent, aligned '
        + 'outward to a fixed block — and now it covers whatever else lives nearby.',
        block, block + 65536,
      );
    }
    const bloom = find((r) => r.kind === 'bloom_filter');
    if (bloom) {
      push(
        `One bloom filter — ${bloom.column}`,
        'DuckDB reads these to skip row groups on an equality predicate. Withhold '
        + 'one for a column you permit and the query fails looking like corruption.',
        bloom.start, bloom.end,
      );
    }
  } else {
    const header = find((r) => r.kind === 'metadata' && r.start === 0);
    if (header) {
      push(
        'The header read',
        'The first thing any TIFF reader does: enough of the front of the file to '
        + 'walk the IFDs and find the tag arrays that locate every tile.',
        0, Math.max(header.end, 16384),
      );
    }
    const full = find((r) => r.kind === 'tile' && r.overview_level === 0);
    if (full) {
      push(
        `One full-resolution tile — (${full.x}, ${full.y})`,
        'Tile-exact, including the 4-byte GDAL leader and trailer that sit either '
        + 'side of the payload. Miss those and every legitimate tile read is denied.',
        full.start, full.end,
      );
      const block = Math.floor(full.start / 65536) * 65536;
      push(
        'The 64 KiB block that tile falls in',
        'geotiff.js block-aligns to 64 KiB unless told otherwise, and GDAL /vsicurl '
        + 'cannot be told otherwise at all.',
        block, block + 65536,
      );
    }
    const overview = find((r) => r.kind === 'tile' && r.overview_level >= 2);
    if (overview) {
      push(
        `One overview tile — level ${overview.overview_level}`,
        'The coarse pyramid. A licence that serves overviews to everyone is serving '
        + 'these, and they still show the ground the full-resolution rule withholds.',
        overview.start, overview.end,
      );
    }
  }
  return out;
}
