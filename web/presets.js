// Seed content for the policy editor: the rules, the principal and the AOI
// polygons the demo pastes into them.
//
// Every polygon here is in EPSG:32610 -- the CRS of `data/s2-tci-512.tif` --
// because cql2's spatial operators compare coordinates, not coordinate
// systems. A WGS84 polygon against a UTM tile is not an error, it is an empty
// intersection, which is the quietest way to write a rule that denies
// everything.
//
// Every polygon is also SNAPPED OUTWARD to the level-0 tile grid, and the
// spatial rule is written `S_CONTAINS(<area>, region.geom)`. Both halves of
// that matter and they are one decision:
//
// A tile is the unit of service -- a qualifying tile is served entire -- so
// `S_INTERSECTS(region.geom, <area>)` grants every tile the area *touches*,
// including tiles whose contact is one shared edge and whose interior overlap
// is zero. On the sample scene that is 49 tiles where 25 were drawn.
// `S_CONTAINS` grants only tiles wholly inside the area, which is fail-closed
// but silently serves nothing for an area smaller than one tile.
//
// Snapping outward first makes the two agree, and that is the point: the same
// tiles go out either way, but now the polygon in the policy document states
// the ground being served instead of the predicate quietly widening it. The
// over-grant is not removed -- it is moved somewhere a licensor can read it.

/** The COG's full extent, from its own tile bboxes. */
export const SCENE_EXTENT = [499980, 4090200, 609780, 4200000];

const ring = ([x0, y0, x1, y1]) =>
  `POLYGON((${x0} ${y0},${x1} ${y0},${x1} ${y1},${x0} ${y1},${x0} ${y0}))`;

// Both land areas sit in the northwest corner, which is where this granule
// actually has terrain -- it is a swath-edge scene, mostly ocean and cloud.
// They are chosen for size, not for looks: a full-resolution tile here is
// 5,120 m across (512 px x 10 m), so a 64 KB block spans several of them and
// reaches outside any licence drawn at this scale.
//
// The bboxes are tile-grid aligned: 5,120 m from the scene origin
// (499980, 4200000), northing descending. Verified against the file by
// `s_intersects_grants_tiles_outside_the_area_and_s_contains_does_not` in
// src/cog.rs, which measures the same grid.
export const AOIS = [
  {
    id: 'coast',
    name: 'Coast and fields',
    note: '15 km of coastline and cultivated land: nine tiles at full resolution, in a 3 × 3 block. One tile is 5,120 m across, so a 64 KB block covers a run of them and crosses the boundary on every side.',
    bbox: [520460, 4184640, 535820, 4200000],
  },
  {
    id: 'headland',
    name: 'Headland',
    note: '10 km over the headland: four tiles, in a 2 × 2 block. Two thirds the width for the same fixed block size, so the reader overshoots the licence proportionally further.',
    bbox: [520460, 4189760, 530700, 4200000],
  },
  {
    id: 'scene',
    name: 'Whole scene',
    note: 'Licensing the entire image. Every tile is inside the area, so nothing straddles and the only limit left is how much a browser will decode at once.',
    bbox: SCENE_EXTENT,
  },
];

/**
 * Widen `bbox` to the union of the level-0 tiles it meets.
 *
 * `S_CONTAINS` serves a tile only if the area covers all of it, so an area
 * drawn without regard to the grid under-serves at every edge -- and for an
 * area narrower than one tile, serves nothing. Snapping outward restores the
 * tiles the drawn area touched, at the cost of naming more ground in the
 * policy. That cost is the honest one: it is ground the reader receives.
 *
 * Returns `bbox` unchanged when no tile meets it, which keeps a deny-all area
 * denying rather than silently growing to the whole scene.
 */
export function snapToTiles(bbox, tileBoxes) {
  const [x0, y0, x1, y1] = bbox;
  const met = tileBoxes.filter((b) => {
    const [tx0, ty0, tx1, ty1] = [
      Math.min(b[0], b[2]), Math.min(b[1], b[3]),
      Math.max(b[0], b[2]), Math.max(b[1], b[3]),
    ];
    // Strict overlap, not mere contact: a tile sharing only an edge with the
    // drawn area is exactly the tile `S_INTERSECTS` over-grants, and pulling
    // it in here would reintroduce that by the back door.
    return tx1 > x0 && tx0 < x1 && ty1 > y0 && ty0 < y1;
  });
  if (!met.length) return bbox;
  return [
    Math.min(...met.map((b) => Math.min(b[0], b[2]))),
    Math.min(...met.map((b) => Math.min(b[1], b[3]))),
    Math.max(...met.map((b) => Math.max(b[0], b[2]))),
    Math.max(...met.map((b) => Math.max(b[1], b[3]))),
  ];
}

export const aoiWkt = (aoi) => ring(aoi.bbox);

/**
 * The same three licensed areas over somebody else's image.
 *
 * The bundled polygons are hand-placed over the land in one Sentinel granule,
 * in that granule's CRS. A file loaded from a URL has neither, so the areas
 * are re-cut as fractions of its own extent: a licence covering a tenth of the
 * scene by side, a twentieth, and all of it. Same shapes, same lesson, no
 * assumption about where anything is.
 */
export function aoisFor(extent, tileBoxes = []) {
  const [x0, y0, x1, y1] = extent;
  const cx = (x0 + x1) / 2;
  const cy = (y0 + y1) / 2;
  const box = (fraction) => {
    const w = ((x1 - x0) * fraction) / 2;
    const h = ((y1 - y0) * fraction) / 2;
    // Snapped for the same reason the bundled areas are, and more urgently: a
    // twentieth of a 22-tile scene is one tile wide, so an unsnapped area
    // under `S_CONTAINS` would routinely license nothing at all.
    return snapToTiles([cx - w, cy - h, cx + w, cy + h], tileBoxes);
  };
  return [
    {
      id: 'coast',
      name: 'Middle tenth',
      note: 'A licence over the centre tenth of this image, by side. Whatever the reader blocks its reads into, that block is fixed and this boundary is not, so the two disagree at the edges.',
      bbox: box(0.1),
    },
    {
      id: 'headland',
      name: 'Middle twentieth',
      note: 'Half the width for the same fixed block size, so the reader overshoots the licence proportionally further.',
      bbox: box(0.05),
    },
    {
      id: 'scene',
      name: 'Whole scene',
      note: 'Licensing the entire image. Every tile is inside the area, so nothing straddles and the only limit left is how much a browser will decode at once.',
      bbox: [x0, y0, x1, y1],
    },
  ];
}

/**
 * Where the column picker starts, for the file this page ships with.
 *
 * The chips themselves come from the loaded file's own index -- this is only
 * the opening selection, and it is used only when every name in it is really
 * in that file. Anything else starts from the first few columns the policy
 * does not withhold.
 */
export const DEFAULT_COLUMNS = [
  'VendorID',
  'passenger_count',
  'trip_distance',
  'fare_amount',
];

export const PRINCIPAL = JSON.stringify(
  { role: 'analyst', level: 2, groups: ['nyc-taxi', 'sentinel-licensee'] },
  null,
  2,
);

const policy = (lines) => `allow:\n${lines.map((l) => `  - "${l}"`).join('\n')}\n`;

const METADATA = "region.kind = 'metadata'";
/** The two columns the bundled Parquet withholds, and the default for any file. */
export const WITHHELD = ['tip_amount', 'total_amount'];
const COLUMN_MASK = (withheld) =>
  `region.kind = 'column_chunk' AND region.column NOT IN (${
    withheld.map((c) => `'${c}'`).join(', ')
  })`;
const OVERVIEWS = "region.kind = 'tile' AND region.overview_level >= 2";
// `S_CONTAINS(<area>, region.geom)`, argument order deliberate: the area
// contains the tile, not the other way round. See the note at the top of this
// file for why the permissive spelling leaks and why the polygon is snapped.
const AOI_RULE = (wkt) =>
  `user.role = 'analyst' AND region.kind = 'tile' AND S_CONTAINS(${wkt}, region.geom)`;

/**
 * A preset is built against one file's vocabulary.
 *
 * `wkt` is the licensed area and `withheld` the columns the mask holds back.
 * Both default to the bundled files' own, so a page with nothing loaded from a
 * URL writes exactly the documents it always did.
 */
const context = (ctx) => ({ wkt: aoiWkt(AOIS[0]), withheld: WITHHELD, ...ctx });

export const POLICY_PRESETS = [
  {
    id: 'licensee',
    name: 'Column mask and licensed area',
    blurb:
      'The realistic case. Two fare columns withheld, overviews public, full resolution inside the licensed area.',
    build: (ctx) => {
      const { wkt, withheld } = context(ctx);
      return policy([METADATA, COLUMN_MASK(withheld), OVERVIEWS, AOI_RULE(wkt)]);
    },
  },
  {
    id: 'open',
    name: 'Everything allowed',
    blurb: 'A baseline. Every read succeeds in both alignment modes.',
    build: () =>
      policy([
        METADATA,
        "region.kind = 'column_chunk'",
        "region.kind = 'bloom_filter'",
        "region.kind = 'tile'",
      ]),
  },
  {
    id: 'no-metadata',
    name: 'Data rules, no metadata rule',
    blurb:
      'Allows every column and every tile, but not the footer or the IFDs. Nothing loads: the reader cannot find the data it is allowed to read.',
    build: () =>
      policy([
        "region.kind = 'column_chunk'",
        "region.kind = 'bloom_filter'",
        "region.kind = 'tile'",
      ]),
  },
  {
    id: 'overviews-naive',
    name: 'Overviews only, written naively',
    blurb:
      'One rule, exactly as you would first write it. It serves nothing at all, because the IFDs and tag arrays that locate the tiles are metadata.',
    build: () => policy([OVERVIEWS]),
  },
  {
    id: 'overviews-fixed',
    name: 'Overviews only, corrected',
    blurb:
      'The same intent with the metadata rule restored. Overviews load; full resolution is refused.',
    build: () => policy([METADATA, OVERVIEWS]),
  },
];

/** Replace the first POLYGON(...) in a policy document with another. */
export function substituteAoi(text, wkt) {
  return text.replace(/POLYGON\s*\(\([^)]*\)\)/i, wkt);
}

/** The bounding box of the first POLYGON(...) in a policy document. */
export function aoiBboxFrom(text) {
  const match = /POLYGON\s*\(\(([^)]*)\)\)/i.exec(text);
  if (!match) return null;
  const points = match[1]
    .split(',')
    .map((pair) => pair.trim().split(/\s+/).map(Number))
    .filter((p) => p.length >= 2 && p.every(Number.isFinite));
  if (points.length < 3) return null;
  return [
    Math.min(...points.map((p) => p[0])),
    Math.min(...points.map((p) => p[1])),
    Math.max(...points.map((p) => p[0])),
    Math.max(...points.map((p) => p[1])),
  ];
}
