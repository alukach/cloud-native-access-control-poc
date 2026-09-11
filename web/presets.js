// Seed content for the policy editor: the rules, the principal and the AOI
// polygons the demo pastes into them.
//
// Every polygon here is in EPSG:32610 -- the CRS of `data/s2-tci-512.tif` --
// because `S_INTERSECTS` compares coordinates, not coordinate systems. A
// WGS84 polygon against a UTM tile is not an error, it is an empty
// intersection, which is the quietest way to write a rule that denies
// everything.

/** The COG's full extent, from its own tile bboxes. */
export const SCENE_EXTENT = [499980, 4090200, 609780, 4200000];

const ring = ([x0, y0, x1, y1]) =>
  `POLYGON((${x0} ${y0},${x1} ${y0},${x1} ${y1},${x0} ${y1},${x0} ${y0}))`;

// Both land areas sit in the northwest corner, which is where this granule
// actually has terrain -- it is a swath-edge scene, mostly ocean and cloud.
// They are chosen for size, not for looks: a full-resolution tile here is
// 4,991 m across, so a 64 KB block spans several of them and reaches outside
// any licence drawn at this scale.
export const AOIS = [
  {
    id: 'coast',
    name: 'Coast and fields',
    note: '10 km of coastline and cultivated land: nine tiles at full resolution, in a 3 × 3 block. One tile is 4,991 m across, so a 64 KB block covers a run of them and crosses the boundary on every side.',
    bbox: [520000, 4188000, 530000, 4198000],
  },
  {
    id: 'headland',
    name: 'Headland',
    note: '5 km over the headland: four tiles, in a 2 × 2 block. Half the width for the same fixed block size, so the reader overshoots the licence proportionally further.',
    bbox: [522000, 4194000, 527000, 4199000],
  },
  {
    id: 'scene',
    name: 'Whole scene',
    note: 'Licensing the entire image. Every tile is inside the area, so nothing straddles and the only limit left is how much a browser will decode at once.',
    bbox: SCENE_EXTENT,
  },
];

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
export function aoisFor(extent) {
  const [x0, y0, x1, y1] = extent;
  const cx = (x0 + x1) / 2;
  const cy = (y0 + y1) / 2;
  const box = (fraction) => {
    const w = ((x1 - x0) * fraction) / 2;
    const h = ((y1 - y0) * fraction) / 2;
    return [cx - w, cy - h, cx + w, cy + h];
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
const AOI_RULE = (wkt) =>
  `user.role = 'analyst' AND region.kind = 'tile' AND S_INTERSECTS(region.geom, ${wkt})`;

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
