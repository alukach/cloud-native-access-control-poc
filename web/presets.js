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

export const AOIS = [
  {
    id: 'northwest',
    name: 'Northwest block',
    note: '10 km over the brightest part of the scene. Three tiles across at full resolution, which is small enough that one 64 KB block reaches well past the licence.',
    bbox: [507660, 4150300, 517660, 4160300],
  },
  {
    id: 'southwest',
    name: 'Southwest block',
    note: '10 km further down the same edge. Different tiles, same shape of answer.',
    bbox: [506380, 4115090, 516380, 4125090],
  },
  {
    id: 'scene',
    name: 'Whole scene',
    note: 'Licensing the entire image. Every tile is inside the area, so nothing straddles and the only limit left is how much a browser will decode at once.',
    bbox: SCENE_EXTENT,
  },
];

export const aoiWkt = (aoi) => ring(aoi.bbox);

/** The columns the Parquet query asks for. */
export const QUERY_COLUMNS = [
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
const COLUMN_MASK =
  "region.kind = 'column_chunk' AND region.column NOT IN ('tip_amount', 'total_amount')";
const OVERVIEWS = "region.kind = 'tile' AND region.overview_level >= 2";
const AOI_RULE = (wkt) =>
  `user.role = 'analyst' AND region.kind = 'tile' AND S_INTERSECTS(region.geom, ${wkt})`;

export const POLICY_PRESETS = [
  {
    id: 'licensee',
    name: 'Column mask and licensed area',
    blurb:
      'The realistic case. Two fare columns withheld, overviews public, full resolution inside the licensed area.',
    build: (wkt) => policy([METADATA, COLUMN_MASK, OVERVIEWS, AOI_RULE(wkt)]),
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
