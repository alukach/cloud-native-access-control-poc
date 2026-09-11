// The page. Three inputs across the top, one run, one result.
//
// The query is built here rather than hardcoded: the column chips come out of
// the loaded file's own index, and the set you pick is what gets handed to
// hyparquet as its `columns` option. Everything else -- the policy, the
// principal, the file, the licensed area -- travels in the query string.

import {
  BLOCK_SIZE,
  Policy,
  buildIndex,
  makeGate,
  probe,
  queryables,
  ready,
  runCog,
  runParquet,
  version,
} from './engine.js';
import {
  AOIS,
  DEFAULT_COLUMNS,
  POLICY_PRESETS,
  PRINCIPAL,
  SCENE_EXTENT,
  WITHHELD,
  aoiBboxFrom,
  aoiWkt,
  aoisFor,
  substituteAoi,
} from './presets.js';
import {
  EXAMPLES,
  FORMATS,
  NOT_YET,
  SAMPLES,
  SourceError,
  detect,
  formatName,
} from './source.js';
import { debounce, pack, unpack, writeQuery } from './share.js';

/** The two files the page ships with, and the only ones it hardcodes prose about. */
const SAMPLE_FILES = [
  {
    key: 'parquet',
    format: 'parquet',
    url: '../data/nyc-taxi-8rg.parquet',
    label: 'nyc-taxi-8rg.parquet',
    rows: 400000,
  },
  {
    key: 'cog',
    format: 'cog',
    url: '../data/s2-tci-512.tif',
    label: 's2-tci-512.tif',
  },
];

/** A file loaded from a URL could have a hundred million rows. This many, then. */
const CUSTOM_ROW_CAP = 100000;

/**
 * The clients. One row of the matrix, one row of bars, each.
 *
 * `aligned` is the only thing that differs between the two hyparquet rows and
 * between the two geotiff rows: same policy, same principal, same query, same
 * file. A `pending` client is drawn and never run.
 */
const CLIENTS = {
  parquet: [
    { id: 'hyparquet', name: 'hyparquet', how: 'as it ships — no projection', aligned: false },
    { id: 'hyparquet-projected', name: 'hyparquet', how: 'columns pushed down', aligned: true },
    {
      id: 'duckdb',
      name: 'DuckDB',
      how: '64 KiB aligned blocks',
      pending: 'the DuckDB-wasm client is a later task. Nothing on this row has been measured.',
    },
  ],
  cog: [
    { id: 'geotiff', name: 'geotiff.js', how: `as it ships — ${BLOCK_SIZE / 1024} KB blocks`, aligned: false },
    { id: 'geotiff-aligned', name: 'geotiff.js', how: 'one structure per range', aligned: true },
  ],
};

const clientsFor = (key) => CLIENTS[key] || [];
const runnableClients = (key) => clientsFor(key).filter((c) => !c.pending);

/**
 * What the gate does with a range that covers both allowed and forbidden bytes.
 *
 * TODO: wire `zerofill`. The crate grew the mode while this page was being
 * rebuilt, so the API it needs now exists and is what to call:
 *
 *   index.check(policy, user, start, end, 'zero_fill')  -> CheckResult
 *   result.zeroFilled                                   // served only because of the mode
 *   result.redact(bytes)                                // blanks in place; bytes must be
 *                                                       // exactly start..end
 *   result.blankStarts / result.blankEnds               // absolute offsets, for drawing
 *
 * `makeGate` in engine.js is the one place that has to change: pass the mode
 * to `check`, and on a `zeroFilled` verdict fetch the range and call `redact`
 * before handing the buffer to the reader. Until a run has actually measured
 * that, the option stays disabled and the matrix column says so rather than
 * guessing at an outcome.
 */
const DENIALS = [
  { id: 'refuse', name: 'Refuse it', summary: 'refuse mixed requests' },
  { id: 'zerofill', name: 'Zero-fill', summary: 'zero-fill mixed requests', pending: true },
];

/** The disclosures whose open/closed state travels in the link. */
const PANELS = ['source', 'log'];
const PANELS_DEFAULT = 'log';

const $ = (id) => document.getElementById(id);

const state = {
  policyText: '',
  policy: null,
  policyError: null,
  user: PRINCIPAL,
  userError: null,
  files: {},
  /** The picked Parquet columns, in the file's own order. */
  columns: [],
  denial: 'refuse',
  // `mode` is SAMPLES or 'custom'. `format` is the override, 'auto' or a
  // format id -- what the *user* said, kept apart from what the URL implies.
  source: { mode: SAMPLES, url: '', format: 'auto' },
  preset: POLICY_PRESETS[0].id,
  aoi: AOIS[0].id,
  panels: new Set(PANELS_DEFAULT.split(',')),
  setupOpen: true,
  /** Which client's ranges the request log is showing. */
  logPick: null,
  refusalPick: {},
  booting: true,
};

// A denial inside geotiff.js's blocked source leaves sibling block promises
// with nobody to await them. Those are this page's own refusals, already
// reported in the log, so they are not also browser console noise.
addEventListener('unhandledrejection', (event) => {
  if (event.reason && event.reason.cnacDeny) event.preventDefault();
});

// ---- formatting ---------------------------------------------------------

const bytes = (n) => {
  if (n < 1000) return `${n} B`;
  if (n < 1e6) return `${(n / 1e3).toFixed(1)} kB`;
  return `${(n / 1e6).toFixed(2)} MB`;
};

const regionLabel = (r) => {
  if (!r) return '?';
  switch (r.kind) {
    case 'metadata': return r.name;
    case 'column_chunk': return `rg${r.row_group}·${r.column}`;
    case 'bloom_filter': return `bloom·${r.column}`;
    case 'column_index': return `pageindex·${r.column}`;
    case 'tile': return `L${r.overview_level} (${r.x},${r.y})`;
    case 'unmapped': return `unmapped ${r.start}–${r.end - 1}`;
    default: return r.kind;
  }
};

function summarise(file, indices) {
  if (!indices.length) return 'no known region';
  if (indices.length <= 2) return indices.map((i) => regionLabel(file.regions[i])).join(', ');
  const first = regionLabel(file.regions[indices[0]]);
  const last = regionLabel(file.regions[indices[indices.length - 1]]);
  return `${indices.length} regions, ${first} → ${last}`;
}

function deniedNames(file, indices) {
  const names = indices.filter((i) => !file.verdicts[i]).map((i) => regionLabel(file.regions[i]));
  if (!names.length) return '';
  const shown = names.slice(0, 3).join(', ');
  return names.length > 3 ? `${shown} and ${names.length - 3} more` : shown;
}

/** "a", "a and b", "a, b and c", "a, b, c and 4 more". */
function listOf(names) {
  if (names.length <= 1) return names[0] || '';
  const shown = names.length > 4 ? names.slice(0, 3) : names.slice(0, -1);
  const tail = names.length > 4 ? `${names.length - 3} more` : names[names.length - 1];
  return `${shown.join(', ')} and ${tail}`;
}

/**
 * The bytes the resolver could not attribute to anything.
 *
 * `LayoutIndex` fills every gap so that coverage of the object is total, and
 * those fillers are their own kind on purpose -- if they classified as
 * metadata, the `region.kind = 'metadata'` rule everybody writes would become
 * a wildcard over exactly the bytes the resolver understood least.
 */
function unmappedNote(regions) {
  const spans = regions.filter((r) => r.kind === 'unmapped');
  if (!spans.length) return '';
  const total = spans.reduce((sum, r) => sum + (r.end - r.start), 0);
  return `\n\n${spans.length} span${spans.length === 1 ? '' : 's'} of it, ${bytes(total)} in all, `
    + 'came back as kind "unmapped" — bytes no resolver rule could attribute to a structure. '
    + 'Coverage of the object is total by construction, so they are in the index, and none of the '
    + 'presets names that kind: a rule that did would be granting precisely the bytes least '
    + 'understood. Any range crossing one is refused, and in a file whose header has a gap that '
    + 'is the very first read.';
}

/** Build an element with text in it. Never markup: most of this is file-derived. */
function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

const text = (s) => document.createTextNode(s);

// ---- the file's own vocabulary ------------------------------------------
//
// The presets are written against the bundled files: four taxi columns to
// select, two to withhold, three polygons over one Sentinel granule. None of
// that survives contact with somebody else's object, so each of them falls
// back to the loaded file's own columns and its own extent.

function fileColumns() {
  const file = state.files.parquet;
  if (!file?.regions) return null;
  const columns = [...new Set(
    file.regions.filter((r) => r.kind === 'column_chunk').map((r) => r.column),
  )];
  return columns.length ? columns : null;
}

function withheldColumns() {
  const columns = fileColumns();
  if (!columns || WITHHELD.every((c) => columns.includes(c))) return WITHHELD;
  return columns.slice(-Math.min(2, Math.max(1, columns.length - 1)));
}

/** Where the picker starts, for whichever file is loaded. */
function defaultColumns() {
  const columns = fileColumns();
  if (!columns) return [];
  if (DEFAULT_COLUMNS.every((c) => columns.includes(c))) return [...DEFAULT_COLUMNS];
  const withheld = withheldColumns();
  const open = columns.filter((c) => !withheld.includes(c));
  return (open.length ? open : columns).slice(0, 4);
}

/** Columns whose every chunk the current policy refuses. Measured, not parsed. */
function deniedColumns(file) {
  if (!file?.verdicts || !file.columns) return [];
  return file.columns.filter((column) => {
    const chunks = file.regions.filter((r) => r.kind === 'column_chunk' && r.column === column);
    return chunks.length > 0 && chunks.every((r) => !file.verdicts[r.i]);
  });
}

/** The union of every tile bbox: the image's own extent, in its own CRS. */
function extentOf(regions) {
  const boxes = regions
    .filter((r) => r.kind === 'tile' && Array.isArray(r.bbox) && r.bbox.length === 4)
    .map((r) => r.bbox);
  if (!boxes.length) return null;
  return [
    Math.min(...boxes.map((b) => b[0])),
    Math.min(...boxes.map((b) => b[1])),
    Math.max(...boxes.map((b) => b[2])),
    Math.max(...boxes.map((b) => b[3])),
  ];
}

const sceneExtent = () => state.files.cog?.extent || SCENE_EXTENT;

const currentAois = () =>
  (state.source.mode === SAMPLES || !state.files.cog ? AOIS : aoisFor(sceneExtent()));

function pickedAoi() {
  const aois = currentAois();
  return aois.find((a) => a.id === state.aoi) || aois[0];
}

// ---- the link -----------------------------------------------------------

const DEFAULT_POLICY = POLICY_PRESETS[0].build({});

async function writeUrl() {
  if (state.booting) return;
  const params = new URLSearchParams();
  if ((state.source.mode !== SAMPLES || state.source.failed) && state.source.url) {
    params.set('file', state.source.url);
    if (state.source.format !== 'auto') params.set('fmt', state.source.format);
  }
  if (state.preset !== POLICY_PRESETS[0].id) params.set('preset', state.preset);
  if (state.aoi !== AOIS[0].id) params.set('aoi', state.aoi);
  if ($('policy').value !== DEFAULT_POLICY) params.set('p', await pack($('policy').value));
  if ($('principal').value !== PRINCIPAL) params.set('u', await pack($('principal').value));
  const columns = state.columns.join(',');
  if (columns && columns !== defaultColumns().join(',')) params.set('cols', columns);
  if (state.denial !== 'refuse') params.set('deny', state.denial);
  const level = $('cog-level').value;
  if (level && level !== '0') params.set('lvl', level);
  const panels = [...state.panels].sort().join(',');
  if (panels !== PANELS_DEFAULT) params.set('panel', panels);
  if (!state.setupOpen) params.set('setup', 'closed');
  writeQuery(params);
}

const writeUrlSoon = debounce(writeUrl, 400);

function copyNote(message, ok = true) {
  const note = $('copy-note');
  note.textContent = message;
  note.style.color = ok ? '' : 'var(--deny)';
  setTimeout(() => { note.textContent = ''; }, 4000);
}

async function copyLink() {
  await writeUrl();
  try {
    await navigator.clipboard.writeText(location.href);
    copyNote(`copied · ${location.href.length} characters`);
  } catch {
    // A page served over plain http, or a browser that wants a gesture it did
    // not see. Select it instead; the reader can still press the shortcut.
    const field = el('input');
    field.value = location.href;
    field.style.cssText = 'position:fixed;opacity:0';
    document.body.append(field);
    field.select();
    const worked = document.execCommand?.('copy');
    field.remove();
    copyNote(
      worked ? `copied · ${location.href.length} characters` : 'copy it from the address bar',
      Boolean(worked),
    );
  }
}

// ---- policy -------------------------------------------------------------

function loadPolicy() {
  const body = $('policy').value;
  state.policyText = body;
  let next = null;
  try {
    next = new Policy(body);
    state.policyError = null;
  } catch (err) {
    state.policyError = String(err.message || err);
  }
  if (next) {
    state.policy?.free();
    state.policy = next;
  }

  const diag = $('policy-diag');
  if (state.policyError) {
    diag.className = 'diag bad';
    diag.textContent = state.policyError;
    $('policy-state').textContent = 'not loaded';
  } else {
    const rules = (body.match(/^\s*-\s/gm) || []).length;
    diag.className = 'diag ok';
    diag.textContent = `Loaded. ${rules} rule${rules === 1 ? '' : 's'}, every property checked against the queryables schema.`;
    $('policy-state').textContent = `${rules} rules · every property checked`;
  }

  try {
    JSON.parse($('principal').value);
    state.user = $('principal').value;
    state.userError = null;
    $('principal-diag').className = 'diag ok';
    $('principal-diag').textContent = 'Valid JSON.';
  } catch (err) {
    state.userError = String(err.message || err);
    $('principal-diag').className = 'diag bad';
    $('principal-diag').textContent = state.userError;
  }

  refreshVerdicts();
}

const policyUsable = () => Boolean(state.policy && !state.policyError && !state.userError);

function refreshVerdicts() {
  const usable = policyUsable();
  for (const file of Object.values(state.files)) {
    if (!file.index) continue;
    file.verdicts = usable
      ? file.index.verdicts(state.policy, state.user)
      : new Uint8Array(file.index.regionCount);
    paintGrid(file);
  }
  renderColumnChips();
  renderQuery();
  for (const key of Object.keys(state.files)) {
    renderMatrix(key);
    renderBars(key);
    renderRefusals(key);
  }
  renderLog();
  renderRunBar();
  $('run-all').disabled = !usable || !Object.keys(state.files).length;
}

// ---- step 1: the query the user builds ----------------------------------

function renderColumnChips() {
  const host = $('column-chips');
  host.textContent = '';
  const file = state.files.parquet;
  if (!file?.columns) return;
  const withheld = new Set(deniedColumns(file));
  for (const column of file.columns) {
    const button = el('button', withheld.has(column) ? 'denied' : '', column);
    button.type = 'button';
    button.setAttribute('aria-pressed', String(state.columns.includes(column)));
    button.title = withheld.has(column)
      ? `${column} — every chunk of it is refused by this policy`
      : column;
    button.addEventListener('click', () => toggleColumn(column));
    host.append(button);
  }
}

function toggleColumn(column) {
  const file = state.files.parquet;
  if (!file) return;
  const picked = new Set(state.columns);
  if (picked.has(column)) {
    // hyparquet needs at least one column to project, and a query that asks
    // for nothing is not a query.
    if (picked.size === 1) return;
    picked.delete(column);
  } else {
    picked.add(column);
  }
  state.columns = file.columns.filter((c) => picked.has(c));
  // The picked set changed, so every run on screen was for a different query.
  file.runs = {};
  state.logPick = null;
  renderColumnChips();
  renderQuery();
  paintGrid(file);
  renderMatrix('parquet');
  renderBars('parquet');
  renderRefusals('parquet');
  renderLog();
  renderRunBar();
  writeUrlSoon();
}

const limitFor = (file) => file.rowEnd ?? file.rows ?? CUSTOM_ROW_CAP;

function keyword(word) {
  return el('b', '', word);
}

function renderQuery() {
  const pq = state.files.parquet;
  $('query-parquet').hidden = !pq;
  if (pq) {
    const sql = $('query-sql');
    sql.textContent = '';
    sql.append(keyword('SELECT '), text(state.columns.join(', ') || '—'));
    sql.append(el('br'), keyword('FROM '), text(pq.label));
    sql.append(text(' '), keyword('LIMIT '), text(String(limitFor(pq))));
  }

  const cog = state.files.cog;
  $('query-cog').hidden = !cog;
  if (cog) {
    const area = queryArea();
    const [x0, y0, x1, y1] = area.bbox;
    const sql = $('cog-sql');
    sql.textContent = '';
    sql.append(keyword('READ '), text(`level ${$('cog-level').value || 0}`));
    sql.append(el('br'), keyword('FROM '), text(cog.label));
    sql.append(
      el('br'),
      keyword('WHERE '),
      text(`area = (${Math.round(x0)} ${Math.round(y0)}, ${Math.round(x1)} ${Math.round(y1)})`),
    );
    const size = `${((x1 - x0) / 1000).toFixed(1)} × ${((y1 - y0) / 1000).toFixed(1)} km`;
    $('aoi-note').textContent = area.licensed
      ? `${area.name}: ${size}. ${area.note}`
      : `This policy has no licensed area, so the query reads the whole scene — ${size}. `
        + 'At full resolution that is more than a browser will decode at once; pick a coarser level.';
  }
}

/**
 * The area the COG query actually reads.
 *
 * `runCog` takes the polygon out of the policy, not out of the chip row, so a
 * policy with no spatial rule reads the whole scene however the chips are set.
 * Saying otherwise on the page would be describing a query nobody runs.
 */
function queryArea() {
  const bbox = aoiBboxFrom(state.policyText);
  if (!bbox) return { bbox: sceneExtent(), name: 'the whole scene', note: '', licensed: false };
  const aoi = currentAois().find((a) => a.bbox.every((v, i) => Math.abs(v - bbox[i]) < 1e-6));
  return {
    bbox,
    name: aoi ? aoi.name : 'a custom area',
    note: aoi ? aoi.note : 'Hand-edited in the policy rather than picked from the chips above.',
    licensed: true,
  };
}

// ---- the run bar --------------------------------------------------------

function principalRole() {
  try {
    const claims = JSON.parse($('principal').value);
    return claims.role || claims.sub || 'anonymous';
  } catch {
    return 'invalid token';
  }
}

function renderRunBar() {
  const pq = state.files.parquet;
  const cog = state.files.cog;
  const node = $('run-sentence');
  node.textContent = '';

  if (!pq && !cog) {
    node.textContent = 'Nothing is loaded.';
  } else if (!policyUsable()) {
    node.textContent = state.policyError
      ? 'The policy does not load, so nothing can be checked against it.'
      : 'The principal is not valid JSON, so nothing can be checked against it.';
  } else {
    if (pq) {
      const withheld = deniedColumns(pq);
      node.append(
        text('Ready to run '),
        el('b', '', `${state.columns.length} of ${pq.columns.length} columns`),
        text(` over ${pq.rowsLabel}, against a policy withholding `),
        el('b', '', withheld.length ? listOf(withheld) : 'nothing'),
        text(`, ${state.denial === 'refuse'
          ? 'refusing any request that covers both'
          : 'blanking the forbidden bytes'}.`),
      );
    }
    if (cog) {
      node.append(
        text(pq ? ' Then the same policy over the image: ' : 'Ready to read '),
        el('b', '', queryArea().name),
        text(` at level ${$('cog-level').value || 0}.`),
      );
    }
  }

  const clients = Object.keys(state.files).flatMap((key) => clientsFor(key)).length;
  $('run-caption').textContent = '';
  $('run-caption').append(
    text(`${clients} client${clients === 1 ? '' : 's'}`),
    el('br'),
    text('same policy · every range checked'),
  );

  const rules = (state.policyText.match(/^\s*-\s/gm) || []).length;
  const denial = DENIALS.find((d) => d.id === state.denial);
  $('setup-summary').textContent = [
    pq ? `${state.columns.length} columns` : null,
    cog ? `${queryArea().name}, L${$('cog-level').value || 0}` : null,
    `${rules} rules`,
    principalRole(),
    denial.summary,
  ].filter(Boolean).join(' · ');
}

// ---- grids --------------------------------------------------------------

function cellFor(file, i) {
  const cell = document.createElement('div');
  cell.className = 'cell';
  cell.dataset.i = String(i);
  cell.title = `${regionLabel(file.regions[i])} · bytes ${file.regions[i].start}–${file.regions[i].end - 1}`;
  file.cells.set(i, cell);
  return cell;
}

function gridTitle(heading, detail) {
  const title = el('div', 'grid-title');
  title.append(el('b', '', heading), el('span', '', detail));
  return title;
}

function buildParquetGrid(file) {
  const host = $('parquet-grid');
  host.textContent = '';
  file.cells = new Map();

  const chunks = file.regions.filter((r) => r.kind === 'column_chunk');
  const columns = [...new Set(chunks.map((r) => r.column))];
  const groups = [...new Set(chunks.map((r) => r.row_group))].sort((a, b) => a - b);
  const byKey = new Map(chunks.map((r) => [`${r.row_group}/${r.column}`, r.i]));

  const scroll = el('div', 'grid-scroll');
  const grid = el('div', 'pq');
  grid.style.gridTemplateColumns = `auto repeat(${columns.length}, 1.25rem)`;

  grid.append(document.createElement('div'));
  for (const column of columns) {
    const head = el('div', 'head', column);
    head.dataset.column = column;
    grid.append(head);
  }
  for (const group of groups) {
    grid.append(el('div', 'rowlab', `rg ${group}`));
    for (const column of columns) grid.append(cellFor(file, byKey.get(`${group}/${column}`)));
  }
  scroll.append(grid);
  host.append(scroll);

  host.append(metadataBlock(file, 'Footer and magic', (r) => r.kind === 'metadata'));

  file.columnHeads = grid.querySelectorAll('.head');
  file.columns = columns;
  file.rowGroups = groups.length;
  file.bloomCount = file.regions.filter((r) => r.kind === 'bloom_filter').length;
  $('parquet-grid-label').textContent =
    `Every column chunk · ${groups.length} row groups × ${columns.length} columns`;
}

function metadataBlock(file, heading, predicate) {
  const block = el('div', 'grid-block');
  const regions = file.regions.filter(predicate);
  block.append(gridTitle(
    heading,
    `${regions.length} regions · the reader needs these to find anything else`,
  ));

  const scroll = el('div', 'grid-scroll');
  const grid = el('div', 'pq');
  grid.style.gridTemplateColumns = `repeat(${regions.length}, 1.25rem)`;
  for (const r of regions) grid.append(cellFor(file, r.i));
  scroll.append(grid);
  block.append(scroll);
  return block;
}

function buildCogGrid(file) {
  const host = $('cog-grid');
  host.textContent = '';
  file.cells = new Map();

  const tiles = file.regions.filter((r) => r.kind === 'tile');
  const levels = [...new Set(tiles.map((r) => r.overview_level))].sort((a, b) => a - b);

  const wrap = el('div', 'levels');
  file.levels = [];

  for (const level of levels) {
    const own = tiles.filter((r) => r.overview_level === level);
    const cols = Math.max(...own.map((r) => r.x)) + 1;
    const rows = Math.max(...own.map((r) => r.y)) + 1;
    const byKey = new Map(own.map((r) => [`${r.x}/${r.y}`, r.i]));

    const box = el('div', 'level');
    box.append(gridTitle(`L${level}`, `${cols}×${rows}`));

    const board = el('div', 'board');
    const side = Math.max(6, Math.min(18, Math.round(160 / cols)));
    board.style.gridTemplateColumns = `repeat(${cols}, ${side}px)`;
    for (let y = 0; y < rows; y += 1) {
      for (let x = 0; x < cols; x += 1) board.append(cellFor(file, byKey.get(`${x}/${y}`)));
    }
    const aoi = el('div', 'aoi');
    board.append(aoi);
    box.append(board);
    wrap.append(box);
    file.levels.push({ level, cols, rows, aoi, tiles: own.length });
  }
  host.append(wrap);
  host.append(metadataBlock(file, 'Header, IFDs and tag arrays', (r) => r.kind === 'metadata'));
  $('cog-grid-label').textContent =
    `Every tile · ${tiles.length} across ${levels.length} overview levels`;
  paintAoi();
}

function paintAoi() {
  const bbox = aoiBboxFrom(state.policyText);
  const file = state.files.cog;
  if (!file?.levels) return;
  const [ex0, ey0, ex1, ey1] = sceneExtent();
  for (const level of file.levels) {
    if (!bbox) { level.aoi.hidden = true; continue; }
    level.aoi.hidden = false;
    const pct = (v) => `${(v * 100).toFixed(2)}%`;
    level.aoi.style.left = pct(Math.max(0, (bbox[0] - ex0) / (ex1 - ex0)));
    level.aoi.style.width = pct(Math.min(1, (bbox[2] - bbox[0]) / (ex1 - ex0)));
    level.aoi.style.top = pct(Math.max(0, (ey1 - bbox[3]) / (ey1 - ey0)));
    level.aoi.style.height = pct(Math.min(1, (bbox[3] - bbox[1]) / (ey1 - ey0)));
  }
}

/** Every region this query asks for: the chips, or the tiles under the area. */
function askedFor(file) {
  const asked = new Set();
  if (file.key === 'parquet') {
    const picked = new Set(state.columns);
    for (const r of file.regions) {
      if (r.kind === 'column_chunk' && picked.has(r.column)) asked.add(r.i);
    }
    return asked;
  }
  const level = Number($('cog-level').value || 0);
  const bbox = aoiBboxFrom(state.policyText) || sceneExtent();
  for (const r of file.regions) {
    if (r.kind !== 'tile' || r.overview_level !== level) continue;
    if (!Array.isArray(r.bbox)) continue;
    const [x0, y0, x1, y1] = r.bbox;
    if (x1 > bbox[0] && x0 < bbox[2] && y1 > bbox[1] && y0 < bbox[3]) asked.add(r.i);
  }
  return asked;
}

function paintGrid(file) {
  const asked = askedFor(file);
  for (const [i, cell] of file.cells) {
    cell.classList.toggle('denied', !file.verdicts?.[i]);
    cell.classList.toggle('picked', asked.has(i));
  }
  if (file.key === 'parquet') {
    const picked = new Set(state.columns);
    for (const head of file.columnHeads || []) {
      const column = head.dataset.column;
      const denied = file.regions.some(
        (r) => r.kind === 'column_chunk' && r.column === column && !file.verdicts?.[r.i],
      );
      head.classList.toggle('denied', denied);
      head.classList.toggle('picked', picked.has(column));
    }
    const note = $('parquet-bloom-note');
    if (file.bloomCount) {
      const allowed = file.regions.filter((r) => r.kind === 'bloom_filter' && file.verdicts?.[r.i]).length;
      note.textContent = `${file.bloomCount} bloom-filter regions, ${allowed} of them allowed. This query does not filter, so it never reads one — but a policy that forgets they exist leaves a value oracle open.`;
    } else {
      note.textContent = '';
    }
  }
  if (file.key === 'cog') paintAoi();
}

// ---- step 4: the matrix -------------------------------------------------

const ZERO_FILL_CELL = {
  tone: 'idle pending',
  verdict: 'not yet wired',
  why: 'the crate can blank the forbidden bytes now; this page has not run a reader against it, and will not print an outcome it did not measure',
};

function refuseCell(file, run) {
  if (!run) {
    return { tone: 'idle', verdict: 'not run yet', why: 'press Run this query' };
  }
  if (run.ok) {
    return {
      tone: 'good',
      verdict: 'completes',
      why: run.straddling
        ? `${run.straddling} of ${run.issued} ranges cross a boundary, and every region inside them is allowed`
        : `${run.issued} chunk-exact ranges, nothing straddles`,
    };
  }
  return {
    tone: 'bad',
    verdict: 'fails',
    why: `${run.denied} of ${run.issued} ranges refused. ${run.detail}`,
  };
}

/** `label` repeats the column header; the stylesheet shows it only when the
 *  matrix has folded into one column and the header row is gone. */
function matrixCell(cell, label) {
  const box = el('div', cell.tone);
  box.append(
    el('div', 'collabel', label),
    el('div', 'verdict', cell.verdict),
    el('div', 'why', cell.why),
  );
  return box;
}

function renderMatrix(key) {
  const host = $(`${key}-matrix`);
  host.textContent = '';
  const file = state.files[key];
  if (!file) return;

  const columns = ['Client', 'Refuse the request', 'Zero-fill'];
  for (const label of columns) {
    const head = el('div', 'mh');
    head.append(el('div', 'lbl', label));
    host.append(head);
  }

  for (const client of clientsFor(key)) {
    const who = el('div', `who-cell${client.pending ? ' pending' : ''}`);
    who.append(el('div', 'who', client.name), el('div', 'how', client.how));
    host.append(who);
    const pending = { tone: 'idle pending', verdict: 'pending', why: client.pending };
    host.append(matrixCell(
      client.pending ? pending : refuseCell(file, file.runs?.[client.id]),
      columns[1],
    ));
    host.append(matrixCell(client.pending ? pending : ZERO_FILL_CELL, columns[2]));
  }
}

// ---- step 4: the request bars -------------------------------------------

/** The whole object, coloured by verdict, as one CSS gradient. */
function verdictGradient(file) {
  const stops = [];
  let colour = null;
  let from = 0;
  const emit = (to) => {
    const a = ((from / file.size) * 100).toFixed(4);
    const b = ((to / file.size) * 100).toFixed(4);
    stops.push(`${colour} ${a}%`, `${colour} ${b}%`);
  };
  for (const r of file.regions) {
    const next = file.verdicts?.[r.i] ? 'var(--allow-soft)' : 'var(--deny-soft)';
    if (colour === null) { colour = next; from = r.start; continue; }
    if (next !== colour) { emit(r.start); colour = next; from = r.start; }
  }
  if (colour !== null) emit(file.size);
  return `linear-gradient(to right, ${stops.join(',')})`;
}

function said(file, run) {
  if (!run) return { cls: 'idle', body: 'not run yet' };
  const share = ((run.bytes / file.size) * 100).toFixed(1);
  const straddle = run.straddling
    ? ` ${run.straddling} of them ${run.straddling === 1 ? 'crosses' : 'cross'} a policy boundary.`
    : ' Nothing straddles a boundary.';
  if (run.ok) {
    return {
      cls: run.straddling ? 'straddled' : 'ok',
      body: `${run.issued} ranges, none refused — ${bytes(run.bytes)}, ${share}% of the file.${straddle} ${run.detail}`,
    };
  }
  return {
    cls: 'no',
    body: `${run.denied} of ${run.issued} ranges refused.${straddle} ${run.detail}`,
  };
}

function barRow(title, subtitle) {
  const row = el('div', 'barrow');
  const who = el('div', 'who', title);
  if (subtitle) who.append(el('span', '', subtitle));
  const track = el('div', 'track');
  row.append(who, track);
  return { row, track };
}

function renderBars(key) {
  const host = $(`${key}-bars`);
  host.textContent = '';
  const file = state.files[key];
  if (!file) return;

  const top = barRow('what the policy allows', 'across the whole file');
  const strip = el('div', 'verdict-strip');
  strip.style.background = verdictGradient(file);
  top.track.append(strip);
  host.append(top.row);

  for (const client of clientsFor(key)) {
    const { row, track } = barRow(client.name, client.how);
    if (client.pending) {
      row.classList.add('pending');
      const empty = el('div', 'reqs');
      empty.append(el('div', 'empty', client.pending));
      track.append(empty, el('div', 'said idle', 'not measured'));
      host.append(row);
      continue;
    }
    const reqs = el('div', 'reqs');
    reqs.id = `${key}-reqs-${client.id}`;
    const run = file.runs?.[client.id];
    if (!run) reqs.append(el('div', 'empty', 'not run yet'));
    const verdict = said(file, run);
    track.append(reqs, el('div', `said ${verdict.cls}`, verdict.body));
    // Appended before the marks are drawn: `markRequest` finds the track by id,
    // which only works once it is in the document.
    host.append(row);
    if (run) for (const entry of run.log) markRequest(file, client.id, entry);
  }
}

function markRequest(file, clientId, entry) {
  const host = $(`${file.key}-reqs-${clientId}`);
  if (!host) return;
  host.querySelector('.empty')?.remove();
  const kind = entry.straddles ? ' both' : entry.allowed ? '' : ' no';
  const mark = el('div', `req${kind}`);
  mark.style.left = `${(entry.start / file.size) * 100}%`;
  mark.style.width = `${Math.max(0.2, (entry.length / file.size) * 100)}%`;
  mark.title = `#${entry.n} bytes=${entry.start}-${entry.end - 1} · ${entry.label}`;
  host.append(mark);
}

// ---- step 4: refusals ---------------------------------------------------

function renderRefusals(key) {
  const tabs = $(`${key}-refusal-tabs`);
  const host = $(`${key}-refusals`);
  tabs.textContent = '';
  host.textContent = '';
  const file = state.files[key];
  if (!file) return;

  const ran = runnableClients(key).filter((c) => file.runs?.[c.id]);
  if (!ran.length) {
    host.append(el('div', 'none', 'Run the query to see what the gate turned down.'));
    return;
  }
  const withRefusals = ran.filter((c) => file.runs[c.id].denied > 0);
  let picked = ran.find((c) => c.id === state.refusalPick[key]) || withRefusals[0] || ran[0];

  for (const client of ran) {
    const count = file.runs[client.id].denied;
    const button = chip(`${client.name} · ${client.how.split('—').pop().trim()} (${count})`, () => {
      state.refusalPick[key] = client.id;
      renderRefusals(key);
    });
    button.setAttribute('aria-pressed', String(client.id === picked.id));
    tabs.append(button);
  }

  const run = file.runs[picked.id];
  const refused = run.log.filter((entry) => !entry.allowed);
  if (!refused.length) {
    host.append(el('div', 'none', `${picked.name} ${picked.how} — no refusals. Every range it issued fell inside what the policy allows.`));
    return;
  }
  for (const entry of refused.slice(0, 200)) {
    const box = el('div', entry.straddles ? 'refusal' : 'refusal flat');
    box.append(el('div', 'range', `bytes=${entry.start}-${entry.end - 1} · ${bytes(entry.length)}`));
    box.append(el('div', 'note', entry.reason === 'bad_range'
      ? 'the range did not parse'
      : `covers ${summarise(file, entry.regions)} — denied by ${deniedNames(file, entry.regions)}`));
    host.append(box);
  }
}

// ---- the full log -------------------------------------------------------

function renderLog() {
  const tabs = $('log-tabs');
  const host = $('log');
  tabs.textContent = '';
  host.textContent = '';

  const available = [];
  for (const key of Object.keys(state.files)) {
    for (const client of runnableClients(key)) {
      if (state.files[key].runs?.[client.id]) available.push({ key, client });
    }
  }
  if (!available.length) {
    $('log-which').textContent = 'nothing run yet';
    host.append(el('div', 'log-empty', 'Run the query to see every range it asked for.'));
    return;
  }
  const picked = available.find(
    (a) => a.key === state.logPick?.key && a.client.id === state.logPick?.client,
  ) || available[0];
  state.logPick = { key: picked.key, client: picked.client.id };

  for (const option of available) {
    const button = chip(`${option.key} · ${option.client.name} ${option.client.how.split('—').pop().trim()}`, () => {
      state.logPick = { key: option.key, client: option.client.id };
      renderLog();
    });
    button.setAttribute('aria-pressed', String(option === picked));
    tabs.append(button);
  }

  const file = state.files[picked.key];
  const run = file.runs[picked.client.id];
  $('log-which').textContent = `${picked.key} · ${picked.client.name}, ${picked.client.how} · ${run.log.length} ranges`;

  const table = el('table', 'log');
  const headRow = document.createElement('tr');
  for (const [label, cls] of [['#', ''], ['range', ''], ['bytes', 'r'], ['resolved to', ''], ['verdict', 'v'], ['why', '']]) {
    headRow.append(el('th', cls, label));
  }
  const thead = document.createElement('thead');
  thead.append(headRow);
  table.append(thead);

  const body = document.createElement('tbody');
  for (const entry of run.log) {
    const tr = document.createElement('tr');
    if (!entry.allowed) tr.classList.add('no');
    if (entry.straddles) tr.classList.add('straddle');
    const why = entry.allowed
      ? entry.fullBody
        ? 'served — CDN answered 200 with the whole body (cold cache)'
        : ''
      : entry.reason === 'bad_range'
        ? 'the range did not parse'
        : `denied by ${deniedNames(file, entry.regions)}`;
    tr.append(
      el('td', 'n', String(entry.n)),
      el('td', '', `${entry.start}–${entry.end - 1}`),
      el('td', 'r', bytes(entry.length)),
      el('td', '', summarise(file, entry.regions)),
      el('td', 'v', `${entry.allowed ? 'allow' : 'DENY'}${entry.straddles ? ' · straddles' : ''}`),
      el('td', 'why', why),
    );
    body.append(tr);
  }
  table.append(body);
  host.append(table);
}

// ---- runs ---------------------------------------------------------------

/**
 * What actually stopped the query.
 *
 * The thrown error is not reliable: geotiff.js replaces the failures of a
 * block group with an `AggregateError` carrying block *ids* and the message
 * "Request failed", so the refusal underneath it is gone by the time it
 * surfaces. The gate's own log still has it, and it is the authority.
 */
function explain(file, gate, err) {
  const refused = gate.log.find((entry) => !entry.allowed);
  if (!refused) return String(err?.message || err);
  const names = deniedNames(file, refused.regions);
  const where = `bytes=${refused.start}-${refused.end - 1}`;
  if (refused.reason === 'bad_range') return `Refused ${where}: the range did not parse.`;
  return `First refusal: ${where}, which covers ${refused.regions.length} region${
    refused.regions.length === 1 ? '' : 's'
  }. Denied by ${names}.`;
}

async function runClient(key, client) {
  const file = state.files[key];
  file.runs ??= {};
  delete file.runs[client.id];
  renderBars(key);
  renderMatrix(key);
  $('run-busy').textContent = `${key} · ${client.name}, ${client.how}…`;

  const gate = makeGate({
    index: file.index,
    policy: state.policy,
    user: state.user,
    url: file.url,
    labels: (regions) => summarise(file, regions),
    onRequest: (entry) => markRequest(file, client.id, entry),
  });

  const started = performance.now();
  let ok = false;
  let detail = '';
  try {
    if (key === 'parquet') {
      const columns = state.columns.length ? state.columns : file.columns.slice(0, 1);
      const { rows } = await runParquet({
        gate,
        size: file.size,
        columns,
        aligned: client.aligned,
        rowEnd: file.rowEnd,
      });
      ok = true;
      detail = `${rows.toLocaleString()} rows decoded from ${
        client.aligned
          ? `${columns.length} projected column${columns.length === 1 ? '' : 's'}`
          : `all ${file.columns.length} columns`
      }.`;
    } else {
      const level = Number($('cog-level').value);
      const bbox = aoiBboxFrom(state.policyText) || sceneExtent();
      const result = await runCog({
        gate,
        size: file.size,
        level,
        bbox,
        aligned: client.aligned,
        maxPixels: 4e6,
      });
      ok = true;
      detail = `${result.width}×${result.height} pixels decoded from level ${level}.`;
      drawPreview(result, level);
    }
  } catch (err) {
    detail = explain(file, gate, err);
  }

  file.runs[client.id] = {
    issued: gate.issued,
    straddling: gate.straddling,
    denied: gate.denied,
    bytes: gate.bytes,
    transferred: gate.transferred,
    fullBodies: gate.fullBodies,
    checkMs: gate.checkMs,
    log: gate.log,
    ok,
    detail,
    ms: Math.round(performance.now() - started),
  };

  $('run-busy').textContent = '';
  renderBars(key);
  renderMatrix(key);
  renderRefusals(key);
  renderLog();
}

async function runAll() {
  if (!policyUsable()) return;
  $('run-all').disabled = true;
  try {
    for (const key of Object.keys(state.files)) {
      for (const client of runnableClients(key)) await runClient(key, client);
    }
  } finally {
    $('run-all').disabled = !policyUsable();
    $('run-busy').textContent = '';
  }
}

function drawPreview(result, level) {
  const host = $('cog-preview');
  const canvas = $('cog-canvas');
  const { width, height, samples, ycbcr, rasters } = result;
  if (samples < 3 || !(rasters instanceof Uint8Array)) { host.hidden = true; return; }
  canvas.width = width;
  canvas.height = height;
  const ctx = canvas.getContext('2d');
  const image = ctx.createImageData(width, height);
  for (let p = 0; p < width * height; p += 1) {
    const a = rasters[p * samples];
    const b = rasters[p * samples + 1];
    const c = rasters[p * samples + 2];
    // JPEG full-range YCbCr, the colour space this file stores.
    image.data[p * 4] = ycbcr ? a + 1.402 * (c - 128) : a;
    image.data[p * 4 + 1] = ycbcr ? a - 0.344136 * (b - 128) - 0.714136 * (c - 128) : b;
    image.data[p * 4 + 2] = ycbcr ? a + 1.772 * (b - 128) : c;
    image.data[p * 4 + 3] = 255;
  }
  ctx.putImageData(image, 0, 0);
  host.hidden = false;
  $('cog-preview-note').textContent = `level ${level}, ${width}×${height} pixels, decoded in the browser from the tiles the policy allowed`;
}

// ---- loading a file -----------------------------------------------------

/**
 * Probe, index and describe one object, touching nothing on the page.
 *
 * Nothing is swapped in until every file in the set has survived this, so a
 * URL that turns out to be CORS-blocked leaves the previous file loaded and
 * the reader looking at a diagnostic rather than at an empty page.
 */
async function prepare(spec, strict) {
  const info = await probe(spec.url, { strict });
  const { index, window } = await buildIndex(spec.format, spec.url, info.size);
  return { spec, info, index, window, regions: JSON.parse(index.regions()) };
}

function commit(prepared) {
  for (const file of Object.values(state.files)) file.index?.free();
  state.files = {};

  const keys = prepared.map((p) => p.spec.key);
  $('parquet-result').hidden = !keys.includes('parquet');
  $('cog-result').hidden = !keys.includes('cog');
  $('cog-preview').hidden = true;
  state.logPick = null;
  state.refusalPick = {};

  const hosting = [];
  const names = [];
  for (const { spec, info, index, window, regions } of prepared) {
    const file = {
      key: spec.key,
      url: spec.url,
      label: spec.label,
      size: info.size,
      index,
      regions,
      window,
      cells: new Map(),
      runs: {},
    };
    state.files[spec.key] = file;
    names.push(spec.label);

    if (spec.key === 'parquet') {
      buildParquetGrid(file);
      file.rows = spec.rows;
      file.rowEnd = spec.rows ? undefined : CUSTOM_ROW_CAP;
      file.rowsLabel = spec.rows
        ? `all ${spec.rows.toLocaleString()} rows`
        : `the first ${CUSTOM_ROW_CAP.toLocaleString()} rows`;
      state.columns = defaultColumns();
      hosting.push(
        `${bytes(info.size)} · ${file.rowGroups} row groups × ${file.columns.length} columns`
        + ` · ${info.rangeStatus}${info.servedWhole ? ' whole body' : ''}, ${info.contentEncoding}`,
      );
      $('parquet-title').textContent =
        `Parquet · ${file.rowGroups} row groups × ${file.columns.length} columns`;
      $('parquet-meta').textContent =
        `${spec.label} · ${bytes(info.size)} · ${index.regionCount} regions · footer read from the last ${bytes(window)}`;
    } else {
      buildCogGrid(file);
      file.extent = extentOf(regions) || SCENE_EXTENT;
      const tiles = file.levels.map((l) => l.tiles).reduce((a, b) => a + b, 0);
      hosting.push(
        `${bytes(info.size)} · ${file.levels.length} levels, ${tiles} tiles`
        + ` · ${info.rangeStatus}${info.servedWhole ? ' whole body' : ''}, ${info.contentEncoding}`,
      );
      $('cog-title').textContent =
        `Cloud-optimized GeoTIFF · ${file.levels.length} levels, ${tiles} tiles`;
      $('cog-meta').textContent =
        `${spec.label} · ${bytes(info.size)} · ${tiles} tiles · IFDs read from the first ${bytes(window)}`;
      const select = $('cog-level');
      select.textContent = '';
      for (const l of file.levels) {
        const option = el('option', '', `L${l.level} — ${l.tiles} tile${l.tiles === 1 ? '' : 's'}`);
        option.value = String(l.level);
        select.append(option);
      }
      select.value = '0';
    }
  }
  $('source-name').textContent = names.join(' + ');
  $('hosting').textContent = hosting.join(' · ');
}

// ---- the source panel ---------------------------------------------------

function sourceDiag(kind, heading, detail, link) {
  const diag = $('source-diag');
  diag.className = `diag ${kind}`;
  diag.textContent = '';
  if (heading) diag.append(el('b', '', heading));
  diag.append(text(detail));
  if (link) {
    diag.append(text('\n'));
    const anchor = el('a', '', link.text);
    anchor.href = link.href;
    anchor.target = '_blank';
    anchor.rel = 'noreferrer';
    diag.append(anchor);
  }
}

/** What the URL box says, judged but not fetched. Runs on every keystroke. */
function describeDetection() {
  const found = detect($('source-url').value);
  const label = $('source-detected');
  if (found.error) { label.textContent = found.error; return found; }
  if (found.notYet) { label.textContent = `${NOT_YET[found.notYet].name}, from ${found.from}`; return found; }
  const override = $('source-format').value;
  if (override !== 'auto') {
    label.textContent = `${formatName(override)}, because you said so`;
  } else if (found.format) {
    label.textContent = `${formatName(found.format)}, from ${found.from}`;
  } else {
    label.textContent = 'format unknown';
  }
  return found;
}

async function loadCustom(url, { announce = true } = {}) {
  const found = detect(url);
  const override = $('source-format').value;

  if (found.error) {
    sourceDiag('bad', '', found.error);
    return false;
  }
  if (found.notYet && override === 'auto') {
    const { name, issue, why } = NOT_YET[found.notYet];
    sourceDiag(
      'bad',
      `${name} is not implemented yet.`,
      `Detected from ${found.from}, so this is a specific answer rather than a parse failure. `
      + `${why}\n\nTracking issue: `,
      { href: issue, text: issue },
    );
    return false;
  }
  const format = override === 'auto' ? found.format : override;
  if (!format) {
    sourceDiag('bad', 'Cannot tell what this is.', found.hint || 'Choose the format below.');
    return false;
  }

  const label = decodeURIComponent(new URL(url, location.href).pathname).split('/').filter(Boolean).pop() || url;
  const spec = { key: format, format, url, label };

  $('source-busy').textContent = 'probing…';
  $('source-load').disabled = true;
  try {
    const prepared = await prepare(spec, true);
    commit([prepared]);
    state.source = { mode: 'custom', url, format: override, failed: false };
    setSourceMode('custom');
    const ranged = prepared.info.rangeStatus === 206;
    sourceDiag(
      'ok',
      `Loaded ${label} as ${formatName(format)}.`,
      `${bytes(prepared.info.size)}, ${prepared.info.crossOrigin ? 'cross-origin' : 'same-origin'}, `
      + `${ranged ? '206 Partial Content' : `${prepared.info.rangeStatus} on the probe`}. `
      + `The layout index came out of the ${format === 'parquet' ? 'last' : 'first'} `
      + `${bytes(prepared.window)}: ${prepared.index.regionCount} regions.`
      + unmappedNote(prepared.regions),
    );
    refreshVerdicts();
    if (announce) await writeUrl();
    return true;
  } catch (err) {
    if (err instanceof SourceError) {
      sourceDiag(err.kind === 'range-ignored' ? 'loud' : 'bad', `${err.message}`, err.detail);
    } else {
      sourceDiag(
        'bad',
        'The bytes arrived and did not parse.',
        `${String(err?.message || err)}\n\nThe host serves ranges, so this is about the file, not `
        + 'the transport. Check that the format above matches what is actually at that URL.',
      );
    }
    return false;
  } finally {
    $('source-busy').textContent = '';
    $('source-load').disabled = false;
  }
}

async function loadSamples() {
  $('source-busy').textContent = 'loading samples…';
  try {
    const prepared = [];
    for (const spec of SAMPLE_FILES) prepared.push(await prepare(spec, false));
    commit(prepared);
    state.source = { ...state.source, mode: SAMPLES };
    setSourceMode(SAMPLES);
    refreshVerdicts();
  } finally {
    $('source-busy').textContent = '';
  }
}

function setSourceMode(mode) {
  const custom = mode === 'custom';
  $('source-samples').setAttribute('aria-checked', String(!custom));
  $('source-custom').setAttribute('aria-checked', String(custom));
  $('custom-fields').hidden = !custom;
}

// ---- wiring -------------------------------------------------------------

function setPanel(id, open) {
  $(`${id}-toggle`).setAttribute('aria-expanded', String(open));
  $(`${id}-body`).hidden = !open;
  if (open) state.panels.add(id); else state.panels.delete(id);
}

function setSetup(open) {
  state.setupOpen = open;
  $('setup-toggle').setAttribute('aria-expanded', String(open));
  $('setup-toggle').textContent = open ? 'collapse' : 'expand';
  $('setup-body').hidden = !open;
}

function setDenial(id) {
  const denial = DENIALS.find((d) => d.id === id) || DENIALS[0];
  if (denial.pending) return;
  state.denial = denial.id;
  for (const option of DENIALS) {
    $(`deny-${option.id}`).setAttribute('aria-checked', String(option.id === denial.id));
  }
  renderRunBar();
}

function applyPreset(preset) {
  const current = aoiBboxFrom($('policy').value);
  const aois = currentAois();
  const aoi = aois.find((a) => current && a.bbox.every((v, i) => v === current[i])) || pickedAoi();
  state.preset = preset.id;
  state.aoi = aoi.id;
  $('policy').value = preset.build({ wkt: aoiWkt(aoi), withheld: withheldColumns() });
  $('preset-note').textContent = preset.blurb;
  loadPolicy();
}

function applyAoi(aoi) {
  const body = $('policy').value;
  if (!/POLYGON/i.test(body)) {
    $('aoi-note').textContent = `This policy has no spatial rule, so ${aoi.name} changes nothing. Pick a policy with a licensed area first.`;
    return;
  }
  state.aoi = aoi.id;
  $('policy').value = substituteAoi(body, aoiWkt(aoi));
  loadPolicy();
}

function chip(label, onClick, title) {
  const button = el('button', '', label);
  button.type = 'button';
  if (title) button.title = title;
  button.addEventListener('click', onClick);
  return button;
}

function buildAoiChips() {
  const host = $('aoi-presets');
  host.textContent = '';
  for (const aoi of currentAois()) {
    const button = chip(aoi.name, () => { applyAoi(aoi); writeUrl(); });
    button.setAttribute('aria-pressed', String(aoi.id === state.aoi));
    host.append(button);
  }
}

/**
 * Everything the query string says, applied.
 *
 * Every value here is untrusted: it goes into a form field as text and then
 * through the same validation a typed one does. A policy that arrives broken
 * shows the inline diagnostic and the page keeps working.
 */
async function applyQuery() {
  const q = new URLSearchParams(location.search);

  const user = q.get('u');
  $('principal').value = user === null ? PRINCIPAL : await unpack(user);

  const fmt = q.get('fmt');
  if (fmt && FORMATS.some((f) => f.id === fmt)) $('source-format').value = fmt;

  const file = q.get('file');
  let loaded = false;
  if (file) {
    $('source-url').value = file;
    setSourceMode('custom');
    describeDetection();
    loaded = await loadCustom(file, { announce: false });
  }
  if (!loaded) {
    await loadSamples();
    if (file) {
      state.source = { ...state.source, url: file, format: fmt || 'auto', failed: true };
      // The URL in the link did not load. Leave the box filled in with the
      // diagnostic showing, but on the samples so the page still works.
      $('source-url').value = file;
      $('custom-fields').hidden = false;
      $('source-samples').setAttribute('aria-checked', 'true');
      $('source-custom').setAttribute('aria-checked', 'false');
      setPanel('source', true);
    }
  }

  const presetId = q.get('preset');
  const preset = POLICY_PRESETS.find((p) => p.id === presetId) || POLICY_PRESETS[0];
  const aoiId = q.get('aoi');
  const aoi = currentAois().find((a) => a.id === aoiId) || currentAois()[0];
  state.aoi = aoi.id;
  applyPreset(preset);
  buildAoiChips();

  const policyText = q.get('p');
  if (policyText !== null) {
    $('policy').value = await unpack(policyText);
    loadPolicy();
  }

  // The columns come after the file, because they are named out of its schema.
  const cols = q.get('cols');
  if (cols !== null && state.files.parquet) {
    const known = new Set(state.files.parquet.columns);
    const wanted = cols.split(',').map((c) => c.trim()).filter((c) => known.has(c));
    if (wanted.length) state.columns = state.files.parquet.columns.filter((c) => wanted.includes(c));
  }

  setDenial(q.get('deny') || 'refuse');

  const level = q.get('lvl');
  if (level && [...$('cog-level').options].some((o) => o.value === level)) {
    $('cog-level').value = level;
  }

  const panels = q.get('panel');
  const open = new Set((panels === null ? PANELS_DEFAULT : panels).split(',').filter(Boolean));
  for (const id of PANELS) setPanel(id, open.has(id));
  setSetup(q.get('setup') !== 'closed');

  refreshVerdicts();
}

async function boot() {
  await ready();
  $('version').textContent = `cnac ${version()} · wasm`;
  const schema = JSON.parse(queryables());
  $('queryable-count').textContent =
    `${schema.length} queryable properties. A rule naming anything else is refused at load, not at evaluation.`;
  $('queryable-count').title = schema.join('\n');

  for (const preset of POLICY_PRESETS) {
    $('policy-presets').append(chip(preset.name, () => { applyPreset(preset); writeUrl(); }));
  }

  const select = $('source-format');
  for (const [value, name] of [['auto', 'detect from the URL'], ...FORMATS.map((f) => [f.id, f.name])]) {
    const option = el('option', '', name);
    option.value = value;
    select.append(option);
  }
  for (const example of EXAMPLES) {
    $('source-examples').append(chip(example.name, () => {
      $('source-url').value = example.url;
      $('source-format').value = 'auto';
      $('source-example-note').textContent = example.note;
      describeDetection();
      loadCustom(example.url).then((ok) => { if (ok) afterLoad(); });
    }, example.url));
  }

  $('policy').addEventListener('input', () => { loadPolicy(); writeUrlSoon(); });
  $('principal').addEventListener('input', () => { loadPolicy(); writeUrlSoon(); });
  $('cog-level').addEventListener('change', () => {
    if (state.files.cog) {
      state.files.cog.runs = {};
      state.logPick = null;
      paintGrid(state.files.cog);
      renderMatrix('cog');
      renderBars('cog');
      renderRefusals('cog');
      renderLog();
    }
    renderQuery();
    renderRunBar();
    writeUrl();
  });
  $('deny-refuse').addEventListener('click', () => { setDenial('refuse'); writeUrl(); });
  $('run-all').addEventListener('click', runAll);

  $('source-samples').addEventListener('click', async () => {
    if (state.source.mode === SAMPLES && !state.source.failed) return;
    await loadSamples();
    state.source.failed = false;
    afterLoad();
    await writeUrl();
  });
  $('source-custom').addEventListener('click', () => {
    $('custom-fields').hidden = false;
    $('source-custom').setAttribute('aria-checked', 'true');
    $('source-samples').setAttribute('aria-checked', 'false');
    $('source-url').focus();
  });
  $('source-url').addEventListener('input', describeDetection);
  $('source-format').addEventListener('change', describeDetection);
  $('source-load').addEventListener('click', async () => {
    if (await loadCustom($('source-url').value)) {
      afterLoad();
      await writeUrl();
    }
  });
  $('source-url').addEventListener('keydown', (event) => {
    if (event.key === 'Enter') $('source-load').click();
  });

  for (const id of PANELS) {
    $(`${id}-toggle`).addEventListener('click', () => {
      setPanel(id, $(`${id}-toggle`).getAttribute('aria-expanded') !== 'true');
      writeUrl();
    });
  }
  $('setup-toggle').addEventListener('click', () => { setSetup(!state.setupOpen); writeUrl(); });
  $('copy-link').addEventListener('click', copyLink);

  await applyQuery();
  state.booting = false;
  await writeUrl();
}

/** A new file means a new vocabulary: new areas, a policy rewritten for it. */
function afterLoad() {
  buildAoiChips();
  applyPreset(POLICY_PRESETS.find((p) => p.id === state.preset) || POLICY_PRESETS[0]);
}

boot().catch((err) => {
  $('version').textContent = `failed: ${err.message || err}`;
  const diag = $('policy-diag');
  diag.className = 'diag bad';
  diag.textContent = String(err.stack || err);
});
