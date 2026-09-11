// The page. Reads the policy, colours the grids, runs the two readers, and
// keeps the four numbers that are the point of all of it.

import {
  BLOCK_SIZE,
  Policy,
  buildIndex,
  isCrossOrigin,
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
  POLICY_PRESETS,
  PRINCIPAL,
  QUERY_COLUMNS,
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
    rowsLabel: 'all 400,000 rows',
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

const MODES = [
  { id: 'coalesced', name: 'Library defaults', hint: 'coalesced' },
  { id: 'aligned', name: 'Boundary-aligned', hint: 'one structure per range' },
];

/** The disclosures whose open/closed state travels in the link. */
const PANELS = ['source', 'log'];
const PANELS_DEFAULT = 'log,source';

const $ = (id) => document.getElementById(id);

const state = {
  mode: 'coalesced',
  policyText: '',
  policy: null,
  policyError: null,
  user: PRINCIPAL,
  userError: null,
  lastLog: null,
  files: {},
  // `mode` is SAMPLES or 'custom'. `format` is the override, 'auto' or a
  // format id -- what the *user* said, kept apart from what the URL implies.
  source: { mode: SAMPLES, url: '', format: 'auto' },
  preset: POLICY_PRESETS[0].id,
  aoi: AOIS[0].id,
  panels: new Set(PANELS),
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

/**
 * The bytes the resolver could not attribute to anything.
 *
 * `LayoutIndex` fills every gap so that coverage of the object is total, and
 * those fillers are their own kind on purpose -- if they classified as
 * metadata, the `region.kind = 'metadata'` rule everybody writes would become
 * a wildcard over exactly the bytes the resolver understood least. The
 * consequence is that a file with a gap in its header denies the first read a
 * reader makes, which is a surprise worth spending a sentence on rather than
 * leaving the reader to find "denied by unmapped" in the log.
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

// ---- the file's own vocabulary ------------------------------------------
//
// The presets are written against the bundled files: four taxi columns to
// select, two to withhold, three polygons over one Sentinel granule. None of
// that survives contact with somebody else's object, so each of them falls
// back to the loaded file's own columns and its own extent -- and returns the
// hardcoded answer whenever the loaded file is in fact the bundled one, so a
// page with nothing in its query string writes exactly the document it always
// wrote.

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

function queryColumns() {
  const columns = fileColumns();
  if (!columns || QUERY_COLUMNS.every((c) => columns.includes(c))) return QUERY_COLUMNS;
  const withheld = withheldColumns();
  const open = columns.filter((c) => !withheld.includes(c));
  return (open.length ? open : columns).slice(0, 4);
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
//
// Read once on load, rewritten on every change. `replaceState`, so the back
// button still goes back to wherever the reader came from rather than to the
// previous keystroke.

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
  if (state.mode !== 'coalesced') params.set('m', state.mode);
  const level = $('cog-level').value;
  if (level && level !== '0') params.set('lvl', level);
  const panels = [...state.panels].sort().join(',');
  if (panels !== PANELS_DEFAULT) params.set('panel', panels);
  writeQuery(params);
}

const writeUrlSoon = debounce(writeUrl, 400);

function copyNote(text, ok = true) {
  const note = $('copy-note');
  note.textContent = text;
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
  const text = $('policy').value;
  state.policyText = text;
  let next = null;
  try {
    next = new Policy(text);
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
    const rules = (text.match(/^\s*-\s/gm) || []).length;
    diag.className = 'diag ok';
    diag.textContent = `Loaded. ${rules} rule${rules === 1 ? '' : 's'}, every property checked against the queryables schema.`;
    $('policy-state').textContent = `${rules} rules`;
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

function refreshVerdicts() {
  const usable = state.policy && !state.policyError && !state.userError;
  for (const file of Object.values(state.files)) {
    if (!file.index) continue;
    file.verdicts = usable
      ? file.index.verdicts(state.policy, state.user)
      : new Uint8Array(file.index.regionCount);
    paintGrid(file);
    paintStrip(file);
  }
  for (const key of Object.keys(state.files)) paintScores(key);
  renderLog();
  for (const button of document.querySelectorAll('.go')) {
    if (button.id !== 'source-load') button.disabled = !usable;
  }
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

  host.append(gridTitle('Column chunks', `${groups.length} row groups × ${columns.length} columns`));

  const scroll = el('div', 'grid-scroll');
  const grid = el('div', 'pq');
  grid.style.gridTemplateColumns = `auto repeat(${columns.length}, 1.375rem)`;

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

  const blooms = file.regions.filter((r) => r.kind === 'bloom_filter');
  if (blooms.length) {
    const note = el('p', 'preset-note');
    note.id = 'parquet-bloom-note';
    note.dataset.count = String(blooms.length);
    host.append(note);
  }
  file.columnHeads = grid.querySelectorAll('.head');
  file.columns = columns;
  file.rowGroups = groups.length;
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
  grid.style.gridTemplateColumns = `repeat(${regions.length}, 1.375rem)`;
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

  host.append(gridTitle('Tiles', `${tiles.length} across ${levels.length} overview levels`));

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
  paintAoi();
}

function paintAoi() {
  const bbox = aoiBboxFrom(state.policyText);
  const area = $('cog-area');
  if (area) {
    area.textContent = bbox
      ? `Reading the licensed area: ${((bbox[2] - bbox[0]) / 1000).toFixed(1)} × ${((bbox[3] - bbox[1]) / 1000).toFixed(1)} km, EPSG:32610.`
      : 'This policy has no licensed area, so the query reads the whole scene. At full resolution that is 120.6 megapixels — pick a coarser overview level.';
  }
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

function paintGrid(file) {
  for (const [i, cell] of file.cells) {
    cell.classList.toggle('denied', !file.verdicts[i]);
    cell.classList.remove('touched', 'blocked');
  }
  const run = file.runs?.[state.mode];
  if (run) for (const entry of run.log) markTouched(file, entry);

  if (file.key === 'parquet') {
    for (const head of file.columnHeads || []) {
      const denied = file.regions.some(
        (r) => r.kind === 'column_chunk' && r.column === head.dataset.column && !file.verdicts[r.i],
      );
      head.classList.toggle('denied', denied);
    }
    const note = $('parquet-bloom-note');
    if (note) {
      const total = Number(note.dataset.count);
      const allowed = file.regions.filter((r) => r.kind === 'bloom_filter' && file.verdicts[r.i]).length;
      note.textContent = `${total} bloom-filter regions, ${allowed} of them allowed. This query does not filter, so it never reads one — but a policy that forgets they exist leaves a value oracle open.`;
    }
  }
}

function markTouched(file, entry) {
  for (const i of entry.regions) {
    const cell = file.cells.get(i);
    if (cell) cell.classList.add(entry.allowed ? 'touched' : 'blocked');
  }
}

// ---- byte strip ---------------------------------------------------------

function paintStrip(file) {
  const host = $(`${file.key}-strip`);
  host.textContent = '';

  const head = el('div', 'strip-head');
  head.append(
    el('span', '', 'byte 0'),
    el('span', '', `the whole object, ${bytes(file.size)}, coloured by verdict`),
    el('span', '', String(file.size)),
  );
  host.append(head);

  const strip = el('div', 'strip');
  const bands = el('div', 'bands');

  const stops = [];
  let colour = null;
  let from = 0;
  const emit = (to) => {
    const a = ((from / file.size) * 100).toFixed(4);
    const b = ((to / file.size) * 100).toFixed(4);
    stops.push(`${colour} ${a}%`, `${colour} ${b}%`);
  };
  for (const r of file.regions) {
    const next = file.verdicts[r.i] ? 'var(--allow-soft)' : 'var(--deny-soft)';
    if (colour === null) { colour = next; from = r.start; continue; }
    if (next !== colour) { emit(r.start); colour = next; from = r.start; }
  }
  if (colour !== null) emit(file.size);
  bands.style.background = `linear-gradient(to right, ${stops.join(',')})`;
  strip.append(bands);

  const hits = el('div', 'hits');
  hits.id = `${file.key}-hits`;
  strip.append(hits);
  host.append(strip);

  const run = file.runs?.[state.mode];
  if (run) for (const entry of run.log) markHit(file, entry);
}

function markHit(file, entry) {
  const hits = $(`${file.key}-hits`);
  if (!hits) return;
  const mark = el('div', entry.allowed ? 'hit' : 'hit no');
  mark.style.left = `${(entry.start / file.size) * 100}%`;
  mark.style.width = `${Math.max(0.15, (entry.length / file.size) * 100)}%`;
  mark.title = `#${entry.n} bytes=${entry.start}-${entry.end - 1}`;
  hits.append(mark);
}

// ---- counters -----------------------------------------------------------

function paintScores(key) {
  const file = state.files[key];
  const host = $(`${key}-scores`);
  host.textContent = '';
  for (const mode of MODES) {
    const run = file.runs?.[mode.id];
    const box = el('div', `score${mode.id === state.mode ? ' live' : ''}`);

    const heading = el('h3', '', mode.name);
    heading.append(el('em', '', mode.hint));
    box.append(heading);

    const dl = document.createElement('dl');
    const row = (term, value, cls = '', why = '') => {
      const dt = el('dt', '', term);
      if (why) dt.title = why;
      dl.append(dt, el('dd', cls, value));
    };
    row(
      'Ranges issued',
      run ? String(run.issued) : '—',
      '',
      'Every range the reader asked for, whether or not it was served.',
    );
    row(
      'Straddling a boundary',
      run ? String(run.straddling) : '—',
      run && run.straddling === 0 ? 'straddle-value zero' : 'straddle-value',
      'Ranges covering both a permitted region and a refused one. A decision that must hold for every byte it authorizes has to refuse all of them.',
    );
    row(
      'Bytes fetched',
      run ? bytes(run.bytes) : '—',
      '',
      'Bytes the policy authorized and the reader then retrieved. Refused ranges are never requested.',
    );
    box.append(dl);

    // `run.detail` quotes region names out of the file, so it is set as text.
    const outcome = el('div');
    if (!run) {
      outcome.className = 'outcome idle';
      outcome.textContent = 'not run yet';
    } else {
      outcome.className = `outcome ${run.ok ? 'ok' : 'no'}`;
      outcome.append(
        el('b', '', run.ok ? 'QUERY COMPLETED' : 'QUERY FAILED'),
        el('span', '', run.detail),
      );
    }
    box.append(outcome);
    host.append(box);
  }
}

// ---- log ----------------------------------------------------------------

function renderLog() {
  const host = $('log');
  host.textContent = '';
  const which = state.lastLog;
  const file = which && state.files[which.key];
  const run = file?.runs?.[which.mode];
  if (!run) {
    $('log-which').textContent = 'nothing run yet';
    host.append(el('div', 'log-empty', 'Run a query to see every range it asked for.'));
    return;
  }
  $('log-which').textContent = `${which.key} · ${MODES.find((m) => m.id === which.mode).name} · ${run.log.length} ranges`;

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
  return `Refused ${where}, which covers ${refused.regions.length} region${
    refused.regions.length === 1 ? '' : 's'
  }. Denied by ${names}.`;
}

async function runOne(key, mode) {
  const file = state.files[key];
  const busy = $(`${key}-busy`);
  const previous = state.mode;
  state.mode = mode;

  file.runs ??= {};
  delete file.runs[mode];
  paintScores(key);
  paintGrid(file);
  paintStrip(file);
  busy.textContent = `running ${MODES.find((m) => m.id === mode).name.toLowerCase()}…`;

  const gate = makeGate({
    index: file.index,
    policy: state.policy,
    user: state.user,
    url: file.url,
    labels: (regions) => summarise(file, regions),
    onRequest: (entry) => { markTouched(file, entry); markHit(file, entry); },
  });

  const started = performance.now();
  let ok = false;
  let detail = '';
  try {
    if (key === 'parquet') {
      const columns = file.queryColumns;
      const { rows } = await runParquet({
        gate,
        size: file.size,
        columns,
        aligned: mode === 'aligned',
        rowEnd: file.rowEnd,
      });
      ok = true;
      detail = `${rows.toLocaleString()} rows decoded from ${
        mode === 'aligned' ? `${columns.length} projected columns` : `all ${file.columns.length} columns`
      }`;
    } else {
      const level = Number($('cog-level').value);
      const bbox = aoiBboxFrom(state.policyText) || sceneExtent();
      const result = await runCog({
        gate,
        size: file.size,
        level,
        bbox,
        aligned: mode === 'aligned',
        maxPixels: 4e6,
      });
      ok = true;
      detail = `${result.width}×${result.height} pixels decoded from level ${level}`;
      drawPreview(result, level);
    }
  } catch (err) {
    detail = explain(file, gate, err);
  }

  file.runs[mode] = {
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

  state.mode = previous;
  state.lastLog = { key, mode };
  busy.textContent = '';
  setMode(mode);
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
  $('parquet-panel').hidden = !keys.includes('parquet');
  $('cog-panel').hidden = !keys.includes('cog');
  $('aoi-block').hidden = !keys.includes('cog');
  $('cog-preview').hidden = true;
  state.lastLog = null;

  const hosting = [];
  for (const { spec, info, index, window, regions } of prepared) {
    const file = {
      key: spec.key,
      url: spec.url,
      size: info.size,
      index,
      regions,
      window,
      cells: new Map(),
      runs: {},
    };
    state.files[spec.key] = file;
    hosting.push(
      `${spec.key} ${info.rangeStatus}${info.servedWhole ? ' whole body' : ''}, ${info.contentEncoding}`,
    );

    if (spec.key === 'parquet') {
      buildParquetGrid(file);
      file.queryColumns = queryColumns();
      file.rowEnd = spec.rowsLabel ? undefined : CUSTOM_ROW_CAP;
      file.rowsLabel = spec.rowsLabel || `the first ${CUSTOM_ROW_CAP.toLocaleString()} rows`;
      $('parquet-title').textContent =
        `Parquet · ${file.rowGroups} row groups × ${file.columns.length} columns`;
      $('parquet-meta').textContent =
        `${spec.label} · ${bytes(info.size)} · ${index.regionCount} regions · footer read from the last ${bytes(window)}`;
    } else {
      buildCogGrid(file);
      file.extent = extentOf(regions) || SCENE_EXTENT;
      const tiles = file.levels.map((l) => l.tiles).reduce((a, b) => a + b, 0);
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
  $('hosting').textContent = hosting.join(' · ');
  describeQueries();
}

function describeQueries() {
  const pq = state.files.parquet;
  if (pq) {
    $('parquet-query').textContent =
      `SELECT ${pq.queryColumns.join(', ')} — ${pq.rowsLabel}, all ${pq.rowGroups} row groups. `
      + 'Boundary-aligned passes that column list to hyparquet; the default position does not pass one, '
      + `so hyparquet reads every one of the ${pq.columns.length} columns and merges each row group `
      + 'into a single request under its 2 MB run limit.';
  }
  if (state.files.cog) {
    $('cog-query').textContent =
      'Read the licensed area at one overview level. Boundary-aligned hands the policy source '
      + 'straight to geotiff.js; the default position wraps it in the same '
      + `${BLOCK_SIZE / 1024} KB blocking layer fromUrl installs, which aligns reads to blocks `
      + 'rather than to tiles.';
  }
}

// ---- the source panel ---------------------------------------------------

function sourceDiag(kind, heading, detail, link) {
  const diag = $('source-diag');
  diag.className = `diag ${kind}`;
  diag.textContent = '';
  if (heading) diag.append(el('b', '', heading));
  diag.append(document.createTextNode(detail));
  if (link) {
    diag.append(document.createTextNode('\n'));
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
  $('source-meta').textContent = custom
    ? `${formatName(state.files.parquet ? 'parquet' : 'cog')} from ${isCrossOrigin(state.source.url || location.href) ? new URL(state.source.url, location.href).host : 'this origin'}`
    : 'two bundled samples';
}

// ---- wiring -------------------------------------------------------------

function setMode(mode) {
  state.mode = mode;
  $('mode-coalesced').setAttribute('aria-checked', String(mode === 'coalesced'));
  $('mode-aligned').setAttribute('aria-checked', String(mode === 'aligned'));
  for (const key of Object.keys(state.files)) {
    const file = state.files[key];
    if (!file.index) continue;
    paintScores(key);
    paintGrid(file);
    paintStrip(file);
  }
  renderLog();
}

function setPanel(id, open) {
  $(`${id}-toggle`).setAttribute('aria-expanded', String(open));
  $(`${id}-body`).hidden = !open;
  if (open) state.panels.add(id); else state.panels.delete(id);
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
  paintAoi();
}

function applyAoi(aoi) {
  const text = $('policy').value;
  if (!/POLYGON/i.test(text)) {
    $('aoi-note').textContent = `This policy has no spatial rule, so ${aoi.name} changes nothing. Pick a policy with a licensed area first.`;
    return;
  }
  state.aoi = aoi.id;
  $('policy').value = substituteAoi(text, aoiWkt(aoi));
  $('aoi-note').textContent = aoi.note;
  loadPolicy();
  paintAoi();
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
  for (const aoi of currentAois()) host.append(chip(aoi.name, () => { applyAoi(aoi); writeUrl(); }));
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
    }
  }

  buildAoiChips();

  const presetId = q.get('preset');
  const preset = POLICY_PRESETS.find((p) => p.id === presetId) || POLICY_PRESETS[0];
  const aoiId = q.get('aoi');
  const aoi = currentAois().find((a) => a.id === aoiId) || currentAois()[0];
  state.aoi = aoi.id;
  applyPreset(preset);
  $('aoi-note').textContent = aoi.note;

  const policyText = q.get('p');
  if (policyText !== null) {
    $('policy').value = await unpack(policyText);
    loadPolicy();
    paintAoi();
  }

  const level = q.get('lvl');
  if (level && [...$('cog-level').options].some((o) => o.value === level)) {
    $('cog-level').value = level;
  }

  setMode(q.get('m') === 'aligned' ? 'aligned' : 'coalesced');

  const panels = q.get('panel');
  const open = new Set((panels === null ? PANELS_DEFAULT : panels).split(',').filter(Boolean));
  for (const id of PANELS) setPanel(id, open.has(id));
}

async function boot() {
  await ready();
  $('version').textContent = `cnac ${version()} · wasm`;
  const schema = JSON.parse(queryables());
  $('queryable-count').textContent = `${schema.length} queryable properties`;
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
      loadCustom(example.url);
    }, example.url));
  }

  $('policy').addEventListener('input', () => { loadPolicy(); paintAoi(); writeUrlSoon(); });
  $('principal').addEventListener('input', () => { loadPolicy(); writeUrlSoon(); });
  $('mode-coalesced').addEventListener('click', () => { setMode('coalesced'); writeUrl(); });
  $('mode-aligned').addEventListener('click', () => { setMode('aligned'); writeUrl(); });
  $('cog-level').addEventListener('change', writeUrl);
  $('parquet-run').addEventListener('click', () => runOne('parquet', state.mode));
  $('cog-run').addEventListener('click', () => runOne('cog', state.mode));
  $('parquet-both').addEventListener('click', async () => {
    await runOne('parquet', 'coalesced');
    await runOne('parquet', 'aligned');
  });
  $('cog-both').addEventListener('click', async () => {
    await runOne('cog', 'coalesced');
    await runOne('cog', 'aligned');
  });

  $('source-samples').addEventListener('click', async () => {
    if (state.source.mode === SAMPLES && !state.source.failed) return;
    await loadSamples();
    state.source.failed = false;
    buildAoiChips();
    applyPreset(POLICY_PRESETS.find((p) => p.id === state.preset) || POLICY_PRESETS[0]);
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
      buildAoiChips();
      applyPreset(POLICY_PRESETS.find((p) => p.id === state.preset) || POLICY_PRESETS[0]);
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
  $('copy-link').addEventListener('click', copyLink);

  await applyQuery();
  state.booting = false;
  await writeUrl();
}

boot().catch((err) => {
  $('version').textContent = `failed: ${err.message || err}`;
  const diag = $('policy-diag');
  diag.className = 'diag bad';
  diag.textContent = String(err.stack || err);
});
