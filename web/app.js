// The page. Reads the policy, colours the grids, runs the two readers, and
// keeps the four numbers that are the point of all of it.

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
  POLICY_PRESETS,
  PRINCIPAL,
  QUERY_COLUMNS,
  SCENE_EXTENT,
  aoiBboxFrom,
  aoiWkt,
  substituteAoi,
} from './presets.js';

const DATA = {
  parquet: '../data/nyc-taxi-8rg.parquet',
  cog: '../data/s2-tci-512.tif',
};

const MODES = [
  { id: 'coalesced', name: 'Library defaults', hint: 'coalesced' },
  { id: 'aligned', name: 'Boundary-aligned', hint: 'one structure per range' },
];

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
  for (const button of document.querySelectorAll('.go')) button.disabled = !usable;
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

function buildParquetGrid(file) {
  const host = $('parquet-grid');
  host.textContent = '';
  file.cells = new Map();

  const chunks = file.regions.filter((r) => r.kind === 'column_chunk');
  const columns = [...new Set(chunks.map((r) => r.column))];
  const groups = [...new Set(chunks.map((r) => r.row_group))].sort((a, b) => a - b);
  const byKey = new Map(chunks.map((r) => [`${r.row_group}/${r.column}`, r.i]));

  const title = document.createElement('div');
  title.className = 'grid-title';
  title.innerHTML = `<b>Column chunks</b><span>${groups.length} row groups × ${columns.length} columns</span>`;
  host.append(title);

  const scroll = document.createElement('div');
  scroll.className = 'grid-scroll';
  const grid = document.createElement('div');
  grid.className = 'pq';
  grid.style.gridTemplateColumns = `auto repeat(${columns.length}, 1.375rem)`;

  grid.append(document.createElement('div'));
  for (const column of columns) {
    const head = document.createElement('div');
    head.className = 'head';
    head.textContent = column;
    head.dataset.column = column;
    grid.append(head);
  }
  for (const group of groups) {
    const label = document.createElement('div');
    label.className = 'rowlab';
    label.textContent = `rg ${group}`;
    grid.append(label);
    for (const column of columns) grid.append(cellFor(file, byKey.get(`${group}/${column}`)));
  }
  scroll.append(grid);
  host.append(scroll);

  host.append(metadataBlock(file, 'Footer and magic', (r) => r.kind === 'metadata'));

  const blooms = file.regions.filter((r) => r.kind === 'bloom_filter');
  if (blooms.length) {
    const note = document.createElement('p');
    note.className = 'preset-note';
    note.id = 'parquet-bloom-note';
    note.dataset.count = String(blooms.length);
    host.append(note);
  }
  file.columnHeads = grid.querySelectorAll('.head');
}

function metadataBlock(file, heading, predicate) {
  const block = document.createElement('div');
  block.className = 'grid-block';
  const regions = file.regions.filter(predicate);
  const title = document.createElement('div');
  title.className = 'grid-title';
  title.innerHTML = `<b>${heading}</b><span>${regions.length} regions · the reader needs these to find anything else</span>`;
  block.append(title);

  const scroll = document.createElement('div');
  scroll.className = 'grid-scroll';
  const grid = document.createElement('div');
  grid.className = 'pq';
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

  const title = document.createElement('div');
  title.className = 'grid-title';
  title.innerHTML = `<b>Tiles</b><span>${tiles.length} across ${levels.length} overview levels</span>`;
  host.append(title);

  const wrap = document.createElement('div');
  wrap.className = 'levels';
  file.levels = [];

  for (const level of levels) {
    const own = tiles.filter((r) => r.overview_level === level);
    const cols = Math.max(...own.map((r) => r.x)) + 1;
    const rows = Math.max(...own.map((r) => r.y)) + 1;
    const byKey = new Map(own.map((r) => [`${r.x}/${r.y}`, r.i]));

    const box = document.createElement('div');
    box.className = 'level';
    const label = document.createElement('div');
    label.className = 'grid-title';
    label.innerHTML = `<b>L${level}</b><span>${cols}×${rows}</span>`;
    box.append(label);

    const board = document.createElement('div');
    board.className = 'board';
    const side = Math.max(6, Math.min(18, Math.round(160 / cols)));
    board.style.gridTemplateColumns = `repeat(${cols}, ${side}px)`;
    for (let y = 0; y < rows; y += 1) {
      for (let x = 0; x < cols; x += 1) board.append(cellFor(file, byKey.get(`${x}/${y}`)));
    }
    const aoi = document.createElement('div');
    aoi.className = 'aoi';
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
  const [ex0, ey0, ex1, ey1] = SCENE_EXTENT;
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

  const head = document.createElement('div');
  head.className = 'strip-head';
  head.innerHTML = `<span>byte 0</span><span>the whole object, ${bytes(file.size)}, coloured by verdict</span><span>${file.size}</span>`;
  host.append(head);

  const strip = document.createElement('div');
  strip.className = 'strip';
  const bands = document.createElement('div');
  bands.className = 'bands';

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

  const hits = document.createElement('div');
  hits.className = 'hits';
  hits.id = `${file.key}-hits`;
  strip.append(hits);
  host.append(strip);

  const run = file.runs?.[state.mode];
  if (run) for (const entry of run.log) markHit(file, entry);
}

function markHit(file, entry) {
  const hits = $(`${file.key}-hits`);
  if (!hits) return;
  const mark = document.createElement('div');
  mark.className = entry.allowed ? 'hit' : 'hit no';
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
    const box = document.createElement('div');
    box.className = `score${mode.id === state.mode ? ' live' : ''}`;

    const heading = document.createElement('h3');
    heading.innerHTML = `${mode.name}<em>${mode.hint}</em>`;
    box.append(heading);

    const dl = document.createElement('dl');
    const row = (term, value, cls = '', why = '') => {
      const dt = document.createElement('dt');
      dt.textContent = term;
      if (why) dt.title = why;
      const dd = document.createElement('dd');
      dd.className = cls;
      dd.innerHTML = value;
      dl.append(dt, dd);
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

    const outcome = document.createElement('div');
    if (!run) {
      outcome.className = 'outcome idle';
      outcome.textContent = 'not run yet';
    } else if (run.ok) {
      outcome.className = 'outcome ok';
      outcome.innerHTML = `<b>QUERY COMPLETED</b><span>${run.detail}</span>`;
    } else {
      outcome.className = 'outcome no';
      outcome.innerHTML = `<b>QUERY FAILED</b><span>${run.detail}</span>`;
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
    host.innerHTML = '<div class="log-empty">Run a query to see every range it asked for.</div>';
    return;
  }
  $('log-which').textContent = `${which.key} · ${MODES.find((m) => m.id === which.mode).name} · ${run.log.length} ranges`;

  const table = document.createElement('table');
  table.className = 'log';
  table.innerHTML =
    '<thead><tr><th>#</th><th>range</th><th class="r">bytes</th><th>resolved to</th><th class="v">verdict</th><th>why</th></tr></thead>';
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
    tr.innerHTML = `
      <td class="n">${entry.n}</td>
      <td>${entry.start}–${entry.end - 1}</td>
      <td class="r">${bytes(entry.length)}</td>
      <td>${summarise(file, entry.regions)}</td>
      <td class="v">${entry.allowed ? 'allow' : 'DENY'}${entry.straddles ? ' · straddles' : ''}</td>
      <td class="why">${why}</td>`;
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
      const { rows } = await runParquet({
        gate,
        size: file.size,
        columns: QUERY_COLUMNS,
        aligned: mode === 'aligned',
      });
      ok = true;
      detail = `${rows.toLocaleString()} rows decoded from ${
        mode === 'aligned' ? `${QUERY_COLUMNS.length} projected columns` : 'all 19 columns'
      }`;
    } else {
      const level = Number($('cog-level').value);
      const bbox = aoiBboxFrom(state.policyText) || SCENE_EXTENT;
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

function applyPreset(preset) {
  const current = aoiBboxFrom($('policy').value);
  const aoi = AOIS.find((a) => current && a.bbox.every((v, i) => v === current[i])) || AOIS[0];
  $('policy').value = preset.build(aoiWkt(aoi));
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
  $('policy').value = substituteAoi(text, aoiWkt(aoi));
  $('aoi-note').textContent = aoi.note;
  loadPolicy();
  paintAoi();
}

function chip(label, onClick) {
  const button = document.createElement('button');
  button.type = 'button';
  button.textContent = label;
  button.addEventListener('click', onClick);
  return button;
}

async function boot() {
  await ready();
  $('version').textContent = `cnac ${version()} · wasm`;
  const schema = JSON.parse(queryables());
  $('queryable-count').textContent = `${schema.length} queryable properties`;
  $('queryable-count').title = schema.join('\n');

  for (const preset of POLICY_PRESETS) {
    $('policy-presets').append(chip(preset.name, () => applyPreset(preset)));
  }
  for (const aoi of AOIS) {
    $('aoi-presets').append(chip(aoi.name, () => applyAoi(aoi)));
  }
  $('principal').value = PRINCIPAL;
  applyPreset(POLICY_PRESETS[0]);
  $('aoi-note').textContent = AOIS[0].note;

  $('policy').addEventListener('input', () => { loadPolicy(); paintAoi(); });
  $('principal').addEventListener('input', loadPolicy);
  $('mode-coalesced').addEventListener('click', () => setMode('coalesced'));
  $('mode-aligned').addEventListener('click', () => setMode('aligned'));
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

  $('parquet-query').textContent =
    `SELECT ${QUERY_COLUMNS.join(', ')} — all 400,000 rows, all 8 row groups. ` +
    'Boundary-aligned passes that column list to hyparquet; the default position does not pass one, ' +
    'so hyparquet reads every column and merges each row group into a single request under its 2 MB run limit.';
  $('cog-query').textContent =
    `Read the licensed area at one overview level. Boundary-aligned hands the policy source straight to geotiff.js; ` +
    `the default position wraps it in the same ${BLOCK_SIZE / 1024} KB blocking layer fromUrl installs, which aligns reads to blocks rather than to tiles.`;

  const hosting = [];
  for (const [key, url] of Object.entries(DATA)) {
    const file = { key, url, cells: new Map(), runs: {} };
    state.files[key] = file;
    const info = await probe(url);
    file.size = info.size;
    hosting.push(
      `${key} ${info.rangeStatus}${info.servedWhole ? ' whole body' : ''}, ${info.contentEncoding}`,
    );

    const { index, window } = await buildIndex(key === 'parquet' ? 'parquet' : 'cog', url, info.size);
    file.index = index;
    file.regions = JSON.parse(index.regions());
    file.window = window;

    if (key === 'parquet') {
      buildParquetGrid(file);
      $('parquet-meta').textContent = `nyc-taxi-8rg.parquet · ${bytes(info.size)} · ${index.regionCount} regions · footer read from the last ${bytes(window)}`;
    } else {
      buildCogGrid(file);
      const levels = file.levels.map((l) => l.tiles).reduce((a, b) => a + b, 0);
      $('cog-meta').textContent = `s2-tci-512.tif · ${bytes(info.size)} · ${levels} tiles · IFDs read from the first ${bytes(window)}`;
      const select = $('cog-level');
      for (const l of file.levels) {
        const option = document.createElement('option');
        option.value = String(l.level);
        option.textContent = `L${l.level} — ${l.tiles} tile${l.tiles === 1 ? '' : 's'}`;
        select.append(option);
      }
      select.value = '0';
    }
  }

  $('hosting').textContent = hosting.join(' · ');
  refreshVerdicts();
}

boot().catch((err) => {
  $('version').textContent = `failed: ${err.message || err}`;
  const diag = $('policy-diag');
  diag.className = 'diag bad';
  diag.textContent = String(err.stack || err);
});
