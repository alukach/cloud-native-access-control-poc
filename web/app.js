// Two questions, one file picker.
//
//   1. What is in this byte range?
//   2. What does a policy withhold from a reader?
//
// Neither answer is computed here. The first comes from the Rust resolver and
// the second from a real engine reading through the gate; this file only picks
// files, draws results, and keeps the address bar in step.

import { open, supported } from './gate.js';
import {
  AREAS, POLICIES, SAMPLES, buildPolicy, policiesFor, sampleById, suggestedRanges,
} from './catalog.js';
import { readersFor, readerById } from './readers.js';
import { pack, unpack } from './share.js';

const $ = (id) => document.getElementById(id);
const el = (tag, cls, text) => {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (text !== undefined) node.textContent = text;
  return node;
};

const bytes = (n) => (
  n >= 1e6 ? `${(n / 1e6).toFixed(2)} MB`
    : n >= 1e3 ? `${(n / 1e3).toFixed(1)} kB`
      : `${n} B`
);

const PERMIT_ALL = 'allow:\n  - "1 = 1"\n';

const state = {
  tab: 'inspect',
  sample: SAMPLES[0].id,
  url: '',
  format: 'auto',
  file: null,
  /** The permit-all gate feature 1 resolves against. */
  lens: null,
  /** The policy gate feature 2 queries through. */
  gate: null,
  policyId: null,
  policyText: '',
  principal: '{"role": "analyst"}',
  mode: 'filter',
  area: AREAS[0].id,
  reader: null,
  range: '',
};

// ---- the file -------------------------------------------------------------

function activeSource() {
  if (state.url) {
    const guessed = state.format === 'auto'
      ? (/\.(parquet|pq)($|\?)/i.test(state.url) ? 'parquet' : 'cog')
      : state.format;
    return { url: state.url, format: guessed, name: state.url.split('/').pop() || state.url };
  }
  const sample = sampleById(state.sample) || SAMPLES[0];
  return {
    url: new URL(sample.path, location.href).href,
    format: sample.format,
    name: sample.name,
    blurb: sample.blurb,
  };
}

async function loadFile() {
  const source = activeSource();
  setState(`indexing ${source.name}…`, 'busy');
  state.lens?.release();
  state.gate?.release();
  state.lens = null;
  state.gate = null;
  state.file = null;

  try {
    state.lens = await open({
      url: source.url,
      format: source.format,
      policy: PERMIT_ALL,
      user: state.principal,
      mode: 'refuse',
    });
    state.file = { ...source, ...state.lens };
    setState(
      `${source.name} · ${bytes(state.lens.size)} · ${state.lens.regionCount} regions · `
      + `metadata read from ${bytes(state.lens.window)}`,
      'ok',
    );
    renderFileMeta();
    renderSuggestions();
    // Policies are per format, so an id carried over from the other one names
    // nothing. Fall back rather than leaving every chip unselected.
    const known = policiesFor(source.format).some((p) => p.id === state.policyId);
    const sameFormat = known && state.policyText;
    choosePolicy(known ? state.policyId : policiesFor(source.format)[0].id,
      { keepText: sameFormat });
    renderReaders();
    $('inspect-result').hidden = true;
    if (state.range) resolveRange(state.range);
  } catch (err) {
    setState(err?.message || String(err), 'bad');
  }
}

function setState(message, tone) {
  const node = $('file-state');
  node.className = `file-state ${tone}`;
  node.textContent = message;
}

function renderFilePicker() {
  const host = $('file-pick');
  host.textContent = '';
  for (const sample of SAMPLES) {
    const chip = el('button', `chip${!state.url && state.sample === sample.id ? ' on' : ''}`);
    chip.type = 'button';
    chip.append(el('b', '', sample.name), el('span', '', sample.format === 'parquet' ? 'Parquet' : 'COG'));
    chip.title = sample.blurb;
    chip.addEventListener('click', () => {
      state.sample = sample.id;
      state.url = '';
      $('file-url').value = '';
      renderFilePicker();
      writeUrl();
      loadFile();
    });
    host.append(chip);
  }
}

function renderFileMeta() {
  const file = state.file;
  const facts = $('file-facts');
  facts.textContent = '';
  const fact = (label, value, note) => {
    const box = el('div', 'fact');
    box.append(el('span', 'fact-label', label), el('span', 'fact-value', value));
    if (note) box.append(el('span', 'fact-note', note));
    facts.append(box);
  };

  const regions = file.regions;
  fact('Format', file.format === 'parquet' ? 'Parquet' : 'Cloud-optimized GeoTIFF');
  fact('Size', bytes(file.size));
  fact('Regions', String(file.regionCount), 'every byte classified');
  fact('Metadata', bytes(file.window), 'one speculative read');

  const layout = $('file-layout');
  layout.textContent = '';
  if (file.format === 'parquet') {
    const columns = [...new Set(regions.filter((r) => r.column).map((r) => r.column))];
    const groups = new Set(regions.filter((r) => r.kind === 'column_chunk').map((r) => r.row_group));
    fact('Shape', `${groups.size} × ${columns.length}`, 'row groups × columns');
    for (const column of columns) {
      const mine = regions.filter((r) => r.column === column);
      const total = mine.reduce((a, r) => a + (r.end - r.start), 0);
      const row = el('div', 'layout-row');
      row.append(el('span', 'layout-name', column));
      row.append(el('span', 'layout-note',
        `${mine.length} regions · ${bytes(total)} · `
        + [...new Set(mine.map((r) => r.kind))].join(', ')));
      layout.append(row);
    }
  } else {
    const levels = new Map();
    for (const r of regions) {
      if (r.kind !== 'tile') continue;
      levels.set(r.overview_level, (levels.get(r.overview_level) || 0) + 1);
    }
    fact('Pyramid', `${levels.size} levels`, `${[...levels.values()].reduce((a, b) => a + b, 0)} tiles`);
    for (const [level, count] of [...levels].sort((a, b) => a[0] - b[0])) {
      const row = el('div', 'layout-row');
      row.append(el('span', 'layout-name', `Level ${level}${level === 0 ? ' — full resolution' : ''}`));
      row.append(el('span', 'layout-note', `${count} tiles`));
      layout.append(row);
    }
    const names = [...new Set(regions.filter((r) => r.kind === 'metadata').map((r) => r.name))];
    const row = el('div', 'layout-row');
    row.append(el('span', 'layout-name', 'Structure'));
    row.append(el('span', 'layout-note', names.join(', ')));
    layout.append(row);
  }
}

// ---- feature 1: what is in this range? ------------------------------------

function renderSuggestions() {
  const host = $('range-suggestions');
  host.textContent = '';
  const file = state.file;
  if (!file) return;
  for (const s of suggestedRanges(file.format, file.regions, file.size)) {
    const card = el('button', 'suggestion');
    card.type = 'button';
    card.append(el('b', '', s.label));
    card.append(el('code', '', `bytes=${s.start}-${s.end - 1}`));
    card.append(el('span', '', s.why));
    card.addEventListener('click', () => {
      $('range-header').value = `bytes=${s.start}-${s.end - 1}`;
      resolveRange($('range-header').value);
    });
    host.append(card);
  }
}

function parseHeader(text, size) {
  const m = /^bytes=(\d+)-(\d*)$/.exec(text.trim());
  if (!m) return null;
  const start = Number(m[1]);
  const end = m[2] === '' ? size : Number(m[2]) + 1;
  if (!(end > start)) return null;
  return [start, Math.min(end, size)];
}

async function resolveRange(text) {
  const diag = $('range-diag');
  const file = state.file;
  if (!file) return;
  const parsed = parseHeader(text, file.size);
  if (!parsed) {
    diag.className = 'diag bad';
    diag.textContent = 'Write it as a reader would send it: bytes=START-END, inclusive.';
    $('inspect-result').hidden = true;
    return;
  }
  const [start, end] = parsed;
  state.range = `bytes=${start}-${end - 1}`;
  $('range-header').value = state.range;
  writeUrl();

  diag.className = 'diag';
  diag.textContent = '';
  try {
    const answer = await state.lens.resolve(start, end);
    renderResolved(answer, start, end);
  } catch (err) {
    diag.className = 'diag bad';
    diag.textContent = err?.message || String(err);
  }
}

function renderResolved(answer, start, end) {
  const file = state.file;
  const covered = answer.regions.map((i) => file.regions[i]).filter(Boolean);
  $('inspect-result').hidden = false;

  const facts = $('inspect-facts');
  facts.textContent = '';
  const fact = (label, value, note) => {
    const box = el('div', 'fact');
    box.append(el('span', 'fact-label', label), el('span', 'fact-value', value));
    if (note) box.append(el('span', 'fact-note', note));
    facts.append(box);
  };
  fact('Asked for', bytes(end - start), `${start.toLocaleString()} – ${(end - 1).toLocaleString()}`);
  fact('Regions covered', String(covered.length));

  const columns = [...new Set(covered.map((r) => r.column).filter(Boolean))];
  const tiles = covered.filter((r) => r.kind === 'tile');
  const structure = covered.filter((r) => r.kind === 'metadata');
  const unmapped = covered.filter((r) => r.kind === 'unmapped');

  if (file.format === 'parquet') {
    fact('Columns exposed', columns.length ? String(columns.length) : 'none',
      columns.length ? columns.slice(0, 4).join(', ') + (columns.length > 4 ? '…' : '') : 'structure only');
    const groups = [...new Set(covered.map((r) => r.row_group).filter((g) => g !== undefined))];
    if (groups.length) fact('Row groups', groups.join(', '));
  } else {
    fact('Tiles exposed', String(tiles.length));
    if (tiles.length) {
      const levels = [...new Set(tiles.map((t) => t.overview_level))].sort();
      fact('Levels', levels.join(', '), levels.includes(0) ? 'includes full resolution' : 'overviews only');
    }
  }
  if (structure.length) {
    fact('Structure', String(structure.length), [...new Set(structure.map((s) => s.name))].join(', '));
  }
  if (unmapped.length) {
    fact('Unclassified', String(unmapped.length), 'bytes no resolver could name');
  }

  // The regions themselves.
  const host = $('inspect-regions');
  host.textContent = '';
  for (const r of covered.slice(0, 60)) {
    const row = el('div', `region ${r.kind}`);
    row.append(el('span', 'region-kind', r.kind.replace(/_/g, ' ')));
    row.append(el('span', 'region-what', describeRegion(r)));
    row.append(el('span', 'region-bytes', `${bytes(r.end - r.start)}`));
    host.append(row);
  }
  if (covered.length > 60) {
    host.append(el('p', 'note', `…and ${covered.length - 60} more.`));
  }

  drawRuler(start, end, covered);
  drawFootprint(tiles);
  $('inspect-json').textContent = JSON.stringify(
    covered.map(({ i, ...rest }) => rest), null, 2,
  ).slice(0, 12000);
}

function describeRegion(r) {
  if (r.kind === 'column_chunk') return `${r.column} · row group ${r.row_group}`;
  if (r.kind === 'tile') return `tile (${r.x}, ${r.y}) · level ${r.overview_level}`;
  if (r.column) return r.column;
  if (r.name) return r.name;
  return '—';
}

/** Where the range lands in the object, and what it swept up getting there. */
function drawRuler(start, end, covered) {
  const host = $('inspect-ruler');
  host.textContent = '';
  const size = state.file.size;
  const bar = el('div', 'ruler-bar');
  const pct = (n) => `${((n / size) * 100).toFixed(4)}%`;
  for (const r of covered) {
    const mark = el('div', `ruler-region ${r.kind}`);
    mark.style.left = pct(r.start);
    mark.style.width = pct(Math.max(r.end - r.start, size / 2000));
    mark.title = describeRegion(r);
    bar.append(mark);
  }
  const ask = el('div', 'ruler-ask');
  ask.style.left = pct(start);
  ask.style.width = pct(Math.max(end - start, size / 2000));
  bar.append(ask);
  host.append(bar);
  host.append(el('p', 'note',
    `The whole object, left to right. The outlined span is what was asked for; the `
    + `blocks beneath it are the regions it covers.`));
}

/** For a COG: the ground the range exposes. */
function drawFootprint(tiles) {
  const wrap = $('inspect-map-wrap');
  const withBbox = tiles.filter((t) => Array.isArray(t.bbox));
  if (!withBbox.length) { wrap.hidden = true; return; }
  wrap.hidden = false;

  const canvas = $('inspect-map');
  const ctx = canvas.getContext('2d');
  const extent = state.file.regions
    .filter((r) => r.kind === 'tile' && Array.isArray(r.bbox))
    .reduce((acc, r) => [
      Math.min(acc[0], r.bbox[0], r.bbox[2]), Math.min(acc[1], r.bbox[1], r.bbox[3]),
      Math.max(acc[2], r.bbox[0], r.bbox[2]), Math.max(acc[3], r.bbox[1], r.bbox[3]),
    ], [Infinity, Infinity, -Infinity, -Infinity]);

  const [ex0, ey0, ex1, ey1] = extent;
  const w = canvas.width;
  const h = canvas.height;
  ctx.clearRect(0, 0, w, h);
  const css = getComputedStyle(document.body);
  ctx.fillStyle = css.getPropertyValue('--sunk') || '#eee';
  ctx.fillRect(0, 0, w, h);
  const toX = (x) => ((x - ex0) / (ex1 - ex0)) * w;
  const toY = (y) => h - ((y - ey0) / (ey1 - ey0)) * h;

  ctx.fillStyle = css.getPropertyValue('--deny-soft') || '#f7dfc4';
  ctx.strokeStyle = css.getPropertyValue('--deny') || '#b3560c';
  ctx.lineWidth = 1;
  for (const t of withBbox) {
    const [x0, y0, x1, y1] = t.bbox;
    const left = toX(Math.min(x0, x1));
    const right = toX(Math.max(x0, x1));
    const top = toY(Math.max(y0, y1));
    const bottom = toY(Math.min(y0, y1));
    ctx.fillRect(left, top, Math.max(right - left, 2), Math.max(bottom - top, 2));
    ctx.strokeRect(left, top, Math.max(right - left, 2), Math.max(bottom - top, 2));
  }
  $('inspect-map-note').textContent =
    `${withBbox.length} tile${withBbox.length === 1 ? '' : 's'} of ground, in the file's own CRS. `
    + 'This is the area that range exposes.';
}

// ---- feature 2: what does a policy withhold? ------------------------------

function renderPolicyPresets() {
  const host = $('policy-presets');
  host.textContent = '';
  const format = state.file?.format || 'parquet';
  for (const preset of policiesFor(format)) {
    const chip = el('button', `chip${state.policyId === preset.id ? ' on' : ''}`);
    chip.type = 'button';
    chip.append(el('b', '', preset.name));
    chip.addEventListener('click', () => choosePolicy(preset.id));
    host.append(chip);
  }
  const current = policiesFor(format).find((p) => p.id === state.policyId);
  $('policy-blurb').textContent = current?.blurb || '';
}

function choosePolicy(id, { keepText = false } = {}) {
  const format = state.file?.format || 'parquet';
  state.policyId = id;
  const area = AREAS.find((a) => a.id === state.area) || AREAS[0];
  const { text } = buildPolicy(format, id, { area: area.id, bbox: area.bbox });
  if (!keepText || !state.policyText) {
    state.policyText = text;
    $('policy').value = text;
  }
  renderPolicyPresets();
  writeUrl();
}

function renderReaders() {
  const host = $('reader-pick');
  host.textContent = '';
  const format = state.file?.format || 'parquet';
  const available = readersFor(format);
  if (!available.length) return;
  if (!available.some((r) => r.id === state.reader)) state.reader = available[0].id;

  for (const reader of available) {
    const chip = el('button', `chip${state.reader === reader.id ? ' on' : ''}`);
    chip.type = 'button';
    chip.append(el('b', '', reader.name), el('span', '', reader.how));
    chip.addEventListener('click', () => { state.reader = reader.id; renderReaders(); writeUrl(); });
    host.append(chip);
  }
  const reader = readerById(state.reader);
  $('reader-note').textContent = reader?.note || '';
  $('query-sql').hidden = reader?.ui !== 'sql';
  $('query-map').hidden = reader?.ui !== 'map';
  $('query-sub').textContent = reader?.ui === 'sql'
    ? 'The engine reads the file over HTTP. It is not told about the policy — whatever it '
      + 'can see is what the gate served it.'
    : 'The reader decodes pixels straight from the file. Whatever renders is what the gate served.';

  if (reader?.ui === 'sql' && !$('sql').value.trim()) {
    $('sql').value = reader.defaultQuery('{table}');
  }
  if (reader?.ui === 'map') {
    const select = $('map-level');
    if (select.dataset.file !== state.file?.url && state.file) {
      select.dataset.file = state.file.url;
      select.textContent = '';
      const levels = [...new Set(state.file.regions
        .filter((r) => r.kind === 'tile').map((r) => r.overview_level))].sort((a, b) => a - b);
      for (const level of levels) {
        const option = el('option', '', `Level ${level}${level === 0 ? ' — full resolution' : ''}`);
        option.value = String(level);
        select.append(option);
      }
      select.value = String(levels[levels.length - 1] ?? 0);
    }
  }
}

async function openGate() {
  const source = activeSource();
  state.gate?.release();
  state.gate = await open({
    url: source.url,
    format: source.format,
    policy: $('policy').value,
    user: $('principal').value,
    mode: state.mode,
  });
  $('gate-url').textContent = state.gate.url;
  return state.gate;
}

async function runQuery() {
  const busy = $('query-busy');
  const diag = $('query-diag');
  const output = $('query-output');
  $('run-query').disabled = true;
  $('query-result').hidden = false;
  diag.className = 'diag';
  diag.textContent = '';
  output.textContent = '';
  busy.textContent = 'opening the gate…';

  try {
    const gate = await openGate();
    renderWithheld(gate);
    if (gate.planError) {
      diag.className = 'diag bad';
      diag.textContent = `The gate refused this policy: ${gate.planError}`;
      return;
    }
    const reader = readerById(state.reader);
    const result = await reader.run({
      url: gate.url,
      query: $('sql').value,
      level: Number($('map-level').value || 0),
      onProgress: (m) => { busy.textContent = m; },
    });
    diag.className = 'diag ok';
    diag.textContent = result.kind === 'table'
      ? `${result.total.toLocaleString()} rows.`
      : `Decoded ${result.width}×${result.height} from level ${result.level}.`;
    renderResult(result, output);
  } catch (err) {
    diag.className = 'diag bad';
    const message = String(err?.message || err);
    diag.textContent = message;
    output.append(el('p', 'note', explainFailure(message)));
  } finally {
    busy.textContent = '';
    $('run-query').disabled = false;
  }
}

/** Turn a reader's error into the thing it actually means. */
function explainFailure(message) {
  if (/Binder Error|not found in FROM clause|Referenced column/i.test(message)) {
    return 'That column is not in the file the reader was served. Under a filtered view '
      + 'a withheld column is absent from the schema entirely — not null, not zeroed, '
      + 'absent — so the engine fails at planning time with an ordinary name error.';
  }
  if (/Range request|403|refused/i.test(message)) {
    return 'The gate refused a range. Under refuse mode any request covering a withheld '
      + 'byte is a 403, and a reader that widens its reads to fixed blocks will hit one '
      + 'even when every column it wants is permitted. That is the interoperability '
      + 'problem this project exists to show.';
  }
  if (/TProtocol|Invalid data|corrupt/i.test(message)) {
    return 'Note the shape of that error: it reads as file corruption, not as a policy '
      + 'decision. A refused range in the middle of a read is indistinguishable, to the '
      + 'engine, from a damaged file.';
  }
  return '';
}

function renderResult(result, host) {
  if (result.kind === 'table') {
    const table = el('table', 'result-table');
    const head = el('tr');
    for (const c of result.columns) head.append(el('th', '', c));
    table.append(head);
    for (const row of result.rows) {
      const tr = el('tr');
      for (const value of row) tr.append(el('td', '', value === null ? '—' : String(value)));
      table.append(tr);
    }
    host.append(table);
    if (result.total > result.rows.length) {
      host.append(el('p', 'note', `Showing ${result.rows.length} of ${result.total.toLocaleString()}.`));
    }
    return;
  }
  const canvas = el('canvas', 'result-image');
  canvas.width = result.width;
  canvas.height = result.height;
  const ctx = canvas.getContext('2d');
  const image = ctx.createImageData(result.width, result.height);
  const src = result.pixels;
  for (let i = 0, p = 0; i < src.length; i += 3, p += 4) {
    image.data[p] = src[i];
    image.data[p + 1] = src[i + 1];
    image.data[p + 2] = src[i + 2];
    image.data[p + 3] = 255;
  }
  ctx.putImageData(image, 0, 0);
  host.append(canvas);
  host.append(el('p', 'note',
    `Level ${result.level} of ${result.levels}, decoded from ${result.source}. `
    + 'Black is a tile the gate withheld: the served file says it was never written.'));
}

function renderWithheld(gate) {
  const card = $('withheld-card');
  const facts = $('withheld-facts');
  const detail = $('withheld-detail');
  facts.textContent = '';
  detail.textContent = '';

  if (state.mode !== 'filter' || !gate.withheld) {
    card.hidden = true;
    return;
  }
  card.hidden = false;
  const fact = (label, value, note) => {
    const box = el('div', 'fact');
    box.append(el('span', 'fact-label', label), el('span', 'fact-value', value));
    if (note) box.append(el('span', 'fact-note', note));
    facts.append(box);
  };
  let scrubbed = 0;
  for (let i = 0; i < gate.scrub.length; i += 2) scrubbed += gate.scrub[i + 1] - gate.scrub[i];

  fact('In storage', bytes(gate.size));
  fact('Served as', bytes(gate.virtualSize),
    gate.size - gate.virtualSize > 0 ? `${bytes(gate.size - gate.virtualSize)} shorter` : 'every offset preserved');
  fact('Zeroed', bytes(scrubbed), `${gate.scrub.length / 2} spans`);
  fact('ETag', gate.etag || '—', 'for the view, not the object');

  const report = gate.withheld;
  if (report.kind === 'columns') {
    const chips = el('div', 'chips tight');
    const withheldNames = new Set(report.withheld.map((w) => w.column));
    const all = [...new Set(state.file.regions.map((r) => r.column).filter(Boolean))];
    for (const column of all) {
      const chip = el('span', withheldNames.has(column) ? 'chip gone' : 'chip', column);
      const w = report.withheld.find((x) => x.column === column);
      if (w) chip.title = `${w.deniedKinds.join(', ')} · ${w.regions} regions · ${bytes(w.bytes)}`;
      chips.append(chip);
    }
    detail.append(chips);
    detail.append(el('p', 'note',
      `${report.withheld.length} of ${all.length} columns are absent from the served footer: `
      + 'no statistics, no bloom-filter pointer, no page-index pointer, and no name anywhere in it.'));
    if (report.strippedKeys?.length) {
      detail.append(el('p', 'note',
        `key_value_metadata stripped: ${report.strippedKeys.join(', ')} — ARROW:schema names `
        + 'every original column, so leaving it would leak them.'));
    }
  } else {
    detail.append(el('p', 'note',
      `${report.withheld.length} tiles withheld. Their TileOffsets and TileByteCounts entries `
      + 'are zero in the served file, which is how a COG says a tile was never written. '
      + 'GDAL reads it as sparse, not as corrupt.'));
  }
}

// ---- the address bar ------------------------------------------------------

async function writeUrl() {
  const params = new URLSearchParams();
  if (state.tab !== 'inspect') params.set('tab', state.tab);
  if (state.url) {
    params.set('file', state.url);
    if (state.format !== 'auto') params.set('fmt', state.format);
  } else if (state.sample !== SAMPLES[0].id) {
    params.set('s', state.sample);
  }
  if (state.range) params.set('r', state.range);
  if (state.policyId) params.set('pol', state.policyId);
  if (state.mode !== 'filter') params.set('mode', state.mode);
  if (state.reader) params.set('rd', state.reader);
  const text = $('policy')?.value;
  if (text && text !== state.policyText) params.set('p', await pack(text));
  const query = params.toString();
  history.replaceState(null, '', query ? `?${query}` : location.pathname);
}

async function readUrl() {
  const q = new URLSearchParams(location.search);
  state.tab = q.get('tab') === 'query' ? 'query' : 'inspect';
  if (q.get('file')) {
    state.url = q.get('file');
    state.format = q.get('fmt') || 'auto';
    $('file-url').value = state.url;
    $('file-format').value = state.format;
  } else if (q.get('s') && sampleById(q.get('s'))) {
    state.sample = q.get('s');
  }
  state.range = q.get('r') || '';
  if (state.range) $('range-header').value = state.range;
  state.policyId = q.get('pol') || null;
  state.mode = q.get('mode') === 'refuse' ? 'refuse' : 'filter';
  state.reader = q.get('rd') || null;
  const packed = q.get('p');
  if (packed) {
    try { state.policyText = await unpack(packed); } catch { /* keep the preset */ }
  }
}

function setTab(tab) {
  state.tab = tab;
  $('panel-inspect').hidden = tab !== 'inspect';
  $('panel-query').hidden = tab !== 'query';
  $('tab-inspect').setAttribute('aria-selected', String(tab === 'inspect'));
  $('tab-query').setAttribute('aria-selected', String(tab === 'query'));
  writeUrl();
}

function setMode(mode) {
  state.mode = mode;
  $('mode-filter').setAttribute('aria-checked', String(mode === 'filter'));
  $('mode-refuse').setAttribute('aria-checked', String(mode === 'refuse'));
  writeUrl();
}

// ---- wiring ---------------------------------------------------------------

async function main() {
  if (!supported()) {
    setState(
      'This browser has no service worker, so the gate has nowhere to run. '
      + 'Everything here depends on intercepting the reader\'s own requests.',
      'bad',
    );
    return;
  }
  await readUrl();
  renderFilePicker();
  setTab(state.tab);
  setMode(state.mode);

  $('tab-inspect').addEventListener('click', () => setTab('inspect'));
  $('tab-query').addEventListener('click', () => setTab('query'));
  $('mode-filter').addEventListener('click', () => setMode('filter'));
  $('mode-refuse').addEventListener('click', () => setMode('refuse'));
  $('range-go').addEventListener('click', () => resolveRange($('range-header').value));
  $('range-header').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') resolveRange($('range-header').value);
  });
  $('run-query').addEventListener('click', runQuery);
  $('policy').addEventListener('input', () => writeUrl());
  $('file-load').addEventListener('click', () => {
    state.url = $('file-url').value.trim();
    state.format = $('file-format').value;
    renderFilePicker();
    writeUrl();
    loadFile();
  });
  $('copy-link').addEventListener('click', async () => {
    await navigator.clipboard.writeText(location.href);
    $('copy-note').textContent = 'copied';
    setTimeout(() => { $('copy-note').textContent = ''; }, 1500);
  });

  $('version').textContent = 'gate: service worker';
  await loadFile();
  if (state.policyText) $('policy').value = state.policyText;
}

main();
