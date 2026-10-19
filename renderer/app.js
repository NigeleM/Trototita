// Renderer: all UI. Talks to the database and network only through window.api (see preload.js).
// DOM is built with el() and textContent, never innerHTML, so imported data cannot inject markup.

const OPERATOR_OPTIONS = [
  ['eq', 'equals'], ['neq', 'not equals'], ['contains', 'contains'],
  ['gt', '>'], ['gte', '>='], ['lt', '<'], ['lte', '<='], ['in', 'is one of'],
];
const OPERATOR_LABEL = Object.fromEntries(OPERATOR_OPTIONS);
const BUCKETS = ['Overdue', 'Next 7 days', 'Next 30 days', 'Later', 'Unscheduled'];
const SEVERITIES = ['Critical', 'High', 'Medium', 'Low', 'Info'];

const main = document.getElementById('main');

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value === false || value == null) continue;
    if (key === 'class') node.className = value;
    else if (key.startsWith('on')) node.addEventListener(key.slice(2), value);
    else if (value === true) node.setAttribute(key, '');
    else node.setAttribute(key, value);
  }
  for (const child of children.flat(Infinity)) {
    if (child == null || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

function toast(message, isError = false) {
  const box = document.getElementById('toast');
  box.textContent = message;
  box.className = isError ? 'error' : '';
  box.hidden = false;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => { box.hidden = true; }, 3500);
}

function errorMessage(err) {
  // IPC errors arrive as "Error invoking remote method '...': Error: real message"
  return String(err.message || err).replace(/^Error invoking remote method '[^']+': (Error: )?/, '');
}

function debounce(fn, ms) {
  let t;
  return (...args) => { clearTimeout(t); t = setTimeout(() => fn(...args), ms); };
}

function table(headers, rows) {
  return el('table', {},
    el('thead', {}, el('tr', {}, headers.map((h) => el('th', {}, h)))),
    el('tbody', {}, rows.map((cells) => el('tr', {}, cells.map((c) => el('td', {}, c ?? '')))))
  );
}

function panel(title, ...content) {
  return el('div', { class: 'panel' }, title ? el('h2', {}, title) : null, content);
}


// ---------- Dashboard ----------

async function renderDashboard(root) {
  const s = await window.api.dashboardStats();
  const defs = await window.api.columnDefs('vulnerabilities');
  const t = s.totals;
  const kpi = (label, value, cls) => el('div', { class: `kpi ${cls || ''}` },
    el('div', { class: 'value' }, value ?? '–'), el('div', { class: 'label' }, label));

  // One panel failing should show its own error, not blank the whole dashboard.
  const safe = (build) => {
    try { return build(); } catch (err) { return el('div', { class: 'note' }, errorMessage(err)); }
  };

  root.append(
    el('h1', {}, 'Dashboard'),
    el('h2', {}, 'Pinned charts'),
    settings.dashboardCharts.length
      ? el('div', { class: 'two-col' }, settings.dashboardCharts.map((cfg, i) => safe(() => pinnedCard(cfg, i, defs))))
      : el('p', { class: 'muted' }, 'No pinned charts. Build one in the Charts view and pin it here.'),
    safe(() => dashboardAlerts()),
    safe(() => dashboardMetrics()),
    el('div', { class: 'kpis' },
      kpi('Open', t.open ?? 0),
      kpi('Overdue', t.overdue ?? 0, t.overdue ? 'danger' : ''),
      kpi('Avg priority', t.avg_priority),
      kpi('Total records', t.total)),
    panel('Top 10 by priority', s.top.length
      ? table(['Priority', 'CVE', 'Title', 'Asset', 'Due', 'Bucket'],
        s.top.map((r) => [r.priority_score, r.cve, r.title, r.asset, r.due_date, r.timeline_bucket]))
      : el('div', { class: 'muted' }, 'No open findings.'))
  );
}

// ---------- Data grid (Excel-style: per-column filters, sort, select, inline edit, delete, export) ----------

const grid = { table: 'vulnerabilities', defs: [], columns: [], rows: [], total: 0, filters: {}, sortBy: null, sortDir: 'asc', selected: new Set(), showColumns: false };
let gridHead;
let gridBody;
let gridStatus;
let columnPanel;

async function renderData(root) {
  const tables = await window.api.tables();
  if (!tables.includes(grid.table)) grid.table = tables[0];

  const tableSelect = el('select', {
    onchange: (e) => {
      grid.table = e.target.value;
      grid.filters = {};
      grid.sortBy = null;
      grid.selected.clear();
      refreshGrid(true);
    },
  }, tables.map((t) => el('option', { value: t, selected: t === grid.table }, t)));

  gridStatus = el('span', { class: 'muted' });
  const addRowBtn = el('button', { class: 'primary', onclick: addRow }, 'Add row');
  const selectAllBtn = el('button', { onclick: selectAllRows }, 'Select all');
  const clearSelBtn = el('button', { onclick: clearSelection }, 'Clear selection');
  const removeBtn = el('button', { class: 'danger', onclick: () => deleteRowIds([...grid.selected]) }, 'Remove row(s)');

  const exportBtn = el('button', {
    onclick: async () => {
      try {
        const res = await window.api.exportCsv({ table: grid.table, filters: grid.filters });
        if (res) toast(`Exported ${res.count} rows`);
      } catch (err) { toast(errorMessage(err), true); }
    },
  }, 'Export CSV');

  const clearBtn = el('button', {
    onclick: () => { grid.filters = {}; refreshGrid(true); },
  }, 'Clear filters');

  const columnsBtn = el('button', {
    onclick: () => { grid.showColumns = !grid.showColumns; paintColumnPanel(); },
  }, 'Columns');

  gridHead = el('thead');
  gridBody = el('tbody');
  columnPanel = el('div', { class: 'panel', hidden: true });
  root.append(
    el('h1', {}, 'Data grid'),
    el('div', { class: 'toolbar' }, tableSelect, clearBtn, exportBtn, columnsBtn, addRowBtn, selectAllBtn, clearSelBtn, el('span', { class: 'spacer' }), removeBtn, gridStatus),
    savedViewsBar(),
    columnPanel,
    el('div', { class: 'grid-wrap' }, el('table', {}, gridHead, gridBody)),
    el('p', { class: 'muted' }, 'Type in a column filter: text is "contains"; numbers accept >, >=, <, <=, = (e.g. >7). Double-click a cell to edit it.')
  );
  await refreshGrid(true);
}

// rebuildHead is false when only the rows change, so filter inputs keep focus while typing.
async function refreshGrid(rebuildHead) {
  const res = await window.api.query({
    table: grid.table, filters: grid.filters, sortBy: grid.sortBy, sortDir: grid.sortDir, limit: 2000,
  });
  Object.assign(grid, { rows: res.rows, total: res.total });
  if (rebuildHead) {
    setDefs(await window.api.columnDefs(grid.table));
    paintHead();
    paintColumnPanel();
    paintSavedViews();
  }
  paintBody();
}

// Removes the selected rows after confirmation.
async function deleteRowIds(ids) {
  if (!ids.length) return toast('Select one or more rows first', true);
  if (!window.confirm(`Remove ${ids.length} row(s) from ${grid.table}? This cannot be undone.`)) return;
  try {
    const n = await window.api.deleteRows({ table: grid.table, rowids: ids });
    grid.selected.clear();
    toast(`Removed ${n} row(s)`);
    refreshGrid(true);
  } catch (err) { toast(errorMessage(err), true); }
}

// Selects every row currently shown (after filters), and clears the selection.
function selectAllRows() {
  grid.rows.forEach((r) => grid.selected.add(r.__rowid));
  paintHead();
  paintBody();
}

function clearSelection() {
  grid.selected.clear();
  paintHead();
  paintBody();
}

// Adds a blank row at the end of the table. Filters and sort are cleared so the new row is on screen.
async function addRow() {
  try {
    await window.api.insertRow({ table: grid.table });
    grid.filters = {};
    grid.sortBy = null;
    await refreshGrid(true);
    toast('Added a row. Double-click a cell to fill it in.');
  } catch (err) { toast(errorMessage(err), true); }
}

// Column definitions drive the header: only visible columns, in the saved order, with their labels.
function setDefs(defs) {
  grid.defs = defs;
  grid.columns = defs.filter((d) => d.visible).map((d) => d.name);
}

function labelOf(name) {
  return grid.defs.find((d) => d.name === name)?.label ?? name;
}

function paintHead() {
  const allVisibleSelected = grid.rows.length > 0 && grid.rows.every((r) => grid.selected.has(r.__rowid));
  gridHead.replaceChildren(
    el('tr', {},
      el('th', {}, el('input', {
        type: 'checkbox',
        checked: allVisibleSelected,
        onchange: (e) => {
          grid.rows.forEach((r) => (e.target.checked ? grid.selected.add(r.__rowid) : grid.selected.delete(r.__rowid)));
          paintBody();
        },
      })),
      grid.columns.map((c) => el('th', {
        class: 'sortable',
        onclick: () => {
          grid.sortDir = grid.sortBy === c && grid.sortDir === 'asc' ? 'desc' : 'asc';
          grid.sortBy = c;
          refreshGrid(true);
        },
      }, labelOf(c), grid.sortBy === c ? (grid.sortDir === 'asc' ? ' ▲' : ' ▼') : ''))),
    el('tr', {},
      el('th', {}),
      grid.columns.map((c) => el('th', {}, el('input', {
        placeholder: 'filter',
        value: grid.filters[c] || '',
        oninput: debounce((e) => { grid.filters[c] = e.target.value; refreshGrid(false); }, 200),
      }))))
  );
}

function paintBody() {
  gridStatus.textContent = `${grid.rows.length} shown · ${grid.total} match · ${grid.selected.size} selected`;
  gridBody.replaceChildren(...grid.rows.map((row) => {
    const rowid = row.__rowid;
    const selected = grid.selected.has(rowid);
    return el('tr', { class: selected ? 'selected' : '' },
      el('td', {}, el('input', {
        type: 'checkbox',
        checked: selected,
        onchange: (e) => {
          if (e.target.checked) grid.selected.add(rowid); else grid.selected.delete(rowid);
          paintBody();
        },
      })),
      grid.columns.map((c) => editableCell(row, rowid, c)));
  }));
}

function editableCell(row, rowid, column) {
  // The ID of a finding opens its details page instead of being edited in place.
  if (column === 'id' && grid.table === 'vulnerabilities') {
    return el('td', {}, el('button', { class: 'link', onclick: () => openFinding(rowid) }, String(row.id)));
  }
  const original = row[column] == null ? '' : String(row[column]);
  const td = el('td', { class: 'cell-edit' }, original);
  td.addEventListener('dblclick', () => {
    td.contentEditable = 'true';
    td.focus();
    document.getSelection().selectAllChildren(td);
  });
  td.addEventListener('keydown', (e) => {
    if (td.contentEditable !== 'true') return;
    if (e.key === 'Enter') { e.preventDefault(); td.blur(); }
    if (e.key === 'Escape') { td.textContent = original; td.contentEditable = 'false'; td.blur(); }
  });
  td.addEventListener('blur', async () => {
    if (td.contentEditable !== 'true') return;
    td.contentEditable = 'false';
    const value = td.textContent;
    if (value === original) return;
    try {
      await window.api.updateCell({ table: grid.table, rowid, column, value });
      toast(`Saved ${column}`);
      refreshGrid(false);
    } catch (err) {
      td.textContent = original;
      toast(errorMessage(err), true);
    }
  });
  return td;
}

// ---------- Columns panel: show/hide, reorder, rename, add and delete custom fields ----------

async function applyPrefs(defs) {
  try {
    setDefs(await window.api.saveColumnPrefs({
      table: grid.table,
      prefs: defs.map((d, i) => ({ name: d.name, visible: d.visible, position: i, label: d.label })),
    }));
    paintHead();
    paintColumnPanel();
    paintBody();
  } catch (err) { toast(errorMessage(err), true); }
}

function paintColumnPanel() {
  if (!columnPanel) return;
  columnPanel.hidden = !grid.showColumns;
  if (!grid.showColumns) return;

  const defs = grid.defs;
  const move = (i, dir) => {
    const copy = [...defs];
    [copy[i], copy[i + dir]] = [copy[i + dir], copy[i]];
    applyPrefs(copy);
  };

  const labelInput = el('input', { placeholder: 'Field name, e.g. Asset owner' });
  const typeSelect = el('select', {}, ['text', 'number', 'date'].map((t) => el('option', { value: t }, t)));

  const addField = async () => {
    const label = labelInput.value.trim();
    if (!label) return toast('Enter a field name', true);
    try {
      setDefs(await window.api.addColumn({ table: grid.table, label, type: typeSelect.value }));
      labelInput.value = '';
      paintHead();
      paintColumnPanel();
      paintBody();
      toast(`Added "${label}"`);
    } catch (err) { toast(errorMessage(err), true); }
  };

  const removeField = async (d) => {
    if (!window.confirm(`Delete custom field "${d.label}"? Its values will be lost.`)) return;
    try {
      setDefs(await window.api.deleteColumn({ table: grid.table, name: d.name }));
      if (grid.sortBy === d.name) grid.sortBy = null;
      delete grid.filters[d.name];
      paintHead();
      paintColumnPanel();
      refreshGrid(false);
    } catch (err) { toast(errorMessage(err), true); }
  };

  columnPanel.replaceChildren(
    el('h2', {}, 'Columns'),
    el('p', { class: 'muted' }, 'Show, hide, reorder or rename columns. Custom fields can be added or deleted. Built-in columns cannot be deleted.'),
    defs.map((d, i) => el('div', { class: 'col-row' },
      el('input', {
        type: 'checkbox',
        checked: d.visible,
        title: 'Show column',
        onchange: (e) => { d.visible = e.target.checked; applyPrefs(defs); },
      }),
      el('input', {
        class: 'col-label',
        value: d.label,
        onchange: (e) => { d.label = e.target.value.trim() || d.label; applyPrefs(defs); },
      }),
      el('span', { class: 'muted' }, d.system ? 'built-in' : `custom · ${d.type}`),
      el('button', { disabled: i === 0, onclick: () => move(i, -1) }, '↑'),
      el('button', { disabled: i === defs.length - 1, onclick: () => move(i, 1) }, '↓'),
      d.system ? null : el('button', { class: 'danger', onclick: () => removeField(d) }, 'Delete'))),
    el('div', { class: 'toolbar' }, labelInput, typeSelect, el('button', { class: 'primary', onclick: addField }, 'Add custom field')));
}

// ---------- Charts: pie, bar and line over any column, with drill-down into the Data grid ----------

const CHART_TYPES = { pie: 'Pie', bar: 'Bar', line: 'Line' };
const TOP_N_OPTIONS = [5, 8, 12, 20];
const SVG_NS = 'http://www.w3.org/2000/svg';
let chartState = { groupBy: 'severity', type: 'pie', openOnly: true, topN: 8 };

// Creates SVG nodes. Attributes go through setAttribute, which the CSP allows (style="" attributes are not).
function svgEl(tag, attrs = {}, ...children) {
  const node = document.createElementNS(SVG_NS, tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value != null && value !== false) node.setAttribute(key, value);
  }
  for (const child of children.flat()) {
    if (child != null && child !== false) node.append(child);
  }
  return node;
}

const sliceClass = (i) => `s${i % 8}`;
const truncate = (s, n) => (s.length > n ? `${s.slice(0, n - 1)}…` : s);

// Top N values stay as they are; the rest collapse into "Other" for pie and bar.
// Line charts keep only the top N and show them in label order, so time or number axes read correctly.
function shapeData(raw, cfg) {
  const top = raw.slice(0, cfg.topN);
  const rest = raw.slice(cfg.topN);
  if (cfg.type === 'line') return top.sort((a, b) => a.label.localeCompare(b.label, undefined, { numeric: true }));
  if (rest.length) return [...top, { label: 'Other', n: rest.reduce((s, d) => s + d.n, 0), other: true }];
  return top;
}

function pieSvg(data, onPick) {
  const total = data.reduce((s, d) => s + d.n, 0) || 1;
  const c = 120;
  const r = 110;
  const svg = svgEl('svg', { viewBox: '0 0 240 240', class: 'chart-svg pie' });
  let angle = -Math.PI / 2;
  data.forEach((d, i) => {
    const cls = `slice clickable ${d.other ? 's-other' : sliceClass(i)}`;
    const title = svgEl('title', {}, `${d.label}: ${d.n}`);
    let shape;
    if (data.length === 1) {
      shape = svgEl('circle', { cx: c, cy: c, r, class: cls }, title);
    } else {
      const end = angle + (d.n / total) * 2 * Math.PI;
      const pt = (a) => `${(c + r * Math.cos(a)).toFixed(2)},${(c + r * Math.sin(a)).toFixed(2)}`;
      shape = svgEl('path', {
        d: `M${c},${c} L${pt(angle)} A${r},${r} 0 ${d.n / total > 0.5 ? 1 : 0} 1 ${pt(end)} Z`,
        class: cls,
      }, title);
      angle = end;
    }
    shape.addEventListener('click', () => onPick(d));
    svg.append(shape);
  });
  return svg;
}

function barSvg(data, onPick) {
  const rowH = 28;
  const labelW = 160;
  const barW = 300;
  const max = Math.max(1, ...data.map((d) => d.n));
  const svg = svgEl('svg', { viewBox: `0 0 ${labelW + barW + 60} ${data.length * rowH}`, class: 'chart-svg bar' });
  data.forEach((d, i) => {
    const y = i * rowH;
    const width = Math.max(2, (d.n / max) * barW);
    const bar = svgEl('rect', {
      x: labelW, y: y + 5, width, height: rowH - 10, rx: 3,
      class: `clickable ${d.other ? 's-other' : sliceClass(i)}`,
    }, svgEl('title', {}, `${d.label}: ${d.n}`));
    bar.addEventListener('click', () => onPick(d));
    svg.append(
      svgEl('text', { x: 0, y: y + rowH / 2 + 4, class: 'axis-label' }, truncate(d.label, 22)),
      bar,
      svgEl('text', { x: labelW + width + 6, y: y + rowH / 2 + 4, class: 'value-label' }, d.n),
    );
  });
  return svg;
}

function lineSvg(data, onPick) {
  const W = 640;
  const H = 280;
  const p = { l: 44, r: 16, t: 16, b: 56 };
  const plotW = W - p.l - p.r;
  const plotH = H - p.t - p.b;
  const max = Math.max(1, ...data.map((d) => d.n));
  const x = (i) => (data.length === 1 ? p.l + plotW / 2 : p.l + (i * plotW) / (data.length - 1));
  const y = (v) => p.t + plotH - (v / max) * plotH;
  const svg = svgEl('svg', { viewBox: `0 0 ${W} ${H}`, class: 'chart-svg line' });

  for (let k = 0; k <= 4; k++) {
    const v = Math.round((max * k) / 4);
    svg.append(
      svgEl('line', { x1: p.l, x2: W - p.r, y1: y(v), y2: y(v), class: 'grid' }),
      svgEl('text', { x: p.l - 6, y: y(v) + 4, class: 'axis-label', 'text-anchor': 'end' }, v),
    );
  }
  svg.append(svgEl('polyline', { points: data.map((d, i) => `${x(i)},${y(d.n)}`).join(' '), class: 'line-path' }));

  const every = Math.ceil(data.length / 10);
  data.forEach((d, i) => {
    const dot = svgEl('circle', { cx: x(i), cy: y(d.n), r: 5, class: 'clickable line-dot' },
      svgEl('title', {}, `${d.label}: ${d.n}`));
    dot.addEventListener('click', () => onPick(d));
    svg.append(dot);
    if (i % every === 0) {
      svg.append(svgEl('text', { x: x(i), y: H - p.b + 18, class: 'axis-label', 'text-anchor': 'middle' }, truncate(d.label, 12)));
    }
  });
  return svg;
}

function legend(data) {
  return el('ul', { class: 'legend' }, data.map((d, i) => el('li', {},
    el('span', { class: `dot ${d.other ? 's-other' : sliceClass(i)}` }),
    `${d.label} · ${d.n}`)));
}

// Clicking a value opens the Data grid filtered to it (and to open items when the chart is open-only).
function drillTo(cfg, label, defs) {
  if (label === '(none)') return toast('Blank values have no filter, so there is nothing to drill into', true);
  const numeric = defs.find((d) => d.name === cfg.groupBy)?.type === 'number';
  grid.table = 'vulnerabilities';
  grid.filters = { [cfg.groupBy]: numeric ? `=${label}` : label };
  if (cfg.openOnly && cfg.groupBy !== 'status') grid.filters.status = 'open';
  grid.sortBy = null;
  currentView = 'data';
  renderView();
}

async function paintChart(host, cfg, defs) {
  host.replaceChildren(el('div', { class: 'muted' }, 'Loading…'));
  try {
    const raw = await window.api.aggregate({ table: 'vulnerabilities', groupBy: cfg.groupBy, openOnly: cfg.openOnly, limit: 500 });
    const data = shapeData(raw, cfg);
    if (!data.length) return host.replaceChildren(el('div', { class: 'muted' }, 'No data for this selection.'));
    const onPick = (d) => (d.other
      ? toast('"Other" groups several values. Pick one of the named slices or bars.', true)
      : drillTo(cfg, d.label, defs));
    const chart = cfg.type === 'pie' ? pieSvg(data, onPick)
      : cfg.type === 'line' ? lineSvg(data, onPick)
        : barSvg(data, onPick);
    host.replaceChildren(el('div', { class: 'chart-wrap' }, chart, cfg.type === 'line' ? null : legend(data)));
  } catch (err) {
    host.replaceChildren(el('div', { class: 'note' }, errorMessage(err)));
  }
}

function pinnedCard(cfg, index, defs) {
  const host = el('div', {});
  paintChart(host, cfg, defs);
  const column = defs.find((d) => d.name === cfg.groupBy)?.label ?? cfg.groupBy;
  return el('div', { class: 'panel' },
    el('div', { class: 'toolbar' },
      el('h2', {}, `${column} · ${CHART_TYPES[cfg.type]}`),
      el('span', { class: 'spacer' }),
      el('button', {
        onclick: () => changeSetting('dashboardCharts', settings.dashboardCharts.filter((_, j) => j !== index)),
      }, 'Unpin')),
    host);
}

async function renderCharts(root) {
  const defs = (await window.api.columnDefs('vulnerabilities')).filter((d) => d.name !== 'id');
  const host = el('div', { class: 'chart-host' });
  const update = () => paintChart(host, chartState, defs);
  const labeled = (text, control) => el('label', { class: 'inline-field' }, el('span', {}, text), control);

  const columnSelect = el('select', {
    onchange: (e) => { chartState.groupBy = e.target.value; update(); },
  }, defs.map((d) => el('option', { value: d.name, selected: d.name === chartState.groupBy }, d.label)));

  const typeSelect = el('select', {
    onchange: (e) => { chartState.type = e.target.value; update(); },
  }, Object.entries(CHART_TYPES).map(([v, l]) => el('option', { value: v, selected: v === chartState.type }, l)));

  const topSelect = el('select', {
    onchange: (e) => { chartState.topN = Number(e.target.value); update(); },
  }, TOP_N_OPTIONS.map((n) => el('option', { value: n, selected: n === chartState.topN }, `${n}`)));

  const openBox = el('input', {
    type: 'checkbox',
    checked: chartState.openOnly,
    onchange: (e) => { chartState.openOnly = e.target.checked; update(); },
  });

  const pin = () => {
    if (settings.dashboardCharts.some((c) => JSON.stringify(c) === JSON.stringify(chartState))) {
      return toast('This chart is already pinned', true);
    }
    changeSetting('dashboardCharts', [...settings.dashboardCharts, { ...chartState }]);
    toast('Pinned to dashboard');
  };

  root.append(
    el('h1', {}, 'Charts'),
    el('div', { class: 'panel' },
      el('div', { class: 'toolbar' },
        labeled('Column', columnSelect),
        labeled('Chart type', typeSelect),
        labeled('Show top', topSelect),
        el('label', { class: 'inline-check' }, openBox, 'Open items only'),
        el('span', { class: 'spacer' }),
        el('button', { class: 'primary', onclick: pin }, 'Pin to dashboard')),
      host),
    el('p', { class: 'muted' }, 'Click a slice, bar or point to open the Data grid filtered to that value. Any column works, including custom fields.')
  );
  update();
}

// ---------- Timeline ----------

async function renderTimeline(root) {
  const res = await window.api.query({ table: 'vulnerabilities', sortBy: 'due_date', limit: 2000 });
  const open = res.rows.filter((r) => r.status === 'open');
  const today = new Date().toISOString().slice(0, 10);

  const lanes = BUCKETS.map((bucket) => {
    const items = open.filter((r) => (r.timeline_bucket || 'Unscheduled') === bucket);
    return el('div', { class: 'lane' },
      el('h2', {}, el('span', {}, bucket), el('span', {}, items.length)),
      items.length === 0 ? el('div', { class: 'muted' }, 'Empty') : items.map((r) => el('div', {
        class: `card ${bucket === 'Overdue' ? 'overdue' : ''}`,
      },
        el('div', { class: 'title' }, r.title),
        el('div', { class: 'meta' }, `${r.cve || 'no CVE'} · ${r.asset || 'no asset'}`),
        el('div', { class: 'meta' }, `Due ${r.due_date} · priority ${r.priority_score ?? '–'}`))));
  });

  root.append(
    el('h1', {}, 'Timeline'),
    el('p', { class: 'muted' }, `Open findings grouped by SLA due date, as of ${today}. Due dates come from severity defaults and rules.`),
    el('div', { class: 'lanes' }, lanes)
  );
}

// ---------- Rules ----------

let editingRule = null;

async function renderRules(root) {
  const [rules, columns, policies] = await Promise.all([
    window.api.listRules(), window.api.columns('vulnerabilities'), policiesPanel(),
  ]);
  root.append(
    el('h1', {}, 'Rules'),
    el('p', { class: 'muted' }, 'Each enabled rule whose conditions all match adds its priority bonus to the score. For SLA, the first matching rule that sets days wins; otherwise severity defaults apply (Critical 7d, High 30d, Medium 90d, Low 180d).'),
    panel('Existing rules', rules.length
      ? rules.map((r) => ruleRow(r))
      : el('div', { class: 'muted' }, 'No rules yet.')),
    panel(editingRule ? `Edit rule #${editingRule.id}` : 'New rule', ruleForm(columns)),
    policies
  );
}

function ruleRow(rule) {
  const summary = rule.conditions.map((c) => `${c.field} ${OPERATOR_LABEL[c.op] || c.op} ${c.value}`).join(' AND ');
  const effects = [
    rule.priority_bonus ? `+${rule.priority_bonus} priority` : null,
    rule.sla_days != null ? `SLA ${rule.sla_days}d` : null,
  ].filter(Boolean).join(' · ') || 'no effect';
  return el('div', { class: 'rule' },
    el('input', {
      type: 'checkbox',
      checked: rule.enabled,
      title: 'Enabled',
      onchange: async (e) => {
        await window.api.saveRule({ ...rule, enabled: e.target.checked });
        renderView();
      },
    }),
    el('div', { class: 'info' },
      el('div', {}, rule.name),
      el('div', { class: 'summary' }, `IF ${summary || '(no conditions)'} → ${effects}`)),
    el('button', { onclick: () => { editingRule = rule; renderView(); } }, 'Edit'),
    el('button', {
      class: 'danger',
      onclick: async () => {
        if (!window.confirm(`Delete rule "${rule.name}"?`)) return;
        await window.api.deleteRule(rule.id);
        if (editingRule && editingRule.id === rule.id) editingRule = null;
        renderView();
      },
    }, 'Delete'));
}

function ruleForm(columns) {
  const seed = editingRule || { name: '', enabled: true, conditions: [{ field: columns[0], op: 'contains', value: '' }], priority_bonus: 0, sla_days: null };
  const nameInput = el('input', { value: seed.name, placeholder: 'e.g. Public web servers get +2' });
  const bonusInput = el('input', { type: 'number', step: '0.5', value: seed.priority_bonus });
  const slaInput = el('input', { type: 'number', min: '0', placeholder: 'default', value: seed.sla_days ?? '' });
  const condWrap = el('div', {});
  const condRows = [];

  const addCondition = (c) => {
    const field = el('select', {}, columns.map((col) => el('option', { value: col, selected: col === c.field }, col)));
    const op = el('select', {}, OPERATOR_OPTIONS.map(([k, label]) => el('option', { value: k, selected: k === c.op }, label)));
    const value = el('input', { value: c.value ?? '', placeholder: 'value' });
    const row = { field, op, value };
    condRows.push(row);
    condWrap.append(el('div', { class: 'cond-row' }, field, op, value, el('button', {
      onclick: (e) => {
        condRows.splice(condRows.indexOf(row), 1);
        e.target.parentElement.remove();
      },
    }, '✕')));
  };
  seed.conditions.forEach(addCondition);

  const enabled = el('input', { type: 'checkbox', checked: seed.enabled });

  const save = async () => {
    const conditions = condRows.map((r) => ({ field: r.field.value, op: r.op.value, value: r.value.value.trim() }));
    if (!nameInput.value.trim()) return toast('Rule needs a name', true);
    if (!conditions.length) return toast('Add at least one condition', true);
    try {
      await window.api.saveRule({
        id: editingRule?.id,
        name: nameInput.value.trim(),
        enabled: enabled.checked,
        conditions,
        priority_bonus: Number(bonusInput.value) || 0,
        sla_days: slaInput.value === '' ? null : Number(slaInput.value),
      });
      editingRule = null;
      toast('Rule saved and applied');
      renderView();
    } catch (err) { toast(errorMessage(err), true); }
  };

  return el('div', {},
    el('div', { class: 'form-grid' },
      el('label', {}, 'Name', nameInput),
      el('label', {}, 'Priority bonus', bonusInput),
      el('label', {}, 'SLA days (optional)', slaInput),
      el('label', {}, 'Enabled', el('div', {}, enabled))),
    el('h2', {}, 'When all of these match'),
    condWrap,
    el('div', { class: 'toolbar' },
      el('button', { onclick: () => addCondition({ field: columns[0], op: 'contains', value: '' }) }, '+ Condition'),
      el('span', { class: 'spacer' }),
      editingRule ? el('button', { onclick: () => { editingRule = null; renderView(); } }, 'Cancel') : null,
      el('button', { class: 'primary', onclick: save }, editingRule ? 'Update rule' : 'Create rule')));
}

// ---------- SQL console ----------

function renderSql(root) {
  const editor = el('textarea', { spellcheck: 'false' }, 'SELECT title, cve, asset, priority_score, due_date\nFROM vulnerabilities\nORDER BY priority_score DESC\nLIMIT 20;');
  const output = el('div');
  // Loaded rows: a read-only copy of what the Data grid shows (same table, filters and sort). Full database: everything.
  const scope = el('select', {}, [
    ['loaded', 'Loaded rows (read-only)'],
    ['full', 'Full database'],
  ].map(([v, label]) => el('option', { value: v }, label)));

  const run = async () => {
    output.replaceChildren();
    try {
      const res = scope.value === 'loaded'
        ? await window.api.sqlLoaded({ table: grid.table, filters: grid.filters, sortBy: grid.sortBy, sortDir: grid.sortDir, sql: editor.value })
        : await window.api.sql(editor.value);
      if (res.kind === 'rows') {
        if (res.loaded != null) output.append(el('div', { class: 'muted pad' }, `Running on ${res.loaded} loaded row(s) from ${grid.table}, with the Data grid's filters and sort.`));
        if (res.truncated) output.append(el('div', { class: 'note' }, 'Showing first 5000 rows.'));
        output.append(resultGrid({ columns: res.columns, rows: res.rows, exportName: 'query-result.csv' }));
      } else {
        output.append(el('div', { class: 'pad' }, `${res.changes} row(s) changed. Rules re-applied.`));
      }
    } catch (err) { output.append(el('div', { class: 'note pad' }, errorMessage(err))); }
  };

  editor.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) { e.preventDefault(); run(); }
  });

  root.append(
    el('h1', {}, 'SQL console'),
    editor,
    el('div', { class: 'toolbar' },
      el('button', { class: 'primary', onclick: run }, 'Run (⌘/Ctrl+Enter)'),
      scope,
      el('span', { class: 'muted' }, 'Tables: vulnerabilities, rules')),
    el('p', { class: 'note' }, 'Loaded rows: the table name is the Data grid\'s table, and only SELECT works. Full database: writes run directly against the database, with no undo.'),
    output
  );
}

// Result rows shown like the Data grid: click a header to sort, filter per column, export what is shown to CSV.
function resultGrid({ columns, rows, exportName }) {
  const state = { sortBy: null, sortDir: 'asc', filters: {} };
  const status = el('span', { class: 'muted' });
  const head = el('thead');
  const body = el('tbody');

  const shownRows = () => {
    let out = rows.filter((r) => columns.every((c) => matchesFilter(r[c], state.filters[c])));
    if (state.sortBy) {
      const dir = state.sortDir === 'asc' ? 1 : -1;
      out = [...out].sort((a, b) => compareValues(a[state.sortBy], b[state.sortBy]) * dir);
    }
    return out;
  };

  const paintBody = () => {
    const shown = shownRows();
    status.textContent = `${shown.length} shown · ${rows.length} rows`;
    body.replaceChildren(...shown.map((r) => el('tr', {}, columns.map((c) => el('td', {}, r[c] == null ? '' : String(r[c]))))));
  };

  // Header and filter row are rebuilt only on sort changes, so filter inputs keep focus while typing.
  const paintHead = () => {
    head.replaceChildren(
      el('tr', {}, columns.map((c) => el('th', {
        class: 'sortable',
        onclick: () => {
          state.sortDir = state.sortBy === c && state.sortDir === 'asc' ? 'desc' : 'asc';
          state.sortBy = c;
          paintHead();
          paintBody();
        },
      }, c, state.sortBy === c ? (state.sortDir === 'asc' ? ' ▲' : ' ▼') : ''))),
      el('tr', {}, columns.map((c) => el('th', {}, el('input', {
        placeholder: 'filter',
        value: state.filters[c] || '',
        oninput: debounce((e) => { state.filters[c] = e.target.value; paintBody(); }, 200),
      }))))
    );
  };

  const exportBtn = el('button', {
    onclick: async () => {
      try {
        const res = await window.api.exportRows({ defaultName: exportName, columns, rows: shownRows() });
        if (res) toast(`Exported ${res.count} rows`);
      } catch (err) { toast(errorMessage(err), true); }
    },
  }, 'Export CSV');

  paintHead();
  paintBody();
  return el('div', {},
    el('div', { class: 'toolbar' }, exportBtn, el('span', { class: 'spacer' }), status),
    el('div', { class: 'grid-wrap' }, el('table', {}, head, body)));
}

// Same filter syntax as the Data grid: numbers accept >, >=, <, <=, = ; anything else is a case-insensitive "contains".
function matchesFilter(value, raw) {
  const text = String(raw ?? '').trim();
  if (!text) return true;
  const m = text.match(/^(>=|<=|>|<|=)\s*(-?\d+(\.\d+)?)$/);
  if (m) {
    const n = Number(value);
    if (value == null || value === '' || Number.isNaN(n)) return false;
    const limit = Number(m[2]);
    return { '>': n > limit, '>=': n >= limit, '<': n < limit, '<=': n <= limit, '=': n === limit }[m[1]];
  }
  return String(value ?? '').toLowerCase().includes(text.toLowerCase());
}

// Numbers sort as numbers, text naturally, and blanks always go last.
function compareValues(a, b) {
  const blankA = a == null || a === '';
  const blankB = b == null || b === '';
  if (blankA || blankB) return blankA === blankB ? 0 : blankA ? 1 : -1;
  if (typeof a === 'number' && typeof b === 'number') return a - b;
  return String(a).localeCompare(String(b), undefined, { numeric: true });
}

// ---------- Settings: theme, font size, density, start view ----------

// Swatch colours mirror the :root[data-theme] blocks in styles.css (bg, panel, accent, text).
const THEMES = [
  { id: 'midnight', name: 'Midnight', colors: ['#0f1419', '#161d24', '#34d3c0', '#d6e2ec'] },
  { id: 'slate', name: 'Slate', colors: ['#1e2430', '#252c3a', '#7aa2f7', '#e3e8f0'] },
  { id: 'nord', name: 'Nord', colors: ['#2e3440', '#3b4252', '#88c0d0', '#eceff4'] },
  { id: 'dracula', name: 'Dracula', colors: ['#282a36', '#303344', '#bd93f9', '#f8f8f2'] },
  { id: 'monokai', name: 'Monokai', colors: ['#272822', '#32332b', '#a6e22e', '#f8f8f2'] },
  { id: 'solarized-dark', name: 'Solarized Dark', colors: ['#002b36', '#073642', '#2aa198', '#eee8d5'] },
  { id: 'matrix', name: 'Matrix', colors: ['#000000', '#0a120a', '#33ff66', '#b8f5b8'] },
  { id: 'high-contrast', name: 'High Contrast', colors: ['#000000', '#0d0d0d', '#00e5ff', '#ffffff'] },
  { id: 'daylight', name: 'Daylight', colors: ['#ffffff', '#f0f3f6', '#0969da', '#1f2328'] },
  { id: 'solarized-light', name: 'Solarized Light', colors: ['#fdf6e3', '#f5efdc', '#268bd2', '#073642'] },
];
const FONT_SIZES = { small: 'Small', medium: 'Medium', large: 'Large' };
const DENSITIES = { comfortable: 'Comfortable', compact: 'Compact' };
const VIEW_LABELS = { dashboard: 'Dashboard', data: 'Data grid', charts: 'Charts', alerts: 'Alerts', poam: 'POA&M / RBD', assets: 'Assets', timeline: 'Timeline', rules: 'Rules', import: 'Import', sql: 'SQL console' };
const DEFAULT_SETTINGS = {
  theme: 'midnight',
  fontSize: 'medium',
  density: 'comfortable',
  startView: 'dashboard',
  alertsEnabled: true,
  desktopNotifications: true,
  leadDays: 7,
  userName: '',
  // Team mode: data lives on the team server. Local mode keeps it on this computer.
  mode: 'local',
  serverUrl: '',
  caFile: '',
  // Charts pinned to the dashboard: { groupBy, type, openOnly, topN }
  dashboardCharts: [
    { groupBy: 'severity', type: 'pie', openOnly: true, topN: 8 },
    { groupBy: 'timeline_bucket', type: 'bar', openOnly: true, topN: 8 },
  ],
};

let settings = { ...DEFAULT_SETTINGS };

function applySettings() {
  const root = document.documentElement;
  root.dataset.theme = settings.theme;
  root.dataset.font = settings.fontSize;
  root.dataset.density = settings.density;
}

async function changeSetting(key, value) {
  settings = { ...settings, [key]: value };
  applySettings();
  try {
    await window.api.saveSettings(settings);
  } catch (err) { toast(errorMessage(err), true); }
  renderView();
}

function renderSettings(root) {
  const themeCards = THEMES.map((t) => {
    const swatch = el('div', { class: 'swatches' }, t.colors.map((c) => {
      const span = el('span');
      span.style.background = c; // set via CSSOM: inline style attributes are blocked by the CSP
      return span;
    }));
    return el('button', {
      class: `theme-card ${settings.theme === t.id ? 'selected' : ''}`,
      onclick: () => changeSetting('theme', t.id),
    }, el('span', { class: 'name' }, t.name), swatch);
  });

  const select = (key, options) => el('select', {
    onchange: (e) => changeSetting(key, e.target.value),
  }, Object.entries(options).map(([value, label]) => el('option', { value, selected: value === settings[key] }, label)));

  root.append(
    el('h1', {}, 'Settings'),
    panel('Theme', el('p', { class: 'muted' }, 'Applies immediately and is saved for this user.'),
      el('div', { class: 'theme-grid' }, themeCards)),
    panel('Display',
      el('div', { class: 'setting-row' },
        el('div', { class: 'info' }, el('div', {}, 'Font size'), el('div', { class: 'muted' }, 'Text size across the app.')),
        select('fontSize', FONT_SIZES)),
      el('div', { class: 'setting-row' },
        el('div', { class: 'info' }, el('div', {}, 'Density'), el('div', { class: 'muted' }, 'Spacing in tables and panels.')),
        select('density', DENSITIES)),
      el('div', { class: 'setting-row' },
        el('div', { class: 'info' }, el('div', {}, 'Start view'), el('div', { class: 'muted' }, 'Screen shown when the app opens.')),
        select('startView', VIEW_LABELS))),
    alertSettingsPanel(),
    teamPanel(),
    backupsPanel(),
    teamAdminPanel()
  );
}

// ---------- Router ----------

const views = {
  dashboard: renderDashboard,
  data: renderData,
  timeline: renderTimeline,
  rules: renderRules,
  sql: renderSql,
  settings: renderSettings,
  charts: renderCharts,
};
let currentView = 'dashboard';

async function renderView() {
  document.querySelectorAll('.sidebar nav button').forEach((b) => {
    b.classList.toggle('active', b.dataset.view === currentView);
    b.setAttribute('aria-current', b.dataset.view === currentView ? 'page' : 'false');
  });
  main.replaceChildren();
  try {
    await views[currentView](main);
  } catch (err) {
    main.replaceChildren(el('div', { class: 'note' }, errorMessage(err)));
  }
}

document.querySelectorAll('.sidebar nav button').forEach((btn) => {
  btn.addEventListener('click', () => {
    currentView = btn.dataset.view;
    editingRule = null;
    renderView();
  });
});

async function boot() {
  try {
    settings = { ...DEFAULT_SETTINGS, ...(await window.api.getSettings()) };
  } catch (err) {
    toast(errorMessage(err), true);
  }
  // A saved theme id that no longer exists (e.g. after a rename) falls back to the default.
  if (!THEMES.some((t) => t.id === settings.theme)) settings.theme = DEFAULT_SETTINGS.theme;
  applySettings();
  currentView = views[settings.startView] ? settings.startView : 'dashboard';
  renderView();
}

boot();
