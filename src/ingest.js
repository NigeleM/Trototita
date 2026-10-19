// Imports from CSV, JSON and Excel files, and from HTTP(S) JSON APIs. All of them normalise their rows
// and go through importRows(), which handles custom fields, date cleaning, optional cleaning steps,
// the upsert, and the rule engine.
const XLSX = require('xlsx');
const { csvToObjects, parseCsv, normaliseHeader } = require('./csv');
const { upsertVulnerabilities } = require('./db');
const { recomputeAll } = require('./rules');
const { ensureCustomColumn, coerceValue, inferType } = require('./columns');
const { normaliseDate, removeDuplicates, pruneSource } = require('./cleaning');

// Common column names from scanner exports, mapped onto the app's schema.
const ALIASES = {
  title: ['title', 'name', 'vulnerability', 'finding', 'plugin_name'],
  cve: ['cve', 'cve_id', 'cves'],
  asset: ['asset', 'host', 'hostname', 'ip', 'target'],
  severity: ['severity', 'risk', 'risk_level'],
  cvss: ['cvss', 'cvss_score', 'cvss_base'],
  status: ['status', 'state'],
  first_seen: ['first_seen', 'discovered', 'date_found', 'detected'],
  source: ['source', 'scanner', 'tool'],
  control_id: ['control', 'control_id', 'nist_control', 'control_ref'],
};

const KNOWN_HEADERS = new Set(Object.values(ALIASES).flat());

// One-click import presets for common scanner exports. Keys are normalised headers (lowercase, underscores).
const SCANNER_PRESETS = {
  nessus: {
    label: 'Tenable Nessus (CSV)',
    aliases: { title: ['name', 'plugin_name'], cve: ['cve'], asset: ['host'], severity: ['risk'], cvss: ['cvss_v3.0_base_score', 'cvss_v2.0_base_score'] },
  },
  qualys: {
    label: 'Qualys host detections (CSV)',
    aliases: { title: ['title'], cve: ['cve_id'], asset: ['dns', 'ip'], severity: ['severity'], cvss: ['cvss_base'], first_seen: ['first_detected'], status: ['status'] },
    numericSeverity: true,
  },
  tenable: {
    label: 'Tenable.io vulnerability export (CSV)',
    aliases: { title: ['plugin_name'], cve: ['cve'], asset: ['asset_name', 'fqdn', 'ip_address'], severity: ['severity'], cvss: ['cvss_v3_base_score', 'cvss_v2_base_score'], first_seen: ['first_found'], status: ['state'] },
  },
};

// Qualys reports severity as 1 (lowest) to 5 (highest).
const QUALYS_SEVERITY = { 5: 'Critical', 4: 'High', 3: 'Medium', 2: 'Low', 1: 'Info' };

// Scanner status words mapped to the app's three states.
function normaliseStatus(value) {
  if (!value) return undefined;
  const v = String(value).toLowerCase();
  if (/fixed|closed|resolved|remediated/.test(v)) return 'closed';
  if (/accept/.test(v)) return 'accepted';
  return 'open'; // active, new, re-opened, resurfaced and anything unknown stay open until someone closes them
}

function pickFromRow(row, aliases) {
  for (const key of aliases) {
    if (row[key] !== undefined && row[key] !== '' && row[key] !== null) return row[key];
  }
  return undefined;
}

function normaliseSeverity(value) {
  if (!value) return undefined;
  const v = String(value).toLowerCase();
  if (v.startsWith('crit')) return 'Critical';
  if (v.startsWith('hi')) return 'High';
  if (v.startsWith('med') || v.startsWith('mod')) return 'Medium';
  if (v.startsWith('lo')) return 'Low';
  if (v.startsWith('inf') || v.startsWith('none')) return 'Info';
  return undefined;
}

// rows: objects keyed by normalised header. labels: normalised key -> the file's own header text.
// options: { source, dedupe, pruneSource, today }
//   dedupe:       remove duplicate CVE + asset rows after the import (keeps the newest)
//   pruneSource:  delete rows from this source that the file no longer contains
function importRows(db, rows, labels, options = {}) {
  const today = options.today || new Date().toISOString().slice(0, 10);
  const headers = rows.length ? Object.keys(rows[0]) : [];

  // Headers that aren't built-in become custom fields. Their values are kept, not dropped.
  const customFields = headers
    .filter((h) => h !== '' && !KNOWN_HEADERS.has(h))
    .map((h) => {
      const type = inferType(rows.map((r) => r[h]));
      const field = ensureCustomColumn(db, 'vulnerabilities', labels[h] || h.replace(/_/g, ' '), type);
      return { header: h, ...field };
    });

  // A scanner preset tries its own column names first, then the general aliases.
  const preset = options.preset ? SCANNER_PRESETS[options.preset] : null;
  if (options.preset && !preset) throw new Error(`Unknown import preset: ${options.preset}`);
  const pick = (field, row) => pickFromRow(row, [...(preset?.aliases[field] || []), ...ALIASES[field]]);

  const records = [];
  let skipped = 0;
  for (const row of rows) {
    const title = pick('title', row);
    if (!title) { skipped++; continue; }
    const extra = Object.fromEntries(customFields.map((f) => [f.name, coerceValue(row[f.header], f.type)]));
    const rawSeverity = pick('severity', row);
    records.push({
      title: String(title).trim(),
      cve: pick('cve', row),
      asset: pick('asset', row),
      severity: preset?.numericSeverity && Number.isFinite(Number(rawSeverity))
        ? QUALYS_SEVERITY[Number(rawSeverity)]
        : normaliseSeverity(rawSeverity),
      cvss: pick('cvss', row),
      status: normaliseStatus(pick('status', row)),
      first_seen: normaliseDate(pick('first_seen', row)),
      control_id: pick('control_id', row),
      source: options.source || pickFromRow(row, ALIASES.source) || 'import',
      extra,
    });
  }

  const written = upsertVulnerabilities(db, records, today);
  const source = options.source || null;
  const pruned = options.pruneSource && source ? pruneSource(db, source, today) : 0;
  const deduped = options.dedupe ? removeDuplicates(db) : 0;
  recomputeAll(db, today);
  return { parsed: rows.length, written, skipped, pruned, deduped };
}

// Keys that would change an object's prototype if used as plain property names.
const UNSAFE_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

// Normalises the header of an object-shaped row set (JSON, Excel). Returns { rows, labels }.
// Objects have no prototype here, so a key such as "__proto__" cannot alter anything.
function normaliseObjects(objects) {
  const labels = Object.create(null);
  const rows = objects.map((obj) => {
    const out = Object.create(null);
    for (const [key, value] of Object.entries(obj)) {
      const norm = normaliseHeader(String(key));
      if (!norm || UNSAFE_KEYS.has(norm)) continue;
      labels[norm] = labels[norm] || String(key).trim();
      out[norm] = value;
    }
    return out;
  });
  return { rows, labels };
}

function importCsvText(db, text, options = {}) {
  const rows = csvToObjects(text);
  const headerRow = parseCsv(text)[0] || [];
  const labels = Object.fromEntries(headerRow.map((h) => [normaliseHeader(h), h.trim()]));
  return importRows(db, rows, labels, options);
}

// JSON file: an array of objects, or an object holding the array at itemsPath (e.g. "findings").
function importJsonText(db, text, options = {}) {
  const body = JSON.parse(text);
  const items = getPath(body, options.itemsPath);
  if (!Array.isArray(items)) throw new Error(`No array found at "${options.itemsPath || '(root)'}"`);
  const { rows, labels } = normaliseObjects(items);
  return importRows(db, rows, labels, options);
}

// Excel workbook (.xlsx, .xls, .csv also accepted by SheetJS). Reads the first sheet unless a name is given.
function importExcelBuffer(db, buffer, options = {}) {
  const workbook = XLSX.read(buffer, { type: 'buffer', cellDates: false });
  const sheetName = options.sheet || workbook.SheetNames[0];
  const sheet = workbook.Sheets[sheetName];
  if (!sheet) throw new Error(`No sheet named "${sheetName}"`);
  const { rows, labels } = normaliseObjects(XLSX.utils.sheet_to_json(sheet, { defval: null }));
  return importRows(db, rows, labels, options);
}

// Reads a dotted path such as "data.items.0.name" out of a parsed JSON value.
function getPath(obj, path) {
  if (!path) return obj;
  return path.split('.').reduce((acc, key) => (acc == null ? undefined : acc[key]), obj);
}

// config: { url, headers, itemsPath, mapping, source, dedupe, pruneSource }
//   itemsPath: where the array of findings lives in the response, e.g. "data.findings"
//   mapping:   { title: "name", cve: "cve_id", asset: "host.hostname", ... } (dotted paths allowed)
const MAX_API_BYTES = 25 * 1024 * 1024;

// allowedHosts: null means any host (the desktop app, on the user's own machine). An array restricts
// pulls to those host names; the team server passes one, so clients cannot make it reach internal hosts.
async function importFromApi(db, config, { allowedHosts = null } = {}) {
  const url = new URL(config.url);
  if (!['https:', 'http:'].includes(url.protocol)) throw new Error('API URL must be http or https');
  if (allowedHosts && !allowedHosts.includes(url.hostname)) {
    throw new Error(`${url.hostname} is not an approved API host for this server`);
  }

  const response = await fetch(url, {
    headers: { Accept: 'application/json', ...(config.headers || {}) },
    signal: AbortSignal.timeout(15000),
    redirect: 'error', // a redirect could point somewhere the host check did not approve
  });
  if (!response.ok) throw new Error(`API returned HTTP ${response.status}`);

  const text = await response.text();
  if (text.length > MAX_API_BYTES) throw new Error('API response is too large');
  const body = JSON.parse(text);
  const items = getPath(body, config.itemsPath);
  if (!Array.isArray(items)) throw new Error(`No array found at "${config.itemsPath || '(root)'}"`);

  const mapping = config.mapping || {};
  const rows = items.map((item) => {
    const pick = (field) => (mapping[field] ? getPath(item, mapping[field]) : item[field]);
    return {
      title: pick('title'),
      cve: pick('cve'),
      asset: pick('asset'),
      severity: normaliseSeverity(pick('severity')),
      cvss: pick('cvss'),
      status: pick('status'),
      first_seen: normaliseDate(pick('first_seen')),
      control_id: pick('control_id'),
      source: config.source || 'api',
    };
  }).filter((r) => r.title);

  const today = new Date().toISOString().slice(0, 10);
  const written = upsertVulnerabilities(db, rows, today);
  const pruned = config.pruneSource ? pruneSource(db, config.source || 'api', today) : 0;
  const deduped = config.dedupe ? removeDuplicates(db) : 0;
  recomputeAll(db);
  return { fetched: items.length, written, skipped: items.length - rows.length, pruned, deduped };
}

module.exports = { importCsvText, importJsonText, importExcelBuffer, importFromApi, normaliseSeverity, normaliseStatus, getPath, SCANNER_PRESETS };
