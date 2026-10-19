// Column model: user-visible column definitions (label, type, order, visibility) on top of the physical
// SQLite columns. Custom fields are real columns named c_<slug>, so filters, sorting, the SQL console and
// (later) charts treat them exactly like built-in columns.
const TYPES = ['text', 'number', 'date'];
const SQL_TYPE = { text: 'TEXT', number: 'REAL', date: 'TEXT' };

// Built-in columns of the vulnerabilities table. Everything else in that table is a custom field.
const SYSTEM_COLUMNS = {
  vulnerabilities: ['id', 'cve', 'title', 'asset', 'severity', 'cvss', 'status', 'source',
    'first_seen', 'due_date', 'priority_score', 'timeline_bucket'],
};

const COLUMN_DEFS_SCHEMA = `
  CREATE TABLE IF NOT EXISTS column_defs (
    table_name TEXT NOT NULL,
    name       TEXT NOT NULL,
    label      TEXT NOT NULL,
    type       TEXT NOT NULL DEFAULT 'text',
    position   INTEGER NOT NULL DEFAULT 0,
    visible    INTEGER NOT NULL DEFAULT 1,
    system     INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (table_name, name)
  );
`;

function assertIdentifier(name) {
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) throw new Error(`Invalid table name: ${name}`);
  return name;
}

function physicalColumns(db, table) {
  return db.prepare(`PRAGMA table_info(${assertIdentifier(table)})`).all();
}

function typeFromSql(sqlType) {
  return /INT|REAL|FLOA|DOUB|NUM/i.test(sqlType || '') ? 'number' : 'text';
}

const ACRONYMS = { id: 'ID', cve: 'CVE', cvss: 'CVSS' };

// "first_seen" -> "First Seen", "cvss" -> "CVSS"; custom "c_" prefixes are dropped.
function defaultLabel(name) {
  return name.replace(/^c_/, '').split('_')
    .map((w) => ACRONYMS[w] || w.charAt(0).toUpperCase() + w.slice(1))
    .join(' ');
}

// Adds a definition for every physical column that lacks one (new tables, columns added by SQL).
function syncDefs(db, table) {
  const known = new Set(db.prepare('SELECT name FROM column_defs WHERE table_name = ?').all(table).map((r) => r.name));
  const system = SYSTEM_COLUMNS[table];
  // Migration: built-in labels saved by earlier builds were lowercase ("first seen"); refresh them.
  for (const name of system || []) {
    db.prepare(`UPDATE column_defs SET label = ? WHERE table_name = ? AND name = ? AND system = 1 AND label = ?`)
      .run(defaultLabel(name), table, name, name.replace(/_/g, ' '));
  }
  let position = db.prepare('SELECT COALESCE(MAX(position), 0) AS p FROM column_defs WHERE table_name = ?').get(table).p;
  for (const col of physicalColumns(db, table)) {
    if (known.has(col.name)) continue;
    position++;
    const isSystem = system ? system.includes(col.name) : true;
    db.prepare(`INSERT INTO column_defs (table_name, name, label, type, position, visible, system)
      VALUES (?, ?, ?, ?, ?, 1, ?)`).run(table, col.name, defaultLabel(col.name), typeFromSql(col.type), position, isSystem ? 1 : 0);
  }
}

// Ordered definitions for a table, after syncing with the physical schema.
function listColumnDefs(db, table) {
  syncDefs(db, assertIdentifier(table));
  return db.prepare('SELECT * FROM column_defs WHERE table_name = ? ORDER BY position, name').all(table)
    .map((d) => ({ ...d, visible: Boolean(d.visible), system: Boolean(d.system) }));
}

// Turns a label into a safe identifier: "Asset Owner" -> c_asset_owner, made unique if needed.
function slugFor(label, taken) {
  let base = 'c_' + String(label).toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '').slice(0, 40);
  if (base === 'c_') base = 'c_field';
  let name = base;
  for (let i = 2; taken.has(name); i++) name = `${base}_${i}`;
  return name;
}

function addCustomColumn(db, table, { label, type = 'text' }) {
  assertIdentifier(table);
  const clean = String(label || '').trim();
  if (!clean) throw new Error('Column label is required');
  if (!TYPES.includes(type)) throw new Error(`Unknown column type: ${type}`);
  const defs = listColumnDefs(db, table);
  if (defs.some((d) => d.label.toLowerCase() === clean.toLowerCase())) {
    throw new Error(`A column named "${clean}" already exists`);
  }
  const name = slugFor(clean, new Set(defs.map((d) => d.name)));
  const position = Math.max(0, ...defs.map((d) => d.position)) + 1;
  db.exec(`ALTER TABLE ${table} ADD COLUMN "${name}" ${SQL_TYPE[type]}`);
  db.prepare(`INSERT INTO column_defs (table_name, name, label, type, position, visible, system)
    VALUES (?, ?, ?, ?, ?, 1, 0)`).run(table, name, clean, type, position);
  return name;
}

// Used by importers: returns { name, type } for a custom field, creating it if it doesn't exist.
// Label matching is case-insensitive, so "Asset Owner" and "asset owner" share one column.
// An existing field keeps its type; the importer converts values to that type.
function ensureCustomColumn(db, table, label, type) {
  const existing = listColumnDefs(db, table).find((d) => !d.system && d.label.toLowerCase() === label.toLowerCase());
  if (existing) return { name: existing.name, type: existing.type };
  const name = addCustomColumn(db, table, { label, type });
  return { name, type };
}

// Converts an imported string to a field's type. Unparseable numbers become null, not errors.
function coerceValue(value, type) {
  const s = String(value ?? '').trim();
  if (s === '') return null;
  if (type === 'number') {
    const n = Number(s);
    return Number.isFinite(n) ? n : null;
  }
  return s;
}

// prefs: [{ name, visible, position, label? }]. Renames apply to custom and system labels alike;
// system columns keep their physical name.
function savePrefs(db, table, prefs) {
  assertIdentifier(table);
  const known = new Set(listColumnDefs(db, table).map((d) => d.name));
  db.exec('BEGIN');
  try {
    const update = db.prepare('UPDATE column_defs SET visible = ?, position = ?, label = COALESCE(?, label) WHERE table_name = ? AND name = ?');
    for (const p of prefs) {
      if (!known.has(p.name)) throw new Error(`Unknown column: ${p.name}`);
      const label = p.label != null && String(p.label).trim() ? String(p.label).trim() : null;
      update.run(p.visible ? 1 : 0, Number(p.position) || 0, label, table, p.name);
    }
    db.exec('COMMIT');
  } catch (err) {
    db.exec('ROLLBACK');
    throw err;
  }
}

// Only custom fields can be dropped. Built-in columns are protected.
function deleteCustomColumn(db, table, name) {
  assertIdentifier(table);
  const def = listColumnDefs(db, table).find((d) => d.name === name);
  if (!def) throw new Error(`Unknown column: ${name}`);
  if (def.system) throw new Error(`"${def.label}" is a built-in column and cannot be deleted`);
  db.exec(`ALTER TABLE ${table} DROP COLUMN "${name}"`);
  db.prepare('DELETE FROM column_defs WHERE table_name = ? AND name = ?').run(table, name);
}

// Infers a field type from sample values: number if all numeric, date if all ISO dates, else text.
function inferType(values) {
  const present = values.map((v) => String(v ?? '').trim()).filter((v) => v !== '');
  if (present.length === 0) return 'text';
  if (present.every((v) => Number.isFinite(Number(v)))) return 'number';
  if (present.every((v) => /^\d{4}-\d{2}-\d{2}/.test(v))) return 'date';
  return 'text';
}

module.exports = {
  TYPES,
  SYSTEM_COLUMNS,
  COLUMN_DEFS_SCHEMA,
  listColumnDefs,
  addCustomColumn,
  ensureCustomColumn,
  coerceValue,
  savePrefs,
  deleteCustomColumn,
  inferType,
};
