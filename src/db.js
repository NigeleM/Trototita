// SQLite access layer. Uses Node's built-in node:sqlite (Node 22.13+ / Electron 35+),
// so there are no native modules to compile.
const { DatabaseSync } = require('node:sqlite');
const { COLUMN_DEFS_SCHEMA } = require('./columns');
const { migrate } = require('./migrations');

const SEVERITIES = ['Critical', 'High', 'Medium', 'Low', 'Info'];

// Columns the app understands. Imports map onto these; anything else is ignored.
const VULN_COLUMNS = [
  'cve', 'title', 'asset', 'severity', 'cvss', 'status',
  'source', 'first_seen', 'due_date', 'priority_score', 'timeline_bucket',
];

const SCHEMA = `
  CREATE TABLE IF NOT EXISTS vulnerabilities (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    cve             TEXT,
    title           TEXT NOT NULL,
    asset           TEXT,
    severity        TEXT CHECK (severity IN ('Critical','High','Medium','Low','Info')),
    cvss            REAL,
    status          TEXT NOT NULL DEFAULT 'open',
    source          TEXT NOT NULL DEFAULT 'manual',
    first_seen      TEXT NOT NULL,
    due_date        TEXT,
    priority_score  REAL,
    timeline_bucket TEXT,
    UNIQUE (source, cve, asset)
  );

  CREATE TABLE IF NOT EXISTS rules (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    name           TEXT NOT NULL,
    enabled        INTEGER NOT NULL DEFAULT 1,
    position       INTEGER NOT NULL DEFAULT 0,
    conditions     TEXT NOT NULL,   -- JSON array of {field, op, value}; all must match
    priority_bonus REAL NOT NULL DEFAULT 0,
    sla_days       INTEGER          -- overrides the severity SLA when set (first match wins)
  );
`;

function openDatabase(file) {
  const db = new DatabaseSync(file);
  db.exec('PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;');
  db.exec(SCHEMA);
  db.exec(COLUMN_DEFS_SCHEMA);
  migrate(db);
  return db;
}

// Table names come from sqlite_master, but are still validated before being put into SQL.
function assertIdentifier(name) {
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) throw new Error(`Invalid table name: ${name}`);
  return name;
}

function listTables(db) {
  return db
    .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' AND name != 'column_defs' ORDER BY name")
    .all()
    .map((r) => r.name);
}

function listColumns(db, table) {
  return db.prepare(`PRAGMA table_info(${assertIdentifier(table)})`).all().map((c) => c.name);
}

// Runs any SQL the user typed in the SQL console.
// Row-returning statements come back as rows, everything else reports changes.
function runSql(db, sql) {
  const trimmed = sql.trim();
  if (!trimmed) throw new Error('Empty SQL');
  if (/^\s*(select|with|pragma|explain)\b/i.test(trimmed)) {
    const rows = db.prepare(trimmed).all();
    const columns = rows.length ? Object.keys(rows[0]) : [];
    return { kind: 'rows', columns, rows: rows.slice(0, 5000), truncated: rows.length > 5000 };
  }
  const result = db.prepare(trimmed).run();
  return { kind: 'changes', changes: Number(result.changes) };
}

// Same row limit the Data grid loads.
const LOADED_ROW_LIMIT = 2000;

// SQL over the rows the Data grid has loaded (same table, filters and sort, up to LOADED_ROW_LIMIT).
// The rows are copied into a separate in-memory database, so the query reads the copy and cannot change real data.
function runSqlOnLoaded(db, { table, filters, sortBy, sortDir }, sql) {
  if (!String(sql).trim()) throw new Error('Empty SQL');
  if (!/^\s*(select|with|pragma|explain)\b/i.test(sql)) {
    throw new Error('SQL on loaded rows is read-only. Switch to the full database to change data.');
  }
  const { columns, rows } = queryTable(db, table, { filters, sortBy, sortDir, limit: LOADED_ROW_LIMIT });
  const copy = new DatabaseSync(':memory:');
  try {
    copy.exec(`CREATE TABLE "${table}" (${columns.map((c) => `"${c}"`).join(', ')})`);
    const insert = copy.prepare(`INSERT INTO "${table}" (${columns.map((c) => `"${c}"`).join(', ')}) VALUES (${columns.map(() => '?').join(', ')})`);
    copy.exec('BEGIN');
    for (const row of rows) insert.run(...columns.map((c) => row[c]));
    copy.exec('COMMIT');
    const changesBefore = copy.prepare('SELECT total_changes() AS n').get().n;
    const result = runSql(copy, sql);
    const wrote = copy.prepare('SELECT total_changes() AS n').get().n !== changesBefore;
    if (result.kind !== 'rows' || wrote) throw new Error('SQL on loaded rows is read-only. Switch to the full database to change data.');
    return { ...result, loaded: rows.length };
  } finally {
    copy.close();
  }
}

// Grid query: optional per-column text filters, sort, and paging. Filters are column-name whitelisted.
// A filter value starting with >, >=, <, <= or = is a numeric comparison; anything else is a
// case-insensitive "contains".
function queryTable(db, table, { filters = {}, sortBy, sortDir = 'asc', limit = 1000, offset = 0 } = {}) {
  assertIdentifier(table);
  const columns = listColumns(db, table);
  const where = [];
  const params = [];

  for (const [column, raw] of Object.entries(filters)) {
    if (!columns.includes(column) || raw === '' || raw == null) continue;
    const text = String(raw).trim();
    const m = text.match(/^(>=|<=|>|<|=)\s*(-?\d+(\.\d+)?)$/);
    if (m) {
      where.push(`"${column}" ${m[1]} ?`);
      params.push(Number(m[2]));
    } else {
      where.push(`CAST("${column}" AS TEXT) LIKE ? ESCAPE '\\'`);
      params.push(`%${text.replace(/[\\%_]/g, (c) => '\\' + c)}%`);
    }
  }

  const order = sortBy && columns.includes(sortBy)
    ? `ORDER BY "${sortBy}" ${sortDir === 'desc' ? 'DESC' : 'ASC'}`
    : 'ORDER BY rowid';
  const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';

  const total = db.prepare(`SELECT COUNT(*) AS n FROM ${table} ${whereSql}`).get(...params).n;
  const rows = db
    .prepare(`SELECT rowid AS __rowid, * FROM ${table} ${whereSql} ${order} LIMIT ? OFFSET ?`)
    .all(...params, limit, offset);

  return { columns, rows, total };
}

// Single-cell write from the grid. Column must exist; rowid is bound as a parameter.
function updateCell(db, table, rowid, column, value) {
  assertIdentifier(table);
  if (!listColumns(db, table).includes(column) || column === 'rowid') {
    throw new Error(`Unknown column: ${column}`);
  }
  db.prepare(`UPDATE ${table} SET "${column}" = ? WHERE rowid = ?`).run(value === '' ? null : value, rowid);
}

// Adds a blank row from the grid. Vulnerabilities need a title and a first-seen date; other tables use their defaults.
function insertRow(db, table, today = new Date().toISOString().slice(0, 10)) {
  assertIdentifier(table);
  const result = table === 'vulnerabilities'
    ? db.prepare('INSERT INTO vulnerabilities (title, first_seen) VALUES (?, ?)').run('New finding', today)
    : db.prepare(`INSERT INTO ${table} DEFAULT VALUES`).run();
  return Number(result.lastInsertRowid);
}

function deleteRows(db, table, rowids) {
  assertIdentifier(table);
  const stmt = db.prepare(`DELETE FROM ${table} WHERE rowid = ?`);
  let deleted = 0;
  db.exec('BEGIN');
  try {
    for (const id of rowids) deleted += Number(stmt.run(id).changes);
    db.exec('COMMIT');
  } catch (err) {
    db.exec('ROLLBACK');
    throw err;
  }
  return deleted;
}

// Upsert used by CSV and API imports. Re-importing the same (source, cve, asset) updates the row.
// records[].extra holds custom field values keyed by physical column name (c_<slug>). Those columns
// must already exist; ensureCustomColumn() in columns.js creates them.
function upsertVulnerabilities(db, records, today = new Date().toISOString().slice(0, 10)) {
  const extraKeys = [...new Set(records.flatMap((r) => Object.keys(r.extra || {})))];
  for (const k of extraKeys) {
    if (!/^c_[a-z0-9_]+$/.test(k)) throw new Error(`Invalid custom column name: ${k}`);
  }
  const extraInsert = extraKeys.map((k) => `, "${k}"`).join('');
  const extraValues = extraKeys.map((k) => `, @${k}`).join('');
  const extraUpdate = extraKeys.map((k) => `,\n      "${k}" = excluded."${k}"`).join('');
  const stmt = db.prepare(`
    INSERT INTO vulnerabilities (cve, title, asset, severity, cvss, status, source, first_seen, due_date, last_seen, control_id${extraInsert})
    VALUES (@cve, @title, @asset, @severity, @cvss, @status, @source, @first_seen, @due_date, @last_seen, @control_id${extraValues})
    ON CONFLICT (source, cve, asset) DO UPDATE SET
      title = excluded.title,
      severity = excluded.severity,
      cvss = excluded.cvss,
      status = excluded.status,
      last_seen = excluded.last_seen,
      control_id = COALESCE(excluded.control_id, control_id)${extraUpdate}
  `);
  let written = 0;
  db.exec('BEGIN');
  try {
    for (const r of records) {
      const cvss = Number(r.cvss);
      const extra = Object.fromEntries(extraKeys.map((k) => [k, r.extra?.[k] ?? null]));
      stmt.run({
        cve: r.cve || null,
        title: r.title,
        asset: r.asset || null,
        severity: SEVERITIES.includes(r.severity) ? r.severity : null,
        cvss: r.cvss == null || r.cvss === '' || !Number.isFinite(cvss) ? null : cvss,
        status: r.status || 'open',
        source: r.source || 'manual',
        first_seen: /^\d{4}-\d{2}-\d{2}/.test(r.first_seen ?? '') ? r.first_seen.slice(0, 10) : today,
        due_date: r.due_date ?? null,
        last_seen: today,
        control_id: r.control_id || null,
        ...extra,
      });
      written++;
    }
    db.exec('COMMIT');
  } catch (err) {
    db.exec('ROLLBACK');
    throw err;
  }
  return written;
}

// Counts rows per value of any column (built-in or custom). Feeds the chart builder.
// Blank values are grouped as "(none)". Results are ordered by count, largest first.
function aggregate(db, table, { groupBy, openOnly = false, limit = 50 }) {
  assertIdentifier(table);
  const columns = listColumns(db, table);
  if (!columns.includes(groupBy)) throw new Error(`Unknown column: ${groupBy}`);
  const where = openOnly && columns.includes('status') ? "WHERE status = 'open'" : '';
  return db.prepare(`
    SELECT COALESCE(CAST("${groupBy}" AS TEXT), '(none)') AS label, COUNT(*) AS n
    FROM ${table} ${where}
    GROUP BY label ORDER BY n DESC LIMIT ?
  `).all(limit).map((r) => ({ label: r.label, n: Number(r.n) }));
}

// Dashboard aggregates computed in SQL.
function dashboardStats(db, today) {
  const bySeverity = db.prepare(`
    SELECT COALESCE(severity, 'Unrated') AS label, COUNT(*) AS n
    FROM vulnerabilities WHERE status = 'open' GROUP BY label
  `).all();
  const byBucket = db.prepare(`
    SELECT COALESCE(timeline_bucket, 'Unscheduled') AS label, COUNT(*) AS n
    FROM vulnerabilities WHERE status = 'open' GROUP BY label
  `).all();
  const totals = db.prepare(`
    SELECT
      COUNT(*) AS total,
      COALESCE(SUM(CASE WHEN status = 'open' THEN 1 ELSE 0 END), 0) AS open,
      COALESCE(SUM(CASE WHEN status = 'open' AND due_date < ? THEN 1 ELSE 0 END), 0) AS overdue,
      ROUND(AVG(CASE WHEN status = 'open' THEN priority_score END), 2) AS avg_priority
    FROM vulnerabilities
  `).get(today);
  const top = db.prepare(`
    SELECT id, cve, title, asset, severity, priority_score, due_date, timeline_bucket
    FROM vulnerabilities WHERE status = 'open'
    ORDER BY priority_score DESC, due_date ASC LIMIT 10
  `).all();
  return { totals, bySeverity, byBucket, top };
}

function listRules(db) {
  return db.prepare('SELECT * FROM rules ORDER BY position, id').all().map((r) => ({
    ...r,
    enabled: Boolean(r.enabled),
    conditions: JSON.parse(r.conditions),
  }));
}

function saveRule(db, rule) {
  const conditions = JSON.stringify(rule.conditions || []);
  const bonus = Number(rule.priority_bonus) || 0;
  const sla = rule.sla_days === '' || rule.sla_days == null ? null : Number(rule.sla_days);
  if (rule.id) {
    db.prepare(`UPDATE rules SET name=?, enabled=?, conditions=?, priority_bonus=?, sla_days=? WHERE id=?`)
      .run(rule.name, rule.enabled ? 1 : 0, conditions, bonus, sla, rule.id);
    return rule.id;
  }
  const pos = db.prepare('SELECT COALESCE(MAX(position), 0) + 1 AS p FROM rules').get().p;
  const result = db.prepare(`INSERT INTO rules (name, enabled, position, conditions, priority_bonus, sla_days)
    VALUES (?, ?, ?, ?, ?, ?)`).run(rule.name, rule.enabled ? 1 : 0, pos, conditions, bonus, sla);
  return Number(result.lastInsertRowid);
}

function deleteRule(db, id) {
  db.prepare('DELETE FROM rules WHERE id = ?').run(id);
}

function seedIfEmpty(db) {
  const { n } = db.prepare('SELECT COUNT(*) AS n FROM vulnerabilities').get();
  if (n > 0) return;
  const today = new Date();
  const ago = (days) => new Date(today.getTime() - days * 864e5).toISOString().slice(0, 10);
  upsertVulnerabilities(db, [
    { cve: 'CVE-2024-3094', title: 'XZ utils backdoor', asset: 'build-01', severity: 'Critical', cvss: 10, source: 'sample', first_seen: ago(3) },
    { cve: 'CVE-2023-44487', title: 'HTTP/2 rapid reset', asset: 'edge-lb-02', severity: 'High', cvss: 7.5, source: 'sample', first_seen: ago(40) },
    { cve: 'CVE-2024-6387', title: 'OpenSSH regreSSHion', asset: 'bastion', severity: 'High', cvss: 8.1, source: 'sample', first_seen: ago(12) },
    { cve: 'CVE-2023-4863', title: 'libwebp heap overflow', asset: 'web-03', severity: 'Medium', cvss: 6.5, source: 'sample', first_seen: ago(70) },
    { cve: 'CVE-2022-0778', title: 'OpenSSL BN_mod_sqrt DoS', asset: 'web-03', severity: 'Medium', cvss: 5.9, source: 'sample', first_seen: ago(20) },
    { cve: 'CVE-2021-44228', title: 'Log4Shell', asset: 'legacy-app', severity: 'Critical', cvss: 10, source: 'sample', first_seen: ago(200) },
    { cve: 'CVE-2019-11043', title: 'PHP-FPM remote code exec', asset: 'legacy-app', severity: 'Low', cvss: 3.2, source: 'sample', first_seen: ago(5) },
  ]);
  saveRule(db, {
    name: 'Internet-facing assets get +2 priority',
    enabled: true,
    conditions: [{ field: 'asset', op: 'contains', value: 'edge' }],
    priority_bonus: 2,
    sla_days: 7,
  });
  saveRule(db, {
    name: 'Critical CVSS >= 9 gets 3-day SLA',
    enabled: true,
    conditions: [{ field: 'cvss', op: 'gte', value: 9 }],
    priority_bonus: 1,
    sla_days: 3,
  });
}

module.exports = {
  SEVERITIES,
  VULN_COLUMNS,
  openDatabase,
  listTables,
  listColumns,
  runSql,
  runSqlOnLoaded,
  queryTable,
  updateCell,
  insertRow,
  deleteRows,
  upsertVulnerabilities,
  dashboardStats,
  aggregate,
  listRules,
  saveRule,
  deleteRule,
  seedIfEmpty,
};
