const test = require('node:test');
const assert = require('node:assert/strict');
const { parseCsv, csvToObjects } = require('../src/csv');
const db = require('../src/db');
const { importCsvText } = require('../src/ingest');
const { recomputeAll } = require('../src/rules');

test('CSV parser handles quotes, embedded commas, newlines and CRLF', () => {
  const rows = parseCsv('a,b\r\n"x, y","say ""hi""\nthere"\r\n\r\n');
  assert.deepEqual(rows, [['a', 'b'], ['x, y', 'say "hi"\nthere']]);
});

test('csvToObjects normalises header names', () => {
  const [obj] = csvToObjects('CVE ID,Host-Name,CVSS Score\nCVE-1,web,7.5');
  assert.deepEqual(obj, { cve_id: 'CVE-1', host_name: 'web', cvss_score: '7.5' });
});

function freshDb() {
  const d = db.openDatabase(':memory:');
  return d;
}

test('CSV import upserts on source + cve + asset and rescoring runs', () => {
  const d = freshDb();
  const csv = [
    'cve_id,title,host,cvss,severity,discovered',
    'CVE-2024-1,Bad thing,web-01,9.8,Critical,2026-10-01',
    'CVE-2024-2,Meh thing,web-01,4.0,Medium,2026-10-02',
    'CVE-2024-3,,web-01,,,',
  ].join('\n');

  const first = importCsvText(d, csv, { source: 'scanA' });
  assert.equal(first.written, 2);
  assert.equal(first.skipped, 1);

  const again = importCsvText(d, csv.replace('Bad thing', 'Worse thing'), { source: 'scanA' });
  assert.equal(again.written, 2);
  const { n } = d.prepare('SELECT COUNT(*) AS n FROM vulnerabilities').get();
  assert.equal(n, 2);
  assert.equal(d.prepare("SELECT title FROM vulnerabilities WHERE cve = 'CVE-2024-1'").get().title, 'Worse thing');
  assert.ok(d.prepare('SELECT due_date FROM vulnerabilities').get().due_date);
});

test('queryTable filters: text contains, numeric comparisons, sorting', () => {
  const d = freshDb();
  db.upsertVulnerabilities(d, [
    { title: 'alpha', asset: 'web-01', cvss: 9, first_seen: '2026-01-01' },
    { title: 'beta', asset: 'db-01', cvss: 4, first_seen: '2026-01-01' },
    { title: 'gamma', asset: 'web-02', cvss: 6, first_seen: '2026-01-01' },
  ]);
  recomputeAll(d);

  const byAsset = db.queryTable(d, 'vulnerabilities', { filters: { asset: 'WEB' } });
  assert.equal(byAsset.total, 2);

  const byScore = db.queryTable(d, 'vulnerabilities', { filters: { cvss: '>5' } });
  assert.deepEqual(byScore.rows.map((r) => r.title).sort(), ['alpha', 'gamma']);

  const sorted = db.queryTable(d, 'vulnerabilities', { sortBy: 'cvss', sortDir: 'desc' });
  assert.equal(sorted.rows[0].title, 'alpha');
});

test('filter values with LIKE wildcards are matched literally', () => {
  const d = freshDb();
  db.upsertVulnerabilities(d, [
    { title: '100% done', first_seen: '2026-01-01' },
    { title: 'other', first_seen: '2026-01-01' },
  ]);
  assert.equal(db.queryTable(d, 'vulnerabilities', { filters: { title: '%' } }).total, 1);
});

test('filters on unknown columns are ignored, not injected', () => {
  const d = freshDb();
  db.upsertVulnerabilities(d, [{ title: 'x', first_seen: '2026-01-01' }]);
  const res = db.queryTable(d, 'vulnerabilities', { filters: { 'title; DROP TABLE rules': 'x' } });
  assert.equal(res.total, 1);
});

test('invalid table names are rejected', () => {
  const d = freshDb();
  assert.throws(() => db.queryTable(d, 'vulnerabilities; DROP TABLE rules', {}), /Invalid table name/);
});

test('updateCell writes a value and rejects unknown columns', () => {
  const d = freshDb();
  db.upsertVulnerabilities(d, [{ title: 'x', first_seen: '2026-01-01' }]);
  const { rowid } = d.prepare('SELECT rowid AS rowid FROM vulnerabilities').get();
  db.updateCell(d, 'vulnerabilities', rowid, 'status', 'closed');
  assert.equal(d.prepare('SELECT status FROM vulnerabilities').get().status, 'closed');
  assert.throws(() => db.updateCell(d, 'vulnerabilities', rowid, 'nope', 'x'), /Unknown column/);
});

test('deleteRows removes only the selected rowids', () => {
  const d = freshDb();
  db.upsertVulnerabilities(d, [
    { title: 'a', first_seen: '2026-01-01' },
    { title: 'b', first_seen: '2026-01-01' },
    { title: 'c', first_seen: '2026-01-01' },
  ]);
  const ids = d.prepare('SELECT rowid AS rowid FROM vulnerabilities WHERE title != ?').all('b').map((r) => r.rowid);
  assert.equal(db.deleteRows(d, 'vulnerabilities', ids), 2);
  assert.deepEqual(d.prepare('SELECT title FROM vulnerabilities').all().map((r) => r.title), ['b']);
});

test('runSql returns rows for SELECT and change counts for writes', () => {
  const d = freshDb();
  db.upsertVulnerabilities(d, [{ title: 'a', first_seen: '2026-01-01' }]);
  const rows = db.runSql(d, 'SELECT title FROM vulnerabilities');
  assert.equal(rows.kind, 'rows');
  assert.deepEqual(JSON.parse(JSON.stringify(rows.rows)), [{ title: 'a' }]);
  const write = db.runSql(d, "UPDATE vulnerabilities SET status = 'closed'");
  assert.deepEqual(write, { kind: 'changes', changes: 1 });
});

test('rules CRUD: create, update, delete, and recompute on seed', () => {
  const d = freshDb();
  db.seedIfEmpty(d);
  const rules = db.listRules(d);
  assert.equal(rules.length, 2);
  const id = db.saveRule(d, { name: 'extra', enabled: true, conditions: [{ field: 'cvss', op: 'gt', value: 1 }], priority_bonus: 1, sla_days: '' });
  assert.equal(db.listRules(d).find((r) => r.id === id).sla_days, null);
  db.saveRule(d, { id, name: 'renamed', enabled: false, conditions: [], priority_bonus: 0, sla_days: 5 });
  assert.equal(db.listRules(d).find((r) => r.id === id).name, 'renamed');
  db.deleteRule(d, id);
  assert.equal(db.listRules(d).length, 2);
  assert.ok(db.dashboardStats(d, '2026-10-17').totals.total >= 7);
});

test('aggregate counts rows per value, blanks as (none), and honours openOnly', () => {
  const d = freshDb();
  db.upsertVulnerabilities(d, [
    { title: 'a', severity: 'High', first_seen: '2026-01-01' },
    { title: 'b', severity: 'High', first_seen: '2026-01-01', asset: 'x' },
    { title: 'c', severity: 'Low', first_seen: '2026-01-01', status: 'closed' },
    { title: 'd', first_seen: '2026-01-01' },
  ]);
  const all = db.aggregate(d, 'vulnerabilities', { groupBy: 'severity' });
  assert.deepEqual(all[0], { label: 'High', n: 2 });
  assert.ok(all.some((r) => r.label === '(none)' && r.n === 1));
  const open = db.aggregate(d, 'vulnerabilities', { groupBy: 'severity', openOnly: true });
  assert.equal(open.some((r) => r.label === 'Low'), false);
  assert.throws(() => db.aggregate(d, 'vulnerabilities', { groupBy: 'nope' }), /Unknown column/);
});

test('insertRow adds a blank finding with a title and first-seen date, and the grid shows it', () => {
  const d = freshDb();
  const rowid = db.insertRow(d, 'vulnerabilities', '2026-10-19');
  const row = d.prepare('SELECT title, first_seen, status, source FROM vulnerabilities WHERE rowid = ?').get(rowid);
  assert.deepEqual({ ...row }, { title: 'New finding', first_seen: '2026-10-19', status: 'open', source: 'manual' });
  assert.equal(db.queryTable(d, 'vulnerabilities').total, 1);
});

test('insertRow uses table defaults for other tables', () => {
  const d = freshDb();
  db.seedIfEmpty(d);
  // rules.name is required with no default, so a blank rule is refused by SQLite
  assert.throws(() => db.insertRow(d, 'rules'), /NOT NULL constraint failed: rules\.name/);
  assert.throws(() => db.insertRow(d, 'rules; DROP TABLE rules'), /Invalid table name/);
  assert.equal(db.listRules(d).length, 2);
});

test('runSqlOnLoaded queries only the loaded rows, with the grid filters applied', () => {
  const d = freshDb();
  db.upsertVulnerabilities(d, [
    { title: 'alpha', asset: 'web-01', cvss: 9, first_seen: '2026-01-01' },
    { title: 'beta', asset: 'db-01', cvss: 4, first_seen: '2026-01-01' },
    { title: 'gamma', asset: 'web-02', cvss: 6, first_seen: '2026-01-01' },
  ]);
  const res = db.runSqlOnLoaded(d, { table: 'vulnerabilities', filters: { asset: 'web' } },
    'SELECT title FROM vulnerabilities ORDER BY title');
  assert.equal(res.kind, 'rows');
  assert.equal(res.loaded, 2);
  assert.deepEqual(res.rows.map((r) => r.title), ['alpha', 'gamma']);
});

test('runSqlOnLoaded is read-only and cannot change the real table', () => {
  const d = freshDb();
  db.upsertVulnerabilities(d, [{ title: 'a', first_seen: '2026-01-01' }]);
  const args = { table: 'vulnerabilities', filters: {} };
  assert.throws(() => db.runSqlOnLoaded(d, args, "UPDATE vulnerabilities SET status = 'closed'"), /read-only/);
  assert.throws(() => db.runSqlOnLoaded(d, args, 'WITH x AS (SELECT 1) DELETE FROM vulnerabilities'), /read-only/);
  assert.equal(d.prepare("SELECT status FROM vulnerabilities").get().status, 'open');
  assert.equal(d.prepare('SELECT COUNT(*) AS n FROM vulnerabilities').get().n, 1);
});
