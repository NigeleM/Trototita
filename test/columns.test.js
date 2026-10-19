const test = require('node:test');
const assert = require('node:assert/strict');
const db = require('../src/db');
const columns = require('../src/columns');
const { importCsvText } = require('../src/ingest');

function freshDb() {
  return db.openDatabase(':memory:');
}

test('inferType picks number, date, or text from sample values', () => {
  assert.equal(columns.inferType(['1', '2.5', '']), 'number');
  assert.equal(columns.inferType(['2026-01-02', '2026-03-04']), 'date');
  assert.equal(columns.inferType(['abc', '5']), 'text');
  assert.equal(columns.inferType(['', '']), 'text');
});

test('built-in columns are flagged as system; physical extras are not', () => {
  const d = freshDb();
  const defs = columns.listColumnDefs(d, 'vulnerabilities');
  assert.equal(defs.find((x) => x.name === 'title').system, true);
  assert.equal(defs.find((x) => x.name === 'cvss').type, 'number');
});

test('addCustomColumn creates a real column and a definition', () => {
  const d = freshDb();
  const name = columns.addCustomColumn(d, 'vulnerabilities', { label: 'Asset Owner', type: 'text' });
  assert.equal(name, 'c_asset_owner');
  assert.ok(db.listColumns(d, 'vulnerabilities').includes('c_asset_owner'));
  const def = columns.listColumnDefs(d, 'vulnerabilities').find((x) => x.name === name);
  assert.equal(def.label, 'Asset Owner');
  assert.equal(def.system, false);
});

test('duplicate labels are rejected; colliding slugs get a numeric suffix', () => {
  const d = freshDb();
  columns.addCustomColumn(d, 'vulnerabilities', { label: 'Owner?', type: 'text' });
  assert.throws(() => columns.addCustomColumn(d, 'vulnerabilities', { label: 'owner?', type: 'text' }), /already exists/);
  const second = columns.addCustomColumn(d, 'vulnerabilities', { label: 'Owner!', type: 'text' });
  assert.equal(second, 'c_owner_2');
});

test('savePrefs hides, reorders and renames', () => {
  const d = freshDb();
  columns.savePrefs(d, 'vulnerabilities', [
    { name: 'title', visible: true, position: 0, label: 'Finding' },
    { name: 'cve', visible: false, position: 1 },
  ]);
  const defs = columns.listColumnDefs(d, 'vulnerabilities');
  assert.equal(defs[0].name, 'title');
  assert.equal(defs[0].label, 'Finding');
  assert.equal(defs.find((x) => x.name === 'cve').visible, false);
});

test('savePrefs rejects unknown columns and rolls back', () => {
  const d = freshDb();
  assert.throws(() => columns.savePrefs(d, 'vulnerabilities', [
    { name: 'title', visible: false, position: 0 },
    { name: 'nope', visible: true, position: 1 },
  ]), /Unknown column/);
  assert.equal(columns.listColumnDefs(d, 'vulnerabilities').find((x) => x.name === 'title').visible, true);
});

test('deleteCustomColumn drops the column; built-in columns are protected', () => {
  const d = freshDb();
  const name = columns.addCustomColumn(d, 'vulnerabilities', { label: 'Ticket', type: 'text' });
  columns.deleteCustomColumn(d, 'vulnerabilities', name);
  assert.equal(db.listColumns(d, 'vulnerabilities').includes(name), false);
  assert.throws(() => columns.deleteCustomColumn(d, 'vulnerabilities', 'title'), /built-in/);
});

test('CSV import creates custom fields from extra headers and keeps their values', () => {
  const d = freshDb();
  const csv = [
    'cve_id,title,host,cvss,Asset Owner,Days Open',
    'CVE-2024-1,Thing one,web-01,9.8,Dana,12',
    'CVE-2024-2,Thing two,web-02,4.0,Lee,40',
  ].join('\n');
  importCsvText(d, csv, { source: 'scanA' });

  const defs = columns.listColumnDefs(d, 'vulnerabilities');
  const days = defs.find((x) => x.label === 'Days Open');
  assert.equal(days.type, 'number');
  assert.equal(days.system, false);

  const res = db.queryTable(d, 'vulnerabilities', { filters: { [days.name]: '>20' } });
  assert.equal(res.total, 1);
  assert.equal(res.rows[0].title, 'Thing two');
});

test('re-importing updates custom field values on the same row', () => {
  const d = freshDb();
  const header = 'cve_id,title,host,Owner\n';
  importCsvText(d, `${header}CVE-1,Thing,web-01,Dana`, { source: 'scanA' });
  importCsvText(d, `${header}CVE-1,Thing,web-01,Lee`, { source: 'scanA' });
  const { n } = d.prepare('SELECT COUNT(*) AS n FROM vulnerabilities').get();
  assert.equal(n, 1);
  assert.equal(d.prepare('SELECT c_owner FROM vulnerabilities').get().c_owner, 'Lee');
});
