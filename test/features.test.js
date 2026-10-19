const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const XLSX = require('xlsx');
const db = require('../src/db');
const intel = require('../src/intel');
const { createHandlers } = require('../src/handlers');
const workflow = require('../src/workflow');
const poam = require('../src/poam');
const backup = require('../src/backup');
const ingest = require('../src/ingest');
const { remediationMetrics } = require('../src/metrics');
const { recomputeAll } = require('../src/rules');

const TODAY = '2026-10-17';
const fresh = () => db.openDatabase(':memory:');
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'vulnmgt-feat-'));

// ---------- Threat intelligence ----------

test('refreshIntel loads KEV and EPSS from the feeds and re-scores findings', async () => {
  const d = fresh();
  db.upsertVulnerabilities(d, [{ title: 'x', cve: 'CVE-2024-1111', asset: 'a', severity: 'Low', cvss: 3, first_seen: TODAY, source: 's' }], TODAY);
  const kevBody = { vulnerabilities: [{ cveID: 'CVE-2024-1111', vulnerabilityName: 'Exploited', dateAdded: TODAY, dueDate: '2026-11-07' }] };
  const epssBody = { data: [{ cve: 'CVE-2024-1111', epss: '0.5', percentile: '0.9' }] };
  const requested = [];
  const fakeFetch = async (url) => {
    requested.push(String(url));
    const body = String(url).startsWith(intel.KEV_URL) ? kevBody : epssBody;
    return { ok: true, status: 200, json: async () => body };
  };

  const result = await intel.refreshIntel(d, { fetchFn: fakeFetch, today: TODAY });
  assert.equal(result.kev, 1);
  assert.equal(result.epss, 1);
  assert.ok(requested.some((u) => u.startsWith(intel.EPSS_URL)));

  recomputeAll(d, TODAY);
  const row = d.prepare('SELECT kev, epss, priority_score FROM vulnerabilities').get();
  assert.equal(row.kev, 1);
  assert.equal(row.epss, 0.5);
  // CVSS 3 + KEV 3 + EPSS 0.5 * 5 = 8.5
  assert.equal(row.priority_score, 8.5);
});

test('feed parsers reject unexpected formats and ignore malformed CVE IDs', () => {
  const d = fresh();
  assert.throws(() => intel.applyKev(d, { nope: true }), /unexpected format/);
  assert.throws(() => intel.applyEpss(d, {}, TODAY), /unexpected format/);
  assert.equal(intel.applyKev(d, { vulnerabilities: [{ cveID: 'not-a-cve' }, { cveID: 'CVE-2025-0001' }] }), 1);
});

test('a failing feed leaves the previous data in place', async () => {
  const d = fresh();
  intel.applyKev(d, { vulnerabilities: [{ cveID: 'CVE-2025-0001' }] });
  const badFetch = async () => ({ ok: false, status: 503, json: async () => ({}) });
  await assert.rejects(intel.refreshIntel(d, { fetchFn: badFetch, today: TODAY }), /HTTP 503/);
  assert.equal(d.prepare('SELECT COUNT(*) AS n FROM kev_catalog').get().n, 1);
});

// ---------- Asset criticality ----------

test('asset criticality raises the priority of findings on that asset', () => {
  const d = fresh();
  const h = createHandlers(d);
  db.upsertVulnerabilities(d, [{ title: 'x', cve: 'CVE-1', asset: 'payroll-db', severity: 'Low', cvss: 3, first_seen: TODAY, source: 's' }], TODAY);
  recomputeAll(d, TODAY);
  const before = d.prepare('SELECT priority_score FROM vulnerabilities').get().priority_score;
  h['assets:save']({ name: 'payroll-db', owner: 'Finance', criticality: 'Critical', environment: 'prod' });
  const after = d.prepare('SELECT priority_score FROM vulnerabilities').get().priority_score;
  assert.equal(after - before, 3);
  assert.throws(() => h['assets:save']({ name: 'x', criticality: 'Severe' }), /Criticality must be one of/);
});

// ---------- Risk acceptance reviews ----------

test('an RBD whose review date is near or past produces a review alert', () => {
  const d = fresh();
  const soon = poam.saveItem(d, { kind: 'rbd', template: 'custom', title: 'Accept A', data: { review_date: '2026-10-20' } });
  const late = poam.saveItem(d, { kind: 'rbd', template: 'custom', title: 'Accept B', data: { review_date: '2026-09-01' } });
  poam.saveItem(d, { kind: 'rbd', template: 'custom', title: 'Accept C', data: { review_date: '2027-06-01' } });
  const reviews = workflow.computeAlerts(d, TODAY, { leadDays: 7 }).filter((a) => a.kind === 'review');
  const keys = reviews.map((a) => a.key).sort();
  assert.deepEqual(keys, [`review-due:${soon}`, `review-overdue:${late}`].sort());
});

test('a closed RBD produces no review alert', () => {
  const d = fresh();
  poam.saveItem(d, { kind: 'rbd', template: 'custom', title: 'Done', status: 'closed', data: { review_date: '2026-09-01' } });
  assert.equal(workflow.computeAlerts(d, TODAY, {}).some((a) => a.kind === 'review'), false);
});

// ---------- Remediation metrics ----------

test('metrics: time to fix from the history log, overdue share, and aging buckets', () => {
  const d = fresh();
  const realToday = new Date().toISOString().slice(0, 10);
  const twoDaysAgo = new Date(Date.now() - 2 * 864e5).toISOString().slice(0, 10);
  db.upsertVulnerabilities(d, [
    { title: 'closed one', severity: 'High', first_seen: twoDaysAgo, source: 'a', cve: 'CVE-1', asset: 'h' },
    { title: 'old open', severity: 'Low', first_seen: '2025-01-01', source: 'a', cve: 'CVE-2', asset: 'h' },
    { title: 'new open', severity: 'Low', first_seen: realToday, source: 'a', cve: 'CVE-3', asset: 'h' },
  ], realToday);
  const id = d.prepare("SELECT id FROM vulnerabilities WHERE cve = 'CVE-1'").get().id;
  d.prepare("UPDATE vulnerabilities SET status = 'closed' WHERE id = ?").run(id);
  recomputeAll(d, realToday); // sets due dates, which the overdue figures depend on

  const m = remediationMetrics(d, realToday);
  assert.equal(m.closedTotal, 1);
  const high = m.bySeverity.find((s) => s.severity === 'High');
  assert.equal(high.closed, 1);
  assert.equal(high.avgDays, 2);
  assert.equal(m.openTotal, 2);
  assert.equal(m.overdueTotal, 1); // the 2025 finding is past its deadline
  assert.equal(m.overduePercent, 50);
  assert.equal(m.aging.find((a) => a.label === 'Over 180 days').count, 1);
  assert.equal(m.aging.find((a) => a.label === '0 to 30 days').count, 1);
});

// ---------- Scanner presets and status words ----------

test('Nessus preset maps Risk and CVSS v3.0 columns; "None" risk becomes Info', () => {
  const d = fresh();
  const csv = 'Plugin ID,CVE,CVSS v3.0 Base Score,Risk,Host,Name\n12345,CVE-2024-5555,7.8,None,web-01,Weak cipher';
  const res = ingest.importCsvText(d, csv, { preset: 'nessus', source: 'nessus-1', today: TODAY });
  assert.equal(res.written, 1);
  const row = d.prepare('SELECT * FROM vulnerabilities').get();
  assert.equal(row.severity, 'Info');
  assert.equal(row.cvss, 7.8);
  assert.equal(row.title, 'Weak cipher');
});

test('Qualys preset reads numeric severity and Active or Fixed statuses', () => {
  const d = fresh();
  const csv = 'Title,CVE ID,IP,Severity,CVSS Base,First Detected,Status\nOld TLS,CVE-2024-6666,10.0.0.5,5,9.1,2026-01-03,Active\nFixed one,CVE-2024-7777,10.0.0.6,3,5.0,2026-01-03,Fixed';
  ingest.importCsvText(d, csv, { preset: 'qualys', source: 'qualys-1', today: TODAY });
  const rows = d.prepare('SELECT title, severity, status, first_seen FROM vulnerabilities ORDER BY title').all();
  assert.equal(rows.find((r) => r.title === 'Old TLS').severity, 'Critical');
  assert.equal(rows.find((r) => r.title === 'Old TLS').status, 'open');
  assert.equal(rows.find((r) => r.title === 'Old TLS').first_seen, '2026-01-03');
  assert.equal(rows.find((r) => r.title === 'Fixed one').status, 'closed');
});

test('Tenable preset reads State and First Found', () => {
  const d = fresh();
  const csv = 'Plugin Name,CVE,Asset Name,Severity,CVSS v3 Base Score,First Found,State\nSMB signing,CVE-2024-8888,fileserver,High,8.1,2026-02-02,RESURFACED';
  ingest.importCsvText(d, csv, { preset: 'tenable', source: 'tenable-1', today: TODAY });
  const row = d.prepare('SELECT * FROM vulnerabilities').get();
  assert.equal(row.asset, 'fileserver');
  assert.equal(row.status, 'open');
  assert.equal(row.first_seen, '2026-02-02');
});

test('an unknown preset is refused', () => {
  const d = fresh();
  assert.throws(() => ingest.importCsvText(d, 'title\nx', { preset: 'nope' }), /Unknown import preset/);
});

// ---------- Saved views ----------

test('saved views are saved per table, listed, updated by name and deleted', () => {
  const d = fresh();
  const h = createHandlers(d);
  const config = { filters: { severity: 'High' }, sortBy: 'due_date', sortDir: 'asc', columns: ['cve', 'title'] };
  h['views:save']({ name: 'High only', table: 'vulnerabilities', config });
  let list = h['views:list']('vulnerabilities');
  assert.equal(list.length, 1);
  assert.deepEqual(list[0].config.filters, { severity: 'High' });
  h['views:save']({ name: 'High only', table: 'vulnerabilities', config: { filters: {} } });
  list = h['views:list']('vulnerabilities');
  assert.equal(list.length, 1);
  h['views:delete'](list[0].id);
  assert.equal(h['views:list']('vulnerabilities').length, 0);
});

test('saved views reject unknown tables and oversized settings', () => {
  const d = fresh();
  const h = createHandlers(d);
  assert.throws(() => h['views:save']({ name: 'x', table: 'nope; DROP TABLE rules', config: {} }), /Invalid table name/);
  assert.throws(() => h['views:save']({ name: 'big', table: 'vulnerabilities', config: { pad: 'x'.repeat(30000) } }), /too large/);
});

// ---------- Attachments ----------

test('attachments: add to a finding, read back identically, list metadata, delete', () => {
  const d = fresh();
  const h = createHandlers(d);
  db.upsertVulnerabilities(d, [{ title: 'evidence', first_seen: TODAY, source: 's', cve: 'CVE-9', asset: 'h' }], TODAY);
  const vulnId = d.prepare('SELECT id FROM vulnerabilities').get().id;
  const bytes = Buffer.from('scan evidence bytes');
  const id = h['attachments:add']({ vulnId, filename: '../../etc/evidence.txt', mime: 'text/plain', content: bytes.toString('base64'), uploadedBy: 'dana' });
  const list = h['attachments:list']({ vulnId });
  assert.equal(list.length, 1);
  assert.equal(list[0].filename, 'evidence.txt'); // path parts stripped
  const got = h['attachments:get'](id);
  assert.equal(Buffer.from(got.content, 'base64').toString(), 'scan evidence bytes');
  h['attachments:delete'](id);
  assert.equal(h['attachments:list']({ vulnId }).length, 0);
});

test('attachments need exactly one target and reject empty or oversized files', () => {
  const d = fresh();
  const h = createHandlers(d);
  const content = Buffer.from('x').toString('base64');
  assert.throws(() => h['attachments:add']({ filename: 'a.txt', content }), /one finding or one POA&M/);
  assert.throws(() => h['attachments:add']({ vulnId: 1, poamId: 1, filename: 'a.txt', content }), /one finding or one POA&M/);
  assert.throws(() => h['attachments:add']({ vulnId: 1, filename: 'a.txt', content: '' }), /empty/);
  const big = Buffer.alloc(10 * 1024 * 1024 + 1).toString('base64');
  assert.throws(() => h['attachments:add']({ vulnId: 1, filename: 'big.bin', content: big }), /10 MB/);
});

// ---------- Excel export ----------

test('POA&M Excel export is a readable workbook in the template layout', () => {
  const d = fresh();
  const h = createHandlers(d);
  poam.saveItem(d, { kind: 'poam', template: 'fedramp', title: 'Patch TLS', data: { weakness_name: 'Old TLS', remediation_plan: 'Upgrade' } });
  const book = XLSX.read(Buffer.from(h['poam:exportXlsx']({ kind: 'poam', template: 'fedramp' }), 'base64'), { type: 'buffer' });
  const rows = XLSX.utils.sheet_to_json(book.Sheets[book.SheetNames[0]], { header: 1 });
  assert.match(String(rows[0][0]), /POA&M records: FedRAMP/);
  assert.ok(rows[2].includes('Weakness name'));
  assert.ok(rows.some((r) => r.includes('Patch TLS')));
});

// ---------- Backups ----------

test('backup: create a verified copy, list it, restore it, and keep only the newest copies', () => {
  const d = fresh();
  db.upsertVulnerabilities(d, [{ title: 'precious', first_seen: TODAY, source: 's', cve: 'CVE-5', asset: 'h' }], TODAY);
  const dir = tmp();
  const live = path.join(dir, 'live.db');
  const times = [new Date('2026-10-15T10:00:00Z'), new Date('2026-10-16T10:00:00Z'), new Date('2026-10-17T10:00:00Z')];
  for (const now of times) backup.createBackup(d, path.join(dir, 'backups'), { keep: 2, now });
  const listed = backup.listBackups(path.join(dir, 'backups'));
  assert.equal(listed.length, 2); // oldest pruned

  // Simulate losing the live file, then restore from the newest backup.
  fs.writeFileSync(live, 'corrupted');
  const res = backup.restoreBackup(live, listed[0].file);
  assert.ok(fs.existsSync(res.safetyCopy));
  const restored = db.openDatabase(live);
  assert.equal(restored.prepare("SELECT title FROM vulnerabilities").get().title, 'precious');
  restored.close();
  fs.rmSync(dir, { recursive: true, force: true });
});

test('restore refuses a file that is not a valid database', () => {
  const dir = tmp();
  const fake = path.join(dir, 'fake.db');
  fs.writeFileSync(fake, 'not a database at all');
  assert.throws(() => backup.restoreBackup(path.join(dir, 'live.db'), fake), /integrity|open|database/i);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('backup:create is refused when no backup folder is configured', () => {
  const d = fresh();
  assert.throws(() => createHandlers(d)['backup:create'](), /not configured/);
});
