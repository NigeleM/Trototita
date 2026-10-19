const test = require('node:test');
const assert = require('node:assert/strict');
const XLSX = require('xlsx');
const db = require('../src/db');
const { recomputeAll, evaluate, addDays } = require('../src/rules');
const workflow = require('../src/workflow');
const poam = require('../src/poam');
const cleaning = require('../src/cleaning');
const ingest = require('../src/ingest');

const TODAY = '2026-10-17';
const fresh = () => db.openDatabase(':memory:');
const one = (d) => d.prepare('SELECT * FROM vulnerabilities').get();

// ---------- Compliance and deadlines ----------

test('deadline policy: open and past due is non-compliant; closed is Closed', () => {
  const policies = [{ kind: 'deadline', params: {} }];
  const overdue = { status: 'open', severity: 'High', cvss: 7, first_seen: '2026-01-01' };
  assert.equal(evaluate(overdue, [], TODAY, policies).compliance_status, 'Non-compliant');
  assert.equal(evaluate({ ...overdue, status: 'closed' }, [], TODAY, policies).compliance_status, 'Closed');
  const fine = { ...overdue, first_seen: TODAY };
  assert.equal(evaluate(fine, [], TODAY, policies).compliance_status, 'Compliant');
});

test('severity threshold policy fails open findings at or above the threshold', () => {
  const policies = [{ kind: 'severity', params: { threshold: 'High' } }];
  const base = { status: 'open', cvss: null, first_seen: TODAY };
  assert.equal(evaluate({ ...base, severity: 'High' }, [], TODAY, policies).compliance_status, 'Non-compliant');
  assert.equal(evaluate({ ...base, severity: 'Critical' }, [], TODAY, policies).compliance_status, 'Non-compliant');
  assert.equal(evaluate({ ...base, severity: 'Medium' }, [], TODAY, policies).compliance_status, 'Compliant');
});

test('control policy fails open findings mapped to a listed control', () => {
  const policies = [{ kind: 'control', params: { controls: ['AC-2'] } }];
  const base = { status: 'open', severity: 'Low', cvss: null, first_seen: TODAY };
  assert.equal(evaluate({ ...base, control_id: 'AC-2' }, [], TODAY, policies).compliance_status, 'Non-compliant');
  assert.equal(evaluate({ ...base, control_id: 'SI-2' }, [], TODAY, policies).compliance_status, 'Compliant');
});

test('combined policies: any failing policy makes the finding non-compliant', () => {
  const policies = [
    { kind: 'deadline', params: {} },
    { kind: 'severity', params: { threshold: 'Critical' } },
  ];
  const row = { status: 'open', severity: 'Critical', cvss: null, first_seen: TODAY };
  assert.equal(evaluate(row, [], TODAY, policies).compliance_status, 'Non-compliant');
});

test('no enabled policies means Not evaluated', () => {
  const row = { status: 'open', severity: 'Low', cvss: null, first_seen: TODAY };
  assert.equal(evaluate(row, [], TODAY, []).compliance_status, 'Not evaluated');
});

test('a per-finding deadline override replaces the computed due date', () => {
  const row = { status: 'open', severity: 'Low', cvss: null, first_seen: '2026-01-01', deadline_override: '2026-11-30' };
  assert.equal(evaluate(row, [], TODAY).due_date, '2026-11-30');
  assert.equal(evaluate({ ...row, deadline_override: null }, [], TODAY).due_date, addDays('2026-01-01', 180));
});

test('recomputeAll stores compliance status from the saved policies', () => {
  const d = fresh();
  db.upsertVulnerabilities(d, [{ title: 'old', severity: 'Critical', first_seen: '2025-01-01', source: 'a', cve: 'CVE-1', asset: 'h' }]);
  recomputeAll(d, TODAY);
  assert.equal(one(d).compliance_status, 'Non-compliant');
});

// ---------- History and comments ----------

test('changes to tracked fields are recorded in history by triggers, including SQL console edits', () => {
  const d = fresh();
  db.upsertVulnerabilities(d, [{ title: 'x', severity: 'High', first_seen: TODAY }]);
  const id = one(d).id;
  d.prepare("UPDATE vulnerabilities SET status = 'closed' WHERE id = ?").run(id);
  d.prepare("UPDATE vulnerabilities SET status = 'closed' WHERE id = ?").run(id); // no change, no row
  const history = workflow.listHistory(d, id);
  assert.equal(history.length, 1);
  assert.equal(history[0].field, 'status');
  assert.equal(history[0].old_value, 'open');
  assert.equal(history[0].new_value, 'closed');
});

test('comments can be added, listed and deleted; empty comments are rejected', () => {
  const d = fresh();
  db.upsertVulnerabilities(d, [{ title: 'x', first_seen: TODAY }]);
  const id = one(d).id;
  workflow.addComment(d, id, 'Dana', 'Patch scheduled');
  assert.throws(() => workflow.addComment(d, id, 'Dana', '   '), /empty/);
  const [c] = workflow.listComments(d, id);
  assert.equal(c.body, 'Patch scheduled');
  workflow.deleteComment(d, c.id);
  assert.equal(workflow.listComments(d, id).length, 0);
});

test('deleting a finding removes its comments', () => {
  const d = fresh();
  db.upsertVulnerabilities(d, [{ title: 'x', first_seen: TODAY }]);
  const id = one(d).id;
  workflow.addComment(d, id, 'Dana', 'note');
  db.deleteRows(d, 'vulnerabilities', [id]);
  assert.equal(d.prepare('SELECT COUNT(*) AS n FROM vuln_comments').get().n, 0);
});

// ---------- Snapshots, policies, alerts ----------

test('daily snapshot counts open, overdue and non-compliant findings; trend is ordered by date', () => {
  const d = fresh();
  db.upsertVulnerabilities(d, [{ title: 'late', severity: 'High', first_seen: '2025-01-01', source: 'a', cve: 'CVE-1' }]);
  recomputeAll(d, TODAY);
  workflow.recordSnapshot(d, '2026-10-16');
  workflow.recordSnapshot(d, TODAY);
  const trend = workflow.listSnapshots(d, 10);
  assert.deepEqual(trend.map((t) => t.snapshot_date), ['2026-10-16', TODAY]);
  assert.equal(trend[1].overdue_count, 1);
});

test('savePolicies replaces the set and validates kinds', () => {
  const d = fresh();
  workflow.savePolicies(d, [{ name: 'Only', kind: 'severity', params: { threshold: 'Low' }, enabled: true }]);
  const list = workflow.listPolicies(d);
  assert.equal(list.length, 1);
  assert.equal(list[0].params.threshold, 'Low');
  assert.throws(() => workflow.savePolicies(d, [{ kind: 'nope' }]), /Unknown policy kind/);
});

test('alerts: overdue, upcoming, non-compliant and overdue milestones; dismissal hides until it expires', () => {
  const d = fresh();
  db.upsertVulnerabilities(d, [
    { title: 'overdue one', severity: 'High', first_seen: '2025-01-01', source: 'a', cve: 'CVE-1', asset: 'h' },
    // Low severity has a 180-day SLA, so this one falls due in 3 days.
    { title: 'due soon', severity: 'Low', first_seen: addDays(TODAY, 3 - 180), source: 'a', cve: 'CVE-2', asset: 'h' },
  ]);
  recomputeAll(d, TODAY);
  const poamId = poam.saveItem(d, { kind: 'poam', template: 'custom', title: 'Plan' });
  poam.saveMilestone(d, { poam_id: poamId, title: 'Patch wave 1', due_date: '2026-10-01' });

  const kinds = workflow.computeAlerts(d, TODAY, { leadDays: 7 }).map((a) => a.kind);
  for (const kind of ['overdue', 'upcoming', 'noncompliant', 'milestone']) {
    assert.ok(kinds.includes(kind), `expected a ${kind} alert`);
  }

  const overdueKey = workflow.computeAlerts(d, TODAY, {}).find((a) => a.kind === 'overdue').key;
  workflow.dismissAlert(d, overdueKey, TODAY, 7);
  assert.equal(workflow.computeAlerts(d, TODAY, {}).some((a) => a.key === overdueKey), false);
  assert.equal(workflow.computeAlerts(d, addDays(TODAY, 8), {}).some((a) => a.key === overdueKey), true);
});

// ---------- POA&M and RBD ----------

test('templates list the four options; RBD adds decision fields on top of the template', () => {
  const ids = poam.listTemplates().map((t) => t.id).sort();
  assert.deepEqual(ids, ['cap', 'custom', 'dod', 'fedramp']);
  const poamFields = poam.fieldsFor('fedramp', 'poam').map((f) => f.key);
  const rbdFields = poam.fieldsFor('fedramp', 'rbd').map((f) => f.key);
  assert.ok(rbdFields.includes('decision'));
  assert.equal(poamFields.includes('decision'), false);
  assert.throws(() => poam.fieldsFor('nope', 'poam'), /Unknown template/);
});

test('POA&M records store template data and link findings; milestones complete with a date', () => {
  const d = fresh();
  db.upsertVulnerabilities(d, [{ title: 'x', first_seen: TODAY, source: 'a', cve: 'CVE-9', asset: 'h' }]);
  const vid = one(d).id;
  const id = poam.saveItem(d, {
    kind: 'poam', template: 'dod', title: 'Patch x',
    data: { weakness: 'Old TLS', scheduled_completion: '2026-12-01', not_a_field: 'dropped' },
    vuln_ids: [vid],
  });
  let item = poam.getItem(d, id);
  assert.equal(item.data.weakness, 'Old TLS');
  assert.equal(item.data.not_a_field, undefined);
  assert.deepEqual(item.vuln_ids, [vid]);

  const mid = poam.saveMilestone(d, { poam_id: id, title: 'Staging', due_date: '2026-11-01', status: 'done' });
  item = poam.getItem(d, id);
  assert.equal(item.milestones[0].id, mid);
  assert.equal(item.milestones[0].status, 'done');
  assert.ok(item.milestones[0].completed_at);
});

test('RBD record requires a title; deleting a POA&M removes its milestones', () => {
  const d = fresh();
  assert.throws(() => poam.saveItem(d, { kind: 'rbd', template: 'custom', title: '  ' }), /title/);
  const id = poam.saveItem(d, { kind: 'rbd', template: 'custom', title: 'Accept SSH risk', data: { decision: 'Accept' } });
  poam.saveMilestone(d, { poam_id: id, title: 'Review', due_date: '2027-01-01' });
  poam.deleteItem(d, id);
  assert.equal(d.prepare('SELECT COUNT(*) AS n FROM milestones').get().n, 0);
});

test('POA&M CSV export uses the template columns', () => {
  const d = fresh();
  poam.saveItem(d, { kind: 'poam', template: 'cap', title: 'Fix, then verify', data: { owner: 'Lee' } });
  const csv = poam.exportCsv(d, 'poam', 'cap');
  assert.match(csv.split('\n')[0], /Corrective action/);
  assert.match(csv, /"Fix, then verify"/);
  assert.match(csv, /Lee/);
});

// ---------- Cleaning ----------

test('normaliseDate reads ISO, US, day-month-name and Excel serial dates', () => {
  assert.equal(cleaning.normaliseDate('2026-01-05T10:00:00Z'), '2026-01-05');
  assert.equal(cleaning.normaliseDate('1/5/2026'), '2026-01-05');
  assert.equal(cleaning.normaliseDate('05-Jan-2026'), '2026-01-05');
  assert.equal(cleaning.normaliseDate(46027), '2026-01-05');
  assert.equal(cleaning.normaliseDate('someday'), null);
});

test('removeDuplicates keeps the most recently seen row per CVE + asset', () => {
  const d = fresh();
  db.upsertVulnerabilities(d, [
    { title: 'a', cve: 'CVE-1', asset: 'web', first_seen: TODAY, source: 'scanA' },
    { title: 'a', cve: 'CVE-1', asset: 'web', first_seen: TODAY, source: 'scanB' },
    { title: 'a', cve: 'CVE-1', asset: 'db', first_seen: TODAY, source: 'scanA' },
  ]);
  // Same CVE and asset from two sources is a duplicate; the other asset is not.
  const groups = cleaning.findDuplicates(d);
  assert.equal(groups.length, 1);
  assert.equal(groups[0].asset, 'web');
  assert.equal(cleaning.removeDuplicates(d), 1);
  assert.equal(d.prepare('SELECT COUNT(*) AS n FROM vulnerabilities').get().n, 2);
});

test('stale findings are those not seen within the window; removing them deletes only those', () => {
  const d = fresh();
  db.upsertVulnerabilities(d, [{ title: 'old', first_seen: '2025-01-01', source: 'a', cve: 'CVE-1' }]);
  d.prepare("UPDATE vulnerabilities SET last_seen = '2026-01-01'").run();
  db.upsertVulnerabilities(d, [{ title: 'fresh', first_seen: TODAY, source: 'a', cve: 'CVE-2' }]);
  assert.equal(cleaning.staleFindings(d, TODAY, 90).length, 1);
  assert.equal(cleaning.removeStale(d, TODAY, 90), 1);
  assert.equal(one(d).title, 'fresh');
});

test('pruneSource drops rows from a source that the latest import no longer contains', () => {
  const d = fresh();
  ingest.importCsvText(d, 'title,cve,host\nA,CVE-1,h\nB,CVE-2,h', { source: 'scanner', today: '2026-01-01' });
  d.prepare("UPDATE vulnerabilities SET last_seen = '2025-12-01'").run();
  ingest.importCsvText(d, 'title,cve,host\nA,CVE-1,h', { source: 'scanner', pruneSource: true, today: TODAY });
  const titles = d.prepare('SELECT title FROM vulnerabilities').all().map((r) => r.title);
  assert.deepEqual(titles, ['A']);
});

// ---------- JSON and Excel import ----------

test('JSON import reads an array at itemsPath and converts dates and custom fields', () => {
  const d = fresh();
  const json = JSON.stringify({ findings: [
    { Title: 'Thing', CVE: 'CVE-7', Host: 'web', 'Asset Owner': 'Dana', Discovered: '1/5/2026' },
  ] });
  const res = ingest.importJsonText(d, json, { itemsPath: 'findings', source: 'json-feed', today: TODAY });
  assert.equal(res.written, 1);
  const row = one(d);
  assert.equal(row.first_seen, '2026-01-05');
  assert.equal(row.cve, 'CVE-7');
  assert.equal(row.c_asset_owner, 'Dana');
});

test('Excel import reads the first sheet and matches headers like CSV', () => {
  const d = fresh();
  const sheet = XLSX.utils.aoa_to_sheet([
    ['Title', 'CVE', 'Asset', 'Severity', 'CVSS', 'Days Open'],
    ['Heartbleed', 'CVE-2014-0160', 'vpn', 'Critical', 7.5, 30],
  ]);
  const wb = XLSX.utils.book_new();
  XLSX.utils.book_append_sheet(wb, sheet, 'Findings');
  const buffer = XLSX.write(wb, { type: 'buffer', bookType: 'xlsx' });
  const res = ingest.importExcelBuffer(d, buffer, { source: 'excel', today: TODAY });
  assert.equal(res.written, 1);
  const row = one(d);
  assert.equal(row.severity, 'Critical');
  assert.equal(row.cvss, 7.5);
  const days = d.prepare("SELECT c_days_open FROM vulnerabilities").get().c_days_open;
  assert.equal(days, 30);
});

test('dedupe option removes duplicates as part of an import', () => {
  const d = fresh();
  ingest.importCsvText(d, 'title,cve,host\nA,CVE-1,web', { source: 'one', today: TODAY });
  const res = ingest.importCsvText(d, 'title,cve,host\nA,CVE-1,web', { source: 'two', dedupe: true, today: TODAY });
  assert.equal(res.deduped, 1);
  assert.equal(d.prepare('SELECT COUNT(*) AS n FROM vulnerabilities').get().n, 1);
});
