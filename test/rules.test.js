const test = require('node:test');
const assert = require('node:assert/strict');
const { evaluate, bucketFor, addDays } = require('../src/rules');

const rule = (overrides) => ({ id: 1, name: 'r', enabled: true, conditions: [], priority_bonus: 0, sla_days: null, ...overrides });
const vuln = (overrides) => ({ title: 't', cve: 'CVE-1', asset: 'web-01', severity: 'High', cvss: 7.5, first_seen: '2026-10-01', ...overrides });
const TODAY = '2026-10-17';

test('priority uses CVSS when present and severity default otherwise', () => {
  assert.equal(evaluate(vuln({ cvss: 8.1 }), [], TODAY).priority_score, 8.1);
  assert.equal(evaluate(vuln({ cvss: null, severity: 'Critical' }), [], TODAY).priority_score, 9.5);
});

test('matching rule adds its bonus; non-matching rule does not', () => {
  const rules = [
    rule({ conditions: [{ field: 'asset', op: 'contains', value: 'WEB' }], priority_bonus: 2 }),
    rule({ conditions: [{ field: 'asset', op: 'eq', value: 'db-01' }], priority_bonus: 5 }),
  ];
  assert.equal(evaluate(vuln({ cvss: 5 }), rules, TODAY).priority_score, 7);
});

test('all conditions in a rule must match', () => {
  const r = rule({
    conditions: [
      { field: 'severity', op: 'eq', value: 'High' },
      { field: 'cvss', op: 'gte', value: 9 },
    ],
    priority_bonus: 10,
  });
  assert.equal(evaluate(vuln({ cvss: 7.5 }), [r], TODAY).priority_score, 7.5);
});

test('disabled rules are ignored', () => {
  const r = rule({ enabled: false, conditions: [{ field: 'cvss', op: 'gt', value: 0 }], priority_bonus: 3 });
  assert.equal(evaluate(vuln({ cvss: 4 }), [r], TODAY).priority_score, 4);
});

test('first matching SLA wins; severity default applies otherwise', () => {
  const rules = [
    rule({ id: 1, conditions: [{ field: 'cvss', op: 'gte', value: 9 }], sla_days: 3 }),
    rule({ id: 2, conditions: [{ field: 'cvss', op: 'gte', value: 5 }], sla_days: 14 }),
  ];
  assert.equal(evaluate(vuln({ cvss: 9.8, severity: 'Critical', first_seen: '2026-10-01' }), rules, TODAY).due_date, '2026-10-04');
  assert.equal(evaluate(vuln({ cvss: 5.5, severity: 'Medium', first_seen: '2026-10-01' }), rules, TODAY).due_date, '2026-10-15');
  assert.equal(evaluate(vuln({ cvss: 2, severity: 'Low', first_seen: '2026-10-01' }), [], TODAY).due_date, addDays('2026-10-01', 180));
});

test('in / neq / lt operators', () => {
  const v = vuln({ severity: 'High', cvss: 3 });
  assert.equal(evaluate(v, [rule({ conditions: [{ field: 'severity', op: 'in', value: 'critical, high' }], priority_bonus: 1 })], TODAY).priority_score, 4);
  assert.equal(evaluate(v, [rule({ conditions: [{ field: 'severity', op: 'neq', value: 'High' }], priority_bonus: 1 })], TODAY).priority_score, 3);
  assert.equal(evaluate(v, [rule({ conditions: [{ field: 'cvss', op: 'lt', value: 5 }], priority_bonus: 1 })], TODAY).priority_score, 4);
});

test('unknown operator throws', () => {
  assert.throws(() => evaluate(vuln({}), [rule({ conditions: [{ field: 'cvss', op: 'regex', value: '.' }] })], TODAY));
});

test('timeline buckets from days until due', () => {
  assert.equal(bucketFor('2026-10-10', TODAY), 'Overdue');
  assert.equal(bucketFor('2026-10-17', TODAY), 'Next 7 days');
  assert.equal(bucketFor('2026-10-24', TODAY), 'Next 7 days');
  assert.equal(bucketFor('2026-10-25', TODAY), 'Next 30 days');
  assert.equal(bucketFor('2027-03-01', TODAY), 'Later');
  assert.equal(bucketFor(null, TODAY), 'Unscheduled');
});
