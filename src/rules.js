// Rule engine: turns user-defined rules into a priority score, an SLA due date and a timeline bucket.
//
// Scoring:   priority = base (CVSS, or a severity default when CVSS is missing) + sum of bonuses from matching rules
// SLA:       due_date = first_seen + days, where days comes from the first matching rule that sets sla_days,
//            otherwise from the severity default
// Timeline:  bucket is derived from days between today and due_date

const { intelMaps } = require('./intel');

const SEVERITY_BASE_SCORE = { Critical: 9.5, High: 7.5, Medium: 5, Low: 2.5, Info: 0 };
const SEVERITY_SLA_DAYS = { Critical: 7, High: 30, Medium: 90, Low: 180, Info: 365 };
const DEFAULT_SLA_DAYS = 90;

const OPERATORS = {
  eq: (a, b) => String(a ?? '').toLowerCase() === String(b).toLowerCase(),
  neq: (a, b) => String(a ?? '').toLowerCase() !== String(b).toLowerCase(),
  contains: (a, b) => String(a ?? '').toLowerCase().includes(String(b).toLowerCase()),
  gt: (a, b) => a != null && Number(a) > Number(b),
  gte: (a, b) => a != null && Number(a) >= Number(b),
  lt: (a, b) => a != null && Number(a) < Number(b),
  lte: (a, b) => a != null && Number(a) <= Number(b),
  in: (a, b) => String(b).split(',').map((s) => s.trim().toLowerCase()).includes(String(a ?? '').toLowerCase()),
};

const OPERATOR_LABELS = {
  eq: 'equals', neq: 'not equals', contains: 'contains',
  gt: '>', gte: '>=', lt: '<', lte: '<=', in: 'is one of',
};

function conditionMatches(row, condition) {
  const op = OPERATORS[condition.op];
  if (!op) throw new Error(`Unknown operator: ${condition.op}`);
  return op(row[condition.field], condition.value);
}

function ruleMatches(row, rule) {
  return rule.enabled && rule.conditions.length > 0 && rule.conditions.every((c) => conditionMatches(row, c));
}

function baseScore(row) {
  if (row.cvss != null && row.cvss !== '') return Number(row.cvss);
  return SEVERITY_BASE_SCORE[row.severity] ?? 0;
}

function addDays(isoDate, days) {
  const d = new Date(`${isoDate}T00:00:00Z`);
  d.setUTCDate(d.getUTCDate() + days);
  return d.toISOString().slice(0, 10);
}

function bucketFor(dueDate, today) {
  if (!dueDate) return 'Unscheduled';
  const days = Math.round((Date.parse(`${dueDate}T00:00:00Z`) - Date.parse(`${today}T00:00:00Z`)) / 864e5);
  if (days < 0) return 'Overdue';
  if (days <= 7) return 'Next 7 days';
  if (days <= 30) return 'Next 30 days';
  return 'Later';
}

// Compliance policies. Each enabled policy is pass/fail for an open finding; any failing policy makes
// the finding Non-compliant. Closed findings are Closed, not evaluated.
const SEVERITY_RANK = { Critical: 5, High: 4, Medium: 3, Low: 2, Info: 1 };

const POLICY_CHECKS = {
  // Open findings must not be past their deadline.
  deadline: (row, _params, dueDate, today) => row.status !== 'open' || !dueDate || dueDate >= today,
  // Open findings at or above the threshold severity fail.
  severity: (row, params) => row.status !== 'open'
    || (SEVERITY_RANK[row.severity] ?? 0) < (SEVERITY_RANK[params.threshold] ?? 99),
  // Open findings mapped to one of the listed controls fail.
  control: (row, params) => row.status !== 'open'
    || !(params.controls || []).includes(row.control_id),
};

function complianceFor(row, policies, dueDate, today) {
  if (row.status !== 'open') return 'Closed';
  if (policies.length === 0) return 'Not evaluated';
  const failed = policies.some((p) => !POLICY_CHECKS[p.kind](row, p.params, dueDate, today));
  return failed ? 'Non-compliant' : 'Compliant';
}

// Built-in signals added on top of the user's rules.
const KEV_BONUS = 3;          // on CISA's Known Exploited Vulnerabilities list
const EPSS_WEIGHT = 5;        // EPSS is 0 to 1, so 0.5 adds 2.5
const CRITICALITY_BONUS = { Critical: 3, High: 2, Medium: 1, Low: 0 };

function intelBonus(row) {
  return (row.kev ? KEV_BONUS : 0)
    + (Number(row.epss) || 0) * EPSS_WEIGHT
    + (CRITICALITY_BONUS[row.criticality] || 0);
}

// Pure function: returns the derived fields for one vulnerability row, given the rules in order.
// A per-finding deadline_override wins over the rule and severity SLA.
function evaluate(row, rules, today, policies = []) {
  let bonus = intelBonus(row);
  let slaDays = null;
  for (const rule of rules) {
    if (!ruleMatches(row, rule)) continue;
    bonus += Number(rule.priority_bonus) || 0;
    if (slaDays == null && rule.sla_days != null) slaDays = Number(rule.sla_days);
  }
  const days = slaDays ?? SEVERITY_SLA_DAYS[row.severity] ?? DEFAULT_SLA_DAYS;
  const dueDate = row.deadline_override || addDays(row.first_seen, days);
  return {
    priority_score: Math.round((baseScore(row) + bonus) * 100) / 100,
    due_date: dueDate,
    timeline_bucket: bucketFor(dueDate, today),
    compliance_status: complianceFor(row, policies, dueDate, today),
  };
}

// Re-scores every vulnerability. Called after rule edits, imports and deletions.
function recomputeAll(db, today = new Date().toISOString().slice(0, 10)) {
  const rules = db.prepare('SELECT * FROM rules ORDER BY position, id').all()
    .map((r) => ({ ...r, enabled: Boolean(r.enabled), conditions: JSON.parse(r.conditions) }));
  const policies = db.prepare('SELECT kind, params FROM compliance_policies WHERE enabled = 1').all()
    .map((p) => ({ kind: p.kind, params: JSON.parse(p.params) }));
  const { kev, epss } = intelMaps(db);
  const criticality = new Map(db.prepare('SELECT name, criticality FROM assets').all().map((a) => [a.name, a.criticality]));
  const rows = db.prepare('SELECT * FROM vulnerabilities').all();
  const update = db.prepare(`UPDATE vulnerabilities
    SET priority_score = ?, due_date = ?, timeline_bucket = ?, compliance_status = ?, kev = ?, epss = ? WHERE id = ?`);

  db.exec('BEGIN');
  try {
    for (const row of rows) {
      row.kev = kev.has(row.cve) ? 1 : 0;
      row.epss = epss.get(row.cve) ?? null;
      row.criticality = criticality.get(row.asset) ?? null;
      const derived = evaluate(row, rules, today, policies);
      update.run(derived.priority_score, derived.due_date, derived.timeline_bucket, derived.compliance_status,
        row.kev, row.epss, row.id);
    }
    db.exec('COMMIT');
  } catch (err) {
    db.exec('ROLLBACK');
    throw err;
  }
  return rows.length;
}

module.exports = {
  POLICY_CHECKS,
  complianceFor,
  OPERATORS,
  OPERATOR_LABELS,
  SEVERITY_BASE_SCORE,
  SEVERITY_SLA_DAYS,
  evaluate,
  recomputeAll,
  bucketFor,
  addDays,
};
