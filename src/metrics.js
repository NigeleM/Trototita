// Remediation metrics for leads and auditors: time to fix by severity, share of findings overdue,
// and open findings by age. Time to fix uses the history log, so it reflects when a finding was closed.
const SEVERITIES = ['Critical', 'High', 'Medium', 'Low', 'Info'];
const AGE_BUCKETS = [
  { label: '0 to 30 days', max: 30 },
  { label: '31 to 90 days', max: 90 },
  { label: '91 to 180 days', max: 180 },
  { label: 'Over 180 days', max: Infinity },
];

function remediationMetrics(db, today) {
  // First time each finding was set to closed. Findings imported as already closed have no history, so they are not counted.
  const closed = db.prepare(`
    SELECT v.severity, v.first_seen, MIN(h.changed_at) AS closed_at
    FROM vulnerabilities v
    JOIN vuln_history h ON h.vuln_id = v.id AND h.field = 'status' AND h.new_value = 'closed'
    GROUP BY v.id
  `).all();

  const bySeverity = SEVERITIES.map((severity) => {
    const rows = closed.filter((r) => (r.severity || '') === severity);
    const days = rows.map((r) => (Date.parse(`${r.closed_at.slice(0, 10)}T00:00:00Z`) - Date.parse(`${r.first_seen}T00:00:00Z`)) / 864e5)
      .map((d) => Math.max(0, Math.round(d)));
    const avgDays = days.length ? Math.round((days.reduce((s, d) => s + d, 0) / days.length) * 10) / 10 : null;
    return { severity, closed: rows.length, avgDays };
  });

  const open = db.prepare(`
    SELECT COUNT(*) AS total,
           COALESCE(SUM(CASE WHEN due_date < ? THEN 1 ELSE 0 END), 0) AS overdue
    FROM vulnerabilities WHERE status = 'open'
  `).get(today);

  const ages = db.prepare(`
    SELECT CAST(julianday(?) - julianday(first_seen) AS INTEGER) AS age
    FROM vulnerabilities WHERE status = 'open'
  `).all(today).map((r) => Math.max(0, r.age));

  const aging = AGE_BUCKETS.map((b, i) => {
    const lower = i === 0 ? 0 : AGE_BUCKETS[i - 1].max + 1;
    return { label: b.label, count: ages.filter((a) => a >= lower && a <= b.max).length };
  });

  return {
    closedTotal: closed.length,
    openTotal: open.total,
    overdueTotal: open.overdue,
    overduePercent: open.total ? Math.round((open.overdue / open.total) * 1000) / 10 : 0,
    bySeverity,
    aging,
  };
}

module.exports = { remediationMetrics };
