// Workflow data: comments, per-finding history, daily snapshots for trends, compliance policies,
// and the alert list (upcoming deadlines, overdue findings, non-compliant findings, overdue milestones).
const { overdueMilestones } = require('./poam');
const { addDays } = require('./rules');

// ---------- Finding details ----------

function getFinding(db, id) {
  const row = db.prepare('SELECT * FROM vulnerabilities WHERE id = ?').get(id);
  if (!row) throw new Error(`No finding with id ${id}`);
  return row;
}

// ---------- Comments ----------

function listComments(db, vulnId) {
  return db.prepare('SELECT * FROM vuln_comments WHERE vuln_id = ? ORDER BY created_at, id').all(vulnId);
}

function addComment(db, vulnId, author, body) {
  const text = String(body || '').trim();
  if (!text) throw new Error('Comment is empty');
  getFinding(db, vulnId); // clear error for a missing finding, instead of a foreign-key failure
  db.prepare('INSERT INTO vuln_comments (vuln_id, author, body, created_at) VALUES (?, ?, ?, ?)')
    .run(vulnId, String(author || 'user').trim() || 'user', text, new Date().toISOString());
}

function deleteComment(db, id) {
  db.prepare('DELETE FROM vuln_comments WHERE id = ?').run(id);
}

// ---------- History (written by triggers in migrations.js) ----------

function listHistory(db, vulnId) {
  return db.prepare('SELECT * FROM vuln_history WHERE vuln_id = ? ORDER BY changed_at DESC, id DESC').all(vulnId);
}

// ---------- Snapshots: one row per day, used for the trend chart ----------

function recordSnapshot(db, today) {
  const counts = db.prepare(`
    SELECT
      SUM(CASE WHEN status = 'open' THEN 1 ELSE 0 END) AS open_count,
      SUM(CASE WHEN status = 'open' AND due_date < ? THEN 1 ELSE 0 END) AS overdue_count,
      SUM(CASE WHEN compliance_status = 'Non-compliant' THEN 1 ELSE 0 END) AS noncompliant_count
    FROM vulnerabilities
  `).get(today);
  db.prepare(`INSERT OR REPLACE INTO snapshots (snapshot_date, open_count, overdue_count, noncompliant_count)
    VALUES (?, ?, ?, ?)`).run(today, counts.open_count ?? 0, counts.overdue_count ?? 0, counts.noncompliant_count ?? 0);
}

function listSnapshots(db, days = 90) {
  return db.prepare('SELECT * FROM snapshots ORDER BY snapshot_date DESC LIMIT ?').all(days).reverse();
}

// ---------- Compliance policies ----------

function listPolicies(db) {
  return db.prepare('SELECT * FROM compliance_policies ORDER BY id').all()
    .map((p) => ({ ...p, enabled: Boolean(p.enabled), params: JSON.parse(p.params) }));
}

// Replaces the policy set (the UI edits them all at once). Caller re-runs recomputeAll afterwards.
function savePolicies(db, policies) {
  const allowed = ['deadline', 'severity', 'control'];
  db.exec('BEGIN');
  try {
    db.exec('DELETE FROM compliance_policies');
    const insert = db.prepare('INSERT INTO compliance_policies (name, kind, params, enabled) VALUES (?, ?, ?, ?)');
    for (const p of policies) {
      if (!allowed.includes(p.kind)) throw new Error(`Unknown policy kind: ${p.kind}`);
      const name = String(p.name || '').trim() || p.kind;
      insert.run(name, p.kind, JSON.stringify(p.params || {}), p.enabled ? 1 : 0);
    }
    db.exec('COMMIT');
  } catch (err) {
    db.exec('ROLLBACK');
    throw err;
  }
}

// ---------- Alerts ----------

// Alerts are computed live from the data. A dismissed alert stays hidden until its dismissal date passes.
function computeAlerts(db, today, { leadDays = 7 } = {}) {
  const horizon = addDays(today, leadDays);
  const alerts = [];

  const overdue = db.prepare(`
    SELECT id, cve, title, asset, severity, due_date FROM vulnerabilities
    WHERE status = 'open' AND due_date < ? ORDER BY due_date
  `).all(today);
  for (const v of overdue) {
    alerts.push({ key: `overdue:${v.id}`, kind: 'overdue', vuln_id: v.id,
      title: `Overdue: ${v.title}`, detail: `${v.cve || 'no CVE'} · ${v.asset || 'no asset'} · due ${v.due_date}` });
  }

  const upcoming = db.prepare(`
    SELECT id, cve, title, asset, due_date FROM vulnerabilities
    WHERE status = 'open' AND due_date >= ? AND due_date <= ? ORDER BY due_date
  `).all(today, horizon);
  for (const v of upcoming) {
    alerts.push({ key: `upcoming:${v.id}`, kind: 'upcoming', vuln_id: v.id,
      title: `Due soon: ${v.title}`, detail: `${v.cve || 'no CVE'} · ${v.asset || 'no asset'} · due ${v.due_date}` });
  }

  const noncompliant = db.prepare(`
    SELECT id, cve, title, asset FROM vulnerabilities WHERE compliance_status = 'Non-compliant' ORDER BY id
  `).all();
  for (const v of noncompliant) {
    alerts.push({ key: `noncompliant:${v.id}`, kind: 'noncompliant', vuln_id: v.id,
      title: `Non-compliant: ${v.title}`, detail: `${v.cve || 'no CVE'} · ${v.asset || 'no asset'}` });
  }

  for (const m of overdueMilestones(db, today)) {
    alerts.push({ key: `milestone:${m.id}`, kind: 'milestone', poam_id: m.poam_id,
      title: `Milestone overdue: ${m.title}`, detail: `${m.poam_title} · due ${m.due_date}` });
  }

  // Risk acceptances (RBDs) are due for review on their review date. Once it passes, the acceptance is
  // overdue for review and should not be relied on until someone re-approves it.
  const rbds = db.prepare("SELECT id, title, data FROM poam_items WHERE kind = 'rbd' AND status != 'closed' ORDER BY id").all();
  for (const r of rbds) {
    const review = JSON.parse(r.data).review_date;
    if (!review) continue;
    if (review < today) {
      alerts.push({ key: `review-overdue:${r.id}`, kind: 'review', poam_id: r.id,
        title: `Risk acceptance overdue for review: ${r.title}`, detail: `review was due ${review}` });
    } else if (review <= horizon) {
      alerts.push({ key: `review-due:${r.id}`, kind: 'review', poam_id: r.id,
        title: `Risk acceptance review due: ${r.title}`, detail: `review due ${review}` });
    }
  }

  const dismissed = new Set(db.prepare('SELECT alert_key FROM alert_dismissals WHERE dismissed_until >= ?')
    .all(today).map((r) => r.alert_key));
  return alerts.filter((a) => !dismissed.has(a.key));
}

function dismissAlert(db, key, today, days = 7) {
  db.prepare('INSERT OR REPLACE INTO alert_dismissals (alert_key, dismissed_until) VALUES (?, ?)')
    .run(key, addDays(today, days));
}

module.exports = {
  getFinding,
  listComments,
  addComment,
  deleteComment,
  listHistory,
  recordSnapshot,
  listSnapshots,
  listPolicies,
  savePolicies,
  computeAlerts,
  dismissAlert,
};
