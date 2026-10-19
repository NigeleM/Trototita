// Schema for workflow features: history, comments, POA&M/RBD, milestones, compliance policies,
// alert dismissals and daily snapshots. Safe to run on every start: it only adds what is missing.

// Columns added to the vulnerabilities table after the first release.
const NEW_COLUMNS = {
  last_seen: 'TEXT',
  control_id: 'TEXT',
  compliance_status: 'TEXT',
  deadline_override: 'TEXT',
  kev: 'INTEGER NOT NULL DEFAULT 0',   // 1 when the CVE is on CISA's Known Exploited Vulnerabilities list
  epss: 'REAL',                        // EPSS exploit-likelihood score, 0 to 1
};

// Fields whose changes are recorded in vuln_history by triggers.
const TRACKED_FIELDS = ['status', 'severity', 'cvss', 'due_date', 'asset', 'title', 'compliance_status', 'control_id', 'deadline_override'];

const TABLES = `
  CREATE TABLE IF NOT EXISTS vuln_comments (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    vuln_id    INTEGER NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    author     TEXT NOT NULL,
    body       TEXT NOT NULL,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS vuln_history (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    vuln_id    INTEGER NOT NULL,
    changed_at TEXT NOT NULL,
    field      TEXT NOT NULL,
    old_value  TEXT,
    new_value  TEXT
  );
  CREATE INDEX IF NOT EXISTS vuln_history_by_vuln ON vuln_history (vuln_id, changed_at);

  CREATE TABLE IF NOT EXISTS poam_items (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    kind       TEXT NOT NULL CHECK (kind IN ('poam', 'rbd')),
    template   TEXT NOT NULL,
    title      TEXT NOT NULL,
    status     TEXT NOT NULL DEFAULT 'open',
    data       TEXT NOT NULL DEFAULT '{}',   -- template field values, JSON
    vuln_ids   TEXT NOT NULL DEFAULT '[]',   -- linked finding ids, JSON array
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS milestones (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    poam_id      INTEGER NOT NULL REFERENCES poam_items(id) ON DELETE CASCADE,
    title        TEXT NOT NULL,
    due_date     TEXT,
    status       TEXT NOT NULL DEFAULT 'open',
    completed_at TEXT
  );

  CREATE TABLE IF NOT EXISTS snapshots (
    snapshot_date     TEXT PRIMARY KEY,
    open_count        INTEGER NOT NULL,
    overdue_count     INTEGER NOT NULL,
    noncompliant_count INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS compliance_policies (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    name    TEXT NOT NULL,
    kind    TEXT NOT NULL CHECK (kind IN ('deadline', 'severity', 'control')),
    params  TEXT NOT NULL DEFAULT '{}',   -- JSON: severity threshold or control list
    enabled INTEGER NOT NULL DEFAULT 1
  );

  CREATE TABLE IF NOT EXISTS alert_dismissals (
    alert_key       TEXT PRIMARY KEY,
    dismissed_until TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS kev_catalog (
    cve        TEXT PRIMARY KEY,
    name       TEXT,
    date_added TEXT,
    due_date   TEXT
  );

  CREATE TABLE IF NOT EXISTS epss_scores (
    cve        TEXT PRIMARY KEY,
    score      REAL NOT NULL,
    percentile REAL,
    updated_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS assets (
    name        TEXT PRIMARY KEY,           -- matches the asset column of findings
    owner       TEXT,
    criticality TEXT CHECK (criticality IN ('Low', 'Medium', 'High', 'Critical')),
    environment TEXT,
    business_unit TEXT,
    updated_at  TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS saved_views (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL UNIQUE,
    table_name TEXT NOT NULL,
    config     TEXT NOT NULL,              -- JSON: filters, sort, visible columns
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS attachments (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    vuln_id     INTEGER REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    poam_id     INTEGER REFERENCES poam_items(id) ON DELETE CASCADE,
    filename    TEXT NOT NULL,
    mime        TEXT NOT NULL,
    size        INTEGER NOT NULL,
    data        BLOB NOT NULL,
    uploaded_by TEXT,
    created_at  TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS attachments_by_vuln ON attachments (vuln_id);
  CREATE INDEX IF NOT EXISTS attachments_by_poam ON attachments (poam_id);
`;

function historyTrigger(field) {
  return `
    CREATE TRIGGER IF NOT EXISTS vuln_hist_${field} AFTER UPDATE OF ${field} ON vulnerabilities
    WHEN OLD.${field} IS NOT NEW.${field}
    BEGIN
      INSERT INTO vuln_history (vuln_id, changed_at, field, old_value, new_value)
      VALUES (NEW.id, strftime('%Y-%m-%dT%H:%M:%SZ', 'now'), '${field}', CAST(OLD.${field} AS TEXT), CAST(NEW.${field} AS TEXT));
    END;
  `;
}

const DEFAULT_POLICIES = [
  { name: 'Deadlines met', kind: 'deadline', params: {}, enabled: 1 },
  { name: 'No open High or Critical findings', kind: 'severity', params: { threshold: 'High' }, enabled: 0 },
  { name: 'Required controls have no open findings', kind: 'control', params: { controls: [] }, enabled: 0 },
];

function migrate(db) {
  db.exec(TABLES);

  const cols = new Set(db.prepare('PRAGMA table_info(vulnerabilities)').all().map((c) => c.name));
  for (const [name, type] of Object.entries(NEW_COLUMNS)) {
    if (!cols.has(name)) db.exec(`ALTER TABLE vulnerabilities ADD COLUMN ${name} ${type}`);
  }
  for (const field of TRACKED_FIELDS) db.exec(historyTrigger(field));

  const { n } = db.prepare('SELECT COUNT(*) AS n FROM compliance_policies').get();
  if (n === 0) {
    const insert = db.prepare('INSERT INTO compliance_policies (name, kind, params, enabled) VALUES (?, ?, ?, ?)');
    for (const p of DEFAULT_POLICIES) insert.run(p.name, p.kind, JSON.stringify(p.params), p.enabled);
  }
}

module.exports = { migrate, NEW_COLUMNS, TRACKED_FIELDS };
