// POA&M and RBD records. A record uses one template (its field set) and one kind:
//   poam = plan of action and milestones (remediation plan for findings)
//   rbd  = risk-based decision (accept, mitigate, transfer or avoid a risk)
// Template field sets are approximations of common formats. Check them against your official template
// before submitting anything.
const { csvEscape } = require('./csvout');

const f = (key, label, type = 'text', options) => ({ key, label, type, ...(options ? { options } : {}) });

const TEMPLATES = {
  custom: {
    name: 'Custom',
    fields: [
      f('description', 'Description', 'long'),
      f('owner', 'Owner'),
      f('scheduled_completion', 'Scheduled completion', 'date'),
      f('notes', 'Notes', 'long'),
    ],
  },
  dod: {
    name: 'DoD (approximate)',
    fields: [
      f('poam_id', 'POA&M ID'),
      f('weakness', 'Weakness'),
      f('control', 'Control'),
      f('asset', 'Asset'),
      f('source', 'Detection source'),
      f('responsible_office', 'Responsible office'),
      f('scheduled_completion', 'Scheduled completion', 'date'),
      f('resources', 'Resources required', 'long'),
      f('comments', 'Comments', 'long'),
    ],
  },
  fedramp: {
    name: 'FedRAMP (approximate)',
    fields: [
      f('poam_id', 'POA&M ID'),
      f('weakness_name', 'Weakness name'),
      f('weakness_description', 'Weakness description', 'long'),
      f('detector_source', 'Detector source'),
      f('asset_identifier', 'Asset identifier'),
      f('point_of_contact', 'Point of contact'),
      f('original_detection_date', 'Original detection date', 'date'),
      f('scheduled_completion_date', 'Scheduled completion date', 'date'),
      f('original_risk_rating', 'Original risk rating', 'select', ['Very High', 'High', 'Moderate', 'Low']),
      f('adjusted_risk_rating', 'Adjusted risk rating', 'select', ['Very High', 'High', 'Moderate', 'Low']),
      f('vendor_dependency', 'Vendor dependency', 'select', ['Yes', 'No']),
      f('false_positive', 'False positive', 'select', ['Yes', 'No']),
      f('remediation_plan', 'Remediation plan', 'long'),
      f('comments', 'Comments', 'long'),
    ],
  },
  cap: {
    name: 'Corrective action plan',
    fields: [
      f('action_id', 'Action ID'),
      f('finding', 'Finding', 'long'),
      f('root_cause', 'Root cause', 'long'),
      f('corrective_action', 'Corrective action', 'long'),
      f('owner', 'Owner'),
      f('verification_method', 'Verification method'),
      f('due_date', 'Due date', 'date'),
      f('comments', 'Comments', 'long'),
    ],
  },
};

// RBD records add decision fields on top of whichever template they use.
const RBD_FIELDS = [
  f('decision', 'Decision', 'select', ['Accept', 'Mitigate', 'Transfer', 'Avoid']),
  f('rationale', 'Rationale', 'long'),
  f('residual_risk', 'Residual risk', 'select', ['Low', 'Moderate', 'High']),
  f('accepted_by', 'Accepted by'),
  f('acceptance_date', 'Acceptance date', 'date'),
  f('review_date', 'Review date', 'date'),
];

const KINDS = ['poam', 'rbd'];

function fieldsFor(template, kind) {
  const base = TEMPLATES[template];
  if (!base) throw new Error(`Unknown template: ${template}`);
  return kind === 'rbd' ? [...base.fields, ...RBD_FIELDS] : base.fields;
}

function listTemplates() {
  return Object.entries(TEMPLATES).map(([id, t]) => ({ id, name: t.name }));
}

function parseItem(row) {
  return { ...row, data: JSON.parse(row.data), vuln_ids: JSON.parse(row.vuln_ids) };
}

function listItems(db, kind) {
  if (!KINDS.includes(kind)) throw new Error(`Unknown kind: ${kind}`);
  return db.prepare('SELECT * FROM poam_items WHERE kind = ? ORDER BY id').all(kind).map(parseItem);
}

function getItem(db, id) {
  const row = db.prepare('SELECT * FROM poam_items WHERE id = ?').get(id);
  if (!row) throw new Error(`No record with id ${id}`);
  const item = parseItem(row);
  item.milestones = db.prepare('SELECT * FROM milestones WHERE poam_id = ? ORDER BY due_date, id').all(id);
  return item;
}

// Keeps only the fields the template defines, so stale keys from an old template are dropped.
function cleanData(template, kind, data) {
  const keys = fieldsFor(template, kind).map((x) => x.key);
  return Object.fromEntries(keys.map((k) => [k, data?.[k] ?? null]));
}

function saveItem(db, item) {
  if (!KINDS.includes(item.kind)) throw new Error(`Unknown kind: ${item.kind}`);
  const title = String(item.title || '').trim();
  if (!title) throw new Error('A title is required');
  const now = new Date().toISOString();
  const data = JSON.stringify(cleanData(item.template, item.kind, item.data));
  const vulnIds = JSON.stringify((item.vuln_ids || []).map(Number).filter(Number.isFinite));
  if (item.id) {
    db.prepare(`UPDATE poam_items SET template = ?, title = ?, status = ?, data = ?, vuln_ids = ?, updated_at = ? WHERE id = ?`)
      .run(item.template, title, item.status || 'open', data, vulnIds, now, item.id);
    return item.id;
  }
  const result = db.prepare(`INSERT INTO poam_items (kind, template, title, status, data, vuln_ids, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)`).run(item.kind, item.template, title, item.status || 'open', data, vulnIds, now, now);
  return Number(result.lastInsertRowid);
}

function deleteItem(db, id) {
  db.prepare('DELETE FROM poam_items WHERE id = ?').run(id);
}

function saveMilestone(db, m) {
  const title = String(m.title || '').trim();
  if (!title) throw new Error('A milestone title is required');
  const done = m.status === 'done';
  const completedAt = done ? (m.completed_at || new Date().toISOString().slice(0, 10)) : null;
  if (m.id) {
    db.prepare('UPDATE milestones SET title = ?, due_date = ?, status = ?, completed_at = ? WHERE id = ?')
      .run(title, m.due_date || null, done ? 'done' : 'open', completedAt, m.id);
    return m.id;
  }
  const result = db.prepare('INSERT INTO milestones (poam_id, title, due_date, status, completed_at) VALUES (?, ?, ?, ?, ?)')
    .run(m.poam_id, title, m.due_date || null, done ? 'done' : 'open', completedAt);
  return Number(result.lastInsertRowid);
}

function deleteMilestone(db, id) {
  db.prepare('DELETE FROM milestones WHERE id = ?').run(id);
}

// Open milestones whose due date has passed. Feeds the alert list.
function overdueMilestones(db, today) {
  return db.prepare(`
    SELECT m.id, m.title, m.due_date, p.id AS poam_id, p.title AS poam_title, p.kind
    FROM milestones m JOIN poam_items p ON p.id = m.poam_id
    WHERE m.status = 'open' AND m.due_date IS NOT NULL AND m.due_date < ?
    ORDER BY m.due_date
  `).all(today);
}

// CSV of all records of one kind, with the columns of the chosen template.
function exportCsv(db, kind, template) {
  const items = listItems(db, kind);
  const fields = fieldsFor(template, kind);
  const header = ['id', 'title', 'status', 'linked_findings', ...fields.map((x) => x.label)];
  const lines = items.map((item) => [
    item.id, item.title, item.status, item.vuln_ids.join(' '),
    ...fields.map((x) => item.data[x.key] ?? ''),
  ].map(csvEscape).join(','));
  return [header.map(csvEscape).join(','), ...lines].join('\n');
}

module.exports = {
  TEMPLATES,
  KINDS,
  fieldsFor,
  listTemplates,
  listItems,
  getItem,
  saveItem,
  deleteItem,
  saveMilestone,
  deleteMilestone,
  overdueMilestones,
  exportCsv,
};
