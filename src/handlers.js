// Every data operation the app performs, as plain functions over a database handle. The desktop app
// calls them directly in local mode; the team server calls the same functions for remote clients.
// Nothing in here depends on Electron, so the server can run under plain Node.
const db = require('./db');
const columns = require('./columns');
const poam = require('./poam');
const workflow = require('./workflow');
const cleaning = require('./cleaning');
const ingest = require('./ingest');
const { recomputeAll } = require('./rules');
const { csvEscape } = require('./csvout');
const path = require('node:path');
const XLSX = require('xlsx');
const { refreshIntel } = require('./intel');
const { remediationMetrics } = require('./metrics');
const { createBackup, listBackups } = require('./backup');
const { SCANNER_PRESETS } = require('./ingest');

const ASSET_CRITICALITY = ['Low', 'Medium', 'High', 'Critical'];
const MAX_ATTACHMENT_BYTES = 10 * 1024 * 1024;
const MAX_VIEW_CONFIG = 20 * 1024;

// Minimum role for each channel in team mode. Local mode ignores roles.
const ROLE_RANK = { viewer: 1, editor: 2, admin: 3 };
const MIN_ROLE = {
  'db:tables': 'viewer',
  'db:columns': 'viewer',
  'db:query': 'viewer',
  'columns:defs': 'viewer',
  'columns:save': 'editor',
  'columns:add': 'admin',
  'columns:delete': 'admin',
  'db:updateCell': 'editor',
  'db:insertRow': 'editor',
  'db:deleteRows': 'editor',
  'db:sql': 'admin',
  'db:sqlLoaded': 'viewer', // read-only, runs on a copy of the loaded rows
  'charts:aggregate': 'viewer',
  'dashboard:stats': 'viewer',
  'trend:snapshots': 'viewer',
  'rules:list': 'viewer',
  'rules:save': 'admin',
  'rules:delete': 'admin',
  'finding:get': 'viewer',
  'finding:comment': 'editor',
  'finding:deleteComment': 'editor',
  'policies:list': 'viewer',
  'policies:save': 'admin',
  'poam:templates': 'viewer',
  'poam:fields': 'viewer',
  'poam:list': 'viewer',
  'poam:get': 'viewer',
  'poam:save': 'editor',
  'poam:delete': 'editor',
  'poam:exportCsv': 'viewer',
  'milestone:save': 'editor',
  'milestone:delete': 'editor',
  'alerts:list': 'viewer',
  'alerts:dismiss': 'editor',
  'cleaning:preview': 'viewer',
  'cleaning:dedupe': 'admin',
  'cleaning:stale': 'admin',
  'import:content': 'editor',
  'import:api': 'editor',
  'import:presets': 'viewer',
  'intel:refresh': 'admin',
  'intel:status': 'viewer',
  'metrics:remediation': 'viewer',
  'assets:list': 'viewer',
  'assets:save': 'editor',
  'assets:delete': 'editor',
  'views:list': 'viewer',
  'views:save': 'editor',
  'views:delete': 'editor',
  'attachments:list': 'viewer',
  'attachments:get': 'viewer',
  'attachments:add': 'editor',
  'attachments:delete': 'editor',
  'poam:exportXlsx': 'viewer',
  'backup:create': 'admin',
  'backup:list': 'admin',
};

function allowed(role, channel) {
  const min = MIN_ROLE[channel];
  return Boolean(min) && (ROLE_RANK[role] || 0) >= ROLE_RANK[min];
}

const todayIso = () => new Date().toISOString().slice(0, 10);

// Reads an import payload: csv and json as text, xlsx as base64.
const MAX_IMPORT_CHARS = 25 * 1024 * 1024;

function importPayload(database, format, content, options) {
  if (typeof content !== 'string' || content.length > MAX_IMPORT_CHARS) throw new Error('The file is missing or too large (limit 25 MB)');
  if (format === 'csv') return ingest.importCsvText(database, content, options);
  if (format === 'json') return ingest.importJsonText(database, content, options);
  if (format === 'xlsx') return ingest.importExcelBuffer(database, Buffer.from(content, 'base64'), options);
  throw new Error(`Unsupported format: ${format}`);
}

// allowedApiHosts: null allows any API host (desktop, local mode). The team server passes its approved list.
const assetRows = (database) => database.prepare('SELECT * FROM assets ORDER BY name').all();

// Attachment names are reduced to a plain file name with no path parts or control characters.
function safeFileName(name) {
  const base = path.basename(String(name || 'attachment')).replace(/[\x00-\x1f]/g, '').trim();
  return (base || 'attachment').slice(0, 200);
}

function createHandlers(database, { allowedApiHosts = null, backupDir = null } = {}) {
  const recompute = () => recomputeAll(database, todayIso());

  const handlers = {
    'db:tables': () => db.listTables(database),
    'db:columns': (table) => db.listColumns(database, table),
    'db:query': (args) => db.queryTable(database, args.table, args),

    'columns:defs': (table) => columns.listColumnDefs(database, table),
    'columns:add': ({ table, label, type }) => {
      columns.addCustomColumn(database, table, { label, type });
      return columns.listColumnDefs(database, table);
    },
    'columns:save': ({ table, prefs }) => {
      columns.savePrefs(database, table, prefs);
      return columns.listColumnDefs(database, table);
    },
    'columns:delete': ({ table, name }) => {
      columns.deleteCustomColumn(database, table, name);
      return columns.listColumnDefs(database, table);
    },

    'db:updateCell': ({ table, rowid, column, value }) => {
      db.updateCell(database, table, rowid, column, value);
      if (table === 'vulnerabilities') recompute();
      return true;
    },
    'db:insertRow': ({ table }) => {
      const rowid = db.insertRow(database, table, todayIso());
      if (table === 'vulnerabilities') recompute();
      return rowid;
    },
    'db:deleteRows': ({ table, rowids }) => {
      const deleted = db.deleteRows(database, table, rowids);
      if (table === 'vulnerabilities') recompute();
      return deleted;
    },
    'db:sql': (sql) => {
      const result = db.runSql(database, sql);
      if (result.kind === 'changes') recompute();
      return result;
    },
    'db:sqlLoaded': ({ table, filters, sortBy, sortDir, sql }) => db.runSqlOnLoaded(database, { table, filters, sortBy, sortDir }, sql),

    'charts:aggregate': (args) => db.aggregate(database, args.table, args),
    'dashboard:stats': () => db.dashboardStats(database, todayIso()),
    'trend:snapshots': (days) => workflow.listSnapshots(database, days),

    'rules:list': () => db.listRules(database),
    'rules:save': (rule) => {
      db.saveRule(database, rule);
      recompute();
      return db.listRules(database);
    },
    'rules:delete': (id) => {
      db.deleteRule(database, id);
      recompute();
      return db.listRules(database);
    },

    'finding:get': (id) => ({
      finding: workflow.getFinding(database, id),
      comments: workflow.listComments(database, id),
      history: workflow.listHistory(database, id),
    }),
    'finding:comment': ({ id, author, body }) => {
      workflow.addComment(database, id, author, body);
      return workflow.listComments(database, id);
    },
    'finding:deleteComment': ({ id, commentId }) => {
      workflow.deleteComment(database, commentId);
      return workflow.listComments(database, id);
    },

    'policies:list': () => workflow.listPolicies(database),
    'policies:save': (policies) => {
      workflow.savePolicies(database, policies);
      recompute();
      return workflow.listPolicies(database);
    },

    'poam:templates': () => poam.listTemplates(),
    'poam:fields': ({ template, kind }) => poam.fieldsFor(template, kind),
    'poam:list': (kind) => poam.listItems(database, kind),
    'poam:get': (id) => poam.getItem(database, id),
    'poam:save': (item) => poam.getItem(database, poam.saveItem(database, item)),
    'poam:delete': (id) => { poam.deleteItem(database, id); return true; },
    'poam:exportCsv': ({ kind, template }) => poam.exportCsv(database, kind, template),
    'milestone:save': (m) => {
      poam.saveMilestone(database, m);
      return poam.getItem(database, m.poam_id);
    },
    'milestone:delete': ({ id, poamId }) => {
      poam.deleteMilestone(database, id);
      return poam.getItem(database, poamId);
    },

    'alerts:list': ({ leadDays = 7 } = {}) => workflow.computeAlerts(database, todayIso(), { leadDays }),
    'alerts:dismiss': (key) => { workflow.dismissAlert(database, key, todayIso()); return true; },

    'cleaning:preview': (days) => {
      const groups = cleaning.findDuplicates(database);
      return {
        duplicateGroups: groups.length,
        duplicateRows: groups.reduce((s, g) => s + g.count - 1, 0),
        staleRows: cleaning.staleFindings(database, todayIso(), days).length,
      };
    },
    'cleaning:dedupe': () => { const n = cleaning.removeDuplicates(database); recompute(); return n; },
    'cleaning:stale': (days) => { const n = cleaning.removeStale(database, todayIso(), days); recompute(); return n; },

    // Import payloads come from the client (local file read, or uploaded by a remote client).
    'import:content': ({ format, content, options = {} }) => importPayload(database, format, content, options),
    'import:api': (config) => ingest.importFromApi(database, config, { allowedHosts: allowedApiHosts }),
    'import:presets': () => Object.entries(SCANNER_PRESETS).map(([id, p]) => ({ id, label: p.label })),

    // Threat intelligence and metrics
    'intel:refresh': async () => {
      const result = await refreshIntel(database, { today: todayIso() });
      recompute();
      return result;
    },
    'intel:status': () => ({
      kev: database.prepare('SELECT COUNT(*) AS n FROM kev_catalog').get().n,
      epss: database.prepare('SELECT COUNT(*) AS n FROM epss_scores').get().n,
      exploitedOpen: database.prepare("SELECT COUNT(*) AS n FROM vulnerabilities WHERE kev = 1 AND status = 'open'").get().n,
    }),
    'metrics:remediation': () => remediationMetrics(database, todayIso()),

    // Asset inventory: owners and criticality feed into priority
    'assets:list': () => assetRows(database),
    'assets:save': ({ name, owner, criticality, environment, business_unit: businessUnit }) => {
      const key = String(name || '').trim();
      if (!key) throw new Error('Asset name is required');
      if (criticality && !ASSET_CRITICALITY.includes(criticality)) throw new Error(`Criticality must be one of: ${ASSET_CRITICALITY.join(', ')}`);
      database.prepare(`INSERT INTO assets (name, owner, criticality, environment, business_unit, updated_at)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT (name) DO UPDATE SET owner = excluded.owner, criticality = excluded.criticality,
          environment = excluded.environment, business_unit = excluded.business_unit, updated_at = excluded.updated_at`)
        .run(key, owner || null, criticality || null, environment || null, businessUnit || null, new Date().toISOString());
      recompute();
      return assetRows(database);
    },
    'assets:delete': (name) => {
      database.prepare('DELETE FROM assets WHERE name = ?').run(name);
      recompute();
      return assetRows(database);
    },

    // Saved grid views, shared with everyone who can read the database
    'views:list': (table) => database.prepare('SELECT id, name, table_name, config FROM saved_views WHERE table_name = ? ORDER BY name')
      .all(table).map((v) => ({ ...v, config: JSON.parse(v.config) })),
    'views:save': ({ name, table, config }) => {
      const key = String(name || '').trim();
      if (!key) throw new Error('View name is required');
      db.listColumns(database, table); // throws for an unknown or invalid table
      const json = JSON.stringify(config || {});
      if (json.length > MAX_VIEW_CONFIG) throw new Error('View settings are too large');
      database.prepare(`INSERT INTO saved_views (name, table_name, config, created_at) VALUES (?, ?, ?, ?)
        ON CONFLICT (name) DO UPDATE SET table_name = excluded.table_name, config = excluded.config`)
        .run(key, table, json, new Date().toISOString());
      return handlers['views:list'](table);
    },
    'views:delete': (id) => {
      const row = database.prepare('SELECT table_name FROM saved_views WHERE id = ?').get(id);
      database.prepare('DELETE FROM saved_views WHERE id = ?').run(id);
      return row ? handlers['views:list'](row.table_name) : [];
    },

    // Attachments: evidence files on a finding or a POA&M / RBD record
    'attachments:list': ({ vulnId, poamId }) => database.prepare(
      `SELECT id, filename, mime, size, uploaded_by, created_at FROM attachments
       WHERE ${vulnId ? 'vuln_id = ?' : 'poam_id = ?'} ORDER BY id`,
    ).all(vulnId || poamId),
    'attachments:add': ({ vulnId, poamId, filename, mime, content, uploadedBy }) => {
      if (Boolean(vulnId) === Boolean(poamId)) throw new Error('Attach a file to one finding or one POA&M record');
      if (typeof content !== 'string' || !content) throw new Error('The file is empty');
      const data = Buffer.from(content, 'base64');
      if (data.length === 0) throw new Error('The file is empty');
      if (data.length > MAX_ATTACHMENT_BYTES) throw new Error('Attachments are limited to 10 MB');
      const result = database.prepare(`INSERT INTO attachments (vuln_id, poam_id, filename, mime, size, data, uploaded_by, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)`).run(vulnId || null, poamId || null, safeFileName(filename),
        String(mime || 'application/octet-stream').slice(0, 100), data.length, data, uploadedBy || null, new Date().toISOString());
      return Number(result.lastInsertRowid);
    },
    'attachments:get': (id) => {
      const row = database.prepare('SELECT filename, mime, data FROM attachments WHERE id = ?').get(id);
      if (!row) throw new Error(`No attachment with id ${id}`);
      return { filename: row.filename, mime: row.mime, content: Buffer.from(row.data).toString('base64') };
    },
    'attachments:delete': (id) => {
      database.prepare('DELETE FROM attachments WHERE id = ?').run(id);
      return true;
    },

    // Official-layout Excel export: title row, then one row per record with the template's column labels
    'poam:exportXlsx': ({ kind, template }) => {
      const fields = poam.fieldsFor(template, kind);
      const items = poam.listItems(database, kind);
      const header = ['ID', 'Title', 'Status', 'Linked findings', ...fields.map((f) => f.label)];
      const rows = items.map((item) => [item.id, item.title, item.status, item.vuln_ids.join(', '),
        ...fields.map((f) => item.data[f.key] ?? '')]);
      const label = kind === 'rbd' ? 'RBD' : 'POA&M';
      const sheet = XLSX.utils.aoa_to_sheet([[`${label} records: ${poam.TEMPLATES[template]?.name || template}`], [], header, ...rows]);
      const book = XLSX.utils.book_new();
      XLSX.utils.book_append_sheet(book, sheet, label);
      return XLSX.write(book, { type: 'base64', bookType: 'xlsx' });
    },

    // Backups of the database file
    'backup:create': () => {
      if (!backupDir) throw new Error('Backups are not configured on this installation');
      const { file, bytes } = createBackup(database, backupDir);
      return { name: path.basename(file), bytes };
    },
    'backup:list': () => (backupDir ? listBackups(backupDir).map(({ name, bytes, created }) => ({ name, bytes, created })) : []),
  };

  return handlers;
}

// CSV text of a query result, used by the desktop export actions.
function rowsToCsv(columnNames, rows) {
  return [columnNames.join(','), ...rows.map((r) => columnNames.map((c) => csvEscape(r[c])).join(','))].join('\n');
}

module.exports = { createHandlers, MIN_ROLE, ROLE_RANK, allowed, rowsToCsv };
