// Data cleaning: date normalisation for imports, duplicate removal, and stale-data removal.
const { addDays } = require('./rules');

const MONTHS = { jan: 1, feb: 2, mar: 3, apr: 4, may: 5, jun: 6, jul: 7, aug: 8, sep: 9, oct: 10, nov: 11, dec: 12 };
const pad = (n) => String(n).padStart(2, '0');

// Accepts ISO (2026-01-05 or 2026-01-05T...), US (1/5/2026 or 01-05-2026), "05-Jan-2026",
// and Excel date serials (numbers such as 46027). Returns YYYY-MM-DD, or null if unreadable.
function normaliseDate(value) {
  if (value == null || value === '') return null;
  if (typeof value === 'number' && value > 20000 && value < 100000) {
    // Excel serial day count; day 0 is 1899-12-30 in the 1900 date system.
    const d = new Date(Date.UTC(1899, 11, 30) + value * 864e5);
    return d.toISOString().slice(0, 10);
  }
  const s = String(value).trim();
  let m = s.match(/^(\d{4})-(\d{1,2})-(\d{1,2})/);
  if (m) return `${m[1]}-${pad(m[2])}-${pad(m[3])}`;
  m = s.match(/^(\d{1,2})[/-](\d{1,2})[/-](\d{4})$/);
  if (m) return `${m[3]}-${pad(m[1])}-${pad(m[2])}`;
  m = s.match(/^(\d{1,2})[- ]([A-Za-z]{3})[a-z]*[- ,]+(\d{4})$/);
  if (m && MONTHS[m[2].toLowerCase()]) return `${m[3]}-${pad(MONTHS[m[2].toLowerCase()])}-${pad(m[1])}`;
  return null;
}

// Groups of findings sharing a CVE and asset across more than one row (typically from different sources).
function findDuplicates(db) {
  const groups = db.prepare(`
    SELECT cve, asset, COUNT(*) AS n, GROUP_CONCAT(id) AS ids, GROUP_CONCAT(source) AS sources
    FROM vulnerabilities
    WHERE cve IS NOT NULL
    GROUP BY cve, COALESCE(asset, '')
    HAVING COUNT(*) > 1
  `).all();
  return groups.map((g) => ({ cve: g.cve, asset: g.asset, count: g.n, ids: g.ids.split(',').map(Number) }));
}

// Keeps the most recently seen row in each duplicate group and deletes the rest. Returns the count removed.
function removeDuplicates(db) {
  const doomed = findDuplicates(db).flatMap((g) => {
    const keep = db.prepare(`SELECT id FROM vulnerabilities WHERE id IN (${g.ids.map(() => '?').join(',')})
      ORDER BY last_seen DESC, id DESC LIMIT 1`).get(...g.ids).id;
    return g.ids.filter((id) => id !== keep);
  });
  return deleteByIds(db, doomed);
}

// Findings not seen by any import in the last `days` days. Preview with count; removal is separate.
function staleFindings(db, today, days) {
  const cutoff = addDays(today, -days);
  return db.prepare('SELECT id, cve, title, asset, status, last_seen FROM vulnerabilities WHERE last_seen < ? ORDER BY last_seen')
    .all(cutoff);
}

function removeStale(db, today, days) {
  return deleteByIds(db, staleFindings(db, today, days).map((r) => r.id));
}

// After a full re-import of one source, rows from that source that the file no longer contains are dropped.
function pruneSource(db, source, today) {
  const result = db.prepare('DELETE FROM vulnerabilities WHERE source = ? AND last_seen < ?').run(source, today);
  return Number(result.changes);
}

function deleteByIds(db, ids) {
  if (ids.length === 0) return 0;
  const stmt = db.prepare('DELETE FROM vulnerabilities WHERE id = ?');
  let removed = 0;
  db.exec('BEGIN');
  try {
    for (const id of ids) removed += Number(stmt.run(id).changes);
    db.exec('COMMIT');
  } catch (err) {
    db.exec('ROLLBACK');
    throw err;
  }
  return removed;
}

module.exports = { normaliseDate, findDuplicates, removeDuplicates, staleFindings, removeStale, pruneSource };
