// Threat intelligence: CISA's Known Exploited Vulnerabilities (KEV) catalogue and FIRST's EPSS scores.
// KEV CVEs get a priority bonus and an "exploited" flag; EPSS (probability of exploitation in 30 days)
// adds a smaller bonus. Feeds are fetched from fixed, trusted URLs only.
const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const EPSS_URL = 'https://api.first.org/data/v1/epss';
const EPSS_BATCH = 100;
const TIMEOUT_MS = 30000;

// Parses the CISA catalogue and replaces the stored copy. Returns the number of entries.
function applyKev(db, catalogue) {
  const entries = Array.isArray(catalogue?.vulnerabilities) ? catalogue.vulnerabilities : null;
  if (!entries) throw new Error('KEV feed has an unexpected format');
  db.exec('BEGIN');
  try {
    db.exec('DELETE FROM kev_catalog');
    const insert = db.prepare('INSERT OR REPLACE INTO kev_catalog (cve, name, date_added, due_date) VALUES (?, ?, ?, ?)');
    let n = 0;
    for (const e of entries) {
      if (!/^CVE-\d{4}-\d{4,}$/.test(e.cveID || '')) continue;
      insert.run(e.cveID, e.vulnerabilityName || null, e.dateAdded || null, e.dueDate || null);
      n++;
    }
    db.exec('COMMIT');
    return n;
  } catch (err) {
    db.exec('ROLLBACK');
    throw err;
  }
}

// Stores EPSS rows from the FIRST API: { data: [{ cve, epss, percentile }] }.
function applyEpss(db, body, today) {
  const rows = Array.isArray(body?.data) ? body.data : null;
  if (!rows) throw new Error('EPSS response has an unexpected format');
  const upsert = db.prepare(`INSERT OR REPLACE INTO epss_scores (cve, score, percentile, updated_at) VALUES (?, ?, ?, ?)`);
  db.exec('BEGIN');
  try {
    let n = 0;
    for (const r of rows) {
      const score = Number(r.epss);
      if (!/^CVE-\d{4}-\d{4,}$/.test(r.cve || '') || !Number.isFinite(score)) continue;
      upsert.run(r.cve, score, Number.isFinite(Number(r.percentile)) ? Number(r.percentile) : null, today);
      n++;
    }
    db.exec('COMMIT');
    return n;
  } catch (err) {
    db.exec('ROLLBACK');
    throw err;
  }
}

async function getJson(url, fetchFn) {
  const res = await fetchFn(url, { headers: { Accept: 'application/json' }, signal: AbortSignal.timeout(TIMEOUT_MS), redirect: 'error' });
  if (!res.ok) throw new Error(`Feed returned HTTP ${res.status}`);
  return res.json();
}

// Refreshes KEV, then EPSS for the CVEs the app actually holds. fetchFn is injectable for tests.
async function refreshIntel(db, { fetchFn = fetch, today = new Date().toISOString().slice(0, 10) } = {}) {
  const kev = applyKev(db, await getJson(KEV_URL, fetchFn));

  const cves = db.prepare('SELECT DISTINCT cve FROM vulnerabilities WHERE cve IS NOT NULL').all().map((r) => r.cve);
  let epss = 0;
  for (let i = 0; i < cves.length; i += EPSS_BATCH) {
    const batch = cves.slice(i, i + EPSS_BATCH);
    const body = await getJson(`${EPSS_URL}?cve=${encodeURIComponent(batch.join(','))}`, fetchFn);
    epss += applyEpss(db, body, today);
  }
  return { kev, epss, cves: cves.length };
}

// Lookup maps used when rules are re-evaluated.
function intelMaps(db) {
  const kev = new Set(db.prepare('SELECT cve FROM kev_catalog').all().map((r) => r.cve));
  const epss = new Map(db.prepare('SELECT cve, score FROM epss_scores').all().map((r) => [r.cve, r.score]));
  return { kev, epss };
}

module.exports = { applyKev, applyEpss, refreshIntel, intelMaps, KEV_URL, EPSS_URL };
