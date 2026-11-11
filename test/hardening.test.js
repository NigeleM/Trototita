// Regression tests for the team-server and data-protection fixes.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const https = require('node:https');
const { execFileSync } = require('node:child_process');
const { openDatabase, queryTable, updateCell, insertRow, deleteRows, listTables, aggregate, listColumns, upsertVulnerabilities } = require('../src/db');
const { createHandlers } = require('../src/handlers');
const { createBackup, restoreBackup } = require('../src/backup');
const { importFromApi } = require('../src/ingest');
const users = require('../src/users');
const { createServer } = require('../server/server');

const PASSWORD = 'correct horse battery';

test('generic data channels cannot reach accounts or the audit log', () => {
  const db = openDatabase(':memory:');
  users.initUsers(db);
  users.createUser(db, { username: 'ed', role: 'editor', password: PASSWORD });
  assert.throws(() => queryTable(db, 'users', {}), /managed by the app/);
  assert.throws(() => queryTable(db, 'audit_log', {}), /managed by the app/);
  assert.throws(() => updateCell(db, 'users', 1, 'role', 'admin'), /managed by the app/);
  assert.throws(() => deleteRows(db, 'audit_log', [1]), /managed by the app/);
  assert.throws(() => insertRow(db, 'users'), /managed by the app/);
  assert.throws(() => aggregate(db, 'users', { groupBy: 'role' }), /managed by the app/);
  assert.throws(() => listColumns(db, 'sqlite_master'), /managed by the app/);
  assert.ok(!listTables(db).includes('users'));
  assert.ok(!listTables(db).includes('audit_log'));
  assert.equal(users.findActive(db, 'ed').role, 'editor'); // the role is unchanged
});

test('the audit log cannot be altered or erased, even with direct SQL', () => {
  const db = openDatabase(':memory:');
  users.initUsers(db);
  users.logAudit(db, 'x', 'login', 'ok');
  assert.throws(() => db.exec("UPDATE audit_log SET outcome = 'ok'"), /append-only/);
  assert.throws(() => db.exec('DELETE FROM audit_log'), /append-only/);
  assert.equal(users.listAudit(db, 10).length, 1);
});

test('the team handler set has no raw SQL console; the desktop one keeps it', () => {
  const db = openDatabase(':memory:');
  assert.equal(typeof createHandlers(db)['db:sql'], 'function');
  assert.equal(createHandlers(db, { teamMode: true })['db:sql'], undefined);
});

test('a finding can be updated through the generic grid for user tables', () => {
  const db = openDatabase(':memory:');
  upsertVulnerabilities(db, [{ title: 'A', cve: 'CVE-1', asset: 'h', first_seen: '2026-01-01', source: 't' }]);
  updateCell(db, 'vulnerabilities', 1, 'status', 'closed');
  assert.equal(queryTable(db, 'vulnerabilities', {}).rows[0].status, 'closed');
});

test('the database file and its backups are owner-only', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vm-perm-'));
  try {
    const file = path.join(dir, 'live.db');
    const db = openDatabase(file);
    upsertVulnerabilities(db, [{ title: 'A', first_seen: '2026-01-01', source: 't' }]);
    const bdir = path.join(dir, 'backups');
    const { file: bfile } = createBackup(db, bdir);
    db.close();
    const mode = (f) => (fs.statSync(f).mode & 0o777).toString(8);
    assert.equal(mode(file), '600');
    assert.equal(mode(bfile), '600');
    assert.equal(mode(bdir), '700');
    restoreBackup(file, bfile);
    assert.equal(mode(file), '600');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('API imports refuse cloud metadata and link-local addresses', async () => {
  const db = openDatabase(':memory:');
  for (const url of ['http://169.254.169.254/latest/meta-data', 'https://metadata.google.internal/x', 'http://[fe80::1]/x']) {
    await assert.rejects(importFromApi(db, { url }), /not allowed|approved/, url);
  }
});

test('certificate script rejects host names that could add certificate fields', () => {
  const script = path.join(__dirname, '..', 'server', 'make-cert.sh');
  assert.throws(() => execFileSync('bash', [script, 'bad,DNS:evil'], { stdio: 'pipe' }));
});

// ---------- team server behaviour ----------

let server;
let base;
let caFile;
let dir;
let db;
let clock;
let sessions;

test.before(async () => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vm-hard-'));
  const key = path.join(dir, 'key.pem');
  const cert = path.join(dir, 'cert.pem');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', key, '-out', cert,
    '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1'], { stdio: 'ignore' });
  caFile = cert;
  db = openDatabase(':memory:');
  users.initUsers(db);
  upsertVulnerabilities(db, [{ title: 'Seed', cve: 'CVE-1', asset: 'web', first_seen: '2026-01-01', source: 'test' }]);
  users.createUser(db, { username: 'vera', role: 'viewer', password: PASSWORD });
  users.createUser(db, { username: 'ed', role: 'editor', password: PASSWORD });
  users.createUser(db, { username: 'ada', role: 'admin', password: PASSWORD });
  clock = 1_000_000;
  sessions = new users.Sessions(() => clock);
  server = createServer({ database: db, cert: fs.readFileSync(cert), key: fs.readFileSync(key), sessions });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  base = `https://localhost:${server.address().port}`;
});

test.after(() => {
  server.close();
  fs.rmSync(dir, { recursive: true, force: true });
});

function call(route, body, token) {
  const payload = JSON.stringify(body || {});
  const headers = { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) };
  if (token) headers.Authorization = `Bearer ${token}`;
  return new Promise((resolve, reject) => {
    const u = new URL(route, base);
    const req = https.request({ method: 'POST', hostname: u.hostname, port: u.port, path: u.pathname, headers, ca: fs.readFileSync(caFile) }, (res) => {
      let data = '';
      res.on('data', (c) => { data += c; });
      res.on('end', () => resolve({ status: res.statusCode, json: JSON.parse(data || '{}') }));
    });
    req.on('error', reject);
    req.end(payload);
  });
}

async function signIn(username, password = PASSWORD) {
  const res = await call('/api/login', { username, password });
  assert.equal(res.status, 200, `sign-in for ${username}`);
  return res.json.token;
}

test('an editor cannot change their own role through the grid', async () => {
  const token = await signIn('ed');
  const rowid = db.prepare("SELECT rowid AS r FROM users WHERE username = 'ed'").get().r;
  const res = await call('/api/call', { channel: 'db:updateCell', args: { table: 'users', rowid, column: 'role', value: 'admin' } }, token);
  assert.equal(res.status, 400);
  assert.equal(users.findActive(db, 'ed').role, 'editor');
});

test('a viewer cannot read password hashes through the grid', async () => {
  const token = await signIn('vera');
  const res = await call('/api/call', { channel: 'db:query', args: { table: 'users' } }, token);
  assert.equal(res.status, 400);
  assert.ok(!JSON.stringify(res.json).includes('scrypt$'));
  const sqlLoaded = await call('/api/call', { channel: 'db:sqlLoaded', args: { table: 'users', sql: 'SELECT * FROM users' } }, token);
  assert.equal(sqlLoaded.status, 400);
});

test('an editor cannot erase audit entries through the grid', async () => {
  const token = await signIn('ed');
  const earlier = users.listAudit(db, 1000).map((e) => e.id);
  const res = await call('/api/call', { channel: 'db:deleteRows', args: { table: 'audit_log', rowids: earlier } }, token);
  assert.equal(res.status, 400);
  const now = new Set(users.listAudit(db, 1000).map((e) => e.id));
  assert.ok(earlier.every((id) => now.has(id)), 'every earlier entry is still there');
});

test('a disabled account loses its session at once', async () => {
  const token = await signIn('vera');
  assert.equal((await call('/api/call', { channel: 'db:tables', args: null }, token)).status, 200);
  users.setDisabled(db, 'vera', true);
  assert.equal((await call('/api/call', { channel: 'db:tables', args: null }, token)).status, 401);
  users.setDisabled(db, 'vera', false);
});

test('a demoted account loses the rights of its old role at once', async () => {
  const token = await signIn('ed');
  assert.equal((await call('/api/call', { channel: 'db:insertRow', args: { table: 'vulnerabilities' } }, token)).status, 200);
  users.setRole(db, 'ed', 'viewer');
  assert.equal((await call('/api/call', { channel: 'db:insertRow', args: { table: 'vulnerabilities' } }, token)).status, 403);
  users.setRole(db, 'ed', 'editor');
});

test('a changed password ends sessions issued under the old password', async () => {
  const token = await signIn('ed');
  users.setPassword(db, 'ed', 'a brand new passphrase');
  assert.equal((await call('/api/call', { channel: 'db:tables', args: null }, token)).status, 401);
  const fresh = await signIn('ed', 'a brand new passphrase');
  assert.equal((await call('/api/call', { channel: 'db:tables', args: null }, fresh)).status, 200);
  users.setPassword(db, 'ed', PASSWORD);
});

test('sessions end after an hour without use', () => {
  const s = new users.Sessions(() => clock);
  const token = s.create({ username: 'x', fingerprint: 'f' });
  clock += 59 * 60 * 1000;
  assert.ok(s.get(token)); // use refreshes the idle timer
  clock += 59 * 60 * 1000;
  assert.ok(s.get(token));
  clock += 61 * 60 * 1000;
  assert.equal(s.get(token), null);
  clock = 1_000_000 + 0; // reset for other tests
});

test('sessions end after eight hours even when used', () => {
  const s = new users.Sessions(() => clock);
  const token = s.create({ username: 'x', fingerprint: 'f' });
  for (let i = 0; i < 10; i++) { clock += 50 * 60 * 1000; s.get(token); } // 8h 20m of use
  assert.equal(s.get(token), null);
  clock = 1_000_000;
});

test('login failures are counted per address and account, so one account cannot be locked from elsewhere', () => {
  const t = new users.LoginThrottle({ limit: 2 });
  t.fail('10.0.0.5|vera');
  t.fail('10.0.0.5|vera');
  assert.equal(t.blocked('10.0.0.5|vera'), true);
  assert.equal(t.blocked('10.0.0.9|vera'), false);
});

test('when the login throttle fills up, only the oldest counter is dropped', () => {
  const t = new users.LoginThrottle({ limit: 2 });
  t.fail('oldest');
  t.fail('oldest');
  t.fail('newer');
  t.fail('newer');
  assert.equal(t.blocked('oldest'), true);
  for (let i = 0; i < 9998; i++) t.fail(`flood-${i}`);
  assert.equal(t.blocked('newer'), true);
  t.fail('one-more');
  assert.equal(t.blocked('oldest'), false); // the oldest entry was dropped
  assert.equal(t.blocked('newer'), true);   // newer counters survive
});

test('the author of a comment is the signed-in account, whatever the request says', async () => {
  const token = await signIn('ed');
  const res = await call('/api/call', { channel: 'finding:comment', args: { id: 1, author: 'ada', body: 'Checking' } }, token);
  assert.equal(res.status, 200);
  assert.equal(res.json.result.at(-1).author, 'ed');
});

test('database errors are not passed to the client', async () => {
  const token = await signIn('ed');
  const res = await call('/api/call', { channel: 'milestone:save', args: { poam_id: 999999, title: 'x' } }, token);
  assert.equal(res.status, 400);
  assert.equal(res.json.error, 'The request could not be completed');
  assert.ok(!/FOREIGN|constraint|SQLITE/i.test(res.json.error));
});

test('sessions do not survive a restart', async () => {
  // Sessions are in memory: a fresh session store (as after a restart) accepts no old token.
  const token = await signIn('vera');
  const other = new users.Sessions();
  assert.equal(other.get(token), null);
});

// ---------- second round: encryption, proxies, delays, DNS ----------

const { clientAddress, accountDelayMs } = require('../server/server');
const { isBlockedAddress } = require('../src/ingest');
const { parseBackupKey, listBackups } = require('../src/backup');

test('backups can be encrypted with a key; the key is required to restore them', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vm-enc-'));
  try {
    const key = parseBackupKey(require('node:crypto').randomBytes(32).toString('base64'));
    const live = path.join(dir, 'live.db');
    const db = openDatabase(live);
    upsertVulnerabilities(db, [{ title: 'Secret finding', first_seen: '2026-01-01', source: 't' }]);
    const bdir = path.join(dir, 'backups');
    const made = createBackup(db, bdir, { key });
    db.close();
    assert.equal(made.encrypted, true);
    assert.ok(made.file.endsWith('.db.enc'));
    const raw = fs.readFileSync(made.file);
    assert.ok(!raw.includes('SQLite format 3'), 'the file is not a readable SQLite database');
    assert.ok(!raw.includes('Secret finding'), 'the data is not visible in the file');
    assert.equal(listBackups(bdir)[0].encrypted, true);
    assert.equal((fs.statSync(made.file).mode & 0o777).toString(8), '600');
    assert.equal(fs.readdirSync(bdir).some((f) => f.startsWith('.')), false, 'no plain temporary copy is left');

    assert.throws(() => restoreBackup(live, made.file), /VULN_BACKUP_KEY/);
    assert.throws(() => restoreBackup(live, made.file, { key: parseBackupKey(require('node:crypto').randomBytes(32).toString('base64')) }), /does not match/);
    restoreBackup(live, made.file, { key });
    const restored = openDatabase(live);
    assert.equal(queryTable(restored, 'vulnerabilities', {}).rows[0].title, 'Secret finding');
    restored.close();
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('the backup key must be 32 bytes', () => {
  assert.equal(parseBackupKey(''), null);
  assert.throws(() => parseBackupKey('c2hvcnQ='), /32 random bytes/);
});

test('an encrypted backup is detected even when tampered with', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vm-tamper-'));
  try {
    const key = parseBackupKey(require('node:crypto').randomBytes(32).toString('base64'));
    const live = path.join(dir, 'live.db');
    const db = openDatabase(live);
    const { file } = createBackup(db, path.join(dir, 'backups'), { key });
    db.close();
    const bytes = fs.readFileSync(file);
    bytes[bytes.length - 1] ^= 0xff;
    fs.writeFileSync(file, bytes);
    assert.throws(() => restoreBackup(live, file, { key }), /does not match/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('behind a trusted proxy the real client is the address the proxy added', () => {
  const req = (remote, xff) => ({ socket: { remoteAddress: remote }, headers: xff ? { 'x-forwarded-for': xff } : {} });
  assert.equal(clientAddress(req('10.0.0.1', '203.0.113.7'), ['10.0.0.1']), '203.0.113.7');
  assert.equal(clientAddress(req('10.0.0.1', '198.51.100.2, 203.0.113.7'), ['10.0.0.1']), '203.0.113.7');
  // Untrusted senders cannot choose their own address with a header.
  assert.equal(clientAddress(req('192.0.2.9', '1.2.3.4'), ['10.0.0.1']), '192.0.2.9');
  assert.equal(clientAddress(req('::ffff:192.0.2.9'), []), '192.0.2.9');
});

test('repeated failures on an account slow the next attempts without locking them', () => {
  assert.equal(accountDelayMs(0), 0);
  assert.equal(accountDelayMs(2), 0);
  assert.equal(accountDelayMs(3), 500);
  assert.equal(accountDelayMs(4), 1000);
  assert.equal(accountDelayMs(50), 4000);
});

test('addresses that point at metadata or link-local networks are recognised', () => {
  assert.equal(isBlockedAddress('169.254.169.254'), true);
  assert.equal(isBlockedAddress('::ffff:169.254.1.1'), true);
  assert.equal(isBlockedAddress('fe80::1'), true);
  assert.equal(isBlockedAddress('203.0.113.10'), false);
  assert.equal(isBlockedAddress('10.1.2.3'), false);
});

test('the API importer fetches JSON, refuses redirects and caps response size', async () => {
  const http = require('node:http');
  const srv = http.createServer((req, res) => {
    if (req.url === '/ok') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ findings: [{ name: 'Local finding', cve: 'CVE-2026-1' }] }));
    }
    if (req.url === '/redirect') { res.writeHead(302, { Location: '/ok' }); return res.end(); }
    if (req.url === '/big') { res.writeHead(200); return res.end('x'.repeat(26 * 1024 * 1024)); }
    res.writeHead(404); res.end();
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${srv.address().port}`;
  try {
    const db = openDatabase(':memory:');
    const ok = await importFromApi(db, { url: `${base}/ok`, itemsPath: 'findings', mapping: { title: 'name', cve: 'cve' }, source: 'local' });
    assert.equal(ok.written, 1);
    await assert.rejects(importFromApi(db, { url: `${base}/redirect`, itemsPath: 'findings' }), /redirects are not followed/);
    await assert.rejects(importFromApi(db, { url: `${base}/big`, itemsPath: 'findings' }), /too large/);
    await assert.rejects(importFromApi(db, { url: `${base}/missing`, itemsPath: 'findings' }), /HTTP 404/);
  } finally {
    srv.close();
  }
});
