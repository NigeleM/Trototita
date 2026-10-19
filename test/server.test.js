const test = require('node:test');
const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { openDatabase, upsertVulnerabilities } = require('../src/db');
const users = require('../src/users');
const { createServer } = require('../server/server');
const remote = require('../src/remote');
const { allowed } = require('../src/handlers');

const PASSWORD = 'correct horse battery';

// One server for the whole file: a throwaway self-signed certificate, three users, one database.
let server;
let base;
let caFile;
let dir;
let auditDb;

test.before(async () => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vulnmgt-test-'));
  const key = path.join(dir, 'key.pem');
  const cert = path.join(dir, 'cert.pem');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', key, '-out', cert,
    '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1'], { stdio: 'ignore' });
  caFile = cert;

  const database = openDatabase(':memory:');
  auditDb = database;
  users.initUsers(database);
  upsertVulnerabilities(database, [{ title: 'Seed finding', cve: 'CVE-1', asset: 'web', first_seen: '2026-01-01', source: 'test' }]);
  users.createUser(database, { username: 'vera', role: 'viewer', password: PASSWORD });
  users.createUser(database, { username: 'ed', role: 'editor', password: PASSWORD });
  users.createUser(database, { username: 'ada', role: 'admin', password: PASSWORD });
  server = createServer({ database, cert: fs.readFileSync(cert), key: fs.readFileSync(key) });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  base = `https://localhost:${server.address().port}`;
});

test.after(() => {
  server.close();
  fs.rmSync(dir, { recursive: true, force: true });
});

// Minimal POST that trusts the test certificate.
function rawRequest(route, body, token) {
  const https = require('node:https');
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
  const { status, json } = await rawRequest('/api/login', { username, password });
  assert.equal(status, 200);
  return json.token;
}

test('health endpoint answers without a session', async () => {
  const res = await new Promise((resolve, reject) => {
    const https = require('node:https');
    https.get(`${base}/api/health`, { ca: fs.readFileSync(caFile) }, (r) => {
      let d = ''; r.on('data', (c) => { d += c; }); r.on('end', () => resolve({ status: r.statusCode, body: JSON.parse(d) }));
    }).on('error', reject);
  });
  assert.equal(res.status, 200);
  assert.equal(res.body.ok, true);
});

test('wrong password is refused; unknown user is refused the same way', async () => {
  assert.equal((await rawRequest('/api/login', { username: 'ada', password: 'wrong wrong wrong' })).status, 401);
  assert.equal((await rawRequest('/api/login', { username: 'nobody', password: 'whatever whatever' })).status, 401);
});

test('calls without a session are refused', async () => {
  const { status } = await rawRequest('/api/call', { channel: 'db:tables', args: null });
  assert.equal(status, 401);
});

test('viewer can read but cannot edit or run SQL', async () => {
  const token = await signIn('vera');
  const read = await rawRequest('/api/call', { channel: 'db:tables', args: null }, token);
  assert.equal(read.status, 200);
  assert.ok(read.json.result.includes('vulnerabilities'));

  const edit = await rawRequest('/api/call', { channel: 'db:updateCell', args: { table: 'vulnerabilities', rowid: 1, column: 'status', value: 'closed' } }, token);
  assert.equal(edit.status, 403);
  const sql = await rawRequest('/api/call', { channel: 'db:sql', args: 'DELETE FROM vulnerabilities' }, token);
  assert.equal(sql.status, 403);
});

test('editor can add a comment but cannot change rules', async () => {
  const token = await signIn('ed');
  const comment = await rawRequest('/api/call', { channel: 'finding:comment', args: { id: 1, author: 'ed', body: 'Looking at this' } }, token);
  assert.equal(comment.status, 200);
  assert.equal(comment.json.result.length, 1);

  const rule = await rawRequest('/api/call', { channel: 'rules:save', args: { name: 'x', enabled: true, conditions: [], priority_bonus: 0 } }, token);
  assert.equal(rule.status, 403);
});

test('admin can run SQL; unknown channels return 404', async () => {
  const token = await signIn('ada');
  const sql = await rawRequest('/api/call', { channel: 'db:sql', args: 'SELECT COUNT(*) AS n FROM vulnerabilities' }, token);
  assert.equal(sql.status, 200);
  const unknown = await rawRequest('/api/call', { channel: 'nope:nothing', args: null }, token);
  assert.equal(unknown.status, 404);
});

test('the team server pulls from no API host unless one is approved', async () => {
  const token = await signIn('ed');
  const res = await rawRequest('/api/call', { channel: 'import:api', args: { url: 'https://internal.example/x' } }, token);
  assert.equal(res.status, 400);
  assert.match(res.json.error, /not an approved API host/);
});

test('handler errors come back as 400 with the message', async () => {
  const token = await signIn('ada');
  const res = await rawRequest('/api/call', { channel: 'db:columns', args: 'vulnerabilities; DROP TABLE x' }, token);
  assert.equal(res.status, 400);
  assert.match(res.json.error, /Invalid table name/);
});

test('every call and denial is written to the audit log', async () => {
  const token = await signIn('vera');
  await rawRequest('/api/call', { channel: 'db:sql', args: 'SELECT 1' }, token);
  await rawRequest('/api/call', { channel: 'db:tables', args: null }, token);
  const entries = users.listAudit(auditDb, 500);
  assert.ok(entries.some((e) => e.username === 'vera' && e.channel === 'db:sql' && e.outcome === 'denied'));
  assert.ok(entries.some((e) => e.username === 'vera' && e.channel === 'db:tables' && e.outcome === 'ok'));
  assert.ok(entries.some((e) => e.channel === 'login' && e.outcome === 'failed'));
});

test('a session ends on sign-out', async () => {
  const token = await signIn('ed');
  await rawRequest('/api/logout', {}, token);
  assert.equal((await rawRequest('/api/call', { channel: 'db:tables', args: null }, token)).status, 401);
});

test('repeated failures lock the account for a while', async () => {
  const name = 'lockout-probe';
  for (let i = 0; i < 5; i++) await rawRequest('/api/login', { username: name, password: 'nope nope nope' });
  assert.equal((await rawRequest('/api/login', { username: name, password: 'nope nope nope' })).status, 429);
});

test('desktop client signs in and calls the server through the CA file', async () => {
  const session = await remote.login(base, { username: 'vera', password: PASSWORD }, caFile);
  assert.equal(session.role, 'viewer');
  const stats = await remote.call(session, 'dashboard:stats', null);
  assert.ok('totals' in stats);
  await remote.logout(session);
});

test('desktop client refuses plain http addresses', async () => {
  await assert.rejects(remote.login('http://example.test', { username: 'a', password: 'b' }), /https/);
});

test('role rules: viewer < editor < admin', () => {
  assert.equal(allowed('viewer', 'db:query'), true);
  assert.equal(allowed('viewer', 'finding:comment'), false);
  assert.equal(allowed('editor', 'finding:comment'), true);
  assert.equal(allowed('editor', 'db:sql'), false);
  assert.equal(allowed('admin', 'db:sql'), true);
  assert.equal(allowed('admin', 'not-a-channel'), false);
});

test('admin channels: viewers and editors are refused, admins can list accounts and the audit log', async () => {
  const viewer = await signIn('vera');
  assert.equal((await rawRequest('/api/call', { channel: 'users:list', args: null }, viewer)).status, 403);
  const admin = await signIn('ada');
  const list = await rawRequest('/api/call', { channel: 'users:list', args: null }, admin);
  assert.equal(list.status, 200);
  assert.ok(list.json.result.some((u) => u.username === 'vera' && u.role === 'viewer'));
  const audit = await rawRequest('/api/call', { channel: 'audit:list', args: 20 }, admin);
  assert.equal(audit.status, 200);
  assert.ok(Array.isArray(audit.json.result));
});

test('the last enabled admin cannot be disabled or demoted', async () => {
  const admin = await signIn('ada');
  const disable = await rawRequest('/api/call', { channel: 'users:setDisabled', args: { username: 'ada', disabled: true } }, admin);
  assert.equal(disable.status, 400);
  assert.match(disable.json.error, /At least one enabled admin/);
  const demote = await rawRequest('/api/call', { channel: 'users:setRole', args: { username: 'ada', role: 'viewer' } }, admin);
  assert.equal(demote.status, 400);
});

test('attachments and saved views work through the server with role checks', async () => {
  const editor = await signIn('ed');
  const content = Buffer.from('evidence').toString('base64');
  const add = await rawRequest('/api/call', { channel: 'attachments:add', args: { vulnId: 1, filename: 'proof.txt', mime: 'text/plain', content } }, editor);
  assert.equal(add.status, 200);
  const viewer = await signIn('vera');
  const get = await rawRequest('/api/call', { channel: 'attachments:get', args: add.json.result }, viewer);
  assert.equal(Buffer.from(get.json.result.content, 'base64').toString(), 'evidence');
  const viewerAdd = await rawRequest('/api/call', { channel: 'attachments:add', args: { vulnId: 1, filename: 'x.txt', content } }, viewer);
  assert.equal(viewerAdd.status, 403);
  const view = await rawRequest('/api/call', { channel: 'views:save', args: { name: 'Team view', table: 'vulnerabilities', config: { filters: {} } } }, editor);
  assert.equal(view.status, 200);
});
