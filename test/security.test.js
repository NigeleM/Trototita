const test = require('node:test');
const assert = require('node:assert/strict');
const { csvEscape } = require('../src/csvout');
const users = require('../src/users');
const ingest = require('../src/ingest');
const { openDatabase } = require('../src/db');

test('CSV export neutralises spreadsheet formulas but leaves numbers alone', () => {
  assert.equal(csvEscape('=HYPERLINK("http://x")'), `"'=HYPERLINK(""http://x"")"`);
  assert.equal(csvEscape('+1+1'), "'+1+1");
  assert.equal(csvEscape('@SUM(A1)'), "'@SUM(A1)");
  assert.equal(csvEscape(-5), '-5');
  assert.equal(csvEscape('-5 steps'), "'-5 steps");
  assert.equal(csvEscape('plain, text'), '"plain, text"');
});

test('JSON keys that could change an object prototype are ignored', () => {
  const db = openDatabase(':memory:');
  const payload = '[{"__proto__": {"polluted": "yes"}, "constructor": "x", "Title": "Safe row", "CVE": "CVE-1"}]';
  const res = ingest.importJsonText(db, payload, { source: 'json', today: '2026-10-17' });
  assert.equal(res.written, 1);
  assert.equal({}.polluted, undefined);
  assert.equal(Object.prototype.polluted, undefined);
});

test('the API importer refuses hosts that are not on the approved list, before any request', async () => {
  const db = openDatabase(':memory:');
  await assert.rejects(
    ingest.importFromApi(db, { url: 'https://internal.example/api' }, { allowedHosts: ['approved.example'] }),
    /not an approved API host/,
  );
  await assert.rejects(
    ingest.importFromApi(db, { url: 'https://internal.example/api' }, { allowedHosts: [] }),
    /not an approved API host/,
  );
});

test('the API importer rejects non-HTTP schemes', async () => {
  const db = openDatabase(':memory:');
  await assert.rejects(ingest.importFromApi(db, { url: 'file:///etc/passwd' }), /http or https/);
});

test('passwords must be 12 to 256 characters', () => {
  const db = openDatabase(':memory:');
  users.initUsers(db);
  assert.throws(() => users.createUser(db, { username: 'shorty', role: 'viewer', password: 'short' }), /at least 12/);
  assert.throws(() => users.createUser(db, { username: 'longy', role: 'viewer', password: 'x'.repeat(300) }), /at most 256/);
  users.createUser(db, { username: 'fine', role: 'viewer', password: 'x'.repeat(12) });
  assert.equal(users.authenticate(db, 'fine', 'x'.repeat(12)).username, 'fine');
});

test('sign-in with non-text input fails cleanly', () => {
  const db = openDatabase(':memory:');
  users.initUsers(db);
  users.createUser(db, { username: 'someone', role: 'admin', password: 'correct horse battery' });
  assert.equal(users.authenticate(db, { $ne: null }, 'correct horse battery'), null);
  assert.equal(users.authenticate(db, 'someone', ['not', 'text']), null);
  assert.equal(users.authenticate(db, 'someone', 'x'.repeat(5000)), null);
});

test('stored passwords are never kept in plain text', () => {
  const db = openDatabase(':memory:');
  users.initUsers(db);
  users.createUser(db, { username: 'hashed', role: 'viewer', password: 'correct horse battery' });
  const { password_hash } = db.prepare("SELECT password_hash FROM users WHERE username = 'hashed'").get();
  assert.ok(password_hash.startsWith('scrypt$'));
  assert.equal(password_hash.includes('correct horse'), false);
});
