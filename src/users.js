// Team accounts for the central server: scrypt password hashes, three roles, sessions and an audit log.
// Local (single-user) mode does not use this module.
const crypto = require('node:crypto');

const ROLES = ['viewer', 'editor', 'admin'];
const USERNAME = /^[a-zA-Z0-9._-]{2,40}$/;
const MIN_PASSWORD = 12;
const MAX_PASSWORD = 256; // long enough for passphrases; caps the cost of hashing one request
const MAX_TRACKED = 10000; // bounds the session and failed-login maps
const SCRYPT = { N: 16384, r: 8, p: 1 };
const SESSION_MS = 8 * 60 * 60 * 1000;
const SESSION_IDLE_MS = 60 * 60 * 1000;

const USERS_SCHEMA = `
  CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE,
    role          TEXT NOT NULL CHECK (role IN ('viewer', 'editor', 'admin')),
    password_hash TEXT NOT NULL,
    disabled      INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS audit_log (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    at       TEXT NOT NULL,
    username TEXT,
    channel  TEXT,
    outcome  TEXT NOT NULL
  );
`;

// The audit log is append-only: entries can be added and read, never changed or removed.
const AUDIT_TRIGGERS = `
  CREATE TRIGGER IF NOT EXISTS audit_log_no_update BEFORE UPDATE ON audit_log
  BEGIN SELECT RAISE(ABORT, 'The audit log is append-only'); END;
  CREATE TRIGGER IF NOT EXISTS audit_log_no_delete BEFORE DELETE ON audit_log
  BEGIN SELECT RAISE(ABORT, 'The audit log is append-only'); END;
`;

function initUsers(db) {
  db.exec(USERS_SCHEMA);
  db.exec(AUDIT_TRIGGERS);
}

// Changes whenever the password hash changes, so a session issued before a password change stops working.
function fingerprintOf(passwordHash) {
  return crypto.createHash('sha256').update(String(passwordHash)).digest('hex');
}

// The account as it is now, or null if it does not exist or is disabled. Sessions are checked against this.
function findActive(db, username) {
  const row = db.prepare('SELECT username, role, password_hash, disabled FROM users WHERE username = ?').get(String(username));
  if (!row || row.disabled) return null;
  return { username: row.username, role: row.role, fingerprint: fingerprintOf(row.password_hash) };
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const key = crypto.scryptSync(password, salt, 32, SCRYPT);
  return `scrypt$${SCRYPT.N}$${SCRYPT.r}$${SCRYPT.p}$${salt.toString('base64')}$${key.toString('base64')}`;
}

function verifyPassword(password, stored) {
  const [scheme, N, r, p, saltB64, keyB64] = String(stored).split('$');
  if (scheme !== 'scrypt') return false;
  const expected = Buffer.from(keyB64, 'base64');
  const key = crypto.scryptSync(password, Buffer.from(saltB64, 'base64'), expected.length, { N: Number(N), r: Number(r), p: Number(p) });
  return key.length === expected.length && crypto.timingSafeEqual(key, expected);
}

function checkPassword(password) {
  if (typeof password !== 'string' || password.length < MIN_PASSWORD) {
    throw new Error(`Password must be at least ${MIN_PASSWORD} characters`);
  }
  if (password.length > MAX_PASSWORD) throw new Error(`Password must be at most ${MAX_PASSWORD} characters`);
}

function validateNew(username, role, password) {
  if (!USERNAME.test(username || '')) throw new Error('Username must be 2 to 40 letters, digits, dots, dashes or underscores');
  if (!ROLES.includes(role)) throw new Error(`Role must be one of: ${ROLES.join(', ')}`);
  checkPassword(password);
}

function createUser(db, { username, role, password }) {
  validateNew(username, role, password);
  db.prepare('INSERT INTO users (username, role, password_hash, created_at) VALUES (?, ?, ?, ?)')
    .run(username, role, hashPassword(password), new Date().toISOString());
}

function listUsers(db) {
  return db.prepare('SELECT id, username, role, disabled, created_at FROM users ORDER BY username')
    .all().map((u) => ({ ...u, disabled: Boolean(u.disabled) }));
}

function setRole(db, username, role) {
  if (!ROLES.includes(role)) throw new Error(`Role must be one of: ${ROLES.join(', ')}`);
  db.prepare('UPDATE users SET role = ? WHERE username = ?').run(role, username);
}

function setDisabled(db, username, disabled) {
  db.prepare('UPDATE users SET disabled = ? WHERE username = ?').run(disabled ? 1 : 0, username);
}

function setPassword(db, username, password) {
  checkPassword(password);
  db.prepare('UPDATE users SET password_hash = ? WHERE username = ?').run(hashPassword(password), username);
}

// Returns { username, role } for valid, enabled credentials; otherwise null.
function authenticate(db, username, password) {
  const name = typeof username === 'string' ? username : '';
  const secret = typeof password === 'string' && password.length <= MAX_PASSWORD ? password : '';
  const row = name ? db.prepare('SELECT username, role, password_hash, disabled FROM users WHERE username = ?').get(name) : null;
  if (!row || row.disabled) {
    // Spend the same time as a real check so unknown users are not distinguishable by timing.
    hashPassword(secret || 'x'.repeat(MIN_PASSWORD));
    return null;
  }
  return verifyPassword(secret, row.password_hash)
    ? { username: row.username, role: row.role, fingerprint: fingerprintOf(row.password_hash) }
    : null;
}

// Sessions. A session stores who signed in and a fingerprint of the password hash it was issued under.
// The server re-reads the account on every request (findActive), so a disabled account, a changed role or a
// changed password ends the session at once. Sessions also end after 8 hours, or 1 hour without use.
class Sessions {
  constructor(now = () => Date.now()) {
    this.now = now;
    this.map = new Map();
  }

  create(user) {
    const token = crypto.randomBytes(32).toString('base64url');
    if (this.map.size >= MAX_TRACKED) this.prune();
    const t = this.now();
    this.map.set(token, {
      username: user.username,
      fingerprint: user.fingerprint,
      issued: t,
      lastSeen: t,
    });
    return token;
  }

  expired(s, t) {
    return t - s.issued > SESSION_MS || t - s.lastSeen > SESSION_IDLE_MS;
  }

  prune() {
    const t = this.now();
    for (const [token, s] of this.map) if (this.expired(s, t)) this.map.delete(token);
  }

  // Returns the stored session, or null. Each use refreshes the idle timer.
  get(token) {
    const s = this.map.get(token);
    if (!s) return null;
    const t = this.now();
    if (this.expired(s, t)) { this.map.delete(token); return null; }
    s.lastSeen = t;
    return s;
  }

  revoke(token) {
    this.map.delete(token);
  }
}

// Failed sign-ins are counted per key (the server uses "ip|username" and "ip" keys). Once `limit` failures
// land inside the window, the key is blocked until the window ends.
class LoginThrottle {
  constructor({ limit = 5, windowMs = 15 * 60 * 1000, now = () => Date.now() } = {}) {
    this.limit = limit;
    this.windowMs = windowMs;
    this.now = now;
    this.failures = new Map();
  }

  blocked(key) {
    const f = this.failures.get(key);
    if (!f) return false;
    if (this.now() - f.first > this.windowMs) { this.failures.delete(key); return false; }
    return f.count >= this.limit;
  }

  fail(key) {
    const t = this.now();
    let f = this.failures.get(key);
    if (!f || t - f.first > this.windowMs) {
      if (!f && this.failures.size >= MAX_TRACKED) this.failures.delete(this.failures.keys().next().value); // drop the oldest key
      f = { count: 0, first: t };
      this.failures.set(key, f);
    }
    f.count += 1;
  }

  succeed(key) {
    this.failures.delete(key);
  }
}

function logAudit(db, username, channel, outcome) {
  db.prepare('INSERT INTO audit_log (at, username, channel, outcome) VALUES (?, ?, ?, ?)')
    .run(new Date().toISOString(), username || null, channel || null, outcome);
}

function listAudit(db, limit = 200) {
  return db.prepare('SELECT * FROM audit_log ORDER BY id DESC LIMIT ?').all(limit);
}

module.exports = {
  ROLES,
  initUsers,
  hashPassword,
  verifyPassword,
  createUser,
  listUsers,
  setRole,
  setDisabled,
  setPassword,
  authenticate,
  findActive,
  fingerprintOf,
  Sessions,
  LoginThrottle,
  logAudit,
  listAudit,
};
