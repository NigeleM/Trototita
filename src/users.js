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

function initUsers(db) {
  db.exec(USERS_SCHEMA);
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
  return verifyPassword(secret, row.password_hash) ? { username: row.username, role: row.role } : null;
}

// In-memory sessions. A server restart signs everyone out, which is acceptable at this scale.
class Sessions {
  constructor(now = () => Date.now()) {
    this.now = now;
    this.map = new Map();
  }

  create(user) {
    const token = crypto.randomBytes(32).toString('base64url');
    if (this.map.size >= MAX_TRACKED) this.prune();
    this.map.set(token, { ...user, expires: this.now() + SESSION_MS });
    return token;
  }

  prune() {
    const now = this.now();
    for (const [token, s] of this.map) if (s.expires < now) this.map.delete(token);
  }

  get(token) {
    const s = this.map.get(token);
    if (!s) return null;
    if (s.expires < this.now()) { this.map.delete(token); return null; }
    return s;
  }

  revoke(token) {
    this.map.delete(token);
  }
}

// Failed sign-ins per username; blocks further attempts for 15 minutes after 5 failures.
class LoginThrottle {
  constructor(now = () => Date.now()) {
    this.now = now;
    this.failures = new Map();
  }

  blocked(username) {
    const f = this.failures.get(username);
    if (!f) return false;
    if (this.now() - f.first > 15 * 60 * 1000) { this.failures.delete(username); return false; }
    return f.count >= 5;
  }

  fail(username) {
    if (this.failures.size >= MAX_TRACKED) this.failures.clear(); // bound memory under a flood of unknown names
    const f = this.failures.get(username);
    if (!f || this.now() - f.first > 15 * 60 * 1000) {
      this.failures.set(username, { count: 1, first: this.now() });
    } else {
      f.count += 1;
    }
  }

  succeed(username) {
    this.failures.delete(username);
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
  Sessions,
  LoginThrottle,
  logAudit,
  listAudit,
};
