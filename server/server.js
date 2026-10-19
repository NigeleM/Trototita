// Team server: one machine owns the database and serves the same operations as the desktop app over HTTPS.
// Clients sign in, then send { channel, args } to /api/call. Every call is checked against the caller's
// role and written to the audit log.
//
// Run:    node server/server.js serve --cert server/cert.pem --key server/key.pem --port 8443
// Users:  printf '%s' 'long-passphrase' | node server/server.js add-user dana editor
const fs = require('node:fs');
const https = require('node:https');
const path = require('node:path');
const { openDatabase } = require('../src/db');
const { createHandlers, allowed } = require('../src/handlers');
const { recordSnapshot } = require('../src/workflow');
const { recomputeAll } = require('../src/rules');
const { refreshIntel } = require('../src/intel');
const { createBackup, listBackups, restoreBackup } = require('../src/backup');
const users = require('../src/users');

const MAX_BODY = 30 * 1024 * 1024; // Excel uploads arrive base64 encoded
const SNAPSHOT_MS = 30 * 60 * 1000;
const VERSION = require('../package.json').version;

function send(res, status, body) {
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
  });
  res.end(JSON.stringify(body));
}

function readJson(req, limit = MAX_BODY) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > limit) { reject(Object.assign(new Error('Request too large'), { status: 413 })); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      try {
        const parsed = chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {};
        resolve(parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : {});
      }
      catch { reject(Object.assign(new Error('Body must be JSON'), { status: 400 })); }
    });
    req.on('error', reject);
  });
}

function bearer(req) {
  const h = req.headers.authorization || '';
  return h.startsWith('Bearer ') ? h.slice(7) : null;
}

// Builds the HTTPS server. Passing an open database and TLS material keeps this testable.
// Admin-only channels: accounts and the audit log. They are not part of the desktop data handlers.
function adminChannels(database) {
  const enabledAdmins = () => database.prepare("SELECT COUNT(*) AS n FROM users WHERE role = 'admin' AND disabled = 0").get().n;
  const guardLastAdmin = (username) => {
    const target = database.prepare('SELECT role, disabled FROM users WHERE username = ?').get(username);
    if (target && target.role === 'admin' && !target.disabled && enabledAdmins() <= 1) {
      throw new Error('At least one enabled admin must remain');
    }
  };
  return {
    'users:list': () => users.listUsers(database),
    'users:create': ({ username, role, password }) => {
      users.createUser(database, { username, role, password });
      return users.listUsers(database);
    },
    'users:setRole': ({ username, role }) => {
      if (role !== 'admin') guardLastAdmin(username);
      users.setRole(database, username, role);
      return users.listUsers(database);
    },
    'users:setDisabled': ({ username, disabled }) => {
      if (disabled) guardLastAdmin(username);
      users.setDisabled(database, username, Boolean(disabled));
      return users.listUsers(database);
    },
    'users:setPassword': ({ username, password }) => {
      users.setPassword(database, username, password);
      return true;
    },
    'audit:list': (limit) => users.listAudit(database, Math.min(Number(limit) || 100, 1000)),
  };
}

// allowedApiHosts: hosts the API importer may pull from. Empty by default, so nothing is pulled until you approve hosts.
// backupDir: where daily backups are written. Defaults to a "backups" folder next to the database file.
function createServer({ database, cert, key, allowedApiHosts = [], backupDir = null, sessions = new users.Sessions(), throttle = new users.LoginThrottle() }) {
  users.initUsers(database);
  const handlers = createHandlers(database, { allowedApiHosts, backupDir });
  const admin = adminChannels(database);

  const handle = async (req, res) => {
    const url = new URL(req.url, 'https://localhost');

    if (req.method === 'GET' && url.pathname === '/api/health') {
      return send(res, 200, { ok: true, version: VERSION });
    }

    if (req.method === 'POST' && url.pathname === '/api/login') {
      const body = await readJson(req, 16 * 1024);
      const username = typeof body.username === 'string' ? body.username.slice(0, 64) : '';
      const password = typeof body.password === 'string' ? body.password : '';
      if (throttle.blocked(username)) {
        users.logAudit(database, username, 'login', 'throttled');
        return send(res, 429, { ok: false, error: 'Too many failed attempts. Try again in 15 minutes.' });
      }
      const user = users.authenticate(database, username, password);
      if (!user) {
        throttle.fail(username);
        users.logAudit(database, username, 'login', 'failed');
        return send(res, 401, { ok: false, error: 'Invalid username or password' });
      }
      throttle.succeed(username);
      users.logAudit(database, user.username, 'login', 'ok');
      return send(res, 200, { ok: true, token: sessions.create(user), username: user.username, role: user.role });
    }

    const token = bearer(req);
    const session = token ? sessions.get(token) : null;
    if (!session) return send(res, 401, { ok: false, error: 'Sign in required' });

    if (req.method === 'POST' && url.pathname === '/api/logout') {
      sessions.revoke(token);
      return send(res, 200, { ok: true });
    }

    if (req.method === 'POST' && url.pathname === '/api/call') {
      const { channel, args } = await readJson(req);
      const isAdminChannel = Object.prototype.hasOwnProperty.call(admin, channel);
      const handler = isAdminChannel ? admin[channel] : (Object.prototype.hasOwnProperty.call(handlers, channel) ? handlers[channel] : null);
      if (!handler) return send(res, 404, { ok: false, error: `Unknown channel: ${channel}` });
      const permitted = isAdminChannel ? session.role === 'admin' : allowed(session.role, channel);
      if (!permitted) {
        users.logAudit(database, session.username, channel, 'denied');
        return send(res, 403, { ok: false, error: `Your role (${session.role}) cannot use this action` });
      }
      try {
        const result = await handler(args);
        users.logAudit(database, session.username, channel, 'ok');
        return send(res, 200, { ok: true, result });
      } catch (err) {
        users.logAudit(database, session.username, channel, 'error');
        return send(res, 400, { ok: false, error: err.message });
      }
    }

    return send(res, 404, { ok: false, error: 'Not found' });
  };

  const server = https.createServer({ cert, key }, (req, res) => {
    handle(req, res).catch((err) => send(res, err.status || 500, { ok: false, error: err.message }));
  });
  // Limits on slow or stalled connections.
  server.headersTimeout = 20 * 1000;
  server.requestTimeout = 120 * 1000;
  server.keepAliveTimeout = 5 * 1000;
  server.maxHeadersCount = 100;

  // Daily-style snapshots for the trend chart, same cadence as the desktop app.
  const timer = setInterval(() => {
    const day = new Date().toISOString().slice(0, 10);
    recordSnapshot(database, day);
  }, SNAPSHOT_MS);
  timer.unref();
  recordSnapshot(database, new Date().toISOString().slice(0, 10));
  recomputeAll(database);

  // Once a day: a verified backup, and a refresh of the threat-intelligence feeds (needs outbound HTTPS).
  const daily = setInterval(async () => {
    if (backupDir) {
      try { createBackup(database, backupDir); } catch (err) { console.error('Backup failed:', err.message); }
    }
    try {
      await refreshIntel(database, { today: new Date().toISOString().slice(0, 10) });
    } catch (err) { console.error('Threat feed refresh failed:', err.message); }
  }, 24 * 60 * 60 * 1000);
  daily.unref();

  server.on('close', () => { clearInterval(timer); clearInterval(daily); });
  return server;
}

// ---------- Command line ----------

function argValue(args, name, fallback) {
  const i = args.indexOf(`--${name}`);
  return i >= 0 && args[i + 1] ? args[i + 1] : fallback;
}

function readPasswordFromStdin() {
  return new Promise((resolve) => {
    if (process.env.VULN_PASSWORD) return resolve(process.env.VULN_PASSWORD);
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (c) => { data += c; });
    process.stdin.on('end', () => resolve(data.replace(/\r?\n$/, '')));
    if (process.stdin.isTTY) {
      console.error('Pipe the password on stdin, or set VULN_PASSWORD. Typed input is not accepted here.');
      process.exit(1);
    }
  });
}

async function main(argv) {
  const [command, ...rest] = argv;
  const dbFile = argValue(rest, 'db', path.join(__dirname, 'team.db'));
  const database = openDatabase(dbFile);
  users.initUsers(database);

  if (command === 'serve') {
    const cert = fs.readFileSync(argValue(rest, 'cert', path.join(__dirname, 'cert.pem')));
    const key = fs.readFileSync(argValue(rest, 'key', path.join(__dirname, 'key.pem')));
    const port = Number(argValue(rest, 'port', 8443));
    const host = argValue(rest, 'host', '0.0.0.0');
    const allowedApiHosts = (process.env.VULN_API_HOSTS || '').split(',').map((h) => h.trim()).filter(Boolean);
    const backupDir = path.join(path.dirname(dbFile), 'backups');
    const server = createServer({ database, cert, key, allowedApiHosts, backupDir });
    server.listen(port, host, () => console.log(`Trototita team server listening on https://${host}:${port}`));
    const shutdown = () => { server.close(); database.close(); process.exit(0); };
    process.on('SIGINT', shutdown);
    process.on('SIGTERM', shutdown);
    return;
  }

  const positional = rest.filter((a, i) => !a.startsWith('--') && (i === 0 || !rest[i - 1].startsWith('--')));
  if (command === 'add-user') {
    const [username, role] = positional;
    users.createUser(database, { username, role, password: await readPasswordFromStdin() });
    console.log(`Added ${username} as ${role}`);
  } else if (command === 'set-role') {
    users.setRole(database, positional[0], positional[1]);
    console.log(`${positional[0]} is now ${positional[1]}`);
  } else if (command === 'disable' || command === 'enable') {
    users.setDisabled(database, positional[0], command === 'disable');
    console.log(`${positional[0]} ${command}d`);
  } else if (command === 'set-password') {
    users.setPassword(database, positional[0], await readPasswordFromStdin());
    console.log(`Password updated for ${positional[0]}`);
  } else if (command === 'list-users') {
    console.table(users.listUsers(database));
  } else if (command === 'audit') {
    console.table(users.listAudit(database, Number(positional[0]) || 50));
  } else if (command === 'backup') {
    const { file, bytes } = createBackup(database, path.join(path.dirname(dbFile), 'backups'));
    console.log(`Backup written: ${file} (${bytes} bytes)`);
  } else if (command === 'backups') {
    console.table(listBackups(path.join(path.dirname(dbFile), 'backups')).map(({ name, bytes, created }) => ({ name, bytes, created })));
  } else if (command === 'restore') {
    // Stop the server first. The current database is kept next to the restored one.
    const from = argValue(rest, 'from', null);
    if (!from) throw new Error('Give the backup file with --from <file>');
    database.close();
    const res = restoreBackup(dbFile, from);
    console.log(`Restored ${from}. The previous database was kept at ${res.safetyCopy}`);
    return;
  } else {
    console.log('Commands: serve | add-user <name> <role> | set-role <name> <role> | enable|disable <name> | set-password <name> | list-users | audit [n] | backup | backups | restore --from <file>');
  }
  database.close();
}

if (require.main === module) {
  main(process.argv.slice(2)).catch((err) => {
    console.error(err.message);
    process.exit(1);
  });
}

module.exports = { createServer };
