// Desktop client for the team server. Only HTTPS is allowed. A CA file can be given so a self-signed
// server certificate is trusted without turning off certificate checks.
const fs = require('node:fs');
const https = require('node:https');

const MAX_RESPONSE = 50 * 1024 * 1024;

function request(baseUrl, { method = 'GET', route, token, body, caFile }) {
  const url = new URL(route, baseUrl);
  if (url.protocol !== 'https:') return Promise.reject(new Error('The team server address must start with https://'));
  const payload = body === undefined ? null : JSON.stringify(body);
  const headers = { Accept: 'application/json' };
  if (payload) {
    headers['Content-Type'] = 'application/json';
    headers['Content-Length'] = Buffer.byteLength(payload);
  }
  if (token) headers.Authorization = `Bearer ${token}`;

  return new Promise((resolve, reject) => {
    const req = https.request({
      method,
      hostname: url.hostname,
      port: url.port || 443,
      path: url.pathname + url.search,
      headers,
      ca: caFile ? fs.readFileSync(caFile) : undefined,
      timeout: 60000,
    }, (res) => {
      const chunks = [];
      let size = 0;
      res.on('data', (c) => {
        size += c.length;
        if (size > MAX_RESPONSE) req.destroy(new Error('The team server sent too much data'));
        else chunks.push(c);
      });
      res.on('end', () => {
        if (size > MAX_RESPONSE) return;
        let json = {};
        try { json = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}'); } catch { /* keep {} */ }
        resolve({ status: res.statusCode, json });
      });
    });
    req.on('timeout', () => req.destroy(new Error('The team server did not respond in time')));
    req.on('error', (err) => reject(new Error(`Cannot reach the team server: ${err.message}`)));
    if (payload) req.write(payload);
    req.end();
  });
}

async function login(baseUrl, { username, password }, caFile) {
  const { status, json } = await request(baseUrl, { method: 'POST', route: '/api/login', body: { username, password }, caFile });
  if (status !== 200 || !json.ok) throw new Error(json.error || `Sign-in failed (HTTP ${status})`);
  return { baseUrl, caFile, token: json.token, username: json.username, role: json.role };
}

// Sends one operation to the server. Throws with the server's message on failure.
async function call(session, channel, args) {
  if (!session || !session.token) throw new Error('Sign in to the team server from Settings first');
  const { status, json } = await request(session.baseUrl, {
    method: 'POST', route: '/api/call', token: session.token, body: { channel, args }, caFile: session.caFile,
  });
  if (status === 401) throw new Error('Your team session has ended. Sign in again from Settings.');
  if (!json.ok) throw new Error(json.error || `Server error (HTTP ${status})`);
  return json.result;
}

async function logout(session) {
  if (!session || !session.token) return;
  await request(session.baseUrl, { method: 'POST', route: '/api/logout', token: session.token, caFile: session.caFile })
    .catch(() => {});
}

module.exports = { login, call, logout };
