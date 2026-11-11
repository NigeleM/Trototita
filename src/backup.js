// Backups of the database file. A backup is a consistent copy made with VACUUM INTO, so it is safe while the
// app is running. Backups are owner-only. When a key is given (VULN_BACKUP_KEY on the team server), each backup
// is also encrypted with AES-256-GCM. Restore replaces the live file, so the caller must close the database first.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');

const PREFIX = 'vulnmgt-backup-';
const PLAIN_EXT = '.db';
const ENCRYPTED_EXT = '.db.enc';
const MAGIC = Buffer.from('VMBK1\n'); // marks an encrypted backup: magic, 12-byte IV, 16-byte tag, ciphertext
const KEEP_DEFAULT = 14;

function stamp(d = new Date()) {
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getUTCFullYear()}${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}-${p(d.getUTCHours())}${p(d.getUTCMinutes())}${p(d.getUTCSeconds())}`;
}

// Backups hold the whole database (including account password hashes), so only the owner may read them.
function ownerOnly(file) {
  fs.chmodSync(file, 0o600);
}

// A 32-byte key, base64 encoded. Returns null when no key is configured.
function parseBackupKey(value) {
  if (!value || !String(value).trim()) return null;
  const key = Buffer.from(String(value).trim(), 'base64');
  if (key.length !== 32) throw new Error('VULN_BACKUP_KEY must be 32 random bytes, base64 encoded');
  return key;
}

function isEncrypted(file) {
  const fd = fs.openSync(file, 'r');
  try {
    const head = Buffer.alloc(MAGIC.length);
    fs.readSync(fd, head, 0, MAGIC.length, 0);
    return head.equals(MAGIC);
  } finally {
    fs.closeSync(fd);
  }
}

function encryptFile(src, dst, key) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const body = Buffer.concat([cipher.update(fs.readFileSync(src)), cipher.final()]);
  fs.writeFileSync(dst, Buffer.concat([MAGIC, iv, cipher.getAuthTag(), body]), { mode: 0o600 });
  ownerOnly(dst);
}

function decryptFile(src, dst, key) {
  if (!key) throw new Error('This backup is encrypted. Set VULN_BACKUP_KEY to the key it was written with.');
  const data = fs.readFileSync(src);
  const iv = data.subarray(MAGIC.length, MAGIC.length + 12);
  const tag = data.subarray(MAGIC.length + 12, MAGIC.length + 28);
  const body = data.subarray(MAGIC.length + 28);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  let plain;
  try {
    plain = Buffer.concat([decipher.update(body), decipher.final()]);
  } catch {
    throw new Error('The backup key does not match this backup');
  }
  fs.writeFileSync(dst, plain, { mode: 0o600 });
  ownerOnly(dst);
}

function listBackups(dir) {
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir)
    .filter((f) => f.startsWith(PREFIX) && (f.endsWith(PLAIN_EXT) || f.endsWith(ENCRYPTED_EXT)))
    .map((f) => {
      const full = path.join(dir, f);
      const st = fs.statSync(full);
      return { file: full, name: f, bytes: st.size, created: st.mtime.toISOString(), encrypted: f.endsWith(ENCRYPTED_EXT) };
    })
    .sort((a, b) => (a.name < b.name ? 1 : -1));
}

// Removes all but the newest `keep` backups.
function prune(dir, keep) {
  const stale = listBackups(dir).slice(keep);
  for (const b of stale) fs.rmSync(b.file, { force: true });
  return stale.length;
}

// Confirms an unencrypted database file opens and passes SQLite's integrity check.
function verifyBackup(file) {
  const db = new DatabaseSync(file);
  try {
    return db.prepare('PRAGMA quick_check').get().quick_check === 'ok';
  } finally {
    db.close();
  }
}

function createBackup(db, dir, { keep = KEEP_DEFAULT, now = new Date(), key = null } = {}) {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  fs.chmodSync(dir, 0o700);
  const base = `${PREFIX}${stamp(now)}`;
  const file = path.join(dir, base + (key ? ENCRYPTED_EXT : PLAIN_EXT));
  if (fs.existsSync(file)) throw new Error('A backup for this second already exists. Try again in a moment.');
  // The plain copy is a hidden temporary file: it is removed once the backup is written (encrypted or not).
  const plainTmp = path.join(dir, `.${base}.tmp`);
  fs.rmSync(plainTmp, { force: true });
  try {
    db.exec(`VACUUM INTO '${plainTmp.replace(/'/g, "''")}'`);
    ownerOnly(plainTmp);
    if (!verifyBackup(plainTmp)) throw new Error('The new backup failed its integrity check and was discarded');
    if (key) encryptFile(plainTmp, file, key);
    else fs.renameSync(plainTmp, file);
  } catch (err) {
    fs.rmSync(file, { force: true });
    throw err;
  } finally {
    fs.rmSync(plainTmp, { force: true });
  }
  prune(dir, keep);
  return { file, bytes: fs.statSync(file).size, encrypted: Boolean(key) };
}

// Replaces the live database with a backup. Keeps a copy of the current file first.
// The caller must close the live database before calling this, and reopen it afterwards.
function restoreBackup(liveFile, backupFile, { now = new Date(), key = null } = {}) {
  const tmp = path.join(path.dirname(liveFile), `.restore-${stamp(now)}-${process.pid}.tmp`);
  fs.rmSync(tmp, { force: true });
  let safety = null;
  try {
    let source = backupFile;
    if (isEncrypted(backupFile)) {
      decryptFile(backupFile, tmp, key);
      source = tmp;
    }
    if (!verifyBackup(source)) throw new Error('That backup failed its integrity check and was not restored');
    safety = `${liveFile}.before-restore-${stamp(now)}`;
    if (fs.existsSync(liveFile)) {
      fs.copyFileSync(liveFile, safety);
      ownerOnly(safety);
    }
    for (const suffix of ['-wal', '-shm']) fs.rmSync(`${liveFile}${suffix}`, { force: true });
    fs.copyFileSync(source, liveFile);
    ownerOnly(liveFile);
  } finally {
    fs.rmSync(tmp, { force: true });
  }
  return { restoredFrom: backupFile, safetyCopy: safety };
}

module.exports = { createBackup, listBackups, prune, verifyBackup, restoreBackup, parseBackupKey, isEncrypted, PREFIX, KEEP_DEFAULT };
