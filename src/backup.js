// Backups of the database file. A backup is a consistent copy made with VACUUM INTO, so it is safe while the
// app is running. Restore replaces the live file, so the caller must close the database first.
const fs = require('node:fs');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');

const PREFIX = 'vulnmgt-backup-';
const KEEP_DEFAULT = 14;

function stamp(d = new Date()) {
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getUTCFullYear()}${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}-${p(d.getUTCHours())}${p(d.getUTCMinutes())}${p(d.getUTCSeconds())}`;
}

function listBackups(dir) {
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir)
    .filter((f) => f.startsWith(PREFIX) && f.endsWith('.db'))
    .map((f) => {
      const full = path.join(dir, f);
      const st = fs.statSync(full);
      return { file: full, name: f, bytes: st.size, created: st.mtime.toISOString() };
    })
    .sort((a, b) => (a.name < b.name ? 1 : -1));
}

// Removes all but the newest `keep` backups.
function prune(dir, keep) {
  const stale = listBackups(dir).slice(keep);
  for (const b of stale) fs.rmSync(b.file, { force: true });
  return stale.length;
}

// Confirms a backup file opens and passes SQLite's integrity check.
function verifyBackup(file) {
  const db = new DatabaseSync(file);
  try {
    return db.prepare('PRAGMA quick_check').get().quick_check === 'ok';
  } finally {
    db.close();
  }
}

function createBackup(db, dir, { keep = KEEP_DEFAULT, now = new Date() } = {}) {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const file = path.join(dir, `${PREFIX}${stamp(now)}.db`);
  if (fs.existsSync(file)) throw new Error('A backup for this second already exists. Try again in a moment.');
  db.exec(`VACUUM INTO '${file.replace(/'/g, "''")}'`);
  if (!verifyBackup(file)) {
    fs.rmSync(file, { force: true });
    throw new Error('The new backup failed its integrity check and was discarded');
  }
  prune(dir, keep);
  return { file, bytes: fs.statSync(file).size };
}

// Replaces the live database with a backup. Keeps a copy of the current file first.
// The caller must close the live database before calling this, and reopen it afterwards.
function restoreBackup(liveFile, backupFile, { now = new Date() } = {}) {
  if (!verifyBackup(backupFile)) throw new Error('That backup failed its integrity check and was not restored');
  const safety = `${liveFile}.before-restore-${stamp(now)}`;
  if (fs.existsSync(liveFile)) fs.copyFileSync(liveFile, safety);
  for (const suffix of ['-wal', '-shm']) fs.rmSync(`${liveFile}${suffix}`, { force: true });
  fs.copyFileSync(backupFile, liveFile);
  return { restoredFrom: backupFile, safetyCopy: safety };
}

module.exports = { createBackup, listBackups, prune, verifyBackup, restoreBackup, PREFIX, KEEP_DEFAULT };
