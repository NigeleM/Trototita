// Electron main process: file dialogs, notifications, settings and the data connection.
// Every data operation goes through call(): it runs against the local database in local mode, or against
// the team server in team mode. The renderer never sees the difference.
const path = require('node:path');
const fs = require('node:fs');
const { app, BrowserWindow, ipcMain, dialog, Notification, session: electronSession } = require('electron');
const { openDatabase, seedIfEmpty } = require('./src/db');
const { createHandlers, rowsToCsv } = require('./src/handlers');
const { recomputeAll } = require('./src/rules');
const workflow = require('./src/workflow');
const remote = require('./src/remote');

const ALERT_CHECK_MS = 30 * 60 * 1000;
const today = () => new Date().toISOString().slice(0, 10);

let database;
let handlers;
let mainWindow;
let alertTimer;
let dailyTimer;
let session = null; // team server sign-in, held in memory only
const notifiedKeys = new Set(); // alerts already shown as desktop notifications this session

const settingsFile = () => path.join(app.getPath('userData'), 'settings.json');
function readSettings() {
  try { return JSON.parse(fs.readFileSync(settingsFile(), 'utf8')); } catch { return {}; }
}
const inTeamMode = () => readSettings().mode === 'team';

// Single entry point for data operations.
async function call(channel, args) {
  if (inTeamMode()) return remote.call(session, channel, args);
  if (!handlers[channel]) throw new Error('This action is only available in team mode');
  return handlers[channel](args);
}

// Some channels take their parameters from settings rather than from the renderer.
function withSettingsDefaults(channel, args) {
  if (channel === 'alerts:list') return { leadDays: readSettings().leadDays ?? 7 };
  return args;
}

const DATA_CHANNELS = [
  'db:tables', 'db:columns', 'db:query', 'db:updateCell', 'db:insertRow', 'db:deleteRows', 'db:sql', 'db:sqlLoaded',
  'columns:defs', 'columns:add', 'columns:save', 'columns:delete',
  'charts:aggregate', 'dashboard:stats', 'trend:snapshots',
  'rules:list', 'rules:save', 'rules:delete',
  'finding:get', 'finding:comment', 'finding:deleteComment',
  'policies:list', 'policies:save',
  'poam:templates', 'poam:fields', 'poam:list', 'poam:get', 'poam:save', 'poam:delete', 'poam:exportCsv',
  'milestone:save', 'milestone:delete',
  'alerts:list', 'alerts:dismiss',
  'cleaning:preview', 'cleaning:dedupe', 'cleaning:stale',
  'import:api', 'import:presets',
  'intel:refresh', 'intel:status', 'metrics:remediation',
  'assets:list', 'assets:save', 'assets:delete',
  'views:list', 'views:save', 'views:delete',
  'attachments:list', 'attachments:get', 'attachments:add', 'attachments:delete',
  'backup:create', 'backup:list',
  'users:list', 'users:create', 'users:setRole', 'users:setDisabled', 'users:setPassword', 'audit:list',
];

// Desktop-only: the local database file, and the backup folder beside it.
const liveDbFile = () => path.join(app.getPath('userData'), 'vulnmgt.db');
const backupFolder = () => path.join(app.getPath('userData'), 'backups');

// Replaces the open database with a backup. Local mode only: a team client does not own the database.
function restoreLocalBackup(name) {
  if (inTeamMode()) throw new Error('Restore is done on the team server, not from a desktop client');
  const { restoreBackup } = require('./src/backup');
  const source = path.join(backupFolder(), path.basename(name));
  database.close();
  const result = restoreBackup(liveDbFile(), source);
  database = openDatabase(liveDbFile());
  handlers = createHandlers(database, { backupDir: backupFolder() });
  recomputeAll(database);
  return result;
}

const IMPORT_FORMATS = { '.csv': 'csv', '.json': 'json', '.xlsx': 'xlsx', '.xls': 'xlsx' };

// Reads a chosen file and sends it through the import channel, which works the same locally and remotely.
async function importFile(filePath, options) {
  const format = IMPORT_FORMATS[path.extname(filePath).toLowerCase()];
  if (!format) throw new Error(`Unsupported file type. Use .csv, .json, .xlsx or .xls`);
  const buffer = fs.readFileSync(filePath);
  const content = format === 'xlsx' ? buffer.toString('base64') : buffer.toString('utf8');
  const opts = { source: options.source || path.basename(filePath), ...options };
  return call('import:content', { format, content, options: opts });
}

async function checkAlerts() {
  const settings = readSettings();
  if (inTeamMode()) {
    if (!session) return; // the team server records snapshots itself
  } else {
    workflow.recordSnapshot(database, today());
  }
  if (settings.alertsEnabled === false) return;

  let alerts;
  try {
    alerts = await call('alerts:list', withSettingsDefaults('alerts:list'));
  } catch (_) {
    return; // offline or signed out: try again on the next check
  }
  const fresh = alerts.filter((a) => !notifiedKeys.has(a.key));
  fresh.forEach((a) => notifiedKeys.add(a.key));
  if (fresh.length === 0 || settings.desktopNotifications === false || !Notification.isSupported()) return;

  const counts = {};
  for (const a of fresh) counts[a.kind] = (counts[a.kind] || 0) + 1;
  const KIND = { overdue: 'overdue', upcoming: 'due soon', noncompliant: 'non-compliant', milestone: 'milestones overdue', review: 'risk reviews due' };
  const summary = Object.entries(counts).map(([k, n]) => `${n} ${KIND[k]}`).join(', ');
  const note = new Notification({ title: 'Trototita alerts', body: summary });
  note.on('click', () => {
    if (mainWindow) { mainWindow.show(); mainWindow.focus(); }
  });
  note.show();
}

function registerIpc() {
  for (const channel of DATA_CHANNELS) {
    ipcMain.handle(channel, (_e, args) => call(channel, withSettingsDefaults(channel, args)));
  }

  // File dialogs run here, on the user's machine, then hand the data to call().
  ipcMain.handle('db:exportCsv', async (_e, { table, filters }) => {
    const { filePath, canceled } = await dialog.showSaveDialog({
      defaultPath: `${table}.csv`,
      filters: [{ name: 'CSV', extensions: ['csv'] }],
    });
    if (canceled || !filePath) return null;
    const { columns, rows } = await call('db:query', { table, filters, limit: 1e9 });
    fs.writeFileSync(filePath, rowsToCsv(columns, rows), 'utf8');
    return { filePath, count: rows.length };
  });

  // Any rows the renderer is showing (for example SQL results), saved as CSV with the same escaping as the grid export.
  ipcMain.handle('export:rows', async (_e, { defaultName, columns, rows }) => {
    const { filePath, canceled } = await dialog.showSaveDialog({
      defaultPath: defaultName || 'export.csv',
      filters: [{ name: 'CSV', extensions: ['csv'] }],
    });
    if (canceled || !filePath) return null;
    fs.writeFileSync(filePath, rowsToCsv(columns, rows), 'utf8');
    return { filePath, count: rows.length };
  });

  ipcMain.handle('poam:export', async (_e, { kind, template }) => {
    const { filePath, canceled } = await dialog.showSaveDialog({
      defaultPath: `${kind}-${template}.csv`,
      filters: [{ name: 'CSV', extensions: ['csv'] }],
    });
    if (canceled || !filePath) return null;
    fs.writeFileSync(filePath, await call('poam:exportCsv', { kind, template }), 'utf8');
    return { filePath };
  });

  // Attachments: pick a file on this computer and send its bytes through the normal attachment channel.
  ipcMain.handle('attachments:pick', async () => {
    const { filePaths, canceled } = await dialog.showOpenDialog({ properties: ['openFile'] });
    if (canceled || !filePaths.length) return null;
    const stat = fs.statSync(filePaths[0]);
    if (stat.size > 10 * 1024 * 1024) throw new Error('Attachments are limited to 10 MB');
    return {
      filename: path.basename(filePaths[0]),
      mime: 'application/octet-stream',
      content: fs.readFileSync(filePaths[0]).toString('base64'),
    };
  });
  ipcMain.handle('attachments:save', async (_e, id) => {
    const file = await call('attachments:get', id);
    const { filePath, canceled } = await dialog.showSaveDialog({ defaultPath: file.filename });
    if (canceled || !filePath) return null;
    fs.writeFileSync(filePath, Buffer.from(file.content, 'base64'));
    return { filePath };
  });
  ipcMain.handle('poam:exportXlsx', async (_e, { kind, template }) => {
    const base64 = await call('poam:exportXlsx', { kind, template });
    const { filePath, canceled } = await dialog.showSaveDialog({
      defaultPath: `${kind}-${template}.xlsx`,
      filters: [{ name: 'Excel workbook', extensions: ['xlsx'] }],
    });
    if (canceled || !filePath) return null;
    fs.writeFileSync(filePath, Buffer.from(base64, 'base64'));
    return { filePath };
  });
  ipcMain.handle('backup:restore', (_e, name) => restoreLocalBackup(name));

  ipcMain.handle('import:file', async (_e, options = {}) => {
    const { filePaths, canceled } = await dialog.showOpenDialog({
      properties: ['openFile'],
      filters: [{ name: 'Data files', extensions: ['csv', 'json', 'xlsx', 'xls'] }],
    });
    if (canceled || !filePaths.length) return null;
    return { file: path.basename(filePaths[0]), ...(await importFile(filePaths[0], options)) };
  });

  // App settings are per user and always local.
  ipcMain.handle('settings:get', () => readSettings());
  ipcMain.handle('settings:save', async (_e, settings) => {
    fs.writeFileSync(settingsFile(), JSON.stringify(settings, null, 2), 'utf8');
    checkAlerts();
    return settings;
  });

  // Team sign-in
  ipcMain.handle('auth:status', () => {
    const s = readSettings();
    return {
      mode: s.mode === 'team' ? 'team' : 'local',
      serverUrl: s.serverUrl || '',
      caFile: s.caFile || '',
      signedIn: Boolean(session),
      username: session?.username || null,
      role: session?.role || null,
    };
  });
  ipcMain.handle('auth:login', async (_e, { username, password }) => {
    const s = readSettings();
    if (!s.serverUrl) throw new Error('Enter the team server address first');
    session = await remote.login(s.serverUrl, { username, password }, s.caFile || undefined);
    checkAlerts();
    return { username: session.username, role: session.role };
  });
  ipcMain.handle('auth:logout', async () => {
    await remote.logout(session);
    session = null;
    return true;
  });
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1280,
    height: 820,
    minWidth: 960,
    minHeight: 600,
    title: 'Trototita',
    backgroundColor: '#0f1419',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      webSecurity: true,
    },
  });
  // The window only ever shows the app's own page: no navigation away, no pop-ups.
  mainWindow.webContents.on('will-navigate', (event) => event.preventDefault());
  mainWindow.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  mainWindow.on('closed', () => { mainWindow = null; });
  mainWindow.loadFile(path.join(__dirname, 'renderer', 'index.html'));
}

app.whenReady().then(() => {
  // The app asks for no browser permissions (camera, location, notifications in the page, and so on).
  electronSession.defaultSession.setPermissionRequestHandler((_wc, _permission, callback) => callback(false));
  electronSession.defaultSession.setPermissionCheckHandler(() => false);

  database = openDatabase(path.join(app.getPath('userData'), 'vulnmgt.db'));
  seedIfEmpty(database);
  recomputeAll(database);
  handlers = createHandlers(database, { backupDir: backupFolder() });
  registerIpc();
  createWindow();
  checkAlerts();
  alertTimer = setInterval(checkAlerts, ALERT_CHECK_MS);
  // Daily, on this computer's own database only: a backup, then a threat-feed refresh.
  dailyTimer = setInterval(dailyLocalJobs, 24 * 60 * 60 * 1000);
  dailyLocalJobs();
  app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

async function dailyLocalJobs() {
  if (inTeamMode()) return; // the team server does its own backups and feed refreshes
  try { handlers['backup:create'](); } catch (err) { console.error('Backup failed:', err.message); }
  try {
    await handlers['intel:refresh']();
  } catch (err) { console.error('Threat feed refresh failed:', err.message); }
}

app.on('before-quit', () => {
  clearInterval(alertTimer);
  clearInterval(dailyTimer);
  if (database) database.close();
});
