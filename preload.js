// Preload script: the only bridge between the renderer page and the main process.
const { contextBridge, ipcRenderer } = require('electron');

const invoke = (channel) => (...args) => ipcRenderer.invoke(channel, ...args);

contextBridge.exposeInMainWorld('api', {
  // database and grid
  tables: invoke('db:tables'),
  columns: invoke('db:columns'),
  query: invoke('db:query'),
  updateCell: invoke('db:updateCell'),
  insertRow: invoke('db:insertRow'),
  deleteRows: invoke('db:deleteRows'),
  sql: invoke('db:sql'),
  sqlLoaded: invoke('db:sqlLoaded'),
  exportCsv: invoke('db:exportCsv'),
  exportRows: invoke('export:rows'),

  // custom columns
  columnDefs: invoke('columns:defs'),
  addColumn: invoke('columns:add'),
  saveColumnPrefs: invoke('columns:save'),
  deleteColumn: invoke('columns:delete'),

  // dashboard, charts, trends
  dashboardStats: invoke('dashboard:stats'),
  aggregate: invoke('charts:aggregate'),
  snapshots: invoke('trend:snapshots'),

  // rules and compliance
  listRules: invoke('rules:list'),
  saveRule: invoke('rules:save'),
  deleteRule: invoke('rules:delete'),
  listPolicies: invoke('policies:list'),
  savePolicies: invoke('policies:save'),

  // findings: details, comments, history
  finding: invoke('finding:get'),
  addComment: invoke('finding:comment'),
  deleteComment: invoke('finding:deleteComment'),

  // POA&M and RBD
  poamTemplates: invoke('poam:templates'),
  poamFields: invoke('poam:fields'),
  poamList: invoke('poam:list'),
  poamGet: invoke('poam:get'),
  poamSave: invoke('poam:save'),
  poamDelete: invoke('poam:delete'),
  milestoneSave: invoke('milestone:save'),
  milestoneDelete: invoke('milestone:delete'),
  poamExport: invoke('poam:export'),

  // alerts
  alerts: invoke('alerts:list'),
  dismissAlert: invoke('alerts:dismiss'),

  // cleaning
  cleaningPreview: invoke('cleaning:preview'),
  dedupe: invoke('cleaning:dedupe'),
  removeStale: invoke('cleaning:stale'),

  // imports
  importFile: invoke('import:file'),
  importApi: invoke('import:api'),

  // imports and threat intelligence
  importPresets: invoke('import:presets'),
  intelRefresh: invoke('intel:refresh'),
  intelStatus: invoke('intel:status'),
  remediationMetrics: invoke('metrics:remediation'),

  // assets (owners and criticality)
  assetsList: invoke('assets:list'),
  assetsSave: invoke('assets:save'),
  assetsDelete: invoke('assets:delete'),

  // saved grid views
  viewsList: invoke('views:list'),
  viewsSave: invoke('views:save'),
  viewsDelete: invoke('views:delete'),

  // attachments and exports
  attachmentsList: invoke('attachments:list'),
  attachmentsPick: invoke('attachments:pick'),
  attachmentsAdd: invoke('attachments:add'),
  attachmentsSave: invoke('attachments:save'),
  attachmentsDelete: invoke('attachments:delete'),
  poamExportXlsx: invoke('poam:exportXlsx'),

  // backups (desktop) and team administration
  backupCreate: invoke('backup:create'),
  backupList: invoke('backup:list'),
  backupRestore: invoke('backup:restore'),
  usersList: invoke('users:list'),
  usersCreate: invoke('users:create'),
  usersSetRole: invoke('users:setRole'),
  usersSetDisabled: invoke('users:setDisabled'),
  usersSetPassword: invoke('users:setPassword'),
  auditList: invoke('audit:list'),

  // settings and team sign-in
  getSettings: invoke('settings:get'),
  saveSettings: invoke('settings:save'),
  authStatus: invoke('auth:status'),
  authLogin: invoke('auth:login'),
  authLogout: invoke('auth:logout'),
});
