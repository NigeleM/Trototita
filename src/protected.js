// Tables the grid, the importers and the team clients may never read or change through the generic
// data channels. Accounts, sessions and the audit log are managed only by src/users.js.
const PROTECTED_TABLES = new Set(['users', 'audit_log', 'sessions', 'column_defs']);

function isProtectedTable(name) {
  const n = String(name || '').toLowerCase();
  return PROTECTED_TABLES.has(n) || n.startsWith('sqlite_');
}

function assertUserTable(name) {
  if (isProtectedTable(name)) throw new Error(`The table "${name}" is managed by the app and cannot be used here`);
  return name;
}

module.exports = { PROTECTED_TABLES, isProtectedTable, assertUserTable };
