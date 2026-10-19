// CSV output helpers: quote values that need it, and neutralise spreadsheet formulas.
// Excel and similar programs run a text cell that starts with = + - @ as a formula (CSV injection),
// so such text is prefixed with an apostrophe. Real numbers are left alone.
const FORMULA_START = /^[=+\-@\t\r]/;

function csvEscape(value) {
  if (value == null) return '';
  let s = String(value);
  if (typeof value !== 'number' && FORMULA_START.test(s)) s = `'${s}`;
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

module.exports = { csvEscape };
