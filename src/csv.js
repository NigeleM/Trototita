// Minimal RFC 4180 CSV parser: quoted fields, embedded commas/newlines, escaped quotes, CRLF or LF.

function parseCsv(text) {
  const rows = [];
  let row = [];
  let field = '';
  let inQuotes = false;

  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (inQuotes) {
      if (ch === '"') {
        if (text[i + 1] === '"') { field += '"'; i++; }
        else inQuotes = false;
      } else {
        field += ch;
      }
    } else if (ch === '"') {
      inQuotes = true;
    } else if (ch === ',') {
      row.push(field); field = '';
    } else if (ch === '\n' || ch === '\r') {
      if (ch === '\r' && text[i + 1] === '\n') i++;
      row.push(field); field = '';
      rows.push(row); row = [];
    } else {
      field += ch;
    }
  }
  if (field !== '' || row.length) { row.push(field); rows.push(row); }

  // Drop fully blank lines.
  return rows.filter((r) => r.some((c) => c.trim() !== ''));
}

// "CVE ID", "cve-id" and "cve_id" all become "cve_id".
function normaliseHeader(header) {
  return header.trim().toLowerCase().replace(/[\s-]+/g, '_');
}

// Turns CSV text into objects keyed by normalised header.
function csvToObjects(text) {
  const [headerRow, ...dataRows] = parseCsv(text);
  if (!headerRow) return [];
  const headers = headerRow.map(normaliseHeader);
  return dataRows.map((cells) => Object.fromEntries(headers.map((h, i) => [h, (cells[i] ?? '').trim()])));
}

module.exports = { parseCsv, normaliseHeader, csvToObjects };
