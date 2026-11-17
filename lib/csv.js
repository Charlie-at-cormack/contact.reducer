// Minimal RFC 4180 CSV parser with delimiter sniffing (IONOS exports use ";").

export function detectDelimiter(text) {
  const first = (text.replace(/^﻿/, '').split(/\r?\n/, 1)[0]) || '';
  let best = ',', bestN = 0;
  for (const c of [';', ',', '\t', '|']) {
    let n = 0, q = false;
    for (const ch of first) {
      if (ch === '"') q = !q;
      else if (ch === c && !q) n++;
    }
    if (n > bestN) { bestN = n; best = c; }
  }
  return best;
}

export function parseCsv(text, delim) {
  text = String(text || '').replace(/^﻿/, '');
  delim = delim || detectDelimiter(text);
  const rows = [];
  let row = [], field = '', q = false, atStart = true;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (q) {
      if (ch === '"') {
        if (text[i + 1] === '"') { field += '"'; i++; }
        else q = false;
      } else field += ch;
      continue;
    }
    if (ch === '"' && atStart) { q = true; atStart = false; continue; }
    if (ch === delim) { row.push(field); field = ''; atStart = true; continue; }
    if (ch === '\r') continue;
    if (ch === '\n') { row.push(field); rows.push(row); row = []; field = ''; atStart = true; continue; }
    field += ch; atStart = false;
  }
  if (field !== '' || row.length) { row.push(field); rows.push(row); }
  const nonEmpty = rows.filter(r => r.some(c => String(c).trim() !== ''));
  const headers = (nonEmpty.shift() || []).map(h => String(h).trim());
  return { delimiter: delim, headers, rows: nonEmpty };
}
