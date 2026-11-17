// CSV import: column mapping, record normalisation and merging that keeps tracking data.
import { parseCsv } from './csv.js';
import { isIonosMx } from './net.js';

export const STATUSES = ['unchecked', 'not_started', 'ready', 'in_progress', 'moved', 'verified', 'na'];

// Columns never stored (transfer auth codes and personal contact data).
export const SENSITIVE = /auth\s*code|authcode|password|passwd|secret|^(reg|admin|tech|owner|billing)c$|contact/i;

export const DOMAIN_FIELDS = [
  { k: 'domain', l: 'Domain name', req: true, match: [/^domain ?name$/i, /^domain$/i, /^(fqdn|host ?name)$/i, /^idn$/i] },
  { k: 'contract', l: 'Contract number', important: true, match: [/^contract ?(number|no|id)?$/i, /contract/i] },
  { k: 'type', l: 'Domain type', match: [/^domain ?type$/i, /^type$/i] },
  { k: 'destination', l: 'Destination / usage', important: true, match: [/^destination$/i, /^usage$/i, /connected ?to/i] },
  { k: 'target', l: 'Target (webspace path / redirect / IPs)', important: true, match: [/^target$/i, /webspace|path/i] },
  { k: 'status', l: 'Status', match: [/^status$/i] },
  { k: 'statusGroup', l: 'Status group', match: [/^status ?group$/i] },
  { k: 'expiration', l: 'Expiry date', match: [/expir/i, /renewal/i] },
  { k: 'ipv4', l: 'IPv4', match: [/^ipv4$/i, /^ip ?address$/i, /^a ?record$/i] },
  { k: 'ipv6', l: 'IPv6', match: [/^ipv6$/i, /^aaaa/i] },
  { k: 'ns1', l: 'Nameserver 1', match: [/^name ?server ?1$/i, /^ns ?1$/i] },
  { k: 'ns2', l: 'Nameserver 2', match: [/^name ?server ?2$/i, /^ns ?2$/i] },
  { k: 'ns3', l: 'Nameserver 3', match: [/^name ?server ?3$/i, /^ns ?3$/i] },
  { k: 'ns4', l: 'Nameserver 4', match: [/^name ?server ?4$/i, /^ns ?4$/i] },
  { k: 'ssl', l: 'SSL enabled', match: [/^ssl/i] },
  { k: 'subdomainCount', l: 'Subdomain count', match: [/subdomain/i] },
  { k: 'transferLock', l: 'Transfer lock', match: [/transfer ?lock/i] },
  { k: 'tld', l: 'TLD', match: [/^tld$/i] },
];

export const EMAIL_FIELDS = [
  { k: 'address', l: 'Email address', req: 'address|domain', match: [/^e-?mail ?address$/i, /^e-?mail$/i, /^address$/i, /^mailbox$/i, /e-?mail/i] },
  { k: 'domain', l: 'Domain (if no address column)', req: 'address|domain', match: [/^domain( ?name)?$/i] },
  { k: 'type', l: 'Type (mailbox, forward, alias…)', match: [/^type$/i, /kind|category/i] },
  { k: 'contract', l: 'Contract number', match: [/contract/i] },
  { k: 'product', l: 'Product / package', match: [/product|package|plan|tariff/i] },
  { k: 'size', l: 'Size / quota', match: [/size|quota|storage|usage/i] },
  { k: 'forward', l: 'Forwards to', match: [/forward|redirect|destination|target/i] },
  { k: 'note', l: 'Note', match: [/note|comment|description/i] },
];

export function suggestMapping(headers, fields) {
  const used = new Set();
  const mapping = {};
  for (const f of fields) {
    for (const re of f.match) {
      const idx = headers.findIndex((h, i) => !used.has(i) && !SENSITIVE.test(h) && re.test(h));
      if (idx >= 0) { mapping[f.k] = headers[idx]; used.add(idx); break; }
    }
  }
  return mapping;
}

export function accountNameFromFile(filename) {
  let n = String(filename || '').replace(/\.[a-z0-9]+$/i, '');
  n = n.replace(/[-_ ]*(domains?|emails?|mail|mailboxes)[-_ ]*export.*$/i, '').replace(/[-_ ]*\d{2}[_-]\d{2}[_-]\d{4}.*$/, '');
  return n.trim() || 'Account';
}

export const slug = s => String(s).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 60) || 'account';

export function preview({ kind, filename, text }) {
  const { headers, rows, delimiter } = parseCsv(text);
  const fields = kind === 'email' ? EMAIL_FIELDS : DOMAIN_FIELDS;
  return {
    kind,
    delimiter,
    headers,
    rowCount: rows.length,
    sample: rows.slice(0, 4),
    fields: fields.map(({ k, l, req, important }) => ({ k, l, req: !!req, important: !!important })),
    mapping: suggestMapping(headers, fields),
    sensitive: headers.filter(h => SENSITIVE.test(h)),
    accountGuess: accountNameFromFile(filename),
  };
}

const splitList = s => String(s || '').split(/[,\s]+/).map(x => x.trim()).filter(Boolean);
function parseTarget(target) {
  const v4 = [], v6 = [], mx = [];
  for (const part of String(target || '').split(',')) {
    const m = part.trim().match(/^(IPv4|IPv6|MX):\s*(.+)$/i);
    if (!m) continue;
    const kind = m[1].toUpperCase();
    if (kind === 'IPV4') v4.push(m[2].trim());
    else if (kind === 'IPV6') v6.push(m[2].trim());
    else mx.push(m[2].trim());
  }
  return { v4, v6, mx };
}
const uniq = a => [...new Set(a.filter(Boolean))];
const WEBSPACE_DEST = new Set(['WEBSPACE', 'WEBSPACE_ROOT', 'CLICK_AND_BUILD']);

function normaliseDomainRow(row, headers, mapping) {
  const get = k => {
    const col = mapping[k];
    if (!col) return '';
    const i = headers.indexOf(col);
    return i >= 0 ? String(row[i] ?? '').trim() : '';
  };
  const domain = get('domain').toLowerCase().replace(/\.$/, '');
  const target = get('target');
  const destination = get('destination').toUpperCase();
  const t = parseTarget(target);
  const rec = {
    domain,
    contract: get('contract'),
    type: get('type').toUpperCase(),
    tld: get('tld') || domain.split('.').slice(-1)[0],
    status: get('status'),
    statusGroup: get('statusGroup'),
    expiration: get('expiration'),
    destination,
    target,
    webspacePath: WEBSPACE_DEST.has(destination) ? target : (target.startsWith('/') ? target : ''),
    redirectTarget: /REDIRECT/.test(destination) ? target : '',
    exportIps: { v4: uniq([...splitList(get('ipv4')), ...t.v4]), v6: uniq([...splitList(get('ipv6')), ...t.v6]) },
    exportMx: t.mx,
    nameservers: ['ns1', 'ns2', 'ns3', 'ns4'].map(get).filter(Boolean),
    ssl: get('ssl'),
    subdomainCount: get('subdomainCount'),
    transferLock: get('transferLock'),
  };
  // Extra, non-sensitive columns are kept for reference.
  const mappedCols = new Set(Object.values(mapping));
  rec.extra = {};
  headers.forEach((h, i) => {
    if (!mappedCols.has(h) && !SENSITIVE.test(h) && String(row[i] ?? '').trim()) rec.extra[h] = String(row[i]).trim().slice(0, 300);
  });
  rec.missing = [];
  rec.warnings = [];
  if (!rec.contract) rec.missing.push('No contract number');
  if (mapping.destination && !rec.destination) rec.missing.push('No destination / usage');
  if (WEBSPACE_DEST.has(destination) && !target) rec.missing.push('Webspace path missing');
  if (destination === 'DNS_TEMPLATE_INTERNAL') rec.warnings.push(`IONOS hosting template "${target || '?'}": webspace path not in export`);
  if (mapping.expiration && rec.type === 'ON_DOMAIN' && !rec.expiration) rec.missing.push('No expiry date');
  if (rec.status && !/^active$/i.test(rec.status)) rec.warnings.push(`IONOS status: ${rec.status}`);
  if (rec.expiration) {
    const days = (Date.parse(rec.expiration) - Date.now()) / 864e5;
    if (days < 0) rec.warnings.push(`Expired ${rec.expiration.slice(0, 10)}`);
    else if (days < 60) rec.warnings.push(`Expires ${rec.expiration.slice(0, 10)} (${Math.round(days)} days)`);
  }
  return rec;
}

function defaultTracks(rec) {
  const t = { domain: { status: 'not_started' }, website: { status: 'not_started' }, email: { status: 'unchecked' } };
  if (rec.type === 'SUB_DOMAIN') t.domain = { status: 'na', auto: 'Subdomain: no separate registration to move' };
  if (rec.type === 'SYSTEM_DOMAIN') t.domain = { status: 'na', auto: 'IONOS system domain: not transferable' };
  if (rec.destination === 'NOT_USED' && !rec.exportIps.v4.length) t.website = { status: 'na', auto: 'IONOS destination NOT_USED, no address' };
  if (rec.exportMx.some(isIonosMx)) t.email = { status: 'not_started', auto: 'IONOS export lists IONOS MX records' };
  return t;
}

export function ensureContract(store, accountId, number) {
  const key = `${accountId}|${number || '(none)'}`;
  let c = store.data.contracts[key];
  if (!c) {
    c = store.data.contracts[key] = {
      key, accountId, number: number || '', label: '', notes: '', services: [], servicesReviewed: false,
      readiness: { confirmed: false }, created: new Date().toISOString(),
    };
    store.bump(c);
  }
  return c;
}

export function commitDomains(store, { filename, text, mapping, accountId, accountName }) {
  const { headers, rows } = parseCsv(text);
  if (!mapping?.domain || !headers.includes(mapping.domain)) throw new Error('Map the domain name column first.');
  for (const col of Object.values(mapping)) if (col && SENSITIVE.test(col)) throw new Error(`Column "${col}" is sensitive and cannot be imported.`);
  const now = new Date().toISOString();
  const data = store.data;
  let acct = accountId && data.accounts[accountId];
  if (!acct) {
    const name = String(accountName || accountNameFromFile(filename)).trim().slice(0, 120);
    let id = slug(name), n = 2;
    while (data.accounts[id] && data.accounts[id].name !== name) id = `${slug(name)}-${n++}`;
    acct = data.accounts[id] || (data.accounts[id] = { id, name, created: now, sourceTemplate: '' });
  }
  store.backup(`before-import-${acct.id}`);
  const seen = new Set();
  const summary = { account: acct.name, accountId: acct.id, rows: rows.length, added: 0, updated: 0, skipped: 0, missingRows: 0, removedFromExport: 0, contracts: 0 };
  const contractsSeen = new Set();
  for (const row of rows) {
    const rec = normaliseDomainRow(row, headers, mapping);
    if (!rec.domain || !/\./.test(rec.domain)) { summary.skipped++; continue; }
    const key = `${acct.id}|${rec.domain}`;
    if (seen.has(key)) { summary.skipped++; continue; }
    seen.add(key);
    const c = ensureContract(store, acct.id, rec.contract);
    contractsSeen.add(c.key);
    let d = data.domains[key];
    if (!d) {
      d = data.domains[key] = {
        key, accountId: acct.id, track: defaultTracks(rec), notes: '', blockers: '', source: null,
        scan: null, scanHistory: [], tech: null, techManual: null, log: [], firstImported: now,
      };
      summary.added++;
    } else summary.updated++;
    Object.assign(d, rec, { contractKey: c.key, inLatest: true, lastImported: now, importFile: filename });
    if (rec.missing.length) summary.missingRows++;
    store.bump(d);
  }
  for (const d of Object.values(data.domains)) {
    if (d.accountId === acct.id && !seen.has(d.key) && d.inLatest !== false) {
      d.inLatest = false;
      summary.removedFromExport++;
      store.bump(d);
    }
  }
  summary.contracts = contractsSeen.size;
  acct.lastImport = { file: filename, at: now, rows: rows.length, mapping, delimiter: undefined };
  acct.importCount = (acct.importCount || 0) + 1;
  store.bump(acct);
  return summary;
}

export function commitEmails(store, { filename, text, mapping, accountId }) {
  const { headers, rows } = parseCsv(text);
  if (!mapping?.address && !mapping?.domain) throw new Error('Map the email address or domain column first.');
  for (const col of Object.values(mapping)) if (col && SENSITIVE.test(col)) throw new Error(`Column "${col}" is sensitive and cannot be imported.`);
  const data = store.data;
  const now = new Date().toISOString();
  store.backup('before-email-import');
  const byName = new Map();
  for (const d of Object.values(data.domains)) {
    const list = byName.get(d.domain) || [];
    list.push(d);
    byName.set(d.domain, list);
  }
  const findDomain = name => {
    let n = String(name || '').toLowerCase();
    while (n.includes('.')) {
      const list = byName.get(n);
      if (list?.length) return list.find(d => !accountId || d.accountId === accountId) || list[0];
      n = n.slice(n.indexOf('.') + 1);
    }
    return null;
  };
  const get = (row, k) => { const col = mapping[k]; const i = col ? headers.indexOf(col) : -1; return i >= 0 ? String(row[i] ?? '').trim() : ''; };
  const summary = { rows: rows.length, added: 0, updated: 0, linked: 0, unlinked: 0, skipped: 0 };
  const counters = {};
  for (const row of rows) {
    const address = get(row, 'address').toLowerCase();
    const domain = (get(row, 'domain') || (address.includes('@') ? address.split('@')[1] : '')).toLowerCase();
    if (!address && !domain) { summary.skipped++; continue; }
    const d = findDomain(domain);
    const acctId = d?.accountId || accountId || null;
    const contractNo = get(row, 'contract');
    let contractKey = d?.contractKey || null;
    if (contractNo && acctId) contractKey = ensureContract(store, acctId, contractNo).key;
    let id = address;
    if (!id) { counters[domain] = (counters[domain] || 0) + 1; id = `${domain}#${counters[domain]}`; }
    let e = data.emails[id];
    if (!e) { e = data.emails[id] = { id, status: 'not_started', notes: '', created: now }; summary.added++; }
    else summary.updated++;
    Object.assign(e, {
      address, domain, type: get(row, 'type'), product: get(row, 'product'), size: get(row, 'size'),
      forward: get(row, 'forward'), note: get(row, 'note'), contractNumber: contractNo,
      domainKey: d?.key || null, accountId: acctId, importFile: filename, lastImported: now,
    });
    if (!e.manualContract) e.contractKey = contractKey;
    if (e.domainKey) summary.linked++; else summary.unlinked++;
    store.bump(e);
  }
  data.emailImports = [...(data.emailImports || []), { file: filename, at: now, rows: rows.length }].slice(-20);
  store.bump();
  return summary;
}
