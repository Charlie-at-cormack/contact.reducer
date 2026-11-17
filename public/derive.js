// Pure derivations: progress, readiness and lookup indexes. No DOM here.
export const STATUSES = [
  { k: 'unchecked', l: 'Unchecked' }, { k: 'not_started', l: 'Not started' }, { k: 'ready', l: 'Ready to move' },
  { k: 'in_progress', l: 'In progress' }, { k: 'moved', l: 'Moved' }, { k: 'verified', l: 'Verified' }, { k: 'na', l: 'N/A' },
];
export const SL = Object.fromEntries(STATUSES.map(s => [s.k, s.l]));
const RANK = { unchecked: 0, not_started: 1, ready: 2, in_progress: 3, moved: 4, verified: 5, na: 6 };
export const TRACKS = [{ k: 'domain', l: 'Domain' }, { k: 'website', l: 'Website' }, { k: 'email', l: 'Email' }];
export const VERDICTS = { verified: 'Verified', old: 'Old hosting', failed: 'Fails checks', review: 'Needs review' };
export const STACKS = {
  wordpress: 'WordPress', cms: 'Other CMS', framework: 'Framework / app', php: 'Custom PHP', static: 'Static HTML',
  builder: 'Site builder', redirect: 'Redirect', parked: 'Parked / not set up', unknown: 'Unknown',
};
export const DEST = {
  WEBSPACE: 'Webspace', WEBSPACE_ROOT: 'Webspace root', CLICK_AND_BUILD: 'Click & Build', DNS_CHANGED: 'Custom DNS',
  DNS_REDIRECT_TEMPLATE: 'Redirect', DNS_FRAME_REDIRECT_TEMPLATE: 'Frame redirect', DNS_TEMPLATE_INTERNAL: 'IONOS template',
  DNS_WEBSITE_TEMPLATE: 'Website builder', NOT_USED: 'Not used', NAMESERVER_EXTERNAL: 'External nameservers',
};
export const DEST_GROUPS = [
  { k: 'webspace', l: 'Connected to webspace', match: d => ['WEBSPACE', 'WEBSPACE_ROOT', 'CLICK_AND_BUILD'].includes(d.destination) },
  { k: 'template', l: 'IONOS hosting template / builder', match: d => ['DNS_TEMPLATE_INTERNAL', 'DNS_WEBSITE_TEMPLATE'].includes(d.destination) },
  { k: 'dns', l: 'Custom DNS (A records)', match: d => d.destination === 'DNS_CHANGED' },
  { k: 'redirect', l: 'IONOS redirect', match: d => /REDIRECT/.test(d.destination || '') },
  { k: 'unused', l: 'Not used', match: d => d.destination === 'NOT_USED' },
  { k: 'extns', l: 'External nameservers', match: d => d.destination === 'NAMESERVER_EXTERNAL' },
  { k: 'none', l: 'No destination', match: d => !d.destination },
];
export const done = s => s === 'verified' || s === 'na';

export function worst(statuses) {
  const live = statuses.filter(s => s !== 'na');
  if (!live.length) return statuses.length ? 'na' : 'unchecked';
  return live.reduce((a, b) => (RANK[b] < RANK[a] ? b : a));
}

export function emptyCounts() { return { total: 0, na: 0, by: {} }; }
export function addCount(c, s) { c.total++; if (s === 'na') c.na++; c.by[s] = (c.by[s] || 0) + 1; }
export function pct(c) { const n = c.total - c.na; return n ? Math.round(((c.by.verified || 0) / n) * 100) : 0; }

function domainUnits(d, counts) {
  addCount(counts.domain, d.track?.domain?.status || 'not_started');
  addCount(counts.website, d.track?.website?.status || 'not_started');
  if (d._emails.length) for (const e of d._emails) addCount(counts.email, e.status || 'not_started');
  else addCount(counts.email, d.track?.email?.status || 'unchecked');
}

export function newCounts() { return { domain: emptyCounts(), website: emptyCounts(), email: emptyCounts(), services: emptyCounts() }; }
export function overallOf(counts) {
  const all = emptyCounts();
  for (const c of Object.values(counts)) {
    all.total += c.total; all.na += c.na;
    for (const [k, v] of Object.entries(c.by)) all.by[k] = (all.by[k] || 0) + v;
  }
  return all;
}

export function exportVps(d, settings) {
  for (const v of settings.vps || []) if ((d.exportIps?.v4 || []).some(ip => (v.ipv4 || []).includes(ip))) return v;
  return null;
}

export function readiness(c, ctx) {
  const items = [];
  const block = (text, ref) => items.push({ lvl: 'block', text, ...ref });
  const warn = (text, ref) => items.push({ lvl: 'warn', text, ...ref });
  for (const d of c._domains) {
    const ref = { key: d.key };
    if (d.inLatest === false) warn(`${d.domain}: no longer in the latest IONOS export`, ref);
    for (const t of ['domain', 'website']) {
      const s = d.track?.[t]?.status || 'not_started';
      if (!done(s)) block(`${d.domain}: ${t} ${SL[s].toLowerCase()}`, { ...ref, tab: t === 'website' ? 'verify' : 'tracking' });
    }
    if (d._emails.length) {
      for (const e of d._emails) if (!done(e.status)) block(`${e.address || e.id}: email ${SL[e.status].toLowerCase()}`, { email: e.id });
    } else {
      const s = d.track?.email?.status || 'unchecked';
      if (!done(s)) block(`${d.domain}: email ${s === 'unchecked' ? 'not checked yet' : SL[s].toLowerCase()}`, { ...ref, tab: 'email' });
    }
    if (d.blockers) block(`${d.domain}: blocker: ${d.blockers.slice(0, 90)}`, ref);
    const ws = d.track?.website?.status;
    if (ws === 'verified' && d.scan && (d.scan.verdict === 'old' || d.scan.verdict === 'failed')) block(`${d.domain}: website marked verified but the last scan says "${VERDICTS[d.scan.verdict]}"`, { ...ref, tab: 'verify' });
    else if (ws === 'verified' && d.scan?.verdict === 'review') warn(`${d.domain}: website verified, last scan needs review`, { ...ref, tab: 'verify' });
    else if (ws === 'verified' && !d.scan) warn(`${d.domain}: website verified manually, no scan on record`, { ...ref, tab: 'verify' });
    if (d.tech?.db?.where === 'ionos' && d.tech.db.conf === 'inferred' && !done(ws)) warn(`${d.domain}: probably uses an IONOS MySQL database`, { ...ref, tab: 'tech' });
    if (d.missing?.length) warn(`${d.domain}: missing ${d.missing.join(', ').toLowerCase()}`, ref);
  }
  for (const e of c._extraEmails) if (!done(e.status)) block(`${e.address || e.id}: email ${SL[e.status].toLowerCase()} (email contract)`, { email: e.id });
  for (const s of c.services || []) {
    if (!done(s.status)) block(`Service "${s.name}": ${SL[s.status].toLowerCase()}`, { service: s.id });
    if (s.blocker) block(`Service "${s.name}": blocker: ${s.blocker.slice(0, 90)}`, { service: s.id });
  }
  if (!c.servicesReviewed) block('Other services on this contract not reviewed yet (databases, SSL, mail packages, backups…)', { review: true });
  if (!ctx.emailImported) warn('No email list imported yet, so mailboxes cannot be checked', {});
  const blocking = items.filter(i => i.lvl === 'block').length;
  let state = blocking ? 'open' : 'ready';
  if (c.readiness?.confirmed) state = blocking ? 'stale' : 'confirmed';
  return { state, items, blocking, warnings: items.length - blocking };
}

export function buildIndex(data) {
  const settings = data.settings;
  const accounts = Object.values(data.accounts).sort((a, b) => a.name.localeCompare(b.name));
  const contracts = Object.values(data.contracts);
  const domains = Object.values(data.domains);
  const emails = Object.values(data.emails);
  const emailImported = (data.emailImports || []).length > 0 || emails.length > 0;

  const emailsByDomain = new Map();
  const emailsByContract = new Map();
  for (const e of emails) {
    if (e.domainKey) (emailsByDomain.get(e.domainKey) || emailsByDomain.set(e.domainKey, []).get(e.domainKey)).push(e);
    if (e.contractKey) (emailsByContract.get(e.contractKey) || emailsByContract.set(e.contractKey, []).get(e.contractKey)).push(e);
  }
  const domainsByContract = new Map();
  for (const d of domains) {
    d._emails = emailsByDomain.get(d.key) || [];
    d._email = d._emails.length ? worst(d._emails.map(e => e.status || 'not_started')) : (d.track?.email?.status || 'unchecked');
    (domainsByContract.get(d.contractKey) || domainsByContract.set(d.contractKey, []).get(d.contractKey)).push(d);
  }
  // Order: parent domain followed by its subdomains.
  for (const list of domainsByContract.values()) {
    const names = new Set(list.map(d => d.domain));
    for (const d of list) {
      let p = d.domain, parent = null;
      while (p.includes('.')) { p = p.slice(p.indexOf('.') + 1); if (names.has(p)) { parent = p; break; } }
      d._parent = parent;
      d._sort = parent ? `${parent} ${d.domain}` : d.domain;
    }
    list.sort((a, b) => a._sort.localeCompare(b._sort));
  }
  const contractsByAccount = new Map();
  const numSort = (a, b) => (a.number ? 0 : 1) - (b.number ? 0 : 1) || (Number(a.number) || 0) - (Number(b.number) || 0) || a.number.localeCompare(b.number);
  for (const c of contracts) {
    c._domains = domainsByContract.get(c.key) || [];
    const domainKeys = new Set(c._domains.map(d => d.key));
    c._extraEmails = (emailsByContract.get(c.key) || []).filter(e => !domainKeys.has(e.domainKey));
    c._counts = newCounts();
    for (const d of c._domains) domainUnits(d, c._counts);
    for (const e of c._extraEmails) addCount(c._counts.email, e.status || 'not_started');
    for (const s of c.services || []) addCount(c._counts.services, s.status);
    c._ready = readiness(c, { emailImported });
    (contractsByAccount.get(c.accountId) || contractsByAccount.set(c.accountId, []).get(c.accountId)).push(c);
  }
  for (const list of contractsByAccount.values()) list.sort(numSort);

  const overall = newCounts();
  const byAccount = new Map();
  for (const a of accounts) byAccount.set(a.id, newCounts());
  for (const d of domains) { domainUnits(d, overall); const ac = byAccount.get(d.accountId); if (ac) domainUnits(d, ac); }
  for (const e of emails) {
    if (e.domainKey && data.domains[e.domainKey]) continue; // counted with its domain
    addCount(overall.email, e.status || 'not_started');
    const ac = byAccount.get(e.accountId);
    if (ac) addCount(ac.email, e.status || 'not_started');
  }
  for (const c of contracts) for (const s of c.services || []) { addCount(overall.services, s.status); const ac = byAccount.get(c.accountId); if (ac) addCount(ac.services, s.status); }

  return { accounts, contracts, domains, emails, emailsByDomain, emailsByContract, domainsByContract, contractsByAccount, overall, byAccount, emailImported, settings };
}
