import { STATUSES, SL, TRACKS, VERDICTS, STACKS, DEST, DEST_GROUPS, buildIndex, pct, overallOf, exportVps } from './derive.js';
import { health, bucketList, SITE, SSL, ipLabel } from './health.js';
import { REVIEW_TYPES, typeOf, verdictMeta, outcomeMeta } from './reviewtypes.js';

// ---------- Utilities ----------
const $ = (s, el = document) => el.querySelector(s);
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const LS = {
  get(k, d) { try { const v = localStorage.getItem(`imt:${k}`); return v ? JSON.parse(v) : d; } catch { return d; } },
  set(k, v) { try { localStorage.setItem(`imt:${k}`, JSON.stringify(v)); } catch {} },
};
const plural = (n, w, p) => `${n} ${n === 1 ? w : (p || `${w}s`)}`;
function ago(iso) {
  if (!iso) return '';
  const s = (Date.now() - Date.parse(iso)) / 1000;
  if (s < 60) return 'just now';
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86400) return `${Math.round(s / 3600)} h ago`;
  return `${Math.round(s / 86400)} days ago`;
}
const fmt = iso => (iso ? new Date(iso).toLocaleString('en-GB', { day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' }) : '—');
const fmtShort = iso => (iso ? new Date(iso).toLocaleString('en-GB', { weekday: 'short', day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' }) : '—');
const dur = ms => { const s = Math.max(0, Math.round(ms / 1000)); return s < 60 ? `${s}s` : `${Math.floor(s / 60)}m ${String(s % 60).padStart(2, '0')}s`; };
const debounce = (fn, ms) => { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; };
// Remix Icon glyphs, as in Domain Manager (vendor/remixicon).
const ri = name => `<i class="ri-${name}" aria-hidden="true"></i>`;
const ICONS = {
  dashboard: ri("home-smile-2-line"), contracts: ri("file-text-line"), email: ri("mail-line"), reviews: ri("list-check-3"), settings: ri("settings-3-line"),
  chev: ri("arrow-right-s-line"), down: ri("arrow-down-s-line"), up: ri("arrow-up-s-line"), upload: ri("upload-2-line"), dl: ri("download-2-line"),
  x: ri("close-line"), scan: ri("radar-line"), refresh: ri("refresh-line"), log: ri("file-list-3-line"), more: ri("more-fill"), filter: ri("filter-3-line"),
  stop: ri("stop-circle-line"), account: ri("user-line"), all: ri("apps-2-line"), flag: ri("flag-line"), plus: ri("add-line"), back: ri("arrow-left-line"),
  ext: ri("external-link-line"), trash: ri("delete-bin-line"), menu: ri("menu-line"), sun: ri("sun-line"), moon: ri("moon-line"), bell: ri("notification-3-line"),
};
const TITLES = { dashboard: "Dashboard", contracts: 'Contracts', email: 'Email', reviews: 'Review lists', settings: 'Settings' };
const TYPE_TAG = { SUB_DOMAIN: 'Sub', X_DOMAIN: 'X', IN_DOMAIN: 'IN', SYSTEM_DOMAIN: 'System' };
const BAR_ORDER = ['verified', 'moved', 'in_progress', 'ready', 'not_started', 'unchecked'];
const VIEWS = ['dashboard', 'contracts', 'email', 'reviews', 'settings'];

// ---------- State ----------
const S = {
  data: null, idx: null, rev: 0, jobs: [], jobsSig: '', blist: [],
  view: 'dashboard', q: '', acct: '', hf: '', flag: '', dt: '',
  rl: '', rvf: '', rinfo: null, rvc: null, pwm: null, rvVisible: [], rvStick: new Set(),
  open: new Set(LS.get('open', [])), det: new Set(LS.get('det', [])),
  ef: { status: '', link: '' },
  drawer: null, menu: null, modal: null, imp: null, draft: null, draftDirty: false,
  visible: [], matched: [], evisible: [], showAll: {}, pdown: 0, pending: false,
};

// ---------- API and sync ----------
async function api(path, body) {
  const opt = body === undefined ? {} : { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) };
  const r = await fetch(path, opt);
  let j = {};
  try { j = await r.json(); } catch {}
  if (r.status === 401 && j.signedOut) location.reload(); // hosted: the session ended, so sign in again through DevToolBox
  if (!r.ok) throw new Error(j.error || `${r.status} ${r.statusText}`);
  return j;
}
function reindex() {
  S.idx = buildIndex(S.data);
  const st = S.data.settings;
  S.blist = bucketList(st);
  const acctName = Object.fromEntries(S.idx.accounts.map(a => [a.id, a.name]));
  for (const d of S.idx.domains) {
    const h = d._h = health(d.scan, st);
    d._hay = [d.domain, d.contract, acctName[d.accountId], d.destination, DEST[d.destination], d.target, d.notes, d.blockers, d.webspacePath,
      ...(d.exportIps?.v4 || []), h?.ip, h?.server, h?.ptr, ...(h?.ips || []).map(i => i.ip), d.tech?.stack?.label, d.techManual?.label,
      ...(d.tech?.findings || []).map(f => f.name), ...(d._emails || []).map(e => e.address)].filter(Boolean).join(' ').toLowerCase();
  }
  for (const c of S.idx.contracts) {
    const hc = { notVps: 0, down: 0, parked: 0, ssl: 0, unscanned: 0, ok: 0, n: c._domains.length };
    for (const d of c._domains) {
      const h = d._h;
      if (!h) { hc.unscanned++; continue; }
      if (!h.onVps && h.bucket !== 'none') hc.notVps++;
      if (h.site === 'down') hc.down++;
      if (h.site === 'parked') hc.parked++;
      if (h.ssl === 'fail' || h.ssl === 'none') hc.ssl++;
      if (h.ok) hc.ok++;
    }
    c._hc = hc;
    c._hay = `${c.number} ${c.label} ${acctName[c.accountId] || ''}`.toLowerCase();
  }
}
function mergeRuns(list) {
  const m = new Map((S.data.scanRuns || []).map(r => [r.id, r]));
  for (const r of list) m.set(r.id, r);
  S.data.scanRuns = [...m.values()].sort((a, b) => b.startedAt.localeCompare(a.startedAt)).slice(0, 40);
}
async function loadAll() {
  const j = await api('/api/state');
  S.data = j.data; S.rev = j.rev; S.jobs = j.jobs; S.jobsSig = JSON.stringify(j.jobs);
  S.data.scanRuns ||= [];
  S.data.reviews ||= {};
  reindex();
  await refreshReviewInfo();
}
async function refreshReviewInfo() {
  try { S.rinfo = await api('/api/review/info'); } catch { S.rinfo = null; }
}
let pollTimer;
async function sync() {
  const j = await api(`/api/changes?since=${S.rev}`);
  const jobsSig = JSON.stringify(j.jobs);
  const jobsChanged = jobsSig !== S.jobsSig;
  S.jobs = j.jobs; S.jobsSig = jobsSig;
  if (j.full) { S.data = j.data; S.data.scanRuns ||= []; S.data.reviews ||= {}; }
  else {
    for (const a of j.accounts) S.data.accounts[a.id] = a;
    for (const c of j.contracts) S.data.contracts[c.key] = c;
    for (const d of j.domains) S.data.domains[d.key] = d;
    for (const e of j.emails) S.data.emails[e.id] = e;
    for (const r of j.reviews || []) S.data.reviews[r.id] = r;
    if (j.settings) S.data.settings = j.settings;
    S.data.emailImports = j.emailImports;
    if (j.runs?.length) mergeRuns(j.runs);
  }
  const changed = j.full || j.rev !== S.rev;
  S.rev = j.rev;
  if (changed) reindex();
  if (changed || jobsChanged) render();
  schedulePoll();
}
const liveRuns = () => (S.data?.scanRuns || []).filter(r => !r.finishedAt);
function schedulePoll() {
  clearTimeout(pollTimer);
  const active = S.jobs.some(j => !j.finishedAt) || liveRuns().length > 0;
  // On a review list, agent answers show up within a few seconds.
  pollTimer = setTimeout(() => sync().catch(() => schedulePoll()), active ? 1500 : S.view === 'reviews' ? 4000 : 20000);
}
async function act(fn, ok) {
  try { await fn(); await sync(); if (ok) toast(ok); }
  catch (e) { toast(e.message, true); }
}
function toast(msg, err) {
  const el = document.createElement('div');
  el.className = `toast${err ? ' err' : ''}`;
  el.textContent = msg;
  $('#toasts').appendChild(el);
  setTimeout(() => el.remove(), err ? 6000 : 3200);
}
const running = (key, kind) => S.jobs.some(j => !j.finishedAt && j.kind === kind && j.current.includes(key));

// ---------- Small renderers ----------
function bar(c) {
  const n = c.total - c.na;
  const title = n ? `${c.by.verified || 0} of ${n} verified · ${BAR_ORDER.filter(s => c.by[s]).map(s => `${SL[s]} ${c.by[s]}`).join(' · ')}${c.na ? ` · N/A ${c.na}` : ''}` : 'Nothing to track';
  return `<div class="bar" title="${esc(title)}">${n ? BAR_ORDER.map(s => (c.by[s] ? `<i class="s-${s}" style="width:${((c.by[s] / n) * 100).toFixed(2)}%"></i>` : '')).join('') : ''}</div>`;
}
const pill = s => `<span class="pill s-${s}"><i></i>${esc(SL[s] || s)}</span>`;
function statusBtn(kind, id, s, track = '', extra = '') {
  return `<button class="pill s-${s}" data-act="status" data-kind="${kind}" data-id="${esc(id)}" data-track="${track}" ${extra} title="Change status"><i></i>${esc(SL[s] || s)}</button>`;
}
function readyBadge(r) {
  if (r.state === 'confirmed') return '<span class="pill confirmed-badge"><i></i>Readiness confirmed</span>';
  if (r.state === 'ready') return '<span class="pill ready-badge"><i></i>Ready for cancellation review</span>';
  if (r.state === 'stale') return `<span class="pill stale-badge" title="Confirmed earlier, but items have reopened"><i></i>Confirmed · ${r.blocking} reopened</span>`;
  return `<span class="pill open-badge" title="${r.blocking} item(s) before cancellation review"><i></i>${r.blocking} open</span>`;
}
const BRAND = [[/^WordPress/i, 'W', '#21759b'], [/^Drupal/i, 'D', '#0678be'], [/^Joomla/i, 'J', '#f44321'], [/^ExpressionEngine/i, 'EE', '#c3352b'],
  [/^Craft/i, 'C', '#e5422b'], [/^TYPO3/i, 'T3', '#f49700'], [/^Magento/i, 'M', '#ee672f'], [/^PrestaShop/i, 'PS', '#df0067'], [/^OpenCart/i, 'OC', '#23a1d1'],
  [/^Concrete/i, 'C5', '#2a5bd7'], [/^Ghost/i, 'G', '#15171a'], [/^Laravel/i, 'L', '#ff2d20'], [/^Symfony/i, 'Sf', '#1a171b'], [/^CodeIgniter/i, 'CI', '#dd4814'],
  [/^Next/i, 'N', '#111111'], [/^Nuxt/i, 'Nx', '#00a565'], [/^Gatsby/i, 'G', '#663399'], [/^Astro/i, 'A', '#ff5d01'], [/Express|Node|Fastify|Nest/i, 'JS', '#5fa04e'],
  [/Django|Flask|Python/i, 'Py', '#3776ab'], [/Rails|Ruby/i, 'Rb', '#cc0000'], [/ASP/i, '.N', '#512bd4'], [/^Wix/i, 'Wx', '#111111'], [/^Squarespace/i, 'Sq', '#111111'],
  [/^Shopify/i, 'S', '#5e8e3e'], [/^Webflow/i, 'Wf', '#4353ff'], [/MyWebsite/i, 'MW', '#003d8f'], [/Hugo/i, 'H', '#ff4088'], [/Jekyll/i, 'Jk', '#cc0000']];
const KEYICON = { wordpress: ['W', '#21759b'], php: ['php', '#777bb4'], static: ['5', '#e34f26'], redirect: ['→', '#71717a'], parked: ['P', '#8e8e96'], unknown: ['?', '#8e8e96'], cms: ['C', '#52525b'], framework: ['{}', '#52525b'], builder: ['B', '#52525b'] };
function techIcon(key, label) {
  if (['static', 'php', 'redirect', 'parked', 'unknown'].includes(key)) return KEYICON[key];
  const b = BRAND.find(([re]) => re.test(label || ''));
  return b ? [b[1], b[2]] : (KEYICON[key] || KEYICON.unknown);
}
const CONF = { detected: 'Detected', inferred: 'Inferred', manual: 'Confirmed by you', unknown: 'Unknown' };
const confTag = c => `<span class="tag ${c === 'detected' ? 'det' : c === 'inferred' ? 'inf' : c === 'manual' ? 'man' : 'unk'}">${CONF[c] || c}</span>`;
function techBadge(key, label, conf, db, size = '') {
  const [t, c] = techIcon(key, label);
  const cls = conf === 'inferred' ? 'inferred' : conf === 'unknown' ? 'unknown' : '';
  return `<span class="tech ${cls} ${size}" title="${esc(`${label} · ${CONF[conf] || conf}`)}"><span class="ico" style="--ic:${c}">${esc(t)}</span><span class="tl">${esc(label)}${db ? `<span class="db">${esc(db)}</span>` : ''}</span></span>`;
}
function dbShort(db) {
  if (!db) return '';
  if (db.uses === 'yes') return `DB: ${db.type || 'yes'}${db.conf === 'inferred' ? ' (inferred)' : ''}`;
  if (db.uses === 'no') return `No DB${db.conf === 'inferred' ? ' (inferred)' : ''}`;
  if (db.uses === 'platform') return 'DB: platform';
  return 'DB: unknown';
}
function techMini(d) {
  const m = d.techManual;
  if (m?.stack) return techBadge(m.stack, m.label || STACKS[m.stack], 'manual', '', 'sm');
  if (d.tech) return techBadge(d.tech.stack.key, d.tech.stack.label, d.tech.stack.conf, '', 'sm');
  return '';
}
const statusOf = (d, t) => (t === 'email' ? d._email : d.track?.[t]?.status || 'not_started');
const isIonosMxStr = s => /ionos\.|1and1\.|kundenserver/i.test(s || '');
const bmeta = k => S.blist.find(b => b.k === k) || { k, l: k, c: 'none' };

// ---------- Filters ----------
const FLAGS = [
  { k: 'notmoved', l: 'Website not moved yet', fn: d => !['moved', 'verified', 'na'].includes(statusOf(d, 'website')) },
  { k: 'auto', l: 'Website status set by a scan', fn: d => d.track?.website?.by === 'scan' },
  { k: 'blocker', l: 'Has blockers', fn: d => !!d.blockers },
  { k: 'contradiction', l: 'Marked verified, scan disagrees', fn: d => d.track?.website?.status === 'verified' && d.scan && ['old', 'failed'].includes(d.scan.verdict) },
  { k: 'missing', l: 'Missing information', fn: d => d.missing?.length > 0 },
  { k: 'warnings', l: 'Expiring soon / IONOS warnings', fn: d => d.warnings?.length > 0 },
  { k: 'mxionos', l: 'Email still on IONOS (MX)', fn: d => !!d.scan?.flags?.mxIonos || (d.exportMx || []).some(isIonosMxStr) },
  { k: 'techreview', l: 'Technology needs review', fn: d => !!(d.tech?.review && !d.techManual) },
  { k: 'ionosdb', l: 'IONOS-hosted database', fn: d => d.tech?.db?.where === 'ionos' },
  { k: 'notinexport', l: 'Not in latest IONOS export', fn: d => d.inLatest === false },
  { k: 'notes', l: 'Has notes', fn: d => !!d.notes },
];
const CFLAGS = [
  { k: 'open', l: 'Still open', fn: c => ['open', 'stale'].includes(c._ready.state) },
  { k: 'ready', l: 'Ready for cancellation review', fn: c => c._ready.state === 'ready' },
  { k: 'confirmed', l: 'Readiness confirmed', fn: c => c._ready.state === 'confirmed' },
];
const flagLabel = f => (f.startsWith('c:') ? CFLAGS.find(x => x.k === f.slice(2))?.l : FLAGS.find(x => x.k === f.slice(2))?.l) || '';
const words = () => S.q.toLowerCase().split(/\s+/).filter(Boolean);
function hfLabel(f) {
  if (f === 'unscanned') return 'Not scanned';
  if (f === 'x=notvps') return 'Not on a VPS';
  if (f === 'x=onvps') return 'On a VPS';
  const t = f.slice(0, 1), v = f.slice(2);
  return t === 'b' ? bmeta(v).l : t === 's' ? `Site: ${SITE[v]?.l}` : `SSL: ${SSL[v]?.l}`;
}
function hfMatch(d) {
  const f = S.hf;
  if (!f) return true;
  const h = d._h;
  if (f === 'unscanned') return !h;
  if (!h) return false;
  const t = f.slice(0, 1), v = f.slice(2);
  if (t === 'b') return h.bucket === v;
  if (t === 's') return h.site === v;
  if (t === 'l') return h.ssl === v;
  if (f === 'x=notvps') return !h.onVps && h.bucket !== 'none';
  if (f === 'x=onvps') return h.onVps;
  return true;
}
// Domain or subdomain: IONOS says SUB_DOMAIN, or its parent domain is in the same contract.
const isSub = d => d.type === 'SUB_DOMAIN' || !!d._parent;
const DT = { root: 'Domains only', sub: 'Subdomains only' };
const dtMatch = d => !S.dt || (S.dt === 'sub') === isSub(d);
function domainMatches(d, ignoreQ, ignoreDt) {
  if (S.acct && d.accountId !== S.acct) return false;
  if (!ignoreDt && !dtMatch(d)) return false;
  if (!hfMatch(d)) return false;
  if (S.flag.startsWith('d:')) { const f = FLAGS.find(x => x.k === S.flag.slice(2)); if (f && !f.fn(d)) return false; }
  if (S.q && !ignoreQ) { for (const w of words()) if (!d._hay.includes(w)) return false; }
  return true;
}
const domFiltering = () => !!(S.q || S.hf || S.dt || S.flag.startsWith('d:'));
function visibleIn(c, ignoreDt) {
  const conHit = !!S.q && words().every(w => c._hay.includes(w));
  return c._domains.filter(d => domainMatches(d, conHit, ignoreDt));
}
// The active filters in words, used as the default review list name.
const filterDesc = () => [S.acct && S.data.accounts[S.acct]?.name, S.hf && hfLabel(S.hf), S.flag && flagLabel(S.flag), S.dt && DT[S.dt], S.q && `“${S.q}”`].filter(Boolean).join(' · ');

// ---------- Render root ----------
function render() {
  if (!S.data) return;
  if (S.pdown && Date.now() - S.pdown < 2000) { S.pending = true; return; } // never swap the DOM under a click in progress
  if (S.dragW) { S.pending = true; return; } // nor while a dashboard widget is being dragged
  S.pending = false;
  renderSide();
  renderTop();
  renderView();
  renderDrawer();
  writeHash();
}

// ---------- Left control panel ----------
function renderSide() {
  const idx = S.idx;
  const dom = S.acct ? idx.domains.filter(d => d.accountId === S.acct) : idx.domains;
  const cons = idx.contracts.filter(c => !S.acct || c.accountId === S.acct);
  const ready = cons.filter(c => c._ready.state === 'ready').length;
  const runs = S.data.scanRuns || [];
  const live = runs.find(r => !r.finishedAt);
  const last = runs.find(r => r.finishedAt);
  const cnt = fn => dom.filter(fn).length;
  const onC = S.view === 'contracts';
  const hq = (key, label, c, n) => { const on = onC && S.hf === key; return `<button class="${on ? 'on' : ''}" data-act="side-hf" data-v="${key}" ${n || on ? '' : 'disabled'}><span class="qd c-${c}"><i></i></span>${label}<span class="count">${n || ''}</span></button>`; };
  const fq = (key, label, n) => { const on = onC && S.flag === key; return `<button class="${on ? 'on' : ''}" data-act="side-flag" data-v="${key}" ${n || on ? '' : 'disabled'}>${ICONS.flag}${label}<span class="count">${n || ''}</span></button>`; };
  const flag = k => FLAGS.find(f => f.k === k).fn;
  const h = d => d._h;
  const lists = reviewLists();
  const waiting = lists.reduce((n, l) => n + rvCounts(l).waiting, 0);
  const badge = (n, cls = '') => (n ? `<span class="count"><span class="nbadge ${cls}">${n}</span></span>` : '');
  $('#side').innerHTML = `
    <div class="side-logo" data-act="nav" data-view="dashboard" title="Dashboard">
      <img src="brand/cormack-light.svg" alt="Cormack" class="logo-light"><img src="brand/cormack-dark.svg" alt="Cormack" class="logo-dark">
      <span class="tool">Domain Move · IONOS → VPS</span></div>
    <div class="side-scroll">
    <div><h4>Overview</h4><div class="nav">
      <button class="${S.view === 'dashboard' ? 'on' : ''}" data-act="nav" data-view="dashboard">${ICONS.dashboard}Dashboard</button>
      <button class="${S.view === 'contracts' ? 'on' : ''}" data-act="nav" data-view="contracts" title="${ready ? `${ready} ready for cancellation review` : ''}">${ICONS.contracts}Contracts${badge(cons.length)}</button>
      <button class="${S.view === 'email' ? 'on' : ''}" data-act="nav" data-view="email">${ICONS.email}Email<span class="count">${idx.emails.length || ''}</span></button>
      <button class="${S.view === 'reviews' && !S.rl ? 'on' : ''}" data-act="rv-home" title="${waiting ? 'Answers from agents waiting for your decision' : ''}">${ICONS.reviews}Review lists${waiting ? badge(waiting, 'warn') : `<span class="count">${lists.length || ''}</span>`}</button>
    </div></div>
    ${lists.length ? `<div><h4>Review lists</h4><div class="nav sub">
      ${lists.slice(0, 12).map(l => { const c = rvCounts(l); return `<button class="${S.view === 'reviews' && S.rl === l.id ? 'on' : ''}" data-act="rv-open" data-id="${esc(l.id)}" title="${esc(l.name)}${l.closed ? ' (closed)' : ''}">
        <span class="qd ${l.closed ? 'c-none' : c.waiting ? 'c-warn' : c.reviewed === c.n ? 'c-ok' : 'c-muted'}"><i></i></span><span class="acct-name">${esc(l.name)}</span>
        <span class="count">${c.waiting ? `<span class="rv-badge">${c.waiting}</span>` : ''}${c.reviewed}/${c.n}</span></button>`; }).join('')}
      ${lists.length > 12 ? `<button data-act="rv-home">${ICONS.all}All ${lists.length} lists</button>` : ''}
    </div></div>` : ''}
    ${idx.accounts.length ? `<div><h4>Accounts</h4><div class="nav sub">
      <button class="${!S.acct ? 'on' : ''}" data-act="acct" data-id="">${ICONS.all}All accounts<span class="count">${idx.domains.length}</span></button>
      ${idx.accounts.map(a => `<button class="${S.acct === a.id ? 'on' : ''}" data-act="acct" data-id="${esc(a.id)}" title="${esc(a.name)}">${ICONS.account}<span class="acct-name">${esc(a.name)}</span><span class="count">${idx.domains.filter(d => d.accountId === a.id).length}</span></button>`).join('')}
    </div></div>` : ''}
    ${idx.domains.length ? `<div><h4>Quick filters</h4><div class="nav sub">
      ${hq('x=notvps', 'Not on a VPS', 'other', cnt(d => h(d) && !h(d).onVps && h(d).bucket !== 'none'))}
      ${hq('s=down', 'Site down', 'bad', cnt(d => h(d)?.site === 'down'))}
      ${hq('s=parked', 'Site not set up', 'warn', cnt(d => h(d)?.site === 'parked'))}
      ${hq('l=fail', 'SSL invalid', 'bad', cnt(d => h(d)?.ssl === 'fail'))}
      ${hq('l=none', 'No HTTPS', 'warn', cnt(d => h(d)?.ssl === 'none'))}
      ${hq('unscanned', 'Not scanned', 'none', cnt(d => !h(d)))}
      ${fq('d:notmoved', 'Website not moved', cnt(flag('notmoved')))}
      ${fq('d:blocker', 'Blockers', cnt(flag('blocker')))}
      ${fq('d:missing', 'Missing info', cnt(flag('missing')))}
      ${fq('d:mxionos', 'Email on IONOS', cnt(flag('mxionos')))}
      ${fq('c:ready', 'Ready for review', ready)}
    </div></div>` : ''}
    <div><h4>System</h4><div class="nav">
      <button class="${S.drawer?.type === 'log' ? 'on' : ''}" data-act="open-log">${ICONS.log}Scan log<span class="count">${live ? `<span class="spin"></span> ${live.done}/${live.total}` : last ? esc(ago(last.finishedAt)) : ''}</span></button>
      <button class="${S.view === 'settings' ? 'on' : ''}" data-act="nav" data-view="settings">${ICONS.settings}Settings</button>
    </div></div>
    <div class="side-foot">
      <button class="btn primary" data-act="import">${ICONS.upload} Import CSV</button>
      <div class="note">Tracking only. Migrations and cancellations are done by you, in IONOS.</div>
    </div></div>`;
}

const theme = () => (document.documentElement.getAttribute('data-theme') === 'dark' ? 'dark' : 'light');
function setTheme(t) {
  document.documentElement.setAttribute('data-theme', t);
  try { localStorage.setItem('cmk-theme', t); } catch {}
}
function renderTop() {
  const rl = S.view === 'reviews' && S.rl && S.data.reviews[S.rl];
  $('#title').textContent = rl ? rl.name : TITLES[S.view];
  $('#crumb').textContent = `Home / ${TITLES[S.view]}${rl ? ` / ${rl.name}` : ''}${S.acct && ['dashboard', 'contracts'].includes(S.view) ? ` · ${S.data.accounts[S.acct]?.name || ''}` : ''}`;
  document.title = `${rl ? rl.name : TITLES[S.view]} · Domain Move · Cormack`;
  // The pill next to the title: a running scan, or when the last full scan finished.
  const runs = S.data.scanRuns || [];
  const live = liveRuns()[0];
  const last = runs.find(r => r.finishedAt && r.kind === 'verify' && r.scope === 'all');
  $('#topPill').innerHTML = live ? `<button class="top-pill" data-act="open-log" title="Open the scan log"><span class="spin"></span>Scanning ${live.done}/${live.total}</button>`
    : last ? `<button class="top-pill" data-act="open-log" title="Open the scan log">${ri('radar-line')}Last scan: ${esc(ago(last.finishedAt))}</button>` : '';
  const waiting = reviewLists().reduce((n, l) => n + rvCounts(l).waiting, 0);
  const dark = theme() === 'dark';
  $('#topActions').innerHTML = `
    <button class="hdr-btn" data-act="theme" title="${dark ? 'Switch to light mode' : 'Switch to dark mode'}">${dark ? ICONS.sun : ICONS.moon}</button>
    <button class="hdr-btn" data-act="bell" title="${waiting ? `${plural(waiting, 'answer')} from agents waiting for your decision` : 'Notifications'}">${ICONS.bell}${waiting ? `<span class="hdr-badge">${waiting > 99 ? '99+' : waiting}</span>` : ''}</button>
    <button class="hdr-btn" data-act="refresh" title="Reload the data">${ICONS.refresh}</button>`;
}

function renderView() {
  const el = $('#view');
  if (S.view === 'settings' && el.dataset.v === 'settings' && S.draftDirty) return;
  // Never replace a review page while a note is being typed; render once focus leaves.
  const ae = document.activeElement;
  if (S.view === 'reviews' && el.dataset.v === 'reviews' && el.contains(ae) && /INPUT|TEXTAREA/.test(ae.tagName)) { S._viewDirty = true; return; }
  S._viewDirty = false;
  const key = S.view === 'reviews' ? `reviews:${S.rl}` : S.view;
  const top = el.scrollTop;
  const same = el.dataset.k === key;
  el.dataset.v = S.view;
  el.dataset.k = key;
  if (!S.idx.domains.length && ['contracts', 'dashboard'].includes(S.view)) { el.innerHTML = emptyState(); return; }
  el.innerHTML = ({ dashboard: viewDashboard, contracts: viewContracts, email: viewEmail, reviews: viewReviews, settings: viewSettings })[S.view]();
  el.scrollTop = same ? top : 0;
}

function emptyState() {
  return `<div class="card empty"><h2>Import your IONOS exports to begin</h2>
    <p>Export the domain list from each IONOS account as CSV and import them here. Domains are grouped by contract.<br>
    Auth codes and contact details in the export are never stored.</p>
    <button class="btn primary" data-act="import">${ICONS.upload} Import CSV</button></div>`;
}

// ---------- Dashboard (laid out like Domain Manager: stat cards, then a draggable widget grid) ----------
const DASH_DEFAULT = ['expiry', 'servers', 'health', 'dest', 'scan', 'progress', 'reviews', 'expiring', 'accounts', 'contracts', 'activity'];
const WIDGETS = {
  expiry: { t: 'Expiration timeline', ic: 'calendar-schedule-line', wide: true },
  servers: { t: 'Where sites are now', ic: 'server-line' },
  health: { t: 'Site health', ic: 'pulse-line' },
  dest: { t: 'IONOS destination', ic: 'route-line' },
  scan: { t: 'Last scan', ic: 'radar-line' },
  progress: { t: 'Migration progress', ic: 'progress-5-line', wide: true },
  reviews: { t: 'Review lists', ic: 'list-check-3' },
  expiring: { t: 'Expiring soon', ic: 'time-line' },
  accounts: { t: 'Accounts', ic: 'folder-line' },
  contracts: { t: 'Contracts closest to ready', ic: 'file-shield-2-line' },
  activity: { t: 'Activity feed', ic: 'history-line', wide: true },
};
// The saved order, with any widget added later appended at the end.
function dashOrder() {
  const saved = LS.get('dash', null);
  const known = Array.isArray(saved) ? saved.filter(k => WIDGETS[k]) : [];
  return [...known, ...DASH_DEFAULT.filter(k => !known.includes(k))];
}
const wEmpty = (ic, html) => `<div class="w-empty">${ri(ic)}${html}</div>`;
// Axis step: the smallest of 1, 2, 2.5, 5, 10 (times a power of ten) that fits, whole numbers only.
const niceStep = v => { const p = 10 ** Math.floor(Math.log10(Math.max(v, 1))); for (const m of [1, 2, 2.5, 5, 10]) { const s = m * p; if (Number.isInteger(s) && s >= v) return s; } return 10 * p; };
const share = (n, total) => (total ? Math.round((n / total) * 100) : 0);

function viewDashboard() {
  const idx = S.idx;
  const dom = S.acct ? idx.domains.filter(d => d.accountId === S.acct) : idx.domains;
  const x = { dom, cons: idx.contracts.filter(c => !S.acct || c.accountId === S.acct) };
  const n = fn => dom.filter(fn).length;
  const stats = [
    { c: 'accent', ic: 'global-fill', tag: 'Total', neutral: true, n: dom.length, l: `Domains in ${plural(x.cons.length, 'contract')}`, hf: '' },
    { c: 'ok', ic: 'checkbox-circle-fill', tag: 'On VPS', n: n(d => d._h?.onVps), l: `On a VPS · ${n(d => d._h?.ok)} fully healthy`, hf: 'x=onvps' },
    { c: 'old', ic: 'server-fill', tag: 'IONOS', n: n(d => d._h?.bucket === 'old'), l: 'Still on IONOS shared', hf: 'b=old' },
    { c: 'bad', ic: 'error-warning-fill', tag: 'Down', n: n(d => d._h?.site === 'down'), l: 'Sites down', hf: 's=down' },
  ];
  return `<div class="stats">${stats.map(s => `<button class="stat c-${s.c}" data-act="dash-go" data-hf="${s.hf}" title="Show these domains on Contracts">
      <div class="stat-top"><span class="stat-ic">${ri(s.ic)}</span><span class="stat-tag${s.neutral ? ' neutral' : ''}">${s.tag}</span></div>
      <span class="stat-n">${s.n.toLocaleString('en-GB')}</span><span class="stat-l">${esc(s.l)}</span></button>`).join('')}</div>
    <div class="wbar"><span class="wbar-h">${ri('drag-move-line')} Drag widgets to rearrange</span>
      <button class="btn sm" data-act="dash-reset" title="Put the widgets back in their original order">${ri('layout-grid-line')} Reset</button></div>
    <div class="wgrid">${dashOrder().map(k => {
      const w = WIDGETS[k];
      const { r = '', b } = WBODY[k](x);
      return `<section class="widget${w.wide ? ' wide' : ''}" data-w="${k}"><div class="widget-h" draggable="true" title="Drag to move"><h3>${ri(w.ic)}${esc(w.t)}</h3>${r ? `<span class="r">${r}</span>` : ''}</div><div class="widget-b">${b}</div></section>`;
    }).join('')}</div>`;
}

// Donut: one ring, a small surface gap between slices, total or headline in the middle, legend with counts below.
function donutBlock(parts, center, sub, clickable) {
  const total = parts.reduce((s, p) => s + p.n, 0);
  const shown = parts.filter(p => p.n);
  const gap = shown.length > 1 ? 0.8 : 0;
  let off = 0;
  const segs = shown.map(p => {
    const len = (p.n / total) * 100;
    const dash = Math.max(len - gap, 0.3);
    const seg = `<circle class="dn-seg c-${p.c}" r="15.915" cx="21" cy="21" stroke-dasharray="${dash.toFixed(2)} ${(100 - dash).toFixed(2)}" stroke-dashoffset="${(25 - off).toFixed(2)}"><title>${esc(p.l)}: ${p.n} (${share(p.n, total)}%)</title></circle>`;
    off += len;
    return seg;
  }).join('');
  const legend = shown.map(p => {
    const btn = clickable && p.k !== undefined;
    const inner = `<i></i><span class="l">${esc(p.l)}</span><b>${p.n}</b><span class="p">${share(p.n, total)}%</span>`;
    return btn ? `<button class="lgd-r c-${p.c}" data-act="dash-go" data-hf="${esc(p.k)}" title="Show these domains">${inner}</button>` : `<div class="lgd-r c-${p.c}">${inner}</div>`;
  }).join('');
  return `<div class="dwrap"><div class="donut"><svg viewBox="0 0 42 42" role="img" aria-label="${esc(shown.map(p => `${p.l} ${p.n}`).join(', '))}"><circle class="dn-track" r="15.915" cx="21" cy="21"/>${segs}</svg>
    <div class="dn-c"><b>${center}</b><span>${esc(sub)}</span></div></div><div class="lgd">${legend}</div></div>`;
}
function gaugeBlock(p, c, big, small) {
  const arc = 'M10 62 A50 50 0 0 1 110 62';
  return `<div class="gauge c-${c}"><svg viewBox="0 0 120 68" aria-hidden="true"><path class="g-track" d="${arc}" pathLength="100"/>${p > 0 ? `<path class="g-val" d="${arc}" pathLength="100" stroke-dasharray="${(p * 100).toFixed(1)} 100"/>` : ''}</svg>
    <div class="g-c"><b>${esc(big)}</b><span>${esc(small)}</span></div></div>`;
}
const DEST_COLOR = { dns: 'c1', webspace: 'c2', redirect: 'c3', unused: 'c4' }; // fixed per category, so colours never move when counts change

const WBODY = {
  expiry(x) {
    const now = new Date();
    const start = new Date(now.getFullYear(), now.getMonth(), 1);
    const months = Array.from({ length: 12 }, (_, i) => ({ d: new Date(start.getFullYear(), start.getMonth() + i, 1), n: 0 }));
    const t0 = Date.now();
    let dated = 0, past = 0, soon = 0;
    for (const d of x.dom) {
      const t = Date.parse(d.expiration || '');
      if (Number.isNaN(t)) continue;
      dated++;
      if (t < t0) { past++; continue; }
      if (t - t0 <= 30 * 864e5) soon++;
      const e = new Date(t);
      const i = (e.getFullYear() - start.getFullYear()) * 12 + e.getMonth() - start.getMonth();
      if (i >= 0 && i < 12) months[i].n++;
    }
    if (!dated) return { b: wEmpty('calendar-schedule-line', 'No expiry dates in the IONOS export.') };
    const step = niceStep(Math.max(...months.map(m => m.n), 1) / 4);
    const top = step * 4;
    return {
      r: 'Next 12 months',
      b: `<div class="cc"><div class="cc-grid">${[4, 3, 2, 1, 0].map(i => `<div class="cc-gl"><span>${step * i}</span></div>`).join('')}</div>
        <div class="cc-bars">${months.map(m => {
          const h = ((m.n / top) * 100).toFixed(1);
          return `<div class="cc-col" style="--h:${h}%"><span class="cc-tip">${m.d.toLocaleDateString('en-GB', { month: 'long', year: 'numeric' })}: ${plural(m.n, 'domain')}</span>
            <div class="cc-bar" style="height:${h}%"></div><span class="cc-x">${m.d.toLocaleDateString('en-GB', { month: 'short', year: '2-digit' })}</span></div>`;
        }).join('')}</div></div>
        <div class="w-foot">${dated} of ${x.dom.length} domains have an expiry date in the IONOS export · <b>${soon}</b> within 30 days${past ? ` · ${past} already past` : ''}</div>`,
    };
  },

  servers(x) {
    const cnt = {};
    let un = 0;
    for (const d of x.dom) { if (!d._h) { un++; continue; } cnt[d._h.bucket] = (cnt[d._h.bucket] || 0) + 1; }
    const vpsCol = ['ok', 'teal', 'c1', 'c3'];
    let vi = 0;
    const parts = S.blist.map(b => ({ k: `b=${b.k}`, l: b.l, n: cnt[b.k] || 0, c: b.k.startsWith('vps:') ? vpsCol[Math.min(vi++, 3)] : b.c }));
    if (un) parts.push({ k: 'unscanned', l: 'Not scanned', n: un, c: 'empty' });
    const scanned = x.dom.length - un;
    const onVps = parts.filter(p => p.k.startsWith('b=vps:')).reduce((s, p) => s + p.n, 0);
    if (!scanned) return { b: wEmpty('server-line', 'Not scanned yet.<br><button class="linkbtn" data-act="scan-all">Scan all sites</button>') };
    return { r: `${scanned} scanned`, b: donutBlock(parts, `${share(onVps, scanned)}%`, 'on a VPS', true) };
  },

  health(x) {
    const site = {}, ssl = {};
    let sc = 0;
    for (const d of x.dom) {
      const h = d._h;
      if (!h) continue;
      sc++;
      site[h.site] = (site[h.site] || 0) + 1;
      if (h.ssl) ssl[h.ssl] = (ssl[h.ssl] || 0) + 1;
    }
    if (!sc) return { b: wEmpty('pulse-line', 'Not scanned yet.') };
    // Redirects get blue here so they do not sit grey-on-grey next to No DNS.
    const parts = ['up', 'redirect', 'parked', 'down', 'nodns'].map(k => ({ k: `s=${k}`, l: SITE[k].l, n: site[k] || 0, c: k === 'redirect' ? 'accent' : SITE[k].c }));
    const answering = (site.up || 0) + (site.redirect || 0);
    const rows = ['ok', 'fail', 'none'].map(k => ({ k: `l=${k}`, l: SSL[k].l, n: ssl[k] || 0, c: SSL[k].c }));
    return {
      r: `${sc} scanned`,
      b: `${donutBlock(parts, `${share(answering, sc)}%`, 'answering', true)}
        <div class="w-sub">SSL</div><div class="hb">${rows.map(r => `<button class="hb-r c-${r.c}" data-act="dash-go" data-hf="${r.k}" title="Show these domains"><span>${r.l}</span><span class="hb-t"><i style="width:${share(r.n, sc)}%"></i></span><b>${r.n}</b></button>`).join('')}</div>`,
    };
  },

  dest(x) {
    const parts = [];
    let rest = 0;
    for (const g of DEST_GROUPS) {
      const n = x.dom.filter(g.match).length;
      if (DEST_COLOR[g.k]) parts.push({ l: g.l, n, c: DEST_COLOR[g.k] });
      else rest += n;
    }
    if (rest) parts.push({ l: 'Other', n: rest, c: 'rest' });
    return { r: 'IONOS export', b: donutBlock(parts, x.dom.length, 'domains', false) };
  },

  scan(x) {
    const runs = S.data.scanRuns || [];
    const live = runs.find(r => !r.finishedAt && r.kind === 'verify' && r.scope === 'all');
    const last = runs.find(r => r.finishedAt && r.kind === 'verify' && r.scope === 'all');
    const un = x.dom.filter(d => !d._h).length;
    let g;
    if (live) {
      const p = live.total ? live.done / live.total : 0;
      g = gaugeBlock(p, 'accent', `${Math.round(p * 100)}%`, `scanning ${live.done} of ${live.total}`);
    } else if (last) {
      const hrs = (Date.now() - Date.parse(last.finishedAt)) / 36e5;
      const big = hrs < 1 ? `${Math.max(1, Math.round(hrs * 60))} min` : hrs < 48 ? `${Math.round(hrs)} h` : `${Math.round(hrs / 24)} days`;
      g = gaugeBlock(Math.min(hrs / 72, 1), hrs < 24 ? 'ok' : hrs < 72 ? 'warn' : 'bad', big, 'since the last full scan');
    } else g = gaugeBlock(0, 'none', 'Never', 'no full scan yet');
    const changes = last ? (last.changes || []).length + (last.moreChanges || 0) : 0;
    return {
      r: last ? esc(fmtShort(last.finishedAt)) : '',
      b: `${g}<div class="sboxes">
          <div class="sbox"><b>${x.dom.length - un}</b><span>Scanned</span></div>
          <div class="sbox"><b class="${un ? 'bad' : ''}">${un}</b><span>Not scanned</span></div>
          <div class="sbox"><b>${changes}</b><span>Changes last scan</span></div>
          <div class="sbox"><b>${runs.length}</b><span>Scans in the log</span></div></div>
        <div style="display:flex;gap:6px;margin-top:12px">${live
          ? `<button class="btn sm" data-act="cancel-run" data-id="${esc(live.id)}" style="flex:1;justify-content:center">${ICONS.stop} Stop scan</button>`
          : `<button class="btn sm primary" data-act="scan-all" style="flex:1;justify-content:center">${ICONS.refresh} ${last ? 'Rescan all sites' : 'Scan all sites'}</button>`}
          <button class="btn sm" data-act="open-log">${ICONS.log} Log</button></div>`,
    };
  },

  progress(x) {
    const counts = S.acct ? S.idx.byAccount.get(S.acct) : S.idx.overall;
    const ord = ['verified', 'moved', 'in_progress', 'ready', 'not_started', 'unchecked', 'na'];
    const rows = [['domain', 'Domain move'], ['website', 'Website'], ['email', 'Email'], ['services', 'Services']].filter(([k]) => counts[k].total);
    const o = overallOf(counts);
    const used = ord.filter(s => o.by[s]);
    const ready = x.cons.filter(c => ['ready', 'confirmed'].includes(c._ready.state)).length;
    const conf = x.cons.filter(c => c._ready.state === 'confirmed').length;
    return {
      r: `${pct(o)}% verified`,
      b: `${rows.map(([k, l]) => {
          const c = counts[k];
          return `<div class="trk"><span class="lb">${l}</span><div class="stk" title="${esc(ord.filter(s => c.by[s]).map(s => `${SL[s]} ${c.by[s]}`).join(' · '))}">${ord.map(s => (c.by[s] ? `<i class="s-${s}" style="width:${((c.by[s] / c.total) * 100).toFixed(2)}%"></i>` : '')).join('')}</div><span class="pc">${pct(c)}%</span></div>`;
        }).join('')}
        <div class="keys">${used.map(s => `<span><i style="--c:var(--s-${s})"></i>${SL[s]}</span>`).join('')}</div>
        <div class="w-foot">Percent is the share Verified (N/A left out). <b>${ready}</b> of ${plural(x.cons.length, 'contract')} ready for cancellation review${conf ? ` · ${conf} confirmed` : ''}.</div>`,
    };
  },

  reviews() {
    const ls = reviewLists();
    if (!ls.length) return { b: wEmpty('list-check-3', 'No review lists yet.<br><button class="linkbtn" data-act="nav" data-view="contracts">Filter domains on Contracts</button>, then create one.') };
    return {
      r: '<button class="btn sm ghost" data-act="rv-home">All</button>',
      b: `<div class="wl">${ls.slice(0, 5).map(l => {
        const c = rvCounts(l);
        return `<button class="wl-r" data-act="rv-open" data-id="${esc(l.id)}"><span class="grow2"><span class="nm" style="display:block">${esc(l.name)}</span><span class="sub">${esc(typeOf(l).l)}${l.closed ? ' · closed' : ''}</span></span>
          <span class="rt">${c.waiting ? `<span class="dbadge c-warn">${c.waiting} waiting</span>` : ''}<span class="mini">${agentParts(l, c).map(p => (p.n ? `<i class="c-${p.c}" style="width:${(p.n / c.n) * 100}%"></i>` : '')).join('')}</span>${c.reviewed}/${c.n}</span></button>`;
      }).join('')}</div>`,
    };
  },

  expiring(x) {
    const t0 = Date.now();
    const list = x.dom.map(d => ({ d, t: Date.parse(d.expiration || '') })).filter(o => o.t >= t0 && o.t - t0 <= 30 * 864e5).sort((a, b) => a.t - b.t);
    if (!list.length) return { b: wEmpty('time-line', 'Nothing expires in the next 30 days.') };
    return {
      r: `${list.length} in 30 days`,
      b: `<div class="wl">${list.slice(0, 8).map(({ d, t }) => {
        const days = Math.ceil((t - t0) / 864e5);
        const c = days <= 7 ? 'bad' : 'warn';
        return `<button class="wl-r" data-act="open" data-key="${esc(d.key)}"><span class="dot c-${c}"></span><span class="nm">${esc(d.domain)}</span><span class="rt">${new Date(t).toLocaleDateString('en-GB')}<span class="dbadge c-${c}">${days}d</span></span></button>`;
      }).join('')}</div>${list.length > 8 ? `<div class="w-foot">and ${list.length - 8} more</div>` : ''}`,
    };
  },

  accounts() {
    const acc = S.idx.accounts;
    return {
      r: `${acc.length}`,
      b: `<div class="wl">${acc.map(a => {
        const ds = S.idx.domains.filter(d => d.accountId === a.id);
        const on = ds.filter(d => d._h?.onVps).length;
        return `<button class="wl-r" data-act="acct" data-id="${esc(a.id)}" title="Show only this account"><span class="dot c-accent"></span><span class="grow2"><span class="nm" style="display:block">${esc(a.name)}</span><span class="sub">${on} of ${ds.length} on a VPS</span></span>
          <span class="rt"><span class="mini"><i class="c-ok" style="width:${share(on, ds.length)}%"></i></span><b style="color:var(--head)">${ds.length}</b></span></button>`;
      }).join('')}</div>`,
    };
  },

  contracts(x) {
    const ready = x.cons.filter(c => ['ready', 'confirmed'].includes(c._ready.state)).length;
    const list = x.cons.filter(c => c._ready.state !== 'confirmed').sort((a, b) => a._ready.blocking - b._ready.blocking || b._domains.length - a._domains.length).slice(0, 6);
    if (!list.length) return { b: wEmpty('file-shield-2-line', 'Every contract is confirmed.') };
    return {
      r: `${ready} of ${x.cons.length} ready`,
      b: `<div class="wl">${list.map(c => {
        const cc = overallOf(c._counts);
        const base = cc.total - cc.na || 1;
        return `<button class="wl-r" data-act="open-contract" data-key="${esc(c.key)}"><span class="grow2"><span class="nm" style="display:block">${c.number ? `Contract ${esc(c.number)}` : 'No contract number'}</span><span class="sub">${esc(S.data.accounts[c.accountId]?.name || '')} · ${plural(c._domains.length, 'domain')}</span></span>
          <span class="rt"><span class="mini">${['verified', 'moved', 'in_progress', 'ready'].map(s => (cc.by[s] ? `<i style="--c:var(--s-${s});width:${(cc.by[s] / base) * 100}%"></i>` : '')).join('')}</span>${c._ready.blocking ? `<span class="dbadge c-muted">${c._ready.blocking} open</span>` : '<span class="dbadge c-ok">ready</span>'}</span></button>`;
      }).join('')}</div>`,
    };
  },

  activity(x) {
    const items = [];
    for (const d of x.dom) for (const e of (d.log || []).slice(0, 10)) items.push({ at: e.at, text: e.text, d });
    if (!items.length) return { b: wEmpty('history-line', 'No changes yet.') };
    items.sort((a, b) => b.at.localeCompare(a.at));
    const icon = t => (/^Review/.test(t) ? ['list-check-3', 'accent'] : /status/.test(t) ? ['exchange-line', 'ok'] : /Blocker/.test(t) ? ['error-warning-line', 'bad'] : /Tech/.test(t) ? ['code-s-slash-line', 'other'] : ['edit-line', 'muted']);
    return {
      r: 'Latest changes',
      b: `<div class="wl">${items.slice(0, 10).map(it => {
        const [ic, c] = icon(it.text);
        return `<button class="wl-r" data-act="open" data-key="${esc(it.d.key)}"><span class="act-ic c-${c}">${ri(ic)}</span><span class="grow2"><span class="nm" style="display:block">${esc(it.text)}</span><span class="sub">${esc(it.d.domain)}</span></span><span class="rt">${esc(fmtShort(it.at))}</span></button>`;
      }).join('')}</div>`,
    };
  },
};

// ---------- Scan panel (the central scan button) ----------
const SITE_TIP = { up: 'Answers with a real page', redirect: 'Redirects to another domain', parked: 'Answers, but with a placeholder: Plesk login or default page, parking page, server default page', down: 'No response, or HTTP 4xx / 5xx' };
function scanPanel(domains) {
  const runs = S.data.scanRuns || [];
  const live = runs.find(r => !r.finishedAt && r.kind === 'verify' && r.scope === 'all');
  const last = runs.find(r => r.finishedAt && r.kind === 'verify' && r.scope === 'all');
  const others = runs.filter(r => !r.finishedAt && r !== live);
  let left;
  if (live) {
    const p = live.total ? Math.round((live.done / live.total) * 100) : 0;
    const el = Date.now() - Date.parse(live.startedAt);
    const eta = live.done > 3 ? dur((el / live.done) * (live.total - live.done)) : '';
    left = `<div class="scanbtn running"><span class="spin lg"></span><div class="grow"><b>Scanning ${live.done} / ${live.total}</b><div class="pbar"><i style="width:${p}%"></i></div></div>
        <button class="btn sm" data-act="cancel-run" data-id="${esc(live.id)}" title="Stop after the sites in progress">${ICONS.stop} Stop</button></div>
      <div class="sp-last">Started ${fmtShort(live.startedAt)} · ${dur(el)} so far${eta ? ` · about ${eta} left` : ''}</div>`;
  } else {
    left = `<div class="sp-btnrow"><button class="scanbtn" data-act="scan-all">${last ? ICONS.refresh : ICONS.scan}<span>${last ? 'Rescan all sites' : 'Scan all sites'}</span></button>
        <button class="ibtn lg" data-act="scan-more" title="More scan options">${ICONS.more}</button></div>
      <div class="sp-last">${last ? `Last scan <b>${fmtShort(last.finishedAt)}</b> · ${ago(last.finishedAt)}<br>${plural(last.total, 'site')} in ${dur(Date.parse(last.finishedAt) - Date.parse(last.startedAt))}${last.cancelled || last.interrupted ? ' · stopped early' : ''}`
        : `Checks every domain: the server IP it points to (anything not on ${S.data.settings.vps.map(v => esc(bmeta(`vps:${v.id}`).l)).join(' or ')} is flagged), whether the site is up, and whether SSL is valid.`}</div>`;
  }
  left += `<button class="btn sm" data-act="open-log">${ICONS.log} Scan log${runs.length ? `<span class="cnt">${runs.length}</span>` : ''}</button>`;
  if (others.length) left += others.map(r => `<div class="sp-last"><span class="spin"></span> ${esc(r.kind === 'tech' ? 'Technology scan' : 'Scanning')} · ${esc(r.label)} · ${r.done}/${r.total}</div>`).join('');

  const t = { bucket: {}, site: {}, ssl: {}, unscanned: 0 };
  for (const d of domains) {
    const h = d._h;
    if (!h) { t.unscanned++; continue; }
    t.bucket[h.bucket] = (t.bucket[h.bucket] || 0) + 1;
    t.site[h.site] = (t.site[h.site] || 0) + 1;
    if (h.ssl) t.ssl[h.ssl] = (t.ssl[h.ssl] || 0) + 1;
  }
  const chip = (key, label, n, c, title = '') => `<button class="hchip c-${c}${S.hf === key ? ' on' : ''}" data-act="hf" data-v="${esc(key)}" title="${esc(title)}" ${n || S.hf === key ? '' : 'disabled'}><i></i>${esc(label)}<b>${n}</b></button>`;
  const scanned = domains.length - t.unscanned;
  const o = overallOf(S.acct ? S.idx.byAccount.get(S.acct) : S.idx.overall);
  const cons = S.idx.contracts.filter(c => !S.acct || c.accountId === S.acct);
  const ready = cons.filter(c => ['ready', 'confirmed'].includes(c._ready.state)).length;
  const right = `
    <div class="hrow"><span class="hl">Server</span>${S.blist.filter(b => b.k.startsWith('vps:') || t.bucket[b.k]).map(b => chip(`b=${b.k}`, b.l, t.bucket[b.k] || 0, b.c, b.k === 'mixed' ? 'Some DNS records on a VPS, others still elsewhere (often IPv6 left on IONOS)' : '')).join('')}
      ${scanned ? chip('x=notvps', 'Not on a VPS', domains.filter(d => d._h && !d._h.onVps && d._h.bucket !== 'none').length, 'other', 'Every scanned domain whose DNS is not fully on a configured VPS') : ''}</div>
    <div class="hrow"><span class="hl">Site</span>${['up', 'redirect', 'parked', 'down'].filter(k => k !== 'parked' || t.site.parked).map(k => chip(`s=${k}`, SITE[k].l, t.site[k] || 0, SITE[k].c, SITE_TIP[k])).join('')}
      <span class="hl" style="margin-left:14px">SSL</span>${['ok', 'fail', 'none'].map(k => chip(`l=${k}`, SSL[k].l, t.ssl[k] || 0, SSL[k].c)).join('')}
      ${t.unscanned ? chip('unscanned', 'Not scanned', t.unscanned, 'none') : ''}</div>
    <div class="sp-prog"><span>Migration progress</span>${bar(o)}<b>${pct(o)}%</b><span>verified · ${ready} of ${plural(cons.length, 'contract')} ready for cancellation review</span></div>`;
  return `<section class="card scanpanel"><div class="sp-left">${left}</div><div class="sp-right">${right}</div></section>`;
}

// ---------- Contracts ----------
function viewContracts() {
  const idx = S.idx;
  const acctDomains = S.acct ? idx.domains.filter(d => d.accountId === S.acct) : idx.domains;
  const filtering = domFiltering();
  const cflag = S.flag.startsWith('c:') ? CFLAGS.find(x => x.k === S.flag.slice(2)) : null;
  const cards = [];
  const visible = [];
  const matched = [];
  const dtn = { all: 0, root: 0, sub: 0 };
  let anyClosed = false;
  for (const a of idx.accounts) {
    if (S.acct && a.id !== S.acct) continue;
    for (const c of idx.contractsByAccount.get(a.id) || []) {
      if (cflag && !cflag.fn(c)) continue;
      const base = visibleIn(c, true);
      for (const d of base) { dtn.all++; dtn[isSub(d) ? 'sub' : 'root']++; }
      const vis = S.dt ? base.filter(dtMatch) : base;
      if (filtering && !vis.length) continue;
      matched.push(...vis.map(d => d.key));
      const open = filtering || S.open.has(c.key);
      if (!open) anyClosed = true;
      else visible.push(...vis.slice(0, S.showAll[`c:${c.key}`] ? 1e9 : 100).map(d => d.key));
      cards.push(contractCard(c, vis, open, filtering));
    }
  }
  S.visible = visible;
  S.matched = matched;
  const active = [S.acct && ['acct', S.data.accounts[S.acct]?.name || S.acct], S.hf && ['hf', hfLabel(S.hf)], S.flag && ['flag', flagLabel(S.flag)], S.q && ['q', `“${S.q}”`]].filter(Boolean);
  const dtSeg = `<span class="seg" title="Show domains, subdomains or both">${[['', 'All', dtn.all], ['root', 'Domains', dtn.root], ['sub', 'Subdomains', dtn.sub]]
    .map(([k, l, n]) => `<button class="${S.dt === k ? 'on' : ''}" data-act="dt" data-v="${k}">${l}<span class="cnt" style="margin-left:2px">${n}</span></button>`).join('')}</span>`;
  return `${scanPanel(acctDomains)}
    <div class="toolbar">
      <button class="chip${S.flag ? ' on' : ''}" data-act="filter-menu">${ICONS.filter}${S.flag ? `<b>${esc(flagLabel(S.flag))}</b>` : 'Filter'} ${ICONS.down}</button>
      ${dtSeg}
      ${active.length || S.dt ? `<span class="muted">${filtering ? `${matched.length} of ${acctDomains.length} domains` : `${cards.length} contracts`}</span>
        ${active.map(([k, l]) => `<button class="chip on" data-act="clear-one" data-k="${k}" title="Remove this filter">${esc(l)} ${ICONS.x}</button>`).join('')}
        <button class="btn sm ghost" data-act="clear-filters">Clear</button>` : ''}
      <span class="grow"></span>
      ${filtering ? '' : `<button class="btn sm ghost" data-act="${anyClosed ? 'expand-all' : 'collapse-all'}">${anyClosed ? 'Expand all' : 'Collapse all'}</button>`}
      <button class="btn sm" data-act="rv-new" ${matched.length ? '' : 'disabled'} title="Make a list of the ${matched.length} matching domains for an agent to review">${ICONS.plus} Create review list<span class="cnt">${matched.length}</span></button>
      <button class="btn sm ghost" data-act="export-csv" title="Download the matching domains as CSV">${ICONS.dl} CSV</button></div>
    <div class="cons">${cards.join('') || `<div class="card empty"><h2>Nothing matches</h2><p>Try another filter or search.</p><button class="btn" data-act="clear-filters">Clear filters</button></div>`}</div>`;
}

function contractCard(c, vis, open, filtering) {
  const acct = S.data.accounts[c.accountId];
  const cc = overallOf(c._counts);
  const hc = c._hc;
  const live = liveRuns().find(r => r.contractKey === c.key);
  const issues = [
    hc.notVps ? `<span class="iss c-other" title="DNS points somewhere other than a configured VPS">${hc.notVps} not on VPS</span>` : '',
    hc.down ? `<span class="iss c-bad" title="No response, or HTTP 4xx / 5xx">${hc.down} down</span>` : '',
    hc.parked ? `<span class="iss c-warn" title="${SITE_TIP.parked}">${hc.parked} not set up</span>` : '',
    hc.ssl ? `<span class="iss c-bad" title="Invalid certificate or no HTTPS">${hc.ssl} SSL</span>` : '',
    hc.unscanned && hc.unscanned < hc.n ? `<span class="iss c-none">${hc.unscanned} not scanned</span>` : '',
  ].join('');
  const fallback = hc.unscanned === hc.n ? '<span class="faint">Not scanned</span>' : hc.ok === hc.n ? '<span class="iss c-ok">All on VPS and healthy</span>' : '';
  return `<div class="con${open ? ' open' : ''}">
    <div class="con-h" data-act="con-toggle" data-key="${esc(c.key)}">
      <span class="tog${open ? ' open' : ''}">${ICONS.chev}</span>
      <div class="con-t"><div class="con-n"><b>${c.number ? `Contract ${esc(c.number)}` : 'No contract number'}</b>${c.label ? ` <span class="muted">· ${esc(c.label)}</span>` : ''}</div>
        <div class="meta">${S.acct ? '' : `<span class="acct-l">${esc(acct?.name || '')}</span> · `}${filtering ? `${vis.length} of ` : ''}${plural(hc.n, 'domain')}${(c.services || []).length ? ` · ${plural(c.services.length, 'service')}` : ''}</div></div>
      <div class="con-p">${bar(cc)}<span class="num">${pct(cc)}%</span></div>
      <div class="con-i">${issues || fallback}</div>
      <div class="con-r">${readyBadge(c._ready)}</div>
      <div class="con-a">${live ? `<span class="spin" title="Scanning ${live.done}/${live.total}"></span>` : `<button class="ibtn" data-act="con-scan" data-key="${esc(c.key)}" title="Rescan this contract">${ICONS.refresh}</button>`}
        <button class="ibtn" data-act="con-menu" data-key="${esc(c.key)}" title="More actions">${ICONS.more}</button></div>
    </div>
    ${open ? contractBody(c, vis) : ''}
  </div>`;
}

function contractBody(c, vis) {
  const all = !!S.showAll[`c:${c.key}`];
  const list = all ? vis : vis.slice(0, 100);
  return `<div class="con-b"><table class="t dt"><colgroup><col class="w-dom"><col class="w-srv"><col class="w-site"><col class="w-ssl"><col class="w-st"><col class="w-st"><col class="w-st"><col class="w-act"></colgroup>
    <thead><tr><th>Domain</th><th>Server</th><th>Site</th><th>SSL</th><th title="Moving the domain into the new contract">Domain move</th><th>Website</th><th>Email</th><th></th></tr></thead>
    <tbody>${list.map(rowHtml).join('') || '<tr class="more-row"><td colspan="8">No domains in this contract.</td></tr>'}
    ${vis.length > list.length ? `<tr class="more-row"><td colspan="8"><button class="btn sm" data-act="show-all" data-k="c:${esc(c.key)}">Show all ${vis.length}</button></td></tr>` : ''}</tbody></table>
    <div class="con-f"><button class="btn sm" data-act="open-contract" data-key="${esc(c.key)}">Readiness, services and notes</button>
      <span class="hint">${c._ready.blocking ? `${plural(c._ready.blocking, 'item')} open before cancellation review` : 'Nothing blocking cancellation review'}${c._extraEmails.length ? ` · ${plural(c._extraEmails.length, 'email record')} on this contract` : ''}</span></div></div>`;
}

function serverCell(d, h) {
  if (running(d.key, 'verify')) return '<span class="spin"></span> <span class="muted">Scanning…</span>';
  if (!h) {
    const v = exportVps(d, S.data.settings);
    const ip = d.exportIps?.v4?.[0];
    return `<span class="faint" title="From the IONOS export, not scanned yet">${ip ? esc(ip) : 'Not scanned'}${v ? ` · export says ${esc(bmeta(`vps:${v.id}`).l)}` : ''}</span>`;
  }
  const b = bmeta(h.bucket);
  const label = h.bucket === 'mixed' ? h.server : b.k.startsWith('vps:') ? b.l : h.server;
  return `<span class="stag c-${b.c}" title="${esc(b.l)}"><i></i>${esc(label)}</span>${h.oddShort ? `<span class="oddw" title="${esc(h.odd.map(o => `${o.text} · ${o.label}`).join('\n'))}">${esc(h.oddShort)}</span>` : ''}
    ${h.ip ? `<div class="meta mono" title="${esc(h.ptr || '')}">${esc(h.ip)}</div>` : ''}`;
}
function siteCell(h) {
  if (!h) return '<span class="faint">—</span>';
  const m = SITE[h.site];
  return `<span class="hs c-${m.c}"><i></i>${m.l}</span><div class="meta" title="${esc(h.siteError || h.finalUrl || '')}">${esc(h.siteDetail || '')}${h.wwwIssue ? ` · <span class="warnc">${esc(h.wwwIssue)}</span>` : ''}</div>`;
}
function sslCell(h) {
  if (!h || !h.ssl) return '<span class="faint">—</span>';
  const m = SSL[h.ssl];
  return `<span class="hs c-${h.sslSoon ? 'warn' : m.c}"><i></i>${h.sslSoon ? 'Expiring' : m.l}</span><div class="meta" title="${esc(h.cert ? `${h.cert.subject} · ${h.cert.issuer} · until ${h.cert.validTo}` : '')}">${esc(h.sslDetail || '')}</div>`;
}
function rowHtml(d) {
  const h = d._h;
  const active = S.drawer?.type === 'domain' && S.drawer.id === d.key;
  const tag = TYPE_TAG[d.type] ? `<span class="tag" title="IONOS type ${esc(d.type)}">${TYPE_TAG[d.type]}</span>` : '';
  const path = d.webspacePath ? `<code title="Webspace path">${esc(d.webspacePath === '/.' ? '/ (root)' : d.webspacePath)}</code>` : '';
  const dest = DEST[d.destination] || d.destination || '';
  const email = d._emails.length ? `${pill(d._email)} <span class="when">${d._emails.length}✉</span>` : statusBtn('domain', d.key, statusOf(d, 'email'), 'email');
  const fl = [d.blockers ? `<span class="flag block" title="Blocker: ${esc(d.blockers)}">!</span>` : '', d.notes ? `<span class="flag" title="${esc(d.notes.slice(0, 300))}">✎</span>` : '',
    d.missing?.length ? `<span class="flag miss" title="Missing: ${esc(d.missing.join(', '))}">?</span>` : ''].join('');
  const ws = statusOf(d, 'website');
  return `<tr class="row${active ? ' active' : ''}" data-key="${esc(d.key)}">
    <td><div class="dn"${d._parent ? ' style="padding-left:14px"' : ''}>${d._parent ? '<span class="sub">↳</span>' : ''}<a data-act="open" data-key="${esc(d.key)}">${esc(d.domain)}</a>${tag}</div>
      <div class="meta"${d._parent ? ' style="padding-left:14px"' : ''}>${techMini(d)}${dest ? `<span>${esc(dest)}</span>` : ''}${path}</div></td>
    <td>${serverCell(d, h)}</td><td>${siteCell(h)}</td><td>${sslCell(h)}</td>
    <td>${statusBtn('domain', d.key, statusOf(d, 'domain'), 'domain')}</td>
    <td>${statusBtn('domain', d.key, ws, 'website', d.track?.website?.by === 'scan' ? `title="Set by scan ${esc(ago(d.track.website.at))}. Click to change."` : '')}${d.track?.website?.by === 'scan' ? '<span class="autot" title="Set automatically by a scan">auto</span>' : ''}</td>
    <td class="nowrap">${email}</td>
    <td class="c-act"><div>${fl}<button class="ibtn" data-act="scan-dom" data-key="${esc(d.key)}" title="Rescan this domain">${ICONS.refresh}</button></div></td></tr>`;
}

// ---------- Email ----------
function viewEmail() {
  const idx = S.idx;
  if (!idx.emails.length) {
    const mx = idx.domains.filter(FLAGS.find(f => f.k === 'mxionos').fn);
    return `<div class="card empty" style="margin-bottom:14px"><h2>No email list imported yet</h2>
      <p>Import a mailbox/forwarding export when you have it. Records are linked to domains by address, and to contracts by contract number when the file has one.<br>Email is tracked separately from the domain and the website.</p>
      <button class="btn primary" data-act="import" data-kind="email">${ICONS.upload} Import email list</button></div>
      <div class="card"><div class="card-h"><h3>Domains whose MX points to IONOS</h3><span class="muted" style="margin-left:auto">${mx.length}</span></div>
      <div class="card-b"><div class="hint" style="margin-bottom:8px">From the IONOS export and scans. These domains probably have mailboxes to move.</div>
      <table class="mt"><thead><tr><th>Domain</th><th>Contract</th><th>Email status</th><th>MX source</th></tr></thead><tbody>
      ${mx.map(d => `<tr><td><button class="linkbtn" data-act="open" data-key="${esc(d.key)}">${esc(d.domain)}</button></td><td class="muted">${esc(d.contract || '—')}</td><td>${statusBtn('domain', d.key, statusOf(d, 'email'), 'email')}</td><td class="muted">${d.scan?.flags?.mxIonos ? 'Scan' : 'Export'}</td></tr>`).join('')}
      </tbody></table></div></div>`;
  }
  const ef = S.ef;
  const q = S.q.toLowerCase();
  const list = idx.emails.filter(e => (!ef.status || e.status === ef.status) && (!ef.link || (ef.link === 'unlinked' ? !e.domainKey && !e.contractKey : !!e.domainKey))
    && (!q || `${e.address} ${e.domain} ${e.type} ${e.product} ${e.notes} ${e.forward}`.toLowerCase().includes(q)))
    .sort((a, b) => (a.domain || '').localeCompare(b.domain || '') || (a.address || '').localeCompare(b.address || ''));
  S.evisible = list.map(e => e.id);
  const unlinked = idx.emails.filter(e => !e.domainKey && !e.contractKey).length;
  const c = { total: 0, na: 0, by: {} };
  for (const e of idx.emails) { c.total++; if (e.status === 'na') c.na++; c.by[e.status] = (c.by[e.status] || 0) + 1; }
  const con = k => S.data.contracts[k];
  return `<div class="card" style="margin-bottom:14px"><div class="card-b"><div class="sp-prog"><span>Email</span>${bar(c)}<b>${c.by.verified || 0} / ${c.total - c.na}</b><span>verified</span></div></div></div>
  <div class="toolbar"><button class="chip${ef.status ? ' on' : ''}" data-act="ef-status">Status${ef.status ? `: <b>${esc(SL[ef.status])}</b>` : ''} ${ICONS.down}</button>
    <span class="seg">${[['', 'All'], ['linked', 'Linked to a domain'], ['unlinked', `Not linked ${unlinked}`]].map(([k, l]) => `<button class="${ef.link === k ? 'on' : ''}" data-act="ef-link" data-v="${k}">${l}</button>`).join('')}</span>
    <span class="grow"></span><span class="muted">${list.length} of ${idx.emails.length}</span>
    <button class="btn sm" data-act="ebulk-status" ${list.length ? '' : 'disabled'}>Set status for ${list.length} shown ${ICONS.down}</button>
    <button class="btn sm" data-act="import" data-kind="email">${ICONS.upload} Import email list</button></div>
  <div class="tbl-wrap"><table class="t"><thead><tr><th>Address</th><th>Type</th><th>Domain</th><th>Contract</th><th>Status</th><th>Notes</th></tr></thead><tbody>
  ${list.slice(0, S.showAll.email ? 5000 : 400).map(e => `<tr class="row">
    <td><button class="linkbtn" data-act="open-email" data-id="${esc(e.id)}"><b>${esc(e.address || e.id)}</b></button>${e.forward ? `<div class="meta">→ ${esc(e.forward)}</div>` : ''}</td>
    <td class="muted">${esc(e.type || '—')}${e.size ? ` · ${esc(e.size)}` : ''}</td>
    <td>${e.domainKey ? `<button class="linkbtn" data-act="open" data-key="${esc(e.domainKey)}">${esc(e.domain)}</button>` : `<span class="muted">${esc(e.domain || '—')}</span> <span class="flag miss" style="display:inline-grid" title="Not linked to an imported domain">?</span>`}</td>
    <td class="muted">${e.contractKey && con(e.contractKey) ? esc(con(e.contractKey).number || '(none)') : '—'}</td>
    <td>${statusBtn('email', e.id, e.status)}</td>
    <td class="muted" style="max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(e.notes || '')}</td></tr>`).join('')}
  ${list.length > 400 && !S.showAll.email ? `<tr class="more-row"><td colspan="6"><button class="btn sm" data-act="show-all" data-k="email">Show all ${list.length}</button></td></tr>` : ''}
  </tbody></table></div>`;
}

// ---------- Review lists ----------
// What the agent can answer and what you can decide depend on the list type (public/reviewtypes.js).
const reviewLists = () => Object.values(S.data?.reviews || {}).sort((a, b) => b.createdAt.localeCompare(a.createdAt));
const answered = i => !!(i.agent?.verdict || i.agent?.note);
const vMeta = (l, k) => verdictMeta(typeOf(l), k);
const oMeta = (l, k) => outcomeMeta(typeOf(l), k, S.data.settings);
function rvCounts(l) {
  const c = { n: l.items.length, reviewed: 0, notes: 0, decided: 0, done: 0, issue: 0, waiting: 0, v: {}, o: {} };
  for (const i of l.items) {
    const v = i.agent?.verdict, o = i.admin?.outcome;
    if (v) { c.reviewed++; c.v[v] = (c.v[v] || 0) + 1; }
    if (i.agent?.note) c.notes++;
    if (o) { c.decided++; c.o[o] = (c.o[o] || 0) + 1; if (oMeta(l, o).done) c.done++; else c.issue++; }
    if (answered(i) && !o) c.waiting++; // the agent answered, you have not decided yet
  }
  return c;
}
// Segments for the progress bars: one per agent answer, one per decision, in the type's order.
const agentParts = (l, c) => typeOf(l).verdicts.map(v => ({ n: c.v[v.k] || 0, c: v.c, l: v.l }));
function outcomeParts(l, c) {
  const known = typeOf(l).outcomes(S.data.settings);
  const extra = Object.keys(c.o).filter(k => !known.some(o => o.k === k)).map(k => oMeta(l, k));
  return [...known, ...extra].map(o => ({ n: c.o[o.k] || 0, c: o.c, l: o.l }));
}
const partsText = parts => parts.filter(p => p.n).map(p => `${esc(p.l)} ${p.n}`).join(' · ');
function rvFilters(l) {
  return [
    { k: '', l: 'All', fn: () => true },
    { k: 'waiting', l: 'Needs your decision', fn: i => answered(i) && !i.admin?.outcome },
    { k: 'pending', l: 'Awaiting agent', fn: i => !i.agent?.verdict },
    ...typeOf(l).verdicts.map(v => ({ k: `v:${v.k}`, l: v.l, fn: i => i.agent?.verdict === v.k })),
    { k: 'note', l: 'Agent notes', fn: i => !!i.agent?.note },
    { k: 'issue', l: 'Issues', fn: i => i.admin?.outcome === 'issue' },
    { k: 'done', l: 'Done', fn: i => !!oMeta(l, i.admin?.outcome)?.done },
  ];
}
function shareBase() {
  const ri = S.rinfo;
  if (ri?.baseUrl) return ri.baseUrl;
  if (ri?.share?.on && ri.share.urls[0]) return ri.share.urls[0];
  return location.origin;
}
const shareUrl = l => `${shareBase().replace(/\/+$/, '')}/r/${l.id}`;
function rvBar(n, parts) {
  return `<div class="sbar rv-bar">${n ? parts.map(p => `<i class="c-${p.c}" style="width:${((p.n / n) * 100).toFixed(2)}%"></i>`).join('') : ''}</div>`;
}

function viewReviews() {
  const l = S.rl && S.data.reviews[S.rl];
  if (S.rl && !l) S.rl = '';
  return l ? reviewDetail(l) : reviewHome();
}

function reviewHome() {
  const lists = reviewLists();
  const rows = lists.map(l => {
    const c = rvCounts(l);
    const parts = agentParts(l, c);
    return `<div class="con rv-row" data-act="rv-open" data-id="${esc(l.id)}">
      <div class="rv-row-t"><b>${esc(l.name)}</b>${l.closed ? ' <span class="tag">Closed</span>' : ''}
        <div class="meta"><span class="tag">${esc(typeOf(l).l)}</span> ${fmt(l.createdAt)} · ${l.people?.length ? esc(l.people.map(p => p.name).join(', ')) : 'not opened yet'}</div></div>
      <div class="rv-row-p" title="${esc(parts.map(p => `${p.l} ${p.n}`).join(' · '))} · awaiting ${c.n - c.reviewed}">${rvBar(c.n, parts)}<span class="num">${c.reviewed}/${c.n}</span></div>
      <div class="con-i">${c.waiting ? `<span class="iss c-warn">${c.waiting} need your decision</span>` : ''}${c.issue ? `<span class="iss c-warn">${plural(c.issue, 'issue')}</span>` : ''}${!c.waiting && !c.issue ? `<span class="faint">${c.reviewed ? `${c.decided} decided` : 'No answers yet'}</span>` : ''}</div>
      <button class="ibtn rv-del" data-act="rv-delete" data-id="${esc(l.id)}" title="Delete this list">${ICONS.trash}</button>
    </div>`;
  }).join('');
  return `<div class="grid two">
    <div class="grid" style="align-content:start">
      ${lists.length ? `<div class="cons">${rows}</div>` : `<div class="card empty"><h2>No review lists yet</h2>
        <p>On Contracts, filter the domains you want checked, for example <b>Site: Down</b> with <b>Domains</b>, then click <b>Create review list</b>.<br>You get a link and a password to send to the agent.</p>
        <button class="btn primary" data-act="nav" data-view="contracts">Go to Contracts</button></div>`}
    </div>
    <div class="grid" style="align-content:start">${reviewSettingsCard()}</div></div>`;
}

function reviewSettingsCard() {
  const ri = S.rinfo;
  if (!ri) return '<div class="card"><div class="card-b hint">Review settings could not be loaded.</div></div>';
  const sh = ri.share;
  const shareText = sh.on
    ? `On. Agents on your network open review links at <code>${esc(sh.urls[0] || `port ${sh.port}`)}</code>${sh.urls.length > 1 ? ` (or ${sh.urls.slice(1).map(u => `<code>${esc(u)}</code>`).join(', ')})` : ''}.`
    : sh.want && sh.error ? `<span class="warnc">${esc(sh.error)}</span>` : 'Off. Review links only open on this Mac.';
  return `<div class="card"><div class="card-h"><h3>Sharing review links</h3></div><div class="card-b">
    <div class="rv-set"><div><b>Master password</b><div class="hint">${ri.masterSet ? 'Set. Every list uses it unless the list has its own password.' : 'Not set yet. You set it when you create your first list, or here.'}</div></div>
      <button class="btn sm" data-act="rv-master">${ri.masterSet ? 'Change' : 'Set password'}</button></div>
    ${ri.hosted ? `<div class="rv-set"><div><b>Review links</b><div class="hint">Online. Agents open links at <code>${esc(shareBase())}/r/…</code> from anywhere, each behind its password. They never see the tracker itself.</div></div></div>` : `
    <div class="rv-set"><div><b>Network sharing</b><div class="hint">${shareText}</div></div>
      <span class="seg"><button class="${!sh.want ? 'on' : ''}" data-act="rv-share" data-v="0">Off</button><button class="${sh.want ? 'on' : ''}" data-act="rv-share" data-v="1">On</button></span></div>
    <div class="hint" style="margin:8px 0 14px">Port ${sh.port} serves review pages only, each behind its password. The tracker itself stays on this Mac. The first time, macOS may ask whether Node can accept incoming connections: allow it.</div>
    <label class="field"><span>Public address (optional)</span><div style="display:flex;gap:6px"><input class="in mono" id="rvBase" value="${esc(ri.baseUrl)}" placeholder="https://review.example.com"><button class="btn sm" data-act="rv-base">Save</button></div>
      <span class="hint">For agents outside your network: run a tunnel (for example Cloudflare Tunnel) to <code>http://localhost:${sh.port}</code> with network sharing on, and enter the tunnel's address here. Links then use it.</span></label>`}
  </div></div>`;
}

function reviewDetail(l) {
  const c = rvCounts(l);
  const t = typeOf(l);
  const filters = rvFilters(l);
  const f = filters.find(x => x.k === S.rvf) || filters[0];
  const ws = words();
  const hay = i => `${i.domain} ${i.contract} ${i.agent?.note || ''} ${i.admin?.note || ''} ${i.agent?.by || ''}`.toLowerCase();
  // Rows you just decided stay in place until the filter changes.
  const items = l.items.filter(i => (f.fn(i) || S.rvStick.has(i.key)) && ws.every(w => hay(i).includes(w)));
  S.rvVisible = items.map(i => i.key);
  const local = !S.rinfo?.baseUrl && !S.rinfo?.share?.on;
  const people = (l.people || []).slice().sort((a, b) => b.lastAt.localeCompare(a.lastAt));
  const pwName = l.pwMode === 'own' ? 'its own password' : 'the master password';
  return `<div class="rv-crumb"><button class="btn sm ghost" data-act="rv-home">${ICONS.back} All review lists</button></div>
  <section class="card rv-head">
    <div class="rv-h1"><h2>${esc(l.name)}</h2>${l.closed ? '<span class="pill s-na"><i></i>Closed</span>' : '<span class="pill s-in_progress"><i></i>Open for answers</span>'}
      <span class="grow"></span><button class="btn sm ghost danger" data-act="rv-delete" data-id="${esc(l.id)}">${ICONS.trash} Delete list</button>
      <button class="ibtn" data-act="rv-menu" title="Rename, close, download">${ICONS.more}</button></div>
    <div class="meta"><span class="tag">${esc(t.l)}</span> Created ${fmt(l.createdAt)}${l.from ? ` · from ${esc(l.from)}` : ''} · ${plural(c.n, 'domain')}</div>
    <div class="rv-share"><input class="in mono" id="rvUrl" readonly value="${esc(shareUrl(l))}">
      <button class="btn sm primary" data-act="rv-copy">Copy link</button>
      <a class="btn sm" href="/r/${esc(l.id)}" target="_blank" rel="noopener noreferrer" title="Open the agent's page on this Mac">${ICONS.ext} Preview</a></div>
    <div class="hint">${local ? `<span class="warnc">This link only opens on this Mac.</span> <button class="linkbtn" data-act="rv-share" data-v="1">Turn on network sharing</button> so an agent on your network can open it. ` : `Send the agent this link and ${pwName}. `}
      Signs in with <button class="linkbtn" data-act="rv-pw">${pwName}</button>.</div>
    <div class="rv-stats">
      <div class="rv-stat"><span class="hl">Agent</span>${rvBar(c.n, agentParts(l, c))}<b>${c.reviewed}/${c.n}</b><span class="muted">reviewed${c.reviewed ? ` · ${partsText(agentParts(l, c))}` : ''}${c.notes ? ` · ${plural(c.notes, 'note')}` : ''}</span></div>
      <div class="rv-stat"><span class="hl">You</span>${rvBar(c.n, outcomeParts(l, c))}<b>${c.decided}/${c.n}</b><span class="muted">decided${c.decided ? ` · ${partsText(outcomeParts(l, c))}` : ''}</span></div>
    </div>
    <div class="meta">${people.length ? `Reviewers: ${people.map(p => `<b>${esc(p.name)}</b> <span class="faint">${esc(ago(p.lastAt))}</span>`).join(' · ')}` : 'Nobody has opened this list yet.'}</div>
  </section>
  <div class="toolbar">
    <span class="seg">${filters.map(x => { const n = l.items.filter(x.fn).length; return `<button class="${S.rvf === x.k ? 'on' : ''}" data-act="rvf" data-v="${x.k}" ${n || S.rvf === x.k ? '' : 'disabled'}>${x.l}<span class="cnt" style="margin-left:2px">${n}</span></button>`; }).join('')}</span>
    <span class="grow"></span>
    <span class="rv-tools">
      <button class="btn sm" data-act="rv-bulk" ${items.length ? '' : 'disabled'}>Decision for ${items.length} shown ${ICONS.down}</button>
      <button class="btn sm" data-act="rv-rescan" ${items.length ? '' : 'disabled'} title="Check server, site and SSL again for the domains shown">${ICONS.refresh} Rescan ${items.length === c.n ? 'all' : items.length}</button>
      <button class="btn sm ghost" data-act="rv-csv" title="Download every row with answers and decisions">${ICONS.dl} CSV</button></span>
  </div>
  <div class="tbl-wrap"><table class="t rvt rvt-${t.k}"><colgroup><col class="w-d"><col class="w-now"><col class="w-ag"><col class="w-dec"><col class="w-note"></colgroup>
    <thead><tr><th>Domain</th><th title="From the latest scan">Now</th><th>Agent review</th><th>Your decision</th><th title="Shown to the agent on their page">Note to agent</th></tr></thead>
    <tbody>${items.map(i => rvRow(l, i)).join('') || '<tr class="more-row"><td colspan="5">Nothing matches.</td></tr>'}</tbody></table></div>`;
}

// Decision buttons, grouped as the type defines them (e.g. "Moved to: VPS 114 | VPS 212").
function decisionCell(l, i) {
  const outs = typeOf(l).outcomes(S.data.settings);
  const cur = i.admin?.outcome;
  if (cur && !outs.some(o => o.k === cur)) outs.push(oMeta(l, cur)); // e.g. a VPS since removed from Settings
  const groups = [];
  for (const o of outs) {
    const last = groups[groups.length - 1];
    if (last && last.g === (o.g || '')) last.items.push(o);
    else groups.push({ g: o.g || '', items: [o] });
  }
  // One compact row: groups split by a thin divider, short labels with an icon, the full name on hover.
  const btn = o => `<button class="${cur === o.k ? `on o-${o.c}` : ''}" data-act="rv-out" data-v="${esc(o.k)}" title="${esc(o.l)}${cur === o.k ? ' · click again to clear' : ''}" aria-label="${esc(o.l)}" aria-pressed="${cur === o.k}">${o.ic ? ri(o.ic) : ''}${esc(o.s || o.l)}</button>`;
  return `<span class="seg rv-dec">${groups.map(gr => gr.items.map(btn).join('')).join('<i class="rv-sep" aria-hidden="true"></i>')}</span>`;
}

function rvRow(l, i) {
  const d = S.data.domains[i.key];
  const h = d?._h;
  const was = i.snap;
  const site = h ? SITE[h.site] : was ? SITE[was.site] : null;
  const changed = h && was && h.site !== was.site;
  const ag = i.agent || {};
  const v = vMeta(l, ag.verdict);
  const when = ag.verdictAt || ag.noteAt;
  const ip = h?.ip || was?.ip;
  return `<tr class="row" data-key="${esc(i.key)}">
    <td><div class="dn">${d ? `<a data-act="open" data-key="${esc(i.key)}" title="Domain details">${esc(i.domain)}</a>` : `<b>${esc(i.domain)}</b>`}${i.sub ? '<span class="tag">Sub</span>' : ''}</div>
      <div class="meta">${i.contract ? `Contract ${esc(i.contract)}` : 'No contract number'}${d ? '' : ' · <span class="warnc">no longer in the tracker</span>'}</div></td>
    <td>${site ? `<span class="hs c-${site.c}"><i></i>${site.l}</span>` : '<span class="faint">Not scanned</span>'}${changed ? `<span class="autot" title="Site status when the list was made">was ${esc(SITE[was.site]?.l || was.site)}</span>` : ''}
      <div class="meta">${esc(h ? (h.onVps ? bmeta(h.bucket).l : h.server) : was?.server || '')}</div>${ip ? `<div class="meta mono">${esc(ip)}</div>` : ''}</td>
    <td>${v ? `<span class="hs c-${v.c}"><i></i>${v.l}</span>` : `<span class="faint">${ag.openedAt ? 'Opened, no answer yet' : 'Awaiting agent'}</span>`}
      ${ag.note ? `<div class="rv-note">${esc(ag.note)}</div>` : ''}
      ${ag.by && when ? `<div class="meta">${esc(ag.by)} · ${esc(ago(when))}${ag.openedAt ? ' · opened the site' : ''}</div>` : ''}</td>
    <td>${decisionCell(l, i)}</td>
    <td><textarea class="in rv-in" rows="1" maxlength="4000" data-rvnote="${esc(i.key)}" placeholder="Note to agent">${esc(i.admin?.note || '')}</textarea></td>
  </tr>`;
}

function exportReviewCsv(l) {
  const rows = [['List type', 'Domain', 'Contract', 'Subdomain', 'Site when listed', 'Site now', 'Server now', 'IP', 'Agent answer', 'Agent note', 'Agent', 'Answered at', 'Opened site at', 'Your decision', 'Note to agent']];
  for (const i of l.items) {
    const h = S.data.domains[i.key]?._h;
    const ag = i.agent || {};
    rows.push([typeOf(l).l, i.domain, i.contract, i.sub ? 'yes' : '', i.snap ? SITE[i.snap.site]?.l : '', h ? SITE[h.site]?.l : '', h ? (h.onVps ? bmeta(h.bucket).l : h.server) : '', h?.ip || i.snap?.ip,
      vMeta(l, ag.verdict)?.l, ag.note, ag.by, ag.verdictAt || ag.noteAt, ag.openedAt, oMeta(l, i.admin?.outcome)?.l, i.admin?.note]);
  }
  downloadCsv(rows, `review-${l.name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 40) || 'list'}-${new Date().toISOString().slice(0, 10)}.csv`);
}

function drReviews(d) {
  const ls = reviewLists().map(l => [l, l.items.find(i => i.key === d.key)]).filter(([, i]) => i);
  if (!ls.length) return '';
  return `<div class="sec"><h4>Reviews <span class="r hint">${plural(ls.length, 'list')}</span></h4><div class="items">${ls.map(([l, i]) => {
    const v = vMeta(l, i.agent?.verdict), o = oMeta(l, i.admin?.outcome);
    return `<div class="item"><span style="flex:1"><button class="linkbtn" data-act="rv-open" data-id="${esc(l.id)}"><b>${esc(l.name)}</b></button> ·
      ${v ? `<span class="hs c-${v.c}"><i></i>${v.l}</span>${i.agent?.by ? ` <span class="muted">${esc(i.agent.by)}</span>` : ''}` : '<span class="faint">awaiting agent</span>'}${o ? ` · you: <span class="hs c-${o.c}"><i></i>${o.l}</span>` : ''}
      ${i.agent?.note ? `<div class="hint">Agent: ${esc(i.agent.note)}</div>` : ''}${i.admin?.note ? `<div class="hint">You: ${esc(i.admin.note)}</div>` : ''}</span></div>`;
  }).join('')}</div></div>`;
}

async function copyText(s) {
  try { await navigator.clipboard.writeText(s); return true; } catch {}
  const el = $('#rvUrl');
  if (el) { el.select(); try { return document.execCommand('copy'); } catch {} }
  return false;
}

// ---------- Settings ----------
function randomToken(id) {
  const b = new Uint8Array(9);
  crypto.getRandomValues(b);
  return `migration-check:${id}:${btoa(String.fromCharCode(...b)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')}`;
}
function viewSettings() {
  if (!S.draft || !S.draftDirty) S.draft = JSON.parse(JSON.stringify(S.data.settings));
  const s = S.draft;
  const mp = s.markerPath || '/.well-known/migration-check.txt';
  const dir = mp.slice(0, mp.lastIndexOf('/')) || '';
  const idx = S.idx;
  return `<div class="grid two">
  <div class="grid" style="align-content:start">
    <div class="card"><div class="card-h"><h3>Destination VPS</h3><button class="btn sm" data-act="vps-add" style="margin-left:auto">Add VPS</button></div><div class="card-b">
      <div class="hint" style="margin-bottom:10px">Scans compare DNS records with these addresses. Anything else is flagged as not on a VPS. IPv4 and IPv6 are checked separately; CIDR ranges are allowed. Each VPS has its own marker token, so a scan can tell which server answered.</div>
      ${s.vps.map((v, i) => `<div class="card vps-card">
        <div class="row2"><label class="field"><span>Name</span><input class="in" data-set="vps.${i}.name" value="${esc(v.name)}"></label>
        <label class="field"><span>Marker token</span><div style="display:flex;gap:6px"><input class="in mono" data-set="vps.${i}.token" value="${esc(v.token)}"><button class="btn sm" data-act="vps-token" data-i="${i}" title="Generate a new token">New</button></div></label></div>
        <div class="row2"><label class="field"><span>IPv4 addresses (comma-separated)</span><input class="in mono" data-set="vps.${i}.ipv4" data-list="1" value="${esc((v.ipv4 || []).join(', '))}"></label>
        <label class="field"><span>IPv6 addresses</span><input class="in mono" data-set="vps.${i}.ipv6" data-list="1" value="${esc((v.ipv6 || []).join(', '))}" placeholder="none"></label></div>
        <label class="field"><span>Source template for sites on this VPS (optional, for deeper tech detection)</span><input class="in mono" data-set="vps.${i}.sourceTemplate" value="${esc(v.sourceTemplate || '')}" placeholder="root@vps-host:/var/www/vhosts/{domain}/httpdocs"></label>
        <div style="text-align:right"><button class="btn sm danger" data-act="vps-del" data-i="${i}">Remove</button></div>
      </div>`).join('')}
    </div></div>
    <div class="card"><div class="card-h"><h3>Verification marker</h3></div><div class="card-b">
      <label class="field"><span>Marker path (served by each migrated site)</span><input class="in mono" data-set="markerPath" value="${esc(s.markerPath || '')}"></label>
      <div class="hint">A matching IP is not proof on its own. Put a small text file at this path in each site's document root on the destination VPS, containing that VPS's token. A scan then sets the website to <b>Verified</b> automatically when DNS, HTTPS and the marker all agree. Without the marker, a healthy site on a VPS is set to <b>Moved</b>.</div>
      ${s.vps.map(v => `<div style="margin-top:12px"><b>${esc(v.name)}</b>: file content
        <pre class="snip">${esc(v.token)}</pre>
        <span class="hint">Plesk example: writes the file into every vhost's httpdocs (adjust if a site uses a different document root):</span>
        <pre class="snip">for d in /var/www/vhosts/*/httpdocs; do mkdir -p "$d${esc(dir)}" &amp;&amp; printf '%s\\n' '${esc(v.token)}' &gt; "$d${esc(mp)}"; done</pre></div>`).join('')}
    </div></div>
  </div>
  <div class="grid" style="align-content:start">
    <div class="card"><div class="card-h"><h3>Scanning</h3><button class="btn primary sm" data-act="settings-save" style="margin-left:auto">Save settings</button></div><div class="card-b">
      <label class="field"><span>Old hosting ranges (one IP or CIDR per line)</span><textarea class="in mono" rows="3" data-set="oldRanges" data-lines="1">${esc((s.oldRanges || []).join('\n'))}</textarea>
      <span class="hint">Default: IONOS shared hosting (217.160.0.0/16, 2001:8d8::/32). Other addresses are named from reverse DNS where possible (for example another IONOS server, Wix or AWS).</span></label>
      <div class="row3"><label class="field"><span>DNS resolvers</span><input class="in mono" data-set="resolvers" data-list="1" value="${esc((s.resolvers || []).join(', '))}"></label>
      <label class="field"><span>Sites scanned at once</span><input class="in" type="number" min="1" max="16" data-set="concurrency" value="${esc(s.concurrency)}"></label>
      <label class="field"><span>Timeout (ms)</span><input class="in" type="number" min="3000" max="30000" step="1000" data-set="timeoutMs" value="${esc(s.timeoutMs)}"></label></div>
      <div style="display:flex;gap:8px;align-items:center"><button class="btn primary" data-act="settings-save">Save settings</button>${S.draftDirty ? '<span class="hint">Unsaved changes</span>' : ''}</div>
    </div></div>
    <div class="card"><div class="card-h"><h3>Accounts and source access</h3></div><div class="card-b">
      <div class="hint" style="margin-bottom:10px">For deeper technology detection, give a source template per account. It applies to domains connected to webspace. Use <code>{path}</code> for the IONOS webspace path and <code>{domain}</code> for the domain. Either a local folder (for example a downloaded or mounted copy of the webspace) or <code>user@host:/path</code> over SSH with key-based login. Only a listing and known config files are read; passwords are never extracted or stored.</div>
      ${idx.accounts.map(a => `<div class="card vps-card">
        <div class="row2"><label class="field"><span>Account name</span><input class="in" id="an-${esc(a.id)}" value="${esc(a.name)}"></label>
        <label class="field"><span>Source template</span><input class="in mono" id="as-${esc(a.id)}" value="${esc(a.sourceTemplate || '')}" placeholder="/Volumes/Backup/webspace{path}"></label></div>
        <div style="display:flex;gap:8px;align-items:center"><span class="hint">Last import: ${esc(a.lastImport?.file || '—')} · ${fmt(a.lastImport?.at)}</span><span style="flex:1"></span>
        <button class="btn sm" data-act="acct-save" data-id="${esc(a.id)}">Save</button><button class="btn sm danger" data-act="acct-del" data-id="${esc(a.id)}">Delete account data</button></div></div>`).join('') || '<div class="muted">No accounts imported.</div>'}
    </div></div>
    <div class="card"><div class="card-h"><h3>Data</h3></div><div class="card-b">
      <div class="hint" style="margin-bottom:10px">Everything is saved to <code>data/store.json</code> in the app folder. A backup is taken automatically before every import or deletion (last 30 in <code>data/backups</code>).</div>
      <div style="display:flex;gap:8px"><a class="btn" href="/api/export">Download JSON export</a><button class="btn" data-act="backup">Back up now</button></div>
    </div></div>
  </div></div>`;
}

// ---------- Drawer ----------
function openDrawer(type, id) {
  S.drawer = { type, id };
  S._drSig = '';
  render();
}
function closeDrawer() { S.drawer = null; render(); }
function renderDrawer() {
  const el = $('#drawer');
  const dr = S.drawer;
  if (!dr) { el.hidden = true; el.innerHTML = ''; S._drSig = ''; return; }
  const ent = dr.type === 'domain' ? S.data.domains[dr.id] : dr.type === 'contract' ? S.data.contracts[dr.id] : dr.type === 'email' ? S.data.emails[dr.id] : dr.type === 'log' ? {} : null;
  if (!ent) { S.drawer = null; el.hidden = true; return; }
  const runSig = dr.type === 'domain' ? `${running(dr.id, 'verify')}${running(dr.id, 'tech')}` : '';
  const sig = `${dr.type}|${dr.id}|${S.rev}|${runSig}|${JSON.stringify(S.showAll)}|${dr.type === 'log' ? Math.floor(Date.now() / 5000) : ''}`;
  if (sig === S._drSig) return;
  const ae = document.activeElement;
  if (el.contains(ae) && /INPUT|TEXTAREA|SELECT/.test(ae.tagName)) { S._drDirty = true; return; }
  S._drSig = sig;
  S._drDirty = false;
  const body = $('.dr-b', el);
  const top = body && el.dataset.k === `${dr.type}|${dr.id}` ? body.scrollTop : 0;
  el.dataset.k = `${dr.type}|${dr.id}`;
  el.hidden = false;
  el.innerHTML = dr.type === 'domain' ? drawerDomain(ent) : dr.type === 'contract' ? drawerContract(ent) : dr.type === 'log' ? drawerLog() : drawerEmail(ent);
  const nb = $('.dr-b', el);
  if (nb) nb.scrollTop = top;
}
function drawerHead(title, crumb, acts = '') {
  return `<div class="dr-h"><div class="dr-top"><div style="min-width:0"><h2>${title}</h2><div class="crumb">${crumb}</div></div>
    <div class="acts">${acts}<button class="btn sm ghost" data-act="close-drawer" title="Close (Esc)">${ICONS.x}</button></div></div></div>`;
}
// Collapsible section whose open/closed state survives re-renders.
const det = (k, title, body, right = '') => `<details class="dsec" data-det="${k}" ${S.det.has(k) ? 'open' : ''}><summary>${title}${right ? `<span class="r">${right}</span>` : ''}</summary><div class="dsec-b">${body}</div></details>`;

function drawerDomain(d) {
  const acct = S.data.accounts[d.accountId];
  const c = S.data.contracts[d.contractKey];
  const h = d._h;
  const run = running(d.key, 'verify');
  const crumb = `${esc(acct?.name || '')} › <button class="linkbtn" data-act="open-contract" data-key="${esc(d.contractKey)}">${c?.number ? `Contract ${esc(c.number)}` : 'No contract number'}</button> · <a href="https://${esc(d.domain)}" target="_blank" rel="noopener noreferrer">open site ↗</a>`;
  const acts = `<button class="btn sm" data-act="scan-one" data-kind="verify" ${run ? 'disabled' : ''}>${run ? '<span class="spin"></span> Scanning' : `${ICONS.refresh} Rescan`}</button>
    <button class="btn sm ghost" data-act="dr-step" data-n="-1" title="Previous (k)">${ICONS.up}</button><button class="btn sm ghost" data-act="dr-step" data-n="1" title="Next (j)">${ICONS.down}</button>`;
  const techRight = d.techManual?.stack ? esc(d.techManual.label || STACKS[d.techManual.stack]) : d.tech ? esc(d.tech.stack.label) : 'not scanned';
  return `${drawerHead(esc(d.domain), crumb, acts)}<div class="dr-b">
    ${healthCard(d, h)}
    ${statusSec(d)}
    ${drReviews(d)}
    ${det('scan', 'Scan details', scanDetails(d), d.scan ? `${(d.scan.checks || []).filter(x => x.level === 'fail').length} failed checks` : '')}
    ${det('tech', 'Technology', drTech(d), techRight)}
    ${det('email', 'Email', drEmail(d), d._emails.length ? plural(d._emails.length, 'record') : '')}
    ${det('ionos', 'IONOS export data', drIonos(d), d.missing?.length ? `<span class="warnc">missing ${esc(d.missing.length)}</span>` : '')}
    ${det('activity', 'Activity', (d.log || []).length ? `<div class="items">${d.log.slice(0, 20).map(l => `<div class="item"><span class="muted nowrap">${fmt(l.at)}</span><span>${esc(l.text)}</span></div>`).join('')}</div>` : '<div class="hint">No changes yet.</div>', (d.log || []).length ? ago(d.log[0].at) : '')}
    </div><div class="dr-f">j / k next and previous · r rescan · Esc close</div>`;
}

function healthCard(d, h) {
  if (!h) {
    const ip = d.exportIps?.v4?.[0];
    const v = exportVps(d, S.data.settings);
    return `<div class="banner"><span class="dot"></span><div style="flex:1"><div class="bt">Not scanned yet</div>${ip ? `The IONOS export lists ${esc(ip)}${v ? ` (${esc(bmeta(`vps:${v.id}`).l)})` : ''}. A scan shows where DNS really points, whether the site is up and whether SSL is valid.` : 'A scan shows where DNS points, whether the site is up and whether SSL is valid.'}</div>
      <button class="btn sm primary" data-act="scan-one" data-kind="verify" ${running(d.key, 'verify') ? 'disabled' : ''}>Scan now</button></div>`;
  }
  const b = bmeta(h.bucket);
  const site = SITE[h.site];
  const ssl = h.ssl ? SSL[h.ssl] : null;
  const ws = d.track?.website?.status;
  return `<div class="hgrid">
    <div class="htile"><div class="hk">Server</div><div class="hv c-${b.c}"><i></i>${esc(h.bucket === 'mixed' || !b.k.startsWith('vps:') ? h.server : b.l)}</div>
      <div class="hd mono">${esc(h.ip || '—')}</div>${h.ptr ? `<div class="hd" title="Reverse DNS">${esc(h.ptr)}</div>` : ''}
      ${h.odd.length ? `<div class="hd warnc">${h.odd.map(o => `${esc(o.text)} · ${esc(o.label)}`).join('<br>')}</div>` : ''}</div>
    <div class="htile"><div class="hk">Site</div><div class="hv c-${site.c}"><i></i>${site.l}</div><div class="hd">${esc(h.siteDetail || '')}</div>
      ${h.finalUrl ? `<div class="hd">${esc(h.finalUrl)}</div>` : ''}${h.siteError && h.siteError !== h.siteDetail ? `<div class="hd">${esc(h.siteError)}</div>` : ''}${h.wwwIssue ? `<div class="hd warnc">${esc(h.wwwIssue)}</div>` : ''}</div>
    <div class="htile"><div class="hk">SSL</div>${ssl ? `<div class="hv c-${h.sslSoon ? 'warn' : ssl.c}"><i></i>${h.sslSoon ? 'Expiring soon' : ssl.l}</div><div class="hd">${esc(h.sslDetail || '')}</div>
      ${h.cert ? `<div class="hd">${esc(h.cert.subject)}${h.cert.issuer ? ` · ${esc(h.cert.issuer)}` : ''}</div>` : ''}` : '<div class="hv c-none"><i></i>—</div><div class="hd">Not checked: site not reachable</div>'}</div>
  </div>
  <div class="hfoot"><span class="pill v-${h.verdict}" title="Marker-based verdict"><i></i>${VERDICTS[h.verdict]}</span><span class="hint">${esc(h.summary)}</span><span class="grow"></span><span class="hint nowrap">Scanned ${ago(h.at)}</span></div>
  ${ws === 'verified' && ['old', 'failed'].includes(h.verdict) ? '<div class="banner warn"><span class="dot" style="--c:var(--warn)"></span><div>The website is marked <b>Verified</b>, but this scan disagrees. The contract stays open until this is resolved.</div></div>' : ''}`;
}

function statusSec(d) {
  const row = t => {
    const tr = d.track?.[t.k] || {};
    if (t.k === 'email' && d._emails.length) return `<div class="track-row"><span class="lbl">Email</span>${pill(d._email)}<span class="note">Rolled up from ${plural(d._emails.length, 'email record')} (Email section below).</span></div>`;
    const note = tr.by === 'scan' ? `Set by scan ${ago(tr.at)}` : tr.auto ? `Default: ${esc(tr.auto)}` : tr.at ? `Changed ${ago(tr.at)}` : '';
    return `<div class="track-row"><span class="lbl">${t.k === 'domain' ? 'Domain move' : t.l}</span>${statusBtn('domain', d.key, tr.status || (t.k === 'email' ? 'unchecked' : 'not_started'), t.k)}<span class="note">${note}</span></div>`;
  };
  return `<div class="sec">${TRACKS.map(row).join('')}</div>
    <div class="sec row2">
      <label class="field"><span>Blockers <span class="faint">(keep the contract open)</span></span><textarea class="in${d.blockers ? ' blocker' : ''}" rows="3" data-save="blockers" placeholder="What is stopping this from moving?">${esc(d.blockers || '')}</textarea></label>
      <label class="field"><span>Notes</span><textarea class="in" rows="3" data-save="notes" placeholder="Notes for this domain">${esc(d.notes || '')}</textarea></label></div>`;
}

const LVL_IC = { pass: '✓', fail: '✕', warn: '!', review: '?', info: 'i' };
function hopsHtml(chain) {
  if (!chain) return '<span class="faint">—</span>';
  return `<div class="hop">${chain.hops.map(h => `<div><b>${h.status || 'ERR'}</b> ${esc(h.url)}${h.ip ? ` <span class="faint">[${esc(h.ip)}]</span>` : ''}${h.error ? ` · ${esc(h.error)}` : ''}${h.tls ? ` · TLS ${h.tls.authorized ? 'valid' : `<span style="color:var(--danger)">${esc(h.tls.error || 'invalid')}</span>`}` : ''}</div>`).join('')}</div>`;
}
function scanDetails(d) {
  const s = d.scan;
  if (!s) return '<div class="hint">Not scanned yet.</div>';
  const st = S.data.settings;
  const ipChip = ip => `<span class="ipchip ${ip.cls}" title="${esc(ip.label)}${ip.ptr ? ` · ${esc(ip.ptr)}` : ''}"><i></i>${esc(ip.ip)} <span class="faint">${esc(ipLabel(ip, st))}</span></span>`;
  return `
    ${s.flags?.cdn ? `<div class="banner v-review"><span class="dot" style="--c:var(--v-review)"></span><div><b>Behind ${esc(s.flags.cdn)}.</b> DNS shows the proxy, not the origin. ${s.flags.markerMatched ? 'The marker confirms the origin.' : 'The origin cannot be confirmed without the marker.'}</div></div>` : ''}
    <div class="sec"><h4>Checks</h4><div class="checks">${s.checks.map(c => `<div class="check ${c.level}"><span class="ic">${LVL_IC[c.level]}</span><div><div class="cl">${esc(c.label)}</div>${c.detail ? `<div class="cd">${esc(c.detail)}</div>` : ''}</div></div>`).join('')}</div></div>
    <div class="sec"><h4>DNS</h4><table class="mt"><thead><tr><th>Name</th><th>IPv4 (A)</th><th>IPv6 (AAAA)</th></tr></thead><tbody>
      ${s.hosts.map(h => `<tr><td><b>${esc(h.host)}</b>${h.cname?.length ? `<div class="faint">CNAME ${esc(h.cname.join(', '))}</div>` : ''}${h.error ? `<div class="faint">${esc(h.error)}</div>` : ''}</td>
        <td>${h.ips.filter(i => i.family === 4).map(ipChip).join('') || '<span class="faint">none</span>'}</td><td>${h.ips.filter(i => i.family === 6).map(ipChip).join('') || '<span class="faint">none</span>'}</td></tr>`).join('')}
    </tbody></table></div>
    <div class="sec"><h4>HTTP and redirects</h4>${s.hosts.filter(h => h.http?.https || h.http?.http).map(h => `<div style="margin-bottom:10px"><b>${esc(h.host)}</b>${hopsHtml(h.http.http)}${hopsHtml(h.http.https)}
      ${(() => { const t = h.http.https?.hops?.[0]?.tls; return t?.cert ? `<div class="hint">Certificate: ${esc(t.cert.subject)} · ${esc(t.cert.issuer)} · expires ${esc(t.cert.validTo)}</div>` : ''; })()}</div>`).join('') || '<div class="hint">No HTTP checks (no DNS address).</div>'}</div>
    <div class="sec"><h4>Verification marker</h4>
      ${s.flags?.markerOn ? `<table class="mt"><thead><tr><th>Request</th><th>Result</th></tr></thead><tbody>
        ${s.hosts.filter(h => h.marker).map(h => `<tr><td>Public · ${esc(h.host)}</td><td>${h.marker.matched ? `<span class="pill v-verified"><i></i>${esc(h.marker.matchedName)}</span>` : `<span class="pill v-review"><i></i>${h.marker.wrong ? 'Unknown token' : 'Not found'}</span> <span class="faint">${h.marker.status ? `HTTP ${h.marker.status}` : esc(h.marker.error || '')}</span>`}</td></tr>`).join('')}
        ${(s.direct || []).map(r => `<tr><td>Direct · ${esc(r.name)} (${esc(r.ip)})</td><td>${r.result === 'found' ? '<span class="pill v-verified"><i></i>Found</span>' : r.result === 'wrong' ? '<span class="pill v-review"><i></i>Other token</span>' : `<span class="pill v-none"><i></i>${r.result === 'error' ? 'Error' : 'Not found'}</span>`} <span class="faint">${r.status ? `HTTP ${r.status}` : ''} ${esc(r.detail || '')}</span></td></tr>`).join('')}
      </tbody></table><div class="hint" style="margin-top:6px">"Direct" asks each VPS for this domain regardless of DNS, which shows whether the site is already set up on the destination.</div>` : '<div class="hint">No marker configured. Set one in Settings so scans can prove where the site is served from.</div>'}</div>
    <div class="sec"><h4>Mail and nameservers</h4><div class="kv">
      <dt>MX</dt><dd>${s.mx?.length ? s.mx.map(m => `${esc(m.host)}${m.ionos ? ' <span class="tag">IONOS</span>' : ''}`).join(', ') : '<span class="faint">none</span>'}</dd>
      <dt>Nameservers</dt><dd>${s.ns?.length ? `${esc(s.ns.join(', '))}${s.flags?.nsIonos ? ' <span class="tag">IONOS</span>' : ''}` : '<span class="faint">—</span>'}</dd></div></div>
    ${(d.scanHistory || []).length > 1 ? `<div class="sec"><h4>History</h4><div class="items">${d.scanHistory.map(x => `<div class="item"><span class="pill v-${x.verdict}"><i></i>${VERDICTS[x.verdict]}</span><span class="muted nowrap">${fmt(x.at)}</span><span class="hint">${esc(x.summary)}</span></div>`).join('')}</div></div>` : ''}`;
}

function effectiveSource(d) {
  if (d.source?.spec) return { spec: d.source.spec, from: 'domain override' };
  const a = S.data.accounts[d.accountId];
  const fill = t => t.replace(/\{domain\}/g, d.domain).replace(/\{path\}/g, d.webspacePath === '/.' ? '' : (d.webspacePath || '').replace(/\/+$/, ''));
  if (a?.sourceTemplate && (!a.sourceTemplate.includes('{path}') || d.webspacePath)) return { spec: fill(a.sourceTemplate), from: `account template (${a.name})` };
  const onVps = new Set((d.scan?.hosts?.[0]?.ips || []).filter(i => i.cls === 'vps').map(i => i.vps));
  for (const v of S.data.settings.vps || []) {
    if (v.sourceTemplate && (onVps.has(v.id) || (d.exportIps?.v4 || []).some(ip => (v.ipv4 || []).includes(ip)))) return { spec: fill(v.sourceTemplate), from: `${v.name} template` };
  }
  return null;
}
const SRC = { public: 'Public site', source: 'Source files', ionos: 'IONOS export' };
function drTech(d) {
  const t = d.tech;
  const run = running(d.key, 'tech');
  const eff = effectiveSource(d);
  const m = d.techManual;
  const head = `<div class="sec" style="display:flex;gap:10px;align-items:center"><button class="btn sm primary" data-act="scan-one" data-kind="tech" ${run ? 'disabled' : ''}>${run ? '<span class="spin"></span> Detecting…' : 'Run technology scan'}</button>
    <span class="hint">Public website signals${eff ? ' plus source files' : ''}. Detected = direct evidence; Inferred = implied or heuristic.</span></div>`;
  const source = `<div class="sec"><h4>Source access</h4>
    <label class="field"><span>Override for this domain</span><input class="in mono" data-save="source" value="${esc(d.source?.spec || '')}" placeholder="/path/to/docroot  or  user@host:/path/to/docroot"></label>
    <div class="hint">${eff ? `Used for the next scan: <code>${esc(eff.spec)}</code> <span class="faint">(${esc(eff.from)})</span>` : 'None set. Detection uses public signals only. Add an account or VPS template in Settings, or an override here.'}</div>
    ${t?.source ? `<div class="hint" style="margin-top:4px">Last scan: ${t.source.ok ? `read ${t.source.files} files at <code>${esc(t.source.root)}</code>` : `<span style="color:var(--danger)">${esc(t.source.error)}</span>`}</div>` : ''}</div>`;
  const manual = `<div class="sec"><h4>Confirm manually ${m ? `<span class="r">${confTag('manual')} ${ago(m.at)}</span>` : ''}</h4>
    <div class="row2"><label class="field"><span>Stack</span><select class="in" id="tm-stack"><option value="">—</option>${Object.entries(STACKS).map(([k, l]) => `<option value="${k}" ${m?.stack === k ? 'selected' : ''}>${l}</option>`).join('')}</select></label>
    <label class="field"><span>Label</span><input class="in" id="tm-label" value="${esc(m?.label || '')}" placeholder="e.g. WordPress 6.6 + Elementor"></label></div>
    <div class="row2"><label class="field"><span>Uses a database</span><select class="in" id="tm-db"><option value="">—</option>${[['yes', 'Yes'], ['no', 'No'], ['platform', 'Managed by platform'], ['unknown', 'Unknown']].map(([k, l]) => `<option value="${k}" ${m?.dbUses === k ? 'selected' : ''}>${l}</option>`).join('')}</select></label>
    <label class="field"><span>Database type / host</span><input class="in" id="tm-dbtype" value="${esc(m?.dbType || '')}" placeholder="e.g. MySQL on IONOS db5001234.hosting-data.io"></label></div>
    <label class="field"><span>Note</span><input class="in" id="tm-note" value="${esc(m?.note || '')}"></label>
    <div style="display:flex;gap:8px"><button class="btn sm primary" data-act="tm-save">Save confirmation</button>${m ? '<button class="btn sm" data-act="tm-clear">Remove</button>' : ''}</div></div>`;
  if (!t) return `${head}<div class="hint" style="margin-bottom:16px">No technology scan yet.</div>${source}${manual}`;
  const db = t.db || {};
  const dbLabel = { yes: 'Uses a database', no: 'No database', platform: 'Managed by the platform', unknown: 'Unknown' }[db.uses] || 'Unknown';
  return `${head}
    <div class="card" style="padding:14px;margin-bottom:12px"><div style="display:flex;gap:12px;align-items:center">
      ${techBadge(t.stack.key, t.stack.label, t.stack.conf, '', 'big')}<span style="flex:1"></span>${confTag(t.stack.conf)}</div>
      <div class="hint" style="margin-top:8px">${esc(t.stack.ev || '')}</div>
      <div class="hint" style="margin-top:4px">Scanned ${fmt(t.at)}${t.page?.url ? ` · ${esc(t.page.url)} (HTTP ${t.page.status})` : ''}${t.page?.title ? ` · “${esc(t.page.title)}”` : ''}</div></div>
    <div class="card" style="padding:14px;margin-bottom:12px"><div style="display:flex;gap:10px;align-items:center"><b>${dbLabel}</b>${db.type ? `<span>${esc(db.type)}</span>` : ''}<span style="flex:1"></span>${confTag(db.conf || 'unknown')}</div>
      <div class="hint" style="margin-top:6px">${esc(db.ev || '')}</div>
      ${db.host || db.name ? `<div class="kv" style="margin-top:8px"><dt>Host</dt><dd><code>${esc(db.host || '—')}</code></dd><dt>Database name</dt><dd>${esc(db.name || '—')}</dd></div>` : ''}
      ${db.whereLabel ? `<div class="hint" style="margin-top:6px">${db.where === 'ionos' ? '<span class="tag">IONOS</span> ' : ''}${esc(db.whereLabel)}${db.whereConf === 'inferred' ? ' (inferred)' : ''}</div>` : ''}
      ${db.others?.length ? `<div class="hint" style="margin-top:6px">Also seen: ${esc(db.others.join('; '))}</div>` : ''}</div>
    ${t.reviewReasons?.length && !m ? `<div class="banner v-review"><span class="dot" style="--c:var(--v-review)"></span><div><div class="bt">Needs manual review</div>${t.reviewReasons.map(esc).join('<br>')}</div></div>` : ''}
    ${t.notes?.length ? `<div class="banner warn"><span class="dot" style="--c:var(--warn)"></span><div>${t.notes.map(esc).join('<br>')}</div></div>` : ''}
    <div class="sec"><h4>Findings</h4>${t.findings.length ? `<table class="mt"><thead><tr><th>Technology</th><th>Type</th><th>Confidence</th><th>From</th><th>Evidence</th></tr></thead><tbody>
      ${t.findings.slice(0, S.showAll.findings ? 999 : 40).map(f => `<tr><td><b>${esc(f.name)}</b>${f.ver ? ` <span class="muted">${esc(f.ver)}</span>` : ''}</td><td class="muted nowrap">${esc(f.cat)}</td><td>${confTag(f.conf)}</td><td class="muted nowrap">${(f.srcs || [f.src]).map(x => SRC[x] || x).join(', ')}</td><td class="muted">${esc(f.ev)}</td></tr>`).join('')}
      </tbody></table>${t.findings.length > 40 && !S.showAll.findings ? '<button class="btn sm ghost" data-act="show-all" data-k="findings">Show all</button>' : ''}` : '<div class="hint">No technologies identified.</div>'}</div>
    ${t.probes?.length ? `<div class="sec"><h4>Probes</h4><table class="mt"><tbody>${t.probes.map(p => `<tr><td class="mono">${esc(p.path)}</td><td>${p.status || esc(p.error || '')}</td><td class="muted">${esc(p.result || '')}</td></tr>`).join('')}</tbody></table></div>` : ''}
    ${source}${manual}`;
}

function drEmail(d) {
  const mxExport = d.exportMx || [];
  const mxScan = d.scan?.mx || [];
  return `${d._emails.length ? `<table class="mt"><thead><tr><th>Address</th><th>Type</th><th>Status</th><th>Notes</th></tr></thead><tbody>
      ${d._emails.map(e => `<tr><td><button class="linkbtn" data-act="open-email" data-id="${esc(e.id)}">${esc(e.address || e.id)}</button></td><td class="muted">${esc(e.type || '—')}</td><td>${statusBtn('email', e.id, e.status)}</td><td class="muted">${esc((e.notes || '').slice(0, 80))}</td></tr>`).join('')}
      </tbody></table>`
    : '<div class="hint">No email records linked. Import an email list (Email tab), or set Email to N/A above if the domain has no mailboxes. Unchecked keeps the contract open.</div>'}
    <div class="kv" style="margin-top:10px">
      <dt>MX in IONOS export</dt><dd>${mxExport.length ? mxExport.map(m => `${esc(m)}${isIonosMxStr(m) ? ' <span class="tag">IONOS</span>' : ''}`).join(', ') : '<span class="faint">none listed</span>'}</dd>
      <dt>MX at last scan</dt><dd>${d.scan ? (mxScan.length ? mxScan.map(m => `${esc(m.host)}${m.ionos ? ' <span class="tag">IONOS</span>' : ''}`).join(', ') : '<span class="faint">no MX record</span>') : '<span class="faint">not scanned</span>'}</dd></div>`;
}

function drIonos(d) {
  const rows = [['Account', S.data.accounts[d.accountId]?.name], ['Contract', d.contract || '—'], ['Domain type', d.type], ['Status', [d.status, d.statusGroup].filter(Boolean).join(' / ')],
    ['Expiry', d.expiration ? fmt(d.expiration) : '—'], ['Destination', `${DEST[d.destination] || ''} ${d.destination ? `(${d.destination})` : ''}`], ['Target', d.target],
    ['Webspace path', d.webspacePath], ['Redirect target', d.redirectTarget], ['IPv4 (export)', (d.exportIps?.v4 || []).join(', ')], ['IPv6 (export)', (d.exportIps?.v6 || []).join(', ')],
    ['MX (export)', (d.exportMx || []).join(', ')], ['Nameservers', (d.nameservers || []).join(', ')], ['SSL enabled', d.ssl], ['Subdomains', d.subdomainCount], ['Transfer lock', d.transferLock],
    ['Import file', d.importFile], ['First imported', fmt(d.firstImported)], ['Last imported', fmt(d.lastImported)], ['In latest export', d.inLatest === false ? 'No' : 'Yes']];
  const extra = Object.entries(d.extra || {});
  return `${d.missing?.length ? `<div class="banner warn"><span class="dot" style="--c:var(--warn)"></span><div><div class="bt">Missing information</div>${esc(d.missing.join(' · '))}</div></div>` : ''}
    ${d.warnings?.length ? `<div class="banner warn"><span class="dot" style="--c:var(--warn)"></span><div>${esc(d.warnings.join(' · '))}</div></div>` : ''}
    <dl class="kv">${rows.map(([k, v]) => `<dt>${k}</dt><dd>${v ? esc(v) : '<span class="faint">—</span>'}</dd>`).join('')}</dl>
    ${extra.length ? `<h4 class="sub-h">Other columns</h4><dl class="kv">${extra.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join('')}</dl>` : ''}
    <div class="hint" style="margin-top:8px">Auth codes and contact details in the export are never stored.</div>`;
}

const SVC_PRESETS = [['database', 'Database'], ['ssl', 'SSL certificate'], ['mail', 'Mail package'], ['webspace', 'Webspace / FTP / SSH users'], ['backup', 'Backups'], ['cron', 'Cron jobs'], ['other', 'Other service']];
function drawerContract(c) {
  const r = c._ready;
  const acct = S.data.accounts[c.accountId];
  const limit = S.showAll.items ? 2000 : 40;
  const groups = [];
  const byKey = new Map();
  for (const i of r.items) {
    const d = i.key && S.data.domains[i.key];
    const prefix = d ? `${d.domain}: ` : '';
    const part = prefix && i.text.startsWith(prefix) ? i.text.slice(prefix.length) : i.text;
    let g = d ? byKey.get(i.key) : null;
    if (!g) { g = { key: i.key || '', email: i.email || '', name: d ? d.domain : '', parts: [], lvl: 'warn' }; groups.push(g); if (d) byKey.set(i.key, g); }
    g.parts.push(part);
    if (i.lvl === 'block') g.lvl = 'block';
  }
  const live = liveRuns().find(x => x.contractKey === c.key);
  const banner = r.state === 'confirmed'
    ? `<div class="banner ok"><span class="dot" style="--c:var(--ok)"></span><div style="flex:1"><div class="bt">Cancellation readiness confirmed</div>${fmt(c.readiness.at)}${c.readiness.note ? ` · ${esc(c.readiness.note)}` : ''}<div class="hint">Recorded only. Cancel the contract in IONOS yourself.</div></div><button class="btn sm" data-act="revoke-ready">Revoke</button></div>`
    : r.state === 'stale'
      ? `<div class="banner warn"><span class="dot" style="--c:var(--warn)"></span><div style="flex:1"><div class="bt">Confirmed ${fmt(c.readiness.at)}, but ${plural(r.blocking, 'item')} reopened</div>Resolve them or revoke the confirmation.</div><button class="btn sm" data-act="revoke-ready">Revoke</button></div>`
      : r.state === 'ready'
        ? `<div class="banner ok"><span class="dot" style="--c:var(--ok)"></span><div style="flex:1"><div class="bt">Ready for cancellation review</div>Every domain, website, email record and service is Verified or N/A, and you have reviewed the services.
            <label class="field" style="margin-top:8px"><span>Confirmation note (optional)</span><input class="in" id="ready-note" placeholder="e.g. Checked in IONOS control panel"></label>
            <button class="btn primary sm" data-act="confirm-ready">Confirm cancellation readiness</button> <span class="hint">This only records your confirmation. The app never cancels anything.</span></div></div>`
        : `<div class="banner"><span class="dot"></span><div><div class="bt">${plural(r.blocking, 'open item')} before cancellation review</div>${r.warnings ? `${plural(r.warnings, 'warning')} as well. ` : ''}Everything stays listed until it is Verified or N/A.</div></div>`;
  const hc = c._hc;
  return `${drawerHead(c.number ? `Contract ${esc(c.number)}` : 'No contract number', `${esc(acct?.name || '')} · ${plural(c._domains.length, 'domain')}${hc.n - hc.unscanned ? ` · ${hc.ok} healthy on VPS, ${hc.notVps} not on VPS, ${hc.down} down, ${hc.ssl} SSL issues` : ''}`,
    `<button class="btn sm" data-act="con-scan" data-key="${esc(c.key)}" ${live ? 'disabled' : ''}>${live ? `<span class="spin"></span> ${live.done}/${live.total}` : `${ICONS.refresh} Rescan contract`}</button>`)}
    <div class="dr-b">
      ${banner}
      <div class="sec"><h4>Checklist <span class="r hint">${r.blocking} blocking · ${r.warnings} warnings · grouped by domain</span></h4>
        ${groups.length ? `<div class="items">${groups.slice(0, limit).map(g => `<div class="item ${g.lvl}"><span class="dot"></span><span style="flex:1">${g.name ? `<b>${esc(g.name)}</b> · ` : ''}${g.parts.map(esc).join(' · ')}</span>${g.key || g.email ? `<button class="btn sm ghost" data-act="goto" data-key="${esc(g.key || '')}" data-email="${esc(g.email || '')}">Open</button>` : ''}</div>`).join('')}</div>
        ${groups.length > limit ? `<button class="btn sm ghost" data-act="show-all" data-k="items">Show all ${groups.length}</button>` : ''}` : '<div class="hint">Nothing outstanding.</div>'}</div>
      <div class="sec"><h4>Services on this contract</h4>
        <div class="hint" style="margin-bottom:6px">Anything else on the contract that must move or be dropped before cancelling: databases, SSL certificates, mail packages, backups, cron jobs.</div>
        ${(c.services || []).map(s => `<div class="svc"><div><div class="nm">${esc(s.name)} <span class="tag">${esc(s.type)}</span>${s.auto ? ' <span class="tag inf" title="Added automatically from a source scan">auto</span>' : ''}</div>
          <input class="in" style="margin-top:4px" data-svc="${esc(s.id)}" data-field="notes" value="${esc(s.notes || '')}" placeholder="Notes">
          <input class="in${s.blocker ? ' blocker' : ''}" style="margin-top:4px" data-svc="${esc(s.id)}" data-field="blocker" value="${esc(s.blocker || '')}" placeholder="Blocker (optional)"></div>
          ${statusBtn('service', s.id, s.status)}<button class="btn sm ghost danger" data-act="svc-del" data-id="${esc(s.id)}" title="Remove">${ICONS.x}</button></div>`).join('')}
        <div style="display:flex;gap:6px;flex-wrap:wrap;margin-top:10px">${SVC_PRESETS.map(([k, l]) => `<button class="btn sm" data-act="svc-add" data-type="${k}" data-name="${esc(l)}">+ ${l}</button>`).join('')}</div>
        <label style="display:flex;gap:8px;align-items:flex-start;margin-top:12px;cursor:pointer"><input type="checkbox" data-act="svc-reviewed" ${c.servicesReviewed ? 'checked' : ''} style="margin-top:2px">
          <span>I have checked this contract in IONOS and every other service is listed above (or there are none).</span></label></div>
      <div class="sec"><h4>Label and notes</h4><input class="in" data-csave="label" value="${esc(c.label || '')}" placeholder="Label, e.g. Hosting package name" style="margin-bottom:8px"><textarea class="in" rows="3" data-csave="notes" placeholder="Contract notes">${esc(c.notes || '')}</textarea></div>
      ${c._extraEmails.length ? `<div class="sec"><h4>Email records on this contract</h4><table class="mt"><tbody>${c._extraEmails.map(e => `<tr><td><button class="linkbtn" data-act="open-email" data-id="${esc(e.id)}">${esc(e.address || e.id)}</button></td><td>${statusBtn('email', e.id, e.status)}</td></tr>`).join('')}</tbody></table></div>` : ''}
    </div>`;
}

function drawerEmail(e) {
  const d = e.domainKey && S.data.domains[e.domainKey];
  const cons = S.idx.contracts.filter(c => !e.accountId || c.accountId === e.accountId);
  return `${drawerHead(esc(e.address || e.id), d ? `Domain <button class="linkbtn" data-act="open" data-key="${esc(d.key)}">${esc(d.domain)}</button>` : `<span style="color:var(--warn)">Not linked to an imported domain</span>`)}
    <div class="dr-b">
      <div class="sec"><h4>Status</h4><div class="track-row"><span class="lbl">Email</span>${statusBtn('email', e.id, e.status)}<span class="note">${e.statusAt ? `Changed ${ago(e.statusAt)}` : ''}</span></div></div>
      <div class="sec"><h4>Contract</h4><select class="in" data-act="email-contract" data-id="${esc(e.id)}"><option value="">— none —</option>${cons.map(c => `<option value="${esc(c.key)}" ${e.contractKey === c.key ? 'selected' : ''}>${esc(S.data.accounts[c.accountId]?.name || '')} · ${c.number ? `Contract ${esc(c.number)}` : 'No contract number'}</option>`).join('')}</select>
        <div class="hint" style="margin-top:4px">Normally set from the domain or the contract number in the email file.</div></div>
      <div class="sec"><h4>Notes</h4><textarea class="in" rows="4" data-esave="notes" data-id="${esc(e.id)}">${esc(e.notes || '')}</textarea></div>
      <div class="sec"><h4>Imported data</h4><dl class="kv">${[['Type', e.type], ['Product', e.product], ['Size / quota', e.size], ['Forwards to', e.forward], ['Contract number', e.contractNumber], ['Note', e.note], ['File', e.importFile], ['Imported', fmt(e.lastImported)]].map(([k, v]) => `<dt>${k}</dt><dd>${v ? esc(v) : '<span class="faint">—</span>'}</dd>`).join('')}</dl></div>
    </div>`;
}

// ---------- Scan log ----------
const SITE_GOOD = { up: 1, redirect: 0, parked: 0, down: -1, nodns: 0 };
function sigText(f, t) {
  const [b1, s1, l1] = f.split('|'), [b2, s2, l2] = t.split('|');
  const parts = [];
  if (b1 !== b2) parts.push(`Server ${bmeta(b1).l} → <b>${esc(bmeta(b2).l)}</b>`);
  if (s1 !== s2) parts.push(`Site ${SITE[s1]?.l || s1} → <b>${esc(SITE[s2]?.l || s2)}</b>`);
  if (l1 !== l2) parts.push(`SSL ${SSL[l1]?.l || '—'} → <b>${esc(SSL[l2]?.l || '—')}</b>`);
  return parts.join(' · ');
}
function changeTone(f, t) {
  const [b1, s1, l1] = f.split('|'), [b2, s2, l2] = t.split('|');
  let score = 0;
  if (b1 !== b2) score += (b2.startsWith('vps:') ? 1 : 0) - (b1.startsWith('vps:') ? 1 : 0);
  if (s1 !== s2) score += (SITE_GOOD[s2] || 0) - (SITE_GOOD[s1] || 0);
  if (l1 !== l2) score += (l2 === 'ok' ? 1 : 0) - (l1 === 'ok' ? 1 : 0);
  return score > 0 ? 'good' : score < 0 ? 'bad' : 'neu';
}
function runCard(r, runs, i) {
  const live = !r.finishedAt;
  const prev = runs.slice(i + 1).find(x => x.counts && x.kind === r.kind && x.scope === r.scope && (x.contractKey || '') === (r.contractKey || ''));
  const took = live ? dur(Date.now() - Date.parse(r.startedAt)) : dur(Date.parse(r.finishedAt) - Date.parse(r.startedAt));
  const head = `<div class="run-h"><b>${fmtShort(r.startedAt)}</b><span class="tag">${r.kind === 'tech' ? 'Technology' : 'Server · site · SSL'}</span><span class="muted">${esc(r.label)}</span><span class="grow"></span>
    <span class="muted nowrap">${live ? `<span class="spin"></span> ${r.done} / ${r.total}` : `${plural(r.total, 'site')} · ${took}`}</span></div>`;
  if (live) return `<div class="run live">${head}<div class="pbar"><i style="width:${r.total ? (r.done / r.total) * 100 : 0}%"></i></div>
    <div class="run-f"><span class="hint">${took} so far</span><button class="btn sm" data-act="cancel-run" data-id="${esc(r.id)}">${ICONS.stop} Stop</button></div></div>`;
  const notes = [r.cancelled ? `Stopped at ${r.done} of ${r.total}` : '', r.interrupted ? 'Interrupted (the app was restarted)' : '', r.errors ? plural(r.errors, 'error') : ''].filter(Boolean);
  const c = r.counts;
  if (!c) return `<div class="run">${head}<div class="hint">${notes.join(' · ') || 'No results recorded.'}</div></div>`;
  if (r.kind === 'tech') {
    return `<div class="run">${head}<div class="rcs">${Object.entries(c.stack || {}).sort((a, b) => b[1] - a[1]).map(([k, n]) => `<span class="rc">${esc(STACKS[k] || k)} <b>${n}</b></span>`).join('')}</div>
      ${c.review || c.dbIonos ? `<div class="hint" style="margin-top:6px">${c.review ? `${c.review} need review` : ''}${c.review && c.dbIonos ? ' · ' : ''}${c.dbIonos ? `${c.dbIonos} with an IONOS database` : ''}</div>` : ''}
      ${notes.length ? `<div class="hint warnc">${notes.join(' · ')}</div>` : ''}</div>`;
  }
  const pc = prev?.counts;
  const delta = (v, pv, goodUp) => {
    if (!pc) return '';
    const dv = v - pv;
    if (!dv) return '';
    const tone = goodUp === null ? 'neu' : (dv > 0) === goodUp ? 'good' : 'bad';
    return `<span class="dl ${tone}">${dv > 0 ? '+' : ''}${dv}</span>`;
  };
  const goodFor = col => (col === 'ok' ? true : ['muted', 'cdn', 'none'].includes(col) ? null : false);
  const shown = S.blist.filter(b => c.bucket[b.k] || pc?.bucket?.[b.k]);
  const seg = c.scanned ? S.blist.filter(b => c.bucket[b.k]).map(b => `<i class="c-${b.c}" style="width:${(c.bucket[b.k] / c.scanned) * 100}%" title="${esc(b.l)}: ${c.bucket[b.k]}"></i>`).join('') : '';
  const metric = (label, v, pv, col, goodUp) => `<span class="rc c-${col}"><i></i>${label} <b>${v}</b>${delta(v, pv, goodUp)}</span>`;
  const chg = r.changes || [];
  return `<div class="run">${head}
    <div class="sbar">${seg}</div>
    <div class="rcs">${shown.map(b => metric(esc(b.l), c.bucket[b.k] || 0, pc?.bucket?.[b.k] || 0, b.c, goodFor(b.c))).join('')}</div>
    <div class="rcs" style="margin-top:6px">${metric('Healthy on VPS', c.healthy, pc?.healthy || 0, 'ok', true)}${metric('Down', c.site.down || 0, pc?.site?.down || 0, 'bad', false)}${c.site.parked || pc?.site?.parked ? metric('Not set up', c.site.parked || 0, pc?.site?.parked || 0, 'warn', false) : ''}
      ${metric('SSL invalid', c.ssl.fail || 0, pc?.ssl?.fail || 0, 'bad', false)}${metric('No HTTPS', c.ssl.none || 0, pc?.ssl?.none || 0, 'warn', false)}${c.marker || pc?.marker ? metric('Marker verified', c.marker, pc?.marker || 0, 'ok', true) : ''}</div>
    ${!pc ? `<div class="hint" style="margin-top:8px">First ${r.scope === 'all' ? 'full scan' : 'scan of this group'}: later scans show what changed against this one.</div>` : ''}
    ${(r.statusChanges || []).length ? `<details class="rdet"><summary>${plural(r.statusChanges.length, 'website')} set to Moved / Verified by this scan</summary>${r.statusChanges.map(x => `<div class="chg"><button class="linkbtn" data-act="open" data-key="${esc(x.k)}">${esc(x.d)}</button><span>→ ${esc(SL[x.to] || x.to)}</span></div>`).join('')}</details>` : ''}
    ${chg.length ? `<details class="rdet"><summary>${plural(chg.length + (r.moreChanges || 0), 'change')} since the previous scan of these domains</summary>${chg.map(x => `<div class="chg ${changeTone(x.f, x.t)}"><span class="dot"></span><button class="linkbtn" data-act="open" data-key="${esc(x.k)}">${esc(x.d)}</button><span>${sigText(x.f, x.t)}</span></div>`).join('')}${r.moreChanges ? `<div class="hint">…and ${r.moreChanges} more</div>` : ''}</details>`
      : pc && r.newlyScanned < r.total ? '<div class="hint" style="margin-top:8px">No changes since the previous scan.</div>' : ''}
    ${notes.length ? `<div class="hint warnc" style="margin-top:6px">${notes.join(' · ')}</div>` : ''}</div>`;
}
function drawerLog() {
  const runs = S.data.scanRuns || [];
  return `${drawerHead('Scan log', `${plural(runs.length, 'scan')}, newest first · each scan is compared with the previous one of the same domains`)}
    <div class="dr-b">${runs.length ? runs.map((r, i) => runCard(r, runs, i)).join('') : '<div class="hint">No scans yet. Use “Scan all sites” at the top of the Contracts page.</div>'}</div>`;
}

// ---------- Menus ----------
function closeMenu() { if (S.menu) { S.menu.remove(); S.menu = null; } }
function menu(anchor, items, onPick) {
  closeMenu();
  const el = document.createElement('div');
  el.className = 'menu';
  el.innerHTML = items.map((it, i) => (it.sep ? '<div class="sep"></div>' : it.head ? `<div class="mh">${esc(it.head)}</div>` : `<button data-i="${i}" class="${it.on ? 'on' : ''}" ${it.disabled ? 'disabled' : ''}>${it.html || esc(it.label)}</button>`)).join('');
  document.body.appendChild(el);
  const r = anchor.getBoundingClientRect();
  const w = el.offsetWidth, h = el.offsetHeight;
  let x = r.left, y = r.bottom + 4;
  if (x + w > innerWidth - 8) x = innerWidth - w - 8;
  if (y + h > innerHeight - 8) y = Math.max(8, r.top - h - 4);
  el.style.left = `${x}px`;
  el.style.top = `${y}px`;
  el.addEventListener('click', e => {
    const b = e.target.closest('button[data-i]');
    if (!b || b.disabled) return;
    const it = items[+b.dataset.i];
    closeMenu();
    onPick(it.value, it);
  });
  S.menu = el;
}
const statusItems = cur => STATUSES.map(s => ({ value: s.k, html: pill(s.k), on: s.k === cur }));

// ---------- Import modal ----------
function openImport(kind = 'domains') {
  S.imp = { kind, filename: '', text: '', preview: null, mapping: {}, accountId: '', accountName: '', result: null, busy: false };
  S.modal = 'import';
  renderModal();
}
function closeModal() {
  const pw = S.pwm;
  S.modal = null; S.imp = null; S.rvc = null; S.pwm = null; S.del = null;
  renderModal();
  pw?.resolve(null);
}
const modalShell = (title, body, foot, cls = '') => `<div class="modal ${cls}" role="dialog" aria-modal="true"><div class="modal-h"><h3>${title}</h3><button class="btn sm ghost" data-act="modal-close" style="margin-left:auto" title="Close (Esc)">${ICONS.x}</button></div>
  <div class="modal-b">${body}</div><div class="modal-f">${foot}</div></div>`;

// Asks for a new password in a small dialog. Resolves with the password, or null when cancelled.
function askPassword(title, hint) {
  return new Promise(resolve => {
    S.pwm = { title, hint, resolve };
    S.modal = 'pw';
    renderModal();
    $('#pwIn')?.focus();
  });
}
function renderPwModal(el) {
  const m = S.pwm;
  el.hidden = false;
  el.innerHTML = modalShell(esc(m.title), `<label class="field"><span>New password</span><input class="in" id="pwIn" type="password" autocomplete="new-password" placeholder="At least 6 characters"></label>${m.hint ? `<div class="hint">${esc(m.hint)}</div>` : ''}`,
    '<button class="btn" data-act="modal-close">Cancel</button><button class="btn primary" data-act="pw-ok">Save password</button>', 'narrow');
}

// The type that fits the current filter best: Site down → Website down; IONOS shared or sites that answer → Website live.
function guessType(keys) {
  if (S.hf === 's=down') return 'down';
  if (['b=old', 's=up', 's=redirect'].includes(S.hf)) return 'live';
  const down = keys.filter(k => S.data.domains[k]?._h?.site === 'down').length;
  return down * 2 >= keys.length ? 'down' : 'live';
}
// Domains that do not look like the chosen type at the last scan (a hint, never a block).
const fitsType = (type, d) => {
  const h = d?._h;
  return type === 'down' ? h?.site === 'down' : !!h && h.bucket === 'old' && h.site !== 'down';
};
function rvcMismatchText() {
  const m = S.rvc;
  const n = [...m.sel].filter(k => !fitsType(m.type, S.data.domains[k])).length;
  if (!n) return '';
  return `${n} of the selected domains ${n === 1 ? 'is' : 'are'} ${m.type === 'down' ? 'not down' : 'not live on IONOS shared'} at the last scan.`;
}
function openReviewCreate() {
  const keys = [...S.matched];
  const from = filterDesc();
  const date = new Date().toLocaleDateString('en-GB', { day: 'numeric', month: 'short' });
  S.rvc = { keys, sel: new Set(keys), from, type: guessType(keys), name: `${from || 'All domains'} · ${date}`, pwMode: 'master', password: '', busy: false };
  S.modal = 'review';
  renderModal();
  $('#rvName')?.select();
}
function renderReviewModal(el) {
  const m = S.rvc;
  const master = !!S.rinfo?.masterSet;
  const needPw = !master || m.pwMode === 'own';
  const hint = !master ? 'This becomes the master password. Every review list uses it unless you give a list its own. You can change it any time under Review lists.'
    : m.pwMode === 'own' ? 'Only this list uses this password.' : 'The agent signs in with the master password you set before.';
  const typeCard = t => `<button class="rvc-type${m.type === t.k ? ' on' : ''}" data-act="rvc-type" data-v="${t.k}" aria-pressed="${m.type === t.k}">
      <b>${esc(t.l)}</b><span class="hint">${esc(t.d)}</span>
      <span class="rvc-opts"><span class="rvc-ol">Agent</span>${t.verdicts.map(v => `<span class="hs c-${v.c}"><i></i>${esc(v.l)}</span>`).join('')}</span>
      <span class="rvc-opts"><span class="rvc-ol">You</span>${t.outcomes(S.data.settings).map(o => `<span class="hs c-${o.c}"><i></i>${esc(o.l)}</span>`).join('')}</span></button>`;
  const mis = rvcMismatchText();
  const body = `<div class="field"><span>List type</span><div class="rvc-types">${Object.values(REVIEW_TYPES).map(typeCard).join('')}</div>
      <span class="hint" id="rvcMisWrap" ${mis ? '' : 'hidden'}><span class="warnc" id="rvcMis">${esc(mis)}</span> <button class="linkbtn" data-act="rvc-fit">Leave them out</button></span></div>
    <label class="field"><span>List name</span><input class="in" id="rvName" maxlength="120" value="${esc(m.name)}"></label>
    <div class="field"><span>Password the agent signs in with</span>
      ${master ? `<span class="seg" style="align-self:flex-start">${[['master', 'Master password'], ['own', 'Own password for this list']].map(([k, l]) => `<button class="${m.pwMode === k ? 'on' : ''}" data-act="rvc-pw" data-v="${k}">${l}</button>`).join('')}</span>` : ''}
      ${needPw ? `<input class="in" id="rvPw" type="password" autocomplete="new-password" placeholder="At least 6 characters" value="${esc(m.password)}">` : ''}
      <span class="hint">${hint}</span></div>
    <div class="sec" style="margin:16px 0 0"><h4><span id="rvcCount">${m.sel.size} of ${m.keys.length}</span> domains<span class="r"><button class="btn sm ghost" data-act="rvc-all">Select all</button><button class="btn sm ghost" data-act="rvc-none">None</button></span></h4>
      ${m.from ? `<div class="hint" style="margin-bottom:6px">From the current filter: <b>${esc(m.from)}</b></div>` : ''}
      <div class="rvc-list">${m.keys.map(k => {
        const d = S.data.domains[k];
        if (!d) return '';
        const s = d._h && SITE[d._h.site];
        const b = d._h && bmeta(d._h.bucket);
        return `<label class="rvc-item"><input type="checkbox" data-rvc="${esc(k)}" ${m.sel.has(k) ? 'checked' : ''}><span class="rvc-d">${esc(d.domain)}</span>${isSub(d) ? '<span class="tag">Sub</span>' : ''}<span class="muted nowrap">${esc(d.contract || '')}</span><span class="grow"></span>
          ${b ? `<span class="hs c-${b.c} rvc-srv"><i></i>${esc(b.l)}</span>` : ''}${s ? `<span class="hs c-${s.c}"><i></i>${s.l}</span>` : '<span class="faint">Not scanned</span>'}</label>`;
      }).join('')}</div></div>`;
  const foot = `<span class="hint" style="margin-right:auto">The agent sees domain, contract, server and site status, never your notes or blockers.</span>
    <button class="btn" data-act="modal-close">Cancel</button><button class="btn primary" id="rvcGo" data-act="rvc-create" ${m.sel.size && !m.busy ? '' : 'disabled'}>${m.busy ? '<span class="spin"></span> Creating…' : `Create list of ${m.sel.size}`}</button>`;
  el.hidden = false;
  el.innerHTML = modalShell('Create review list', body, foot, 'narrow');
}

function renderModal() {
  const el = $('#modal');
  if (!S.modal) { el.hidden = true; el.innerHTML = ''; return; }
  if (S.modal === 'review') return renderReviewModal(el);
  if (S.modal === 'pw') return renderPwModal(el);
  if (S.modal === 'del') return renderDelModal(el);
  const m = S.imp;
  el.hidden = false;
  let body = '', foot = '';
  if (m.result) {
    const r = m.result;
    body = m.kind === 'email'
      ? `<div class="banner ok"><span class="dot" style="--c:var(--ok)"></span><div><div class="bt">Email list imported</div>${r.rows} rows · ${r.added} new · ${r.updated} updated · ${r.linked} linked to domains · ${r.unlinked} not linked${r.skipped ? ` · ${r.skipped} skipped` : ''}</div></div>
         ${r.unlinked ? '<div class="hint">Unlinked records are listed in the Email tab (filter "Not linked"). You can assign a contract to each.</div>' : ''}`
      : `<div class="banner ok"><span class="dot" style="--c:var(--ok)"></span><div><div class="bt">${esc(r.account)} imported</div>${r.rows} rows · ${r.added} new · ${r.updated} updated (tracking kept) · ${plural(r.contracts, 'contract')}${r.skipped ? ` · ${r.skipped} skipped` : ''}</div></div>
         ${r.missingRows ? `<div class="banner warn"><span class="dot" style="--c:var(--warn)"></span><div>${plural(r.missingRows, 'record')} with missing information. Use Filter → Missing information.</div></div>` : ''}
         ${r.removedFromExport ? `<div class="banner warn"><span class="dot" style="--c:var(--warn)"></span><div>${plural(r.removedFromExport, 'domain')} from earlier imports are not in this file. They are kept and flagged "Not in latest IONOS export".</div></div>` : ''}`;
    foot = '<button class="btn" data-act="imp-again">Import another file</button><button class="btn primary" data-act="imp-done">Done</button>';
  } else if (!m.preview) {
    body = `<div class="seg" style="margin-bottom:14px">${[['domains', 'IONOS domain export'], ['email', 'Email list']].map(([k, l]) => `<button class="${m.kind === k ? 'on' : ''}" data-act="imp-kind" data-v="${k}">${l}</button>`).join('')}</div>
      <label class="drop" id="drop"><input type="file" accept=".csv,.txt,text/csv" id="impFile" hidden>
        <div style="font-weight:600;color:var(--text);margin-bottom:4px">${m.busy ? '<span class="spin"></span> Reading…' : 'Drop a CSV file here or click to choose'}</div>
        <div>${m.kind === 'email' ? 'Mailboxes, forwards or aliases. Columns are mapped on the next step.' : 'The domain list exported from one IONOS account. Import each account separately; re-importing updates the records and keeps your tracking.'}</div></label>`;
    foot = '<button class="btn" data-act="imp-cancel">Cancel</button>';
  } else {
    const p = m.preview;
    const opts = sel => `<option value="">— not mapped —</option>${p.headers.map(h => (p.sensitive.includes(h) ? `<option disabled>${esc(h)} (sensitive, never imported)</option>` : `<option value="${esc(h)}" ${sel === h ? 'selected' : ''}>${esc(h)}</option>`)).join('')}`;
    const sample = col => { const i = p.headers.indexOf(col); return i < 0 ? '' : p.sample.map(r => r[i]).filter(Boolean).slice(0, 3).join(' · '); };
    const reqOk = m.kind === 'email' ? (m.mapping.address || m.mapping.domain) : m.mapping.domain;
    const missingImp = p.fields.filter(f => f.important && !m.mapping[f.k]);
    const accts = S.idx.accounts;
    body = `<div class="hint" style="margin-bottom:12px"><b>${esc(m.filename)}</b> · ${p.rowCount} rows · delimiter "${esc(p.delimiter === '\t' ? 'tab' : p.delimiter)}" · ${p.headers.length} columns</div>
      ${m.kind === 'domains' ? `<div class="row2" style="margin-bottom:10px"><label class="field"><span>Import into account</span><select class="in" id="impAcct"><option value="">New account…</option>${accts.map(a => `<option value="${esc(a.id)}" ${m.accountId === a.id ? 'selected' : ''}>${esc(a.name)}</option>`).join('')}</select></label>
        <label class="field ${m.accountId ? 'hidden' : ''}" id="impNameWrap"><span>New account name</span><input class="in" id="impName" value="${esc(m.accountName)}"></label></div>`
      : `<label class="field" style="max-width:420px"><span>Account for records whose domain is not found</span><select class="in" id="impAcct"><option value="">Automatic (match by domain only)</option>${accts.map(a => `<option value="${esc(a.id)}" ${m.accountId === a.id ? 'selected' : ''}>${esc(a.name)}</option>`).join('')}</select></label>`}
      ${p.sensitive.length ? `<div class="hint" style="margin-bottom:10px">Never imported: ${p.sensitive.map(esc).join(', ')}.</div>` : ''}
      <table class="mt map-t"><thead><tr><th>Field</th><th>CSV column</th><th>Sample values</th></tr></thead><tbody>
      ${p.fields.map(f => `<tr><td>${esc(f.l)}${f.req ? ' <span style="color:var(--danger)">*</span>' : ''}${f.important && !m.mapping[f.k] ? ' <span class="tag" style="color:var(--warn)">recommended</span>' : ''}</td>
        <td><select class="in" data-map="${f.k}">${opts(m.mapping[f.k])}</select></td><td class="sample" title="${esc(sample(m.mapping[f.k]))}">${esc(sample(m.mapping[f.k]))}</td></tr>`).join('')}
      </tbody></table>
      ${!reqOk ? `<div class="banner warn" style="margin-top:12px"><span class="dot" style="--c:var(--warn)"></span><div>Map ${m.kind === 'email' ? 'the email address or domain column' : 'the domain name column'} to continue.</div></div>` : ''}
      ${missingImp.length && reqOk ? `<div class="banner warn" style="margin-top:12px"><span class="dot" style="--c:var(--warn)"></span><div>Not mapped: ${missingImp.map(f => esc(f.l)).join(', ')}. Records will be flagged as missing this information.</div></div>` : ''}
      <div class="hint" style="margin-top:10px">Other non-sensitive columns are kept as reference on each record.</div>`;
    foot = `<button class="btn" data-act="imp-back">Back</button><button class="btn primary" data-act="imp-commit" ${!reqOk || m.busy ? 'disabled' : ''}>${m.busy ? '<span class="spin"></span> Importing…' : `Import ${p.rowCount} rows`}</button>`;
  }
  el.innerHTML = `<div class="modal" role="dialog" aria-modal="true"><div class="modal-h"><h3>${m.kind === 'email' ? 'Import email list' : 'Import IONOS domain export'}</h3><button class="btn sm ghost" data-act="imp-cancel" style="margin-left:auto">${ICONS.x}</button></div><div class="modal-b">${body}</div><div class="modal-f">${foot}</div></div>`;
  const drop = $('#drop');
  if (drop) {
    drop.addEventListener('dragover', e => { e.preventDefault(); drop.classList.add('over'); });
    drop.addEventListener('dragleave', () => drop.classList.remove('over'));
    drop.addEventListener('drop', e => { e.preventDefault(); drop.classList.remove('over'); if (e.dataTransfer.files[0]) readImportFile(e.dataTransfer.files[0]); });
    $('#impFile').addEventListener('change', e => { if (e.target.files[0]) readImportFile(e.target.files[0]); });
  }
  const ia = $('#impAcct');
  if (ia) ia.addEventListener('change', () => { m.accountId = ia.value; renderModal(); });
  const nm = $('#impName');
  if (nm) nm.addEventListener('input', () => { m.accountName = nm.value; });
}
async function readImportFile(file) {
  const m = S.imp;
  m.busy = true; renderModal();
  try {
    m.text = await file.text();
    m.filename = file.name;
    m.preview = await api('/api/import/preview', { kind: m.kind, filename: file.name, text: m.text });
    m.mapping = { ...m.preview.mapping };
    if (m.kind === 'domains') {
      const ex = S.idx.accounts.find(a => a.name.toLowerCase() === m.preview.accountGuess.toLowerCase());
      m.accountId = ex ? ex.id : '';
      m.accountName = m.preview.accountGuess;
    }
  } catch (e) { toast(e.message, true); }
  m.busy = false; renderModal();
}

// ---------- Actions ----------
const patchDomain = (key, patch) => api('/api/domain', { key, patch });
async function setStatus(kind, id, track, status, extra) {
  if (kind === 'domain') return patchDomain(id, { track: { [track]: status } });
  if (kind === 'email') return api('/api/email', { id, patch: { status } });
  if (kind === 'service') return api('/api/contract', { key: extra.contract, patch: { service: { id, status } } });
}
async function startScan(body, quiet) {
  const r = await api('/api/scan', body);
  if (!quiet) toast(`${body.kind === 'tech' ? 'Technology' : 'Server, site and SSL'} scan started for ${plural(r.job.total, 'domain')}${r.job.skipped ? ` (${r.job.skipped} already running)` : ''}`);
  await sync();
}
function stepDrawer(n) {
  const list = S.visible.includes(S.drawer.id) ? S.visible : S.matched.length ? S.matched : S.idx.domains.map(d => d.key);
  const i = list.indexOf(S.drawer.id);
  const next = list[(i + n + list.length) % list.length];
  if (next) openDrawer('domain', next);
}
function exportCsv() {
  const rows = [['Account', 'Contract', 'Domain', 'Type', 'Destination', 'Webspace path', 'Server', 'Server IP', 'Reverse DNS', 'Other records', 'Site', 'Site detail', 'SSL', 'SSL detail', 'Scanned at',
    'Domain status', 'Website status', 'Email status', 'Scan verdict', 'Stack', 'Stack confidence', 'Database', 'Database type', 'Blockers', 'Notes']];
  for (const k of S.matched) {
    const d = S.data.domains[k];
    if (!d) continue;
    const h = d._h;
    const m = d.techManual;
    rows.push([S.data.accounts[d.accountId]?.name, d.contract, d.domain, d.type, d.destination, d.webspacePath,
      h ? (h.onVps ? bmeta(h.bucket).l : h.server) : '', h?.ip, h?.ptr, (h?.odd || []).map(o => `${o.text} (${o.label})`).join('; '), h ? SITE[h.site]?.l : '', h?.siteDetail, h?.ssl ? SSL[h.ssl].l : '', h?.sslDetail, h?.at,
      SL[statusOf(d, 'domain')], SL[statusOf(d, 'website')], SL[statusOf(d, 'email')], d.scan ? VERDICTS[d.scan.verdict] : '',
      m?.stack ? (m.label || STACKS[m.stack]) : d.tech?.stack?.label, m?.stack ? 'manual' : d.tech?.stack?.conf, m?.dbUses || d.tech?.db?.uses, m?.dbType || d.tech?.db?.type, d.blockers, d.notes]);
  }
  downloadCsv(rows, `domain-move-${new Date().toISOString().slice(0, 10)}.csv`);
}
function downloadCsv(rows, name) {
  const csv = rows.map(r => r.map(v => `"${String(v ?? '').replace(/"/g, '""')}"`).join(',')).join('\r\n');
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }));
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 2000);
}
function clearFilters() { S.hf = ''; S.flag = ''; S.acct = ''; S.dt = ''; S.q = ''; $('#q').value = ''; }
// Deleting a list asks for DELETE to be typed in a warning dialog.
function deleteReviewList(id) {
  if (!S.data.reviews[id]) return;
  S.del = { id };
  S.modal = 'del';
  renderModal();
  $('#delIn')?.focus();
}
function renderDelModal(el) {
  const l = S.data.reviews[S.del?.id];
  if (!l) { closeModal(); return; }
  const c = rvCounts(l);
  const body = `<div class="banner warn"><span class="dot" style="--c:var(--danger)"></span><div>
      <div class="bt">Delete “${esc(l.name)}”?</div>
      This removes the list of ${plural(c.n, 'domain')}${c.reviewed || c.decided ? `, with ${plural(c.reviewed, 'agent answer')} and ${plural(c.decided, 'decision')}` : ''}. The link stops working for the agent${l.people?.length ? ` (${esc(l.people.map(p => p.name).join(', '))})` : ''}.
      This cannot be undone. Answers and decisions already written to each domain's Activity log stay there.</div></div>
    <label class="field"><span>Type <b>DELETE</b> to confirm</span><input class="in mono" id="delIn" autocomplete="off" spellcheck="false" placeholder="DELETE"></label>`;
  el.hidden = false;
  el.innerHTML = modalShell('Delete review list', body, '<button class="btn" data-act="modal-close">Cancel</button><button class="btn danger-fill" id="delGo" data-act="del-ok" disabled>Delete list</button>', 'narrow');
}
async function changeMaster() {
  const set = S.rinfo?.masterSet;
  const pw = await askPassword(set ? 'Change the master password' : 'Set the master password', set ? 'Agents on lists that use the master password sign in again with the new one.' : 'Review lists use this password unless you give a list its own.');
  if (pw) act(async () => { S.rinfo = await api('/api/review/master', { password: pw }); }, 'Master password saved');
}
const saveOpen = () => LS.set('open', [...S.open]);

document.addEventListener('pointerdown', () => { S.pdown = Date.now(); }, true);
for (const ev of ['pointerup', 'pointercancel']) document.addEventListener(ev, () => { S.pdown = 0; if (S.pending) setTimeout(render, 0); }, true);
window.addEventListener('blur', () => { S.pdown = 0; });

document.addEventListener('click', async e => {
  if (S.menu && !e.target.closest('.menu')) closeMenu();
  // On narrow screens the sidebar opens over the page: close it on any choice in it, or a click outside it.
  if (document.body.classList.contains('side-open') && !e.target.closest('[data-act="side-toggle"]') && (!e.target.closest('.side') || e.target.closest('.side [data-act]'))) document.body.classList.remove('side-open');
  const t = e.target.closest('[data-act]');
  if (!t || t.tagName === 'INPUT' || t.tagName === 'SELECT' || t.disabled) return;
  const a = t.dataset.act;
  const ds = t.dataset;
  switch (a) {
    case 'nav': S.view = ds.view; if (ds.view === 'settings') { S.draftDirty = false; S.draft = null; } if (ds.view === 'reviews') S.rl = ''; render(); $('#view').scrollTop = 0; schedulePoll(); break;
    case 'dt': S.dt = ds.v; render(); break;

    // ----- Header, sidebar, dashboard -----
    case 'theme': setTheme(theme() === 'dark' ? 'light' : 'dark'); renderTop(); break;
    case 'side-toggle':
      if (innerWidth <= 900) document.body.classList.toggle('side-open');
      else { document.body.classList.toggle('side-hidden'); LS.set('sideHidden', document.body.classList.contains('side-hidden')); }
      break;
    case 'refresh':
      try { await loadAll(); render(); toast('Up to date'); } catch (err) { toast(err.message, true); }
      break;
    case 'bell': {
      const ls = reviewLists().filter(l => rvCounts(l).waiting);
      const ready = S.idx.contracts.filter(c => c._ready.state === 'ready').length;
      menu(t, [{ head: 'Waiting for you' },
        ...(ls.length ? ls.map(l => ({ value: `rv:${l.id}`, html: `<span class="nbadge warn">${rvCounts(l).waiting}</span> ${esc(l.name)}` })) : [{ value: '', label: 'No agent answers waiting', disabled: true }]),
        ...(ready ? [{ value: 'ready', html: `${ri('checkbox-circle-line')} ${plural(ready, 'contract')} ready for cancellation review` }] : []),
        { sep: true }, { value: 'log', html: `${ICONS.log} Scan log` }], v => {
        if (v.startsWith('rv:')) { S.view = 'reviews'; S.rl = v.slice(3); S.rvf = 'waiting'; S.rvStick.clear(); render(); schedulePoll(); }
        else if (v === 'ready') { S.view = 'contracts'; S.flag = 'c:ready'; S.hf = ''; render(); }
        else if (v === 'log') openDrawer('log', 'all');
      });
      break;
    }
    case 'dash-go': S.view = 'contracts'; S.hf = ds.hf || ''; S.flag = ''; S.dt = ''; S.q = ''; $('#q').value = ''; render(); $('#view').scrollTop = 0; schedulePoll(); break;
    case 'dash-reset': LS.set('dash', null); renderView(); toast('Widgets back in their original order'); break;

    // ----- Review lists -----
    case 'rv-new': openReviewCreate(); break;
    case 'rv-home': S.view = 'reviews'; S.rl = ''; render(); schedulePoll(); refreshReviewInfo().then(() => S.view === 'reviews' && renderView()); break;
    case 'rv-open': S.view = 'reviews'; S.rl = ds.id; S.rvf = ''; S.rvStick.clear(); S.drawer = null; render(); schedulePoll(); break;
    case 'rvf': S.rvf = ds.v; S.rvStick.clear(); render(); break;
    case 'rv-out': {
      const l = S.data.reviews[S.rl];
      const key = t.closest('[data-key]')?.dataset.key;
      const it = l?.items.find(i => i.key === key);
      if (!it) break;
      S.rvStick.add(key);
      act(() => api('/api/review/decide', { id: l.id, key, patch: { outcome: it.admin?.outcome === ds.v ? null : ds.v } }));
      break;
    }
    case 'rv-copy': { const ok = await copyText($('#rvUrl').value); toast(ok ? 'Link copied. Send it with the password.' : 'Could not copy: select the link and copy it.', !ok); break; }
    case 'rv-share':
      act(async () => {
        S.rinfo = await api('/api/review/config', { share: ds.v === '1' });
        if (S.rinfo.share.want && !S.rinfo.share.on) throw new Error(S.rinfo.share.error || 'Network sharing could not start');
      }, ds.v === '1' ? 'Network sharing on: review links now open from other devices' : 'Network sharing off');
      break;
    case 'rv-base': act(async () => { S.rinfo = await api('/api/review/config', { baseUrl: $('#rvBase').value }); }, 'Public address saved'); break;
    case 'rv-master': await changeMaster(); break;
    case 'rv-pw': {
      const l = S.data.reviews[S.rl];
      menu(t, [{ head: 'Password for this list' }, { value: 'master', label: 'Use the master password', on: l.pwMode === 'master', disabled: !S.rinfo?.masterSet },
        { value: 'own', label: l.pwMode === 'own' ? 'Change its own password…' : 'Give it its own password…', on: l.pwMode === 'own' }, { sep: true }, { value: 'mchange', label: 'Change the master password…' }], async v => {
        if (v === 'master') act(() => api('/api/review/update', { id: l.id, patch: { pwMode: 'master' } }), 'This list now uses the master password');
        else if (v === 'own') {
          const pw = await askPassword(`Password for “${l.name}”`, 'Anyone signed in to this list signs in again with the new password.');
          if (pw) act(() => api('/api/review/update', { id: l.id, patch: { pwMode: 'own', password: pw } }), 'Password saved');
        } else if (v === 'mchange') await changeMaster();
      });
      break;
    }
    case 'rv-menu': {
      const l = S.data.reviews[S.rl];
      menu(t, [{ value: 'rename', label: 'Rename…' }, { value: 'close', label: l.closed ? 'Reopen for answers' : 'Close list (agents can only read it)' }, { value: 'csv', html: `${ICONS.dl} Download results (CSV)` },
        { sep: true }, { value: 'delete', html: '<span style="color:var(--danger)">Delete list…</span>' }], v => {
        if (v === 'rename') { const n = prompt('List name', l.name); if (n && n.trim()) act(() => api('/api/review/update', { id: l.id, patch: { name: n } }), 'List renamed'); }
        else if (v === 'close') act(() => api('/api/review/update', { id: l.id, patch: { closed: !l.closed } }), l.closed ? 'List reopened' : 'List closed: agents can still read it');
        else if (v === 'csv') exportReviewCsv(l);
        else if (v === 'delete') deleteReviewList(l.id);
      });
      break;
    }
    case 'rv-delete': deleteReviewList(ds.id); break;
    case 'del-ok': {
      if ($('#delIn')?.value.trim() !== 'DELETE' || !S.del) break;
      const id = S.del.id;
      closeModal();
      act(async () => { await api('/api/review/delete', { id, confirm: 'DELETE' }); if (S.rl === id) S.rl = ''; }, 'Review list deleted');
      break;
    }
    case 'rv-bulk': {
      const l = S.data.reviews[S.rl];
      const keys = [...S.rvVisible];
      menu(t, [{ head: `Decision for ${plural(keys.length, 'domain')}` }, ...typeOf(l).outcomes(S.data.settings).map(o => ({ value: o.k, html: `<span class="hs c-${o.c}"><i></i>${esc(o.l)}</span>` })), { sep: true }, { value: '', label: 'Clear decision' }],
        v => { for (const k of keys) S.rvStick.add(k); act(() => api('/api/review/decide', { id: l.id, keys, patch: { outcome: v || null } }), `Updated ${plural(keys.length, 'domain')}`); });
      break;
    }
    case 'rv-rescan': { const keys = S.rvVisible.filter(k => S.data.domains[k]); if (keys.length) act(() => startScan({ kind: 'verify', keys })); break; }
    case 'rv-csv': exportReviewCsv(S.data.reviews[S.rl]); break;
    case 'rvc-pw': S.rvc.pwMode = ds.v; renderModal(); $('#rvPw')?.focus(); break;
    case 'rvc-type': {
      const top = $('.rvc-list')?.scrollTop || 0;
      S.rvc.type = ds.v;
      renderModal();
      if ($('.rvc-list')) $('.rvc-list').scrollTop = top;
      break;
    }
    case 'rvc-all': S.rvc.sel = new Set(S.rvc.keys); renderModal(); break;
    case 'rvc-fit': {
      const m = S.rvc;
      const before = m.sel.size;
      m.sel = new Set([...m.sel].filter(k => fitsType(m.type, S.data.domains[k])));
      renderModal();
      toast(`Left out ${plural(before - m.sel.size, 'domain')} that did not fit “${REVIEW_TYPES[m.type].l}”`);
      break;
    }
    case 'rvc-none': S.rvc.sel = new Set(); renderModal(); break;
    case 'rvc-create': {
      const m = S.rvc;
      if ((!S.rinfo?.masterSet || m.pwMode === 'own') && m.password.length < 6) { toast('The password needs at least 6 characters', true); $('#rvPw')?.focus(); break; }
      m.busy = true; renderModal();
      try {
        const r = await api('/api/review/create', { name: m.name, type: m.type, keys: m.keys.filter(k => m.sel.has(k)), from: m.from, pwMode: m.pwMode, password: m.password });
        closeModal();
        await refreshReviewInfo();
        await sync();
        S.view = 'reviews'; S.rl = r.id; S.rvf = ''; S.rvStick.clear();
        render(); schedulePoll();
        toast('Review list created. Copy the link and send it with the password.');
      } catch (err) { m.busy = false; renderModal(); toast(err.message, true); }
      break;
    }
    case 'modal-close': closeModal(); break;
    case 'pw-ok': {
      const v = $('#pwIn').value;
      if (v.length < 6) { toast('The password needs at least 6 characters', true); break; }
      const resolve = S.pwm.resolve;
      S.pwm = null;
      closeModal();
      resolve(v);
      break;
    }
    case 'acct': S.acct = ds.id; if (S.view !== 'dashboard') S.view = 'contracts'; render(); break;
    case 'hf': S.hf = S.hf === ds.v ? '' : ds.v; render(); break;
    case 'clear-one': if (ds.k === 'hf') S.hf = ''; else if (ds.k === 'flag') S.flag = ''; else if (ds.k === 'acct') S.acct = ''; else { S.q = ''; $('#q').value = ''; } render(); break;
    case 'side-hf': S.view = 'contracts'; S.hf = S.hf === ds.v ? '' : ds.v; render(); $('#view').scrollTop = 0; break;
    case 'side-flag': S.view = 'contracts'; S.flag = S.flag === ds.v ? '' : ds.v; render(); $('#view').scrollTop = 0; break;
    case 'clear-filters': clearFilters(); render(); break;
    case 'filter-menu': {
      const dom = S.idx.domains.filter(d => !S.acct || d.accountId === S.acct);
      const cons = S.idx.contracts.filter(c => !S.acct || c.accountId === S.acct);
      menu(t, [{ value: '', label: 'No filter', on: !S.flag }, { head: 'Contracts' }, ...CFLAGS.map(f => ({ value: `c:${f.k}`, label: `${f.l} (${cons.filter(f.fn).length})`, on: S.flag === `c:${f.k}` })),
        { head: 'Domains' }, ...FLAGS.map(f => ({ value: `d:${f.k}`, label: `${f.l} (${dom.filter(f.fn).length})`, on: S.flag === `d:${f.k}` }))], v => { S.flag = v; render(); });
      break;
    }
    case 'import': openImport(ds.kind || 'domains'); break;
    case 'status': {
      const cur = t.className.match(/s-(\w+)/)?.[1];
      if (ds.kind === 'service') { const key = S.drawer?.id; menu(t, statusItems(cur), v => act(() => setStatus('service', ds.id, '', v, { contract: key }))); }
      else menu(t, statusItems(cur), v => act(() => setStatus(ds.kind, ds.id, ds.track, v)));
      break;
    }
    case 'open': openDrawer('domain', ds.key); break;
    case 'open-contract': openDrawer('contract', ds.key); break;
    case 'open-email': openDrawer('email', ds.id); break;
    case 'open-log': openDrawer('log', 'all'); break;
    case 'goto': if (ds.email) openDrawer('email', ds.email); else if (ds.key) openDrawer('domain', ds.key); break;
    case 'close-drawer': closeDrawer(); break;
    case 'dr-step': stepDrawer(+ds.n); break;
    case 'con-toggle': if (S.open.has(ds.key)) S.open.delete(ds.key); else S.open.add(ds.key); saveOpen(); render(); break;
    case 'expand-all': for (const c of S.idx.contracts) if (!S.acct || c.accountId === S.acct) S.open.add(c.key); saveOpen(); render(); break;
    case 'collapse-all': S.open.clear(); saveOpen(); render(); break;
    case 'scan-all': act(() => startScan({ kind: 'verify', all: true })); break;
    case 'scan-more': menu(t, [{ value: 'verify', html: `${ICONS.refresh} Rescan all sites (server, site, SSL)` }, { value: 'tech', html: 'Technology scan of all sites (slower)' }, { sep: true }, { value: 'log', html: `${ICONS.log} Open scan log` }],
      v => (v === 'log' ? openDrawer('log', 'all') : act(() => startScan({ kind: v, all: true })))); break;
    case 'cancel-run': {
      const r = (S.data.scanRuns || []).find(x => x.id === ds.id);
      if (r?.jobId) act(() => api('/api/jobs/cancel', { id: r.jobId }), 'Stopping after the sites in progress');
      break;
    }
    case 'con-scan': {
      const c = S.data.contracts[ds.key];
      const keys = domFiltering() ? visibleIn(c).map(d => d.key) : null;
      act(() => startScan({ kind: 'verify', contractKey: c.key, ...(keys ? { keys } : {}) }));
      break;
    }
    case 'con-menu': {
      const c = S.data.contracts[ds.key];
      const vis = visibleIn(c);
      const keys = vis.map(d => d.key);
      const scope = domFiltering() ? `${vis.length} shown` : `all ${vis.length}`;
      const bulk = (track, label) => ({ value: `set:${track}`, html: `Set ${label} for ${scope}…` });
      menu(t, [{ value: 'scan', html: `${ICONS.refresh} Rescan ${scope} sites` }, { value: 'tech', html: `Technology scan of ${scope}` }, { sep: true },
        bulk('domain', 'Domain move'), bulk('website', 'Website'), bulk('email', 'Email'), { sep: true }, { value: 'details', html: 'Readiness, services and notes' }], v => {
        if (v === 'scan' || v === 'tech') act(() => startScan({ kind: v === 'tech' ? 'tech' : 'verify', contractKey: c.key, keys }));
        else if (v === 'details') openDrawer('contract', c.key);
        else if (v.startsWith('set:')) {
          const track = v.slice(4);
          menu(t, [{ head: `${track === 'domain' ? 'Domain move' : track === 'website' ? 'Website' : 'Email'} for ${scope}` }, ...statusItems('')],
            st => act(() => api('/api/domains/bulk', { keys, patch: { track: { [track]: st } } }), `Updated ${plural(keys.length, 'domain')}`));
        }
      });
      break;
    }
    case 'scan-dom': act(() => startScan({ kind: 'verify', keys: [ds.key] }, true)); break;
    case 'scan-one': act(() => startScan({ kind: ds.kind, keys: [S.drawer.id] }, true)); break;
    case 'export-csv': exportCsv(); break;
    case 'show-all': S.showAll[ds.k] = true; S._drSig = ''; render(); break;
    case 'ebulk-status': {
      const ids = [...S.evisible];
      menu(t, [{ head: `Status for ${ids.length} email records` }, ...statusItems('')], v => act(() => api('/api/email', { ids, patch: { status: v } }), `Updated ${plural(ids.length, 'email record')}`));
      break;
    }
    case 'ef-status': menu(t, [{ value: '', label: 'Any status', on: !S.ef.status }, ...statusItems(S.ef.status)], v => { S.ef.status = v; render(); }); break;
    case 'ef-link': S.ef.link = ds.v; render(); break;
    case 'confirm-ready': {
      const c = S.data.contracts[S.drawer.id];
      act(() => api('/api/contract', { key: c.key, patch: { readiness: { confirmed: true, note: $('#ready-note')?.value || '', snapshot: { domains: c._domains.length, services: (c.services || []).length } } } }), 'Cancellation readiness confirmed');
      break;
    }
    case 'revoke-ready': if (confirm('Revoke the cancellation readiness confirmation for this contract?')) act(() => api('/api/contract', { key: S.drawer.id, patch: { readiness: { confirmed: false } } }), 'Confirmation revoked'); break;
    case 'svc-add': {
      const name = prompt('Service name', ds.type === 'other' ? '' : ds.name);
      if (!name) break;
      act(() => api('/api/contract', { key: S.drawer.id, patch: { service: { type: ds.type, name, status: 'not_started' } } }), 'Service added');
      break;
    }
    case 'svc-del': if (confirm('Remove this service from the contract?')) act(() => api('/api/contract', { key: S.drawer.id, patch: { service: { remove: ds.id } } })); break;
    case 'tm-save': {
      const stack = $('#tm-stack').value;
      if (!stack) { toast('Choose a stack first', true); break; }
      act(() => patchDomain(S.drawer.id, { techManual: { stack, label: $('#tm-label').value, dbUses: $('#tm-db').value, dbType: $('#tm-dbtype').value, note: $('#tm-note').value } }), 'Technology confirmed');
      break;
    }
    case 'tm-clear': act(() => patchDomain(S.drawer.id, { techManual: null }), 'Manual confirmation removed'); break;
    case 'vps-add': { const n = S.draft.vps.length + 1; const id = `vps${Date.now().toString(36)}`; S.draft.vps.push({ id, name: `VPS ${n}`, ipv4: [], ipv6: [], token: randomToken(id), sourceTemplate: '' }); S.draftDirty = true; $('#view').innerHTML = viewSettings(); break; }
    case 'vps-del': if (confirm('Remove this VPS from the destination list?')) { S.draft.vps.splice(+ds.i, 1); S.draftDirty = true; $('#view').innerHTML = viewSettings(); } break;
    case 'vps-token': { const v = S.draft.vps[+ds.i]; v.token = randomToken(v.id); S.draftDirty = true; $('#view').innerHTML = viewSettings(); toast('New token generated. Save, then update the marker files on that VPS.'); break; }
    case 'settings-save':
      try { await api('/api/settings', { settings: S.draft }); S.draftDirty = false; S.draft = null; await sync(); $('#view').innerHTML = viewSettings(); toast('Settings saved'); }
      catch (err) { toast(err.message, true); }
      break;
    case 'acct-save': act(() => api('/api/account', { id: ds.id, patch: { name: $(`#an-${CSS.escape(ds.id)}`).value, sourceTemplate: $(`#as-${CSS.escape(ds.id)}`).value } }), 'Account saved'); break;
    case 'acct-del': {
      const ac = S.data.accounts[ds.id];
      if (prompt(`This removes all domains, contracts and tracking for "${ac.name}". A backup is taken first. Type DELETE to confirm.`) !== 'DELETE') break;
      act(() => api('/api/account/delete', { id: ds.id }), 'Account data deleted');
      break;
    }
    case 'backup': act(() => api('/api/backup', {}), 'Backup saved in data/backups'); break;
    case 'imp-kind': S.imp.kind = ds.v; renderModal(); break;
    case 'imp-cancel': case 'imp-done': { const k = S.imp?.kind; closeModal(); if (a === 'imp-done') { S.view = k === 'email' ? 'email' : 'contracts'; render(); } break; }
    case 'imp-back': S.imp.preview = null; renderModal(); break;
    case 'imp-again': openImport(S.imp.kind); break;
    case 'imp-commit': {
      const m = S.imp;
      m.busy = true; renderModal();
      try {
        const r = await api('/api/import/commit', { kind: m.kind, filename: m.filename, text: m.text, mapping: m.mapping, accountId: m.accountId || null, accountName: m.accountName });
        m.result = r.summary;
        await sync();
      } catch (err) { toast(err.message, true); }
      m.busy = false; renderModal();
      break;
    }
  }
});

document.addEventListener('change', e => {
  const t = e.target;
  const a = t.dataset.act;
  if (a === 'svc-reviewed') act(() => api('/api/contract', { key: S.drawer.id, patch: { servicesReviewed: t.checked } }));
  else if (a === 'email-contract') act(() => api('/api/email', { id: t.dataset.id, patch: { contractKey: t.value || null } }), 'Contract updated');
  else if (t.dataset.map !== undefined && S.imp) { S.imp.mapping[t.dataset.map] = t.value; renderModal(); }
  else if (t.dataset.svc) act(() => api('/api/contract', { key: S.drawer.id, patch: { service: { id: t.dataset.svc, [t.dataset.field]: t.value } } }));
  else if (t.dataset.save === 'source') act(() => patchDomain(S.drawer.id, { source: { spec: t.value } }), 'Source access saved');
  else if (t.dataset.rvnote !== undefined && S.rl) act(() => api('/api/review/decide', { id: S.rl, key: t.dataset.rvnote, patch: { note: t.value } }), 'Note saved. The agent sees it on their page.');
  else if (t.dataset.rvc !== undefined && S.rvc) {
    if (t.checked) S.rvc.sel.add(t.dataset.rvc); else S.rvc.sel.delete(t.dataset.rvc);
    $('#rvcCount').textContent = `${S.rvc.sel.size} of ${S.rvc.keys.length}`;
    const mis = rvcMismatchText();
    $('#rvcMis').textContent = mis;
    $('#rvcMisWrap').hidden = !mis;
    const b = $('#rvcGo');
    b.disabled = !S.rvc.sel.size;
    b.textContent = `Create list of ${S.rvc.sel.size}`;
  }
});

// Remember which drawer sections are open ("toggle" does not bubble, so listen in the capture phase).
document.addEventListener('toggle', e => {
  const el = e.target;
  if (!el.matches?.('details[data-det]')) return;
  if (el.open) S.det.add(el.dataset.det); else S.det.delete(el.dataset.det);
  LS.set('det', [...S.det]);
}, true);

// Autosave text fields
const saveDomainField = debounce((key, field, value) => act(() => patchDomain(key, { [field]: value })), 700);
const saveContractField = debounce((key, field, value) => act(() => api('/api/contract', { key, patch: { [field]: value } })), 700);
const saveEmailField = debounce((id, value) => act(() => api('/api/email', { id, patch: { notes: value } })), 700);
const searchRender = debounce(() => { renderView(); writeHash(); }, 120);
document.addEventListener('input', e => {
  const t = e.target;
  if (t.id === 'q') { S.q = t.value.trim(); if (S.view === 'settings') { S.view = 'contracts'; render(); } else searchRender(); return; }
  if (t.id === 'delIn') { $('#delGo').disabled = t.value.trim() !== 'DELETE'; return; }
  if (S.rvc && t.id === 'rvName') { S.rvc.name = t.value; return; }
  if (S.rvc && t.id === 'rvPw') { S.rvc.password = t.value; return; }
  if (t.dataset.save === 'notes' || t.dataset.save === 'blockers') { saveDomainField(S.drawer.id, t.dataset.save, t.value); if (t.dataset.save === 'blockers') t.classList.toggle('blocker', !!t.value.trim()); }
  else if (t.dataset.csave) saveContractField(S.drawer.id, t.dataset.csave, t.value);
  else if (t.dataset.esave) saveEmailField(t.dataset.id, t.value);
  else if (t.dataset.set && S.draft) {
    const path = t.dataset.set.split('.');
    let o = S.draft;
    for (const p of path.slice(0, -1)) o = o[p];
    const k = path[path.length - 1];
    o[k] = t.dataset.list ? t.value.split(/[,\s]+/).filter(Boolean) : t.dataset.lines ? t.value.split(/\n+/).map(x => x.trim()).filter(Boolean) : t.value;
    S.draftDirty = true;
  }
});
document.addEventListener('focusout', () => {
  setTimeout(() => {
    const ae = document.activeElement;
    if (S._drDirty && !($('#drawer').contains(ae) && /INPUT|TEXTAREA|SELECT/.test(ae.tagName))) renderDrawer();
    if (S._viewDirty && !($('#view').contains(ae) && /INPUT|TEXTAREA/.test(ae.tagName))) renderView();
  }, 50);
});

document.addEventListener('keydown', e => {
  if (e.key === 'Escape') {
    if (S.menu) closeMenu();
    else if (S.modal) closeModal();
    else if (S.drawer) closeDrawer();
    return;
  }
  if (e.key === 'Enter' && ['pwIn', 'rvPw', 'rvName', 'delIn'].includes(e.target.id)) {
    e.preventDefault();
    $({ pwIn: '[data-act="pw-ok"]', delIn: '#delGo' }[e.target.id] || '#rvcGo')?.click(); // a disabled button ignores the click
    return;
  }
  if (/INPUT|TEXTAREA|SELECT/.test(e.target.tagName) || e.metaKey || e.ctrlKey || e.altKey) return;
  if (e.key === '/') { e.preventDefault(); $('#q').focus(); $('#q').select(); }
  else if (S.drawer?.type === 'domain') {
    if (e.key === 'j') stepDrawer(1);
    else if (e.key === 'k') stepDrawer(-1);
    else if (e.key === 'r') act(() => startScan({ kind: 'verify', keys: [S.drawer.id] }, true));
  }
});

// ---------- Deep links ----------
function writeHash() {
  const p = new URLSearchParams();
  p.set('view', S.view);
  if (S.view === 'reviews' && S.rl) p.set('rl', S.rl);
  if (S.drawer) p.set(S.drawer.type === 'log' ? 'log' : S.drawer.type[0], S.drawer.id);
  const h = `#${p.toString()}`;
  if (location.hash !== h) history.replaceState(null, '', h);
}
function readHash() {
  const p = new URLSearchParams(location.hash.slice(1));
  S.view = VIEWS.includes(p.get('view')) ? p.get('view') : 'dashboard';
  S.rl = S.view === 'reviews' ? p.get('rl') || '' : '';
  S.drawer = null;
  if (p.get('d')) S.drawer = { type: 'domain', id: p.get('d') };
  else if (p.get('c')) S.drawer = { type: 'contract', id: p.get('c') };
  else if (p.get('e')) S.drawer = { type: 'email', id: p.get('e') };
  else if (p.get('log')) S.drawer = { type: 'log', id: 'all' };
}
window.addEventListener('hashchange', () => { readHash(); S._drSig = ''; render(); });

// ---------- Boot ----------
// ---------- Dashboard: drag a widget by its header to move it ----------
function endDrag() {
  for (const el of document.querySelectorAll('.widget.dragging, .widget.drop-before, .widget.drop-after')) el.classList.remove('dragging', 'drop-before', 'drop-after');
  S.dragW = null;
  S.pdown = 0;
  render();
}
document.addEventListener('dragstart', e => {
  const h = e.target.closest?.('.widget-h');
  if (!h) return;
  const w = h.closest('.widget');
  S.dragW = w.dataset.w;
  e.dataTransfer.effectAllowed = 'move';
  try { e.dataTransfer.setData('text/plain', S.dragW); e.dataTransfer.setDragImage(w, 24, 20); } catch {}
  setTimeout(() => w.classList.add('dragging'), 0);
});
document.addEventListener('dragover', e => {
  if (!S.dragW) return;
  const w = e.target.closest?.('.widget');
  if (!w || w.dataset.w === S.dragW) return;
  e.preventDefault();
  e.dataTransfer.dropEffect = 'move';
  const r = w.getBoundingClientRect();
  const after = e.clientX > r.left + r.width / 2;
  for (const el of document.querySelectorAll('.widget.drop-before, .widget.drop-after')) if (el !== w) el.classList.remove('drop-before', 'drop-after');
  w.classList.toggle('drop-after', after);
  w.classList.toggle('drop-before', !after);
});
document.addEventListener('drop', e => {
  if (!S.dragW) return;
  e.preventDefault();
  const w = e.target.closest?.('.widget');
  if (w && w.dataset.w !== S.dragW) {
    const order = dashOrder().filter(k => k !== S.dragW);
    const i = order.indexOf(w.dataset.w) + (w.classList.contains('drop-after') ? 1 : 0);
    order.splice(i, 0, S.dragW);
    LS.set('dash', order);
  }
  endDrag();
});
document.addEventListener('dragend', () => { if (S.dragW) endDrag(); });

(async () => {
  if (LS.get('sideHidden', false)) document.body.classList.add('side-hidden');
  readHash();
  try { await loadAll(); }
  catch (e) { $('#view').innerHTML = `<div class="card empty"><h2>Cannot reach the server</h2><p>${esc(e.message)}</p></div>`; return; }
  render();
  schedulePoll();
  setInterval(() => { if (!S.pdown && !S.dragW && liveRuns().length === 0) { renderSide(); renderTop(); if (['contracts', 'dashboard'].includes(S.view)) renderView(); } }, 60000); // keep "x min ago" fresh
})();
