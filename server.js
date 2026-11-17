// IONOS migration tracker: local-only server (127.0.0.1). No dependencies.
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { Store, makeToken } from './lib/store.js';
import { preview, commitDomains, commitEmails, STATUSES, slug } from './lib/importer.js';
import { Jobs } from './lib/jobs.js';
import { verifyDomain } from './lib/verify.js';
import { techScan } from './lib/tech.js';
import { resolveSource, parseSpec } from './lib/source.js';
import { health, sig, tally } from './public/health.js';
import { createList, updateList, setMaster, deleteList, decide, reviewRoute, lanUrls, withoutSecrets } from './lib/review.js';
import { hosted, publicUrl, publicHost, configProblem, sessionUser, loginRedirect, handleCallback, handleLogout } from './lib/sso.js';

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const PUB = path.join(ROOT, 'public');
const PORT = Number(process.env.PORT) || 4760;
const HOST = '127.0.0.1';
// Review pages only, for agents on other devices. Off until turned on in the app.
const REVIEW_PORT = Number(process.env.REVIEW_PORT) || PORT + 1;
const REVIEW_HOST = process.env.REVIEW_HOST || '0.0.0.0'; // 127.0.0.1 = tunnel only, not the local network
const REVIEW_ASSETS = new Set(['/review.js', '/review.css', '/theme.js']);
const REVIEW_ASSET_DIRS = ['/brand/', '/vendor/']; // logo, fonts, icons: shared with the agent page, never data
const isReviewAsset = p => REVIEW_ASSETS.has(p) || REVIEW_ASSET_DIRS.some(d => p.startsWith(d));
// Hosted (IMT_PUBLIC_URL set, see lib/sso.js): refuse to start without DevToolBox sign-in configured.
if (configProblem()) { console.error(`Not starting: ${configProblem()}`); process.exit(1); }
const store = new Store(path.join(ROOT, 'data'));
const jobs = new Jobs();
const STATUS_SET = new Set(STATUSES);
const TRACKS = ['domain', 'website', 'email'];
const ALLOWED_HOSTS = new Set([`127.0.0.1:${PORT}`, `localhost:${PORT}`, ...(hosted ? [publicHost] : [])]);
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon', '.json': 'application/json',
  '.woff2': 'font/woff2', '.woff': 'font/woff', '.ttf': 'font/ttf' };
const SECURITY_HEADERS = {
  'Content-Security-Policy': "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
};

const now = () => new Date().toISOString();
const str = (v, max = 20000) => String(v ?? '').slice(0, max);

function send(res, code, obj, extra = {}) {
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...SECURITY_HEADERS, ...extra });
  res.end(JSON.stringify(obj));
}

function readBody(req, limit = 30e6) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', c => {
      size += c.length;
      if (size > limit) { reject(new Error('Request too large')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      if (!chunks.length) return resolve({});
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); } catch { reject(new Error('Invalid JSON')); }
    });
    req.on('error', reject);
  });
}

function log(d, text) {
  d.log = [{ at: now(), text }, ...(d.log || [])].slice(0, 60);
}
const logDomain = (d, text) => { log(d, text); store.bump(d); };

function setTrack(d, track, status, why = '') {
  if (!TRACKS.includes(track) || !STATUS_SET.has(status)) throw new Error(`Invalid status ${track}=${status}`);
  const prev = d.track?.[track]?.status;
  if (prev === status) return false;
  d.track = d.track || {};
  d.track[track] = { status, at: now(), ...(why ? { by: 'scan', why } : {}) };
  log(d, `${track} status: ${prev || '—'} → ${status}${why ? ` (${why})` : ''}`);
  return true;
}

// A scan only ever moves the website status forward, never back, and never touches N/A.
// Verified needs the marker (verdict "verified"); Moved needs every DNS record on a VPS,
// the site answering and a valid certificate.
function autoWebsite(d, r, h) {
  const ws = d.track?.website?.status || 'not_started';
  if (ws === 'verified' || ws === 'na') return null;
  if (r.verdict === 'verified') return setTrack(d, 'website', 'verified', `scan: ${r.summary}`) ? 'verified' : null;
  if (h?.ok && ws !== 'moved') return setTrack(d, 'website', 'moved', `scan: on ${h.server}, site answering, SSL valid`) ? 'moved' : null;
  return null;
}

function patchDomain(d, p) {
  if (p.track) for (const [t, s] of Object.entries(p.track)) setTrack(d, t, s);
  if ('notes' in p) d.notes = str(p.notes);
  if ('blockers' in p) {
    const b = str(p.blockers).trim();
    if (b !== (d.blockers || '')) log(d, b ? 'Blocker updated' : 'Blocker cleared');
    d.blockers = b;
  }
  if ('source' in p) {
    const spec = str(p.source?.spec, 500).trim();
    if (spec) {
      const parsed = parseSpec(spec);
      if (parsed?.error) throw new Error(parsed.error);
      d.source = { spec };
    } else d.source = null;
  }
  if ('techManual' in p) {
    const m = p.techManual;
    d.techManual = m ? { stack: str(m.stack, 40), label: str(m.label, 120), dbUses: str(m.dbUses, 20), dbType: str(m.dbType, 120), note: str(m.note, 2000), at: now() } : null;
    log(d, m ? `Tech confirmed manually: ${d.techManual.label || d.techManual.stack || '—'}` : 'Manual tech confirmation removed');
  }
}

const isIpOrCidr = s => {
  const [ip, len] = String(s).split('/');
  if (!net.isIP(ip)) return false;
  return len === undefined || (/^\d+$/.test(len) && +len <= (net.isIPv6(ip) ? 128 : 32));
};

function cleanSettings(input, current) {
  const s = { ...current };
  if (Array.isArray(input.vps)) {
    const ids = new Set();
    s.vps = input.vps.slice(0, 20).map((v, i) => {
      let id = slug(v.id || v.name || `vps${i + 1}`);
      while (ids.has(id)) id += 'x';
      ids.add(id);
      const ipv4 = (v.ipv4 || []).map(x => String(x).trim()).filter(Boolean);
      const ipv6 = (v.ipv6 || []).map(x => String(x).trim()).filter(Boolean);
      for (const ip of ipv4) if (!isIpOrCidr(ip) || ip.includes(':')) throw new Error(`Invalid IPv4 "${ip}" for ${v.name}`);
      for (const ip of ipv6) if (!isIpOrCidr(ip) || !ip.includes(':')) throw new Error(`Invalid IPv6 "${ip}" for ${v.name}`);
      const tpl = str(v.sourceTemplate, 500).trim();
      if (tpl && parseSpec(tpl.replace(/\{domain\}/g, 'example.com').replace(/\{path\}/g, ''))?.error) throw new Error(`Invalid source template for ${v.name}`);
      return { id, name: str(v.name || id, 80), ipv4, ipv6, token: str(v.token, 200).trim() || makeToken(id), sourceTemplate: tpl };
    });
  }
  if (Array.isArray(input.oldRanges)) {
    s.oldRanges = input.oldRanges.map(x => String(x).trim()).filter(Boolean);
    for (const r of s.oldRanges) if (!isIpOrCidr(r)) throw new Error(`Invalid old-hosting range "${r}"`);
  }
  if ('markerPath' in input) {
    const p = str(input.markerPath, 200).trim();
    if (p && (!p.startsWith('/') || /\s/.test(p))) throw new Error('Marker path must start with / and contain no spaces');
    s.markerPath = p;
  }
  if (Array.isArray(input.resolvers)) {
    s.resolvers = input.resolvers.map(x => String(x).trim()).filter(Boolean);
    for (const r of s.resolvers) if (!net.isIP(r)) throw new Error(`Resolver "${r}" must be an IP address`);
  }
  if ('concurrency' in input) s.concurrency = Math.min(16, Math.max(1, parseInt(input.concurrency, 10) || 6));
  if ('timeoutMs' in input) s.timeoutMs = Math.min(30000, Math.max(3000, parseInt(input.timeoutMs, 10) || 10000));
  return s;
}

// ---------- Scan runs (the scan log) ----------
const RUN_KEEP = 40;
const LIST_CAP = 400;
function newRun(kind, scope, label, contractKey) {
  const run = {
    id: `run${Date.now().toString(36)}${crypto.randomBytes(2).toString('hex')}`, kind, scope, label, contractKey: contractKey || null,
    startedAt: now(), finishedAt: null, total: 0, done: 0, errors: 0, cancelled: false, interrupted: false, jobId: null,
    counts: null, newlyScanned: 0, changes: [], moreChanges: 0, statusChanges: [],
  };
  store.data.scanRuns.unshift(run);
  store.data.scanRuns = store.data.scanRuns.slice(0, RUN_KEEP);
  return run;
}
function techTally(domains) {
  const c = { total: domains.length, scanned: 0, stack: {}, review: 0, dbIonos: 0 };
  for (const d of domains) {
    if (!d.tech) continue;
    c.scanned++;
    const k = d.techManual?.stack || d.tech.stack?.key || 'unknown';
    c.stack[k] = (c.stack[k] || 0) + 1;
    if (d.tech.review && !d.techManual) c.review++;
    if (d.tech.db?.where === 'ionos') c.dbIonos++;
  }
  return c;
}
function finishRun(run, job, keys) {
  run.finishedAt = now();
  run.cancelled = job.cancelled;
  run.total = job.total;
  const domains = run.scope === 'all' ? Object.values(store.data.domains) : keys.map(k => store.data.domains[k]).filter(Boolean);
  run.counts = run.kind === 'tech' ? techTally(domains) : tally(domains, store.data.settings);
  store.bump(run);
}

// ---------- Scan workers ----------
async function verifyWorker(key, run) {
  const d = store.data.domains[key];
  if (!d) return;
  const settings = store.data.settings;
  const before = health(d.scan, settings);
  const r = await verifyDomain(d, settings);
  const cur = store.data.domains[key];
  if (!cur) return;
  cur.scan = r;
  cur.scanHistory = [{ at: r.at, verdict: r.verdict, summary: r.summary }, ...(cur.scanHistory || [])].slice(0, 12);
  const after = health(r, settings);
  const moved = autoWebsite(cur, r, after);
  store.bump(cur);
  if (!run) return;
  if (!before) run.newlyScanned++;
  else if (sig(before) !== sig(after)) {
    if (run.changes.length < LIST_CAP) run.changes.push({ k: key, d: cur.domain, f: sig(before), t: sig(after) });
    else run.moreChanges++;
  }
  if (moved && run.statusChanges.length < LIST_CAP) run.statusChanges.push({ k: key, d: cur.domain, to: moved });
}

async function techWorker(key) {
  const d = store.data.domains[key];
  if (!d) return;
  const acct = store.data.accounts[d.accountId];
  const source = resolveSource(d, acct, store.data.settings);
  const r = await techScan(d, { settings: store.data.settings, source });
  const cur = store.data.domains[key];
  if (!cur) return;
  cur.tech = r;
  store.bump(cur);
  // A database confirmed (from config) to be hosted by IONOS becomes a contract service to track.
  if (r.db?.where === 'ionos' && r.db.conf === 'detected') {
    const c = store.data.contracts[cur.contractKey];
    if (c) {
      const name = `Database ${r.db.host}${r.db.name ? ` / ${r.db.name}` : ''}`;
      if (!c.services.some(s => s.name === name)) {
        c.services.push({ id: crypto.randomUUID(), type: 'database', name, status: 'not_started', notes: `Found in ${r.db.ev} for ${cur.domain}`, blocker: '', domainKey: cur.key, auto: true, at: now() });
        store.bump(c);
      }
    }
  }
}

// ---------- Routes ----------
async function api(req, res, url) {
  const route = `${req.method} ${url.pathname}`;
  const data = store.data;
  const body = req.method === 'GET' ? {} : await readBody(req);

  switch (route) {
    case 'GET /api/state':
      return send(res, 200, { rev: data.rev, data: withoutSecrets(data), jobs: jobs.summary() });

    case 'GET /api/changes': {
      const since = parseInt(url.searchParams.get('since'), 10) || 0;
      const ch = store.changes(since);
      if (ch.full) ch.data = withoutSecrets(ch.data);
      return send(res, 200, { ...ch, jobs: jobs.summary() });
    }

    // ---------- Review lists (admin side) ----------
    case 'GET /api/review/info':
      return send(res, 200, reviewInfo());

    case 'POST /api/review/config': {
      const cfg = data.reviewConfig;
      if ('baseUrl' in body) {
        const u = str(body.baseUrl, 300).trim().replace(/\/+$/, '');
        if (u) {
          let ok = false;
          try { ok = ['http:', 'https:'].includes(new URL(u).protocol); } catch {}
          if (!ok) throw new Error('The public address must look like https://review.example.com');
        }
        cfg.baseUrl = u;
      }
      if ('share' in body) cfg.share = !!body.share;
      store.bump();
      await applyShare();
      return send(res, 200, reviewInfo());
    }

    case 'POST /api/review/master':
      setMaster(store, body.password);
      return send(res, 200, reviewInfo());

    case 'POST /api/review/create': {
      const list = createList(store, body);
      return send(res, 200, { ok: true, id: list.id });
    }

    case 'POST /api/review/update':
      updateList(store, body.id, body.patch || {});
      return send(res, 200, { ok: true });

    case 'POST /api/review/delete':
      if (body.confirm !== 'DELETE') throw new Error('Type DELETE to confirm');
      deleteList(store, body.id);
      return send(res, 200, { ok: true });

    case 'POST /api/review/decide': {
      const keys = Array.isArray(body.keys) ? body.keys : [body.key];
      return send(res, 200, { ok: true, count: decide(store, body.id, keys, body.patch || {}, logDomain) });
    }

    case 'POST /api/import/preview':
      return send(res, 200, preview({ kind: body.kind === 'email' ? 'email' : 'domains', filename: str(body.filename, 300), text: str(body.text, 30e6) }));

    case 'POST /api/import/commit': {
      const args = { filename: str(body.filename, 300), text: str(body.text, 30e6), mapping: body.mapping || {}, accountId: body.accountId || null, accountName: body.accountName };
      const summary = body.kind === 'email' ? commitEmails(store, args) : commitDomains(store, args);
      store.flush();
      return send(res, 200, { ok: true, summary });
    }

    case 'POST /api/domain': {
      const d = data.domains[body.key];
      if (!d) return send(res, 404, { error: 'Domain not found' });
      patchDomain(d, body.patch || {});
      store.bump(d);
      return send(res, 200, { ok: true });
    }

    case 'POST /api/domains/bulk': {
      const keys = (body.keys || []).filter(k => data.domains[k]);
      const p = body.patch || {};
      const allowed = {};
      if (p.track) allowed.track = p.track;
      if ('blockers' in p) allowed.blockers = p.blockers;
      for (const k of keys) { patchDomain(data.domains[k], allowed); store.bump(data.domains[k]); }
      return send(res, 200, { ok: true, count: keys.length });
    }

    case 'POST /api/contract': {
      const c = data.contracts[body.key];
      if (!c) return send(res, 404, { error: 'Contract not found' });
      const p = body.patch || {};
      if ('notes' in p) c.notes = str(p.notes);
      if ('label' in p) c.label = str(p.label, 120);
      if ('servicesReviewed' in p) c.servicesReviewed = !!p.servicesReviewed;
      if (p.readiness) {
        c.readiness = p.readiness.confirmed
          ? { confirmed: true, at: now(), note: str(p.readiness.note, 2000), snapshot: p.readiness.snapshot || null }
          : { confirmed: false, revokedAt: now(), previous: c.readiness?.confirmed ? c.readiness : null };
      }
      if (p.service) {
        const s = p.service;
        if (s.remove) c.services = c.services.filter(x => x.id !== s.remove);
        else {
          if (s.status && !STATUS_SET.has(s.status)) throw new Error('Invalid status');
          const ex = c.services.find(x => x.id === s.id);
          const clean = { type: str(s.type || 'other', 40), name: str(s.name, 200), status: s.status || 'not_started', notes: str(s.notes, 4000), blocker: str(s.blocker, 2000) };
          if (ex) Object.assign(ex, Object.fromEntries(Object.entries(clean).filter(([k]) => k in s)), { at: now() });
          else c.services.push({ id: crypto.randomUUID(), ...clean, at: now() });
        }
      }
      store.bump(c);
      return send(res, 200, { ok: true });
    }

    case 'POST /api/email': {
      const ids = body.ids || [body.id];
      const p = body.patch || {};
      let n = 0;
      for (const id of ids) {
        const e = data.emails[id];
        if (!e) continue;
        if (p.status) { if (!STATUS_SET.has(p.status)) throw new Error('Invalid status'); e.status = p.status; e.statusAt = now(); }
        if ('notes' in p) e.notes = str(p.notes);
        if ('contractKey' in p) {
          if (p.contractKey && !data.contracts[p.contractKey]) throw new Error('Unknown contract');
          e.contractKey = p.contractKey || null;
          e.manualContract = !!p.contractKey;
          if (p.contractKey) e.accountId = data.contracts[p.contractKey].accountId;
        }
        store.bump(e);
        n++;
      }
      return send(res, 200, { ok: true, count: n });
    }

    case 'POST /api/settings': {
      data.settings = cleanSettings(body.settings || {}, data.settings);
      store.bump(data.settings);
      return send(res, 200, { ok: true, settings: data.settings });
    }

    case 'POST /api/account': {
      const a = data.accounts[body.id];
      if (!a) return send(res, 404, { error: 'Account not found' });
      const p = body.patch || {};
      if ('name' in p && str(p.name, 120).trim()) a.name = str(p.name, 120).trim();
      if ('sourceTemplate' in p) {
        const tpl = str(p.sourceTemplate, 500).trim();
        if (tpl && parseSpec(tpl.replace(/\{domain\}/g, 'example.com').replace(/\{path\}/g, ''))?.error) throw new Error('Invalid source template');
        a.sourceTemplate = tpl;
      }
      store.bump(a);
      return send(res, 200, { ok: true });
    }

    case 'POST /api/account/delete': {
      const a = data.accounts[body.id];
      if (!a) return send(res, 404, { error: 'Account not found' });
      store.backup(`before-delete-${a.id}`);
      for (const [k, d] of Object.entries(data.domains)) if (d.accountId === a.id) delete data.domains[k];
      for (const [k, c] of Object.entries(data.contracts)) if (c.accountId === a.id) delete data.contracts[k];
      for (const e of Object.values(data.emails)) if (e.accountId === a.id) { e.accountId = null; e.domainKey = null; e.contractKey = null; e.manualContract = false; }
      delete data.accounts[a.id];
      store.markReset();
      return send(res, 200, { ok: true });
    }

    case 'POST /api/scan': {
      // Scope: every domain (the central scan button), one contract, or a list of keys.
      const kind = body.kind === 'tech' ? 'tech' : 'verify';
      let keys, scope = 'selection', label = '', contractKey = null;
      if (body.all) { keys = Object.keys(data.domains); scope = 'all'; label = 'All sites'; }
      else if (body.contractKey) {
        const c = data.contracts[body.contractKey];
        if (!c) return send(res, 404, { error: 'Contract not found' });
        const inC = Object.values(data.domains).filter(d => d.contractKey === c.key).map(d => d.key);
        keys = Array.isArray(body.keys) && body.keys.length ? body.keys.filter(k => inC.includes(k)) : inC;
        scope = 'contract';
        contractKey = c.key;
        label = `${c.number ? `Contract ${c.number}` : 'No contract number'}${Array.isArray(body.keys) && body.keys.length && keys.length < inC.length ? ` (${keys.length} shown)` : ''}`;
      } else keys = (body.keys || []).filter(k => data.domains[k]);
      if (!keys.length) return send(res, 400, { error: 'No domains to scan' });
      if (scope === 'all' && data.scanRuns.some(r => !r.finishedAt && r.kind === kind && r.scope === 'all')) return send(res, 409, { error: 'A full scan is already running' });
      const run = scope !== 'selection' || keys.length > 1 ? newRun(kind, scope, label || `${keys.length} domains`, contractKey) : null;
      const conc = data.settings.concurrency || 6;
      const base = kind === 'tech' ? techWorker : verifyWorker;
      const worker = !run ? k => base(k, null) : async k => {
        try { await base(k, run); }
        catch (e) { run.errors++; throw e; }
        finally { run.done++; store.bump(run); }
      };
      const job = jobs.start(kind, keys, worker, kind === 'tech' ? Math.max(1, Math.ceil(conc / 2)) : conc, run ? j => finishRun(run, j, keys) : null);
      if (run) { run.jobId = job.id; run.total = job.total; store.bump(run); }
      return send(res, 200, { ok: true, job, run: run ? run.id : null });
    }

    case 'POST /api/jobs/cancel':
      return send(res, 200, { ok: jobs.cancel(body.id) });

    case 'POST /api/backup':
      return send(res, 200, { ok: true, file: store.backup('manual') });

    case 'GET /api/export': {
      store.flush();
      const name = `ionos-migration-${new Date().toISOString().slice(0, 10)}.json`;
      res.writeHead(200, { 'Content-Type': 'application/json', 'Content-Disposition': `attachment; filename="${name}"`, ...SECURITY_HEADERS });
      return res.end(JSON.stringify(withoutSecrets(data), null, 1));
    }
  }
  return send(res, 404, { error: 'Not found' });
}

function serveStatic(req, res, url) {
  let p = decodeURIComponent(url.pathname);
  if (p === '/') p = '/index.html';
  const file = path.normalize(path.join(PUB, p));
  if (!file.startsWith(PUB + path.sep)) { res.writeHead(403); return res.end(); }
  fs.readFile(file, (err, buf) => {
    if (err) { res.writeHead(404, SECURITY_HEADERS); return res.end('Not found'); }
    // Fonts, icons and logos never change between versions of the app: let the browser keep them for a week.
    const stable = p.startsWith('/vendor/') || p.startsWith('/brand/');
    res.writeHead(200, { 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream', 'Cache-Control': stable ? 'public, max-age=604800' : 'no-cache', ...SECURITY_HEADERS });
    res.end(buf);
  });
}

// ---------- Review pages (/r/<list id>) ----------
function sendReviewPage(res) {
  fs.readFile(path.join(PUB, 'review.html'), (err, buf) => {
    if (err) { res.writeHead(500, SECURITY_HEADERS); return res.end('Review page missing'); }
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', 'X-Robots-Tag': 'noindex, nofollow', ...SECURITY_HEADERS });
    res.end(buf);
  });
}
const reviewHandler = reviewRoute({ store, send, readBody, sendPage: sendReviewPage, logDomain });
async function handleReview(req, res, url) {
  if (req.method !== 'GET') {
    // Same-origin JSON only: blocks form posts and cross-site scripts from other pages.
    const origin = req.headers.origin;
    if (origin && origin.replace(/^https?:\/\//, '') !== String(req.headers.host || '')) return send(res, 403, { error: 'Cross-origin request blocked' });
    if (!String(req.headers['content-type'] || '').startsWith('application/json')) return send(res, 415, { error: 'JSON required' });
  }
  try { await reviewHandler(req, res, url); }
  catch (e) { if (!res.headersSent) send(res, 400, { error: e.message }); }
}

// The share listener serves review pages and their two assets, nothing else.
// The tracker itself is never reachable through it.
let shareServer = null;
let shareError = '';
function shareHandler(req, res) {
  let url;
  try { url = new URL(req.url, 'http://review.invalid'); } catch { res.writeHead(400); return res.end(); }
  if (url.pathname.startsWith('/r/')) return handleReview(req, res, url);
  // Check the decoded, normalised path, so "/vendor/..%2fapp.js" cannot reach other files.
  let clean = '';
  try { clean = path.posix.normalize(decodeURIComponent(url.pathname)); } catch {}
  if (req.method === 'GET' && isReviewAsset(clean)) return serveStatic(req, res, url);
  res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8', ...SECURITY_HEADERS });
  res.end('Not found');
}
function applyShare() {
  return new Promise(resolve => {
    // Hosted: review links are served from the public address itself, so never open a second port.
    const want = !hosted && !!store.data.reviewConfig.share;
    if (want && !shareServer) {
      shareError = '';
      const srv = http.createServer(shareHandler);
      shareServer = srv;
      srv.once('error', e => {
        shareError = e.code === 'EADDRINUSE' ? `Port ${REVIEW_PORT} is already in use. Restart with REVIEW_PORT=4771 npm start to use another port.` : e.message;
        if (shareServer === srv) shareServer = null;
        resolve();
      });
      srv.listen(REVIEW_PORT, REVIEW_HOST, () => {
        console.log(`Review links shared at: ${shareUrls().join(', ') || `port ${REVIEW_PORT}`}`);
        resolve();
      });
    } else if (!want && shareServer) {
      const srv = shareServer;
      shareServer = null;
      srv.close();
      srv.closeAllConnections?.();
      console.log('Review link sharing turned off');
      resolve();
    } else resolve();
  });
}
const shareUrls = () => (REVIEW_HOST === '0.0.0.0' ? lanUrls(REVIEW_PORT) : [`http://${REVIEW_HOST}:${REVIEW_PORT}`]);
function reviewInfo() {
  const on = !!shareServer?.listening;
  return {
    hosted,
    masterSet: !!store.data.reviewAuth.master,
    baseUrl: store.data.reviewConfig.baseUrl || (hosted ? publicUrl : ''),
    share: { want: !!store.data.reviewConfig.share, on, port: REVIEW_PORT, urls: on ? shareUrls() : [], error: shareError },
  };
}

const server = http.createServer(async (req, res) => {
  // Local-only guard: reject other Host headers (DNS rebinding) and cross-site writes.
  if (!ALLOWED_HOSTS.has(String(req.headers.host || ''))) { res.writeHead(421); return res.end('Misdirected request'); }
  const url = new URL(req.url, `http://${req.headers.host}`);
  if (req.method !== 'GET') {
    const origin = req.headers.origin;
    if (origin && !ALLOWED_HOSTS.has(origin.replace(/^https?:\/\//, ''))) return send(res, 403, { error: 'Cross-origin request blocked' });
    if (!String(req.headers['content-type'] || '').startsWith('application/json')) return send(res, 415, { error: 'JSON required' });
  }
  if (url.pathname.startsWith('/r/')) return handleReview(req, res, url); // review pages: their own passwords
  if (hosted) {
    // Everything else needs a DevToolBox sign-in (lib/sso.js).
    if (url.pathname === '/_sso' && req.method === 'GET') return handleCallback(req, res, url, SECURITY_HEADERS);
    if (url.pathname === '/_sso/logout' && req.method === 'GET') return handleLogout(res, SECURITY_HEADERS);
    if (!sessionUser(req)) {
      let clean = '';
      try { clean = path.posix.normalize(decodeURIComponent(url.pathname)); } catch {}
      if (req.method === 'GET' && isReviewAsset(clean)) return serveStatic(req, res, url); // files the review page loads
      if (url.pathname.startsWith('/api/')) return send(res, 401, { error: 'Signed out. Reload the page to sign in again.', signedOut: true });
      if (req.method !== 'GET') { res.writeHead(401, SECURITY_HEADERS); return res.end(); }
      res.writeHead(302, { Location: loginRedirect(url), 'Cache-Control': 'no-store', ...SECURITY_HEADERS });
      return res.end();
    }
  }
  if (url.pathname.startsWith('/api/')) {
    try { await api(req, res, url); }
    catch (e) { if (!res.headersSent) send(res, 400, { error: e.message }); }
    return;
  }
  if (req.method !== 'GET') { res.writeHead(405); return res.end(); }
  serveStatic(req, res, url);
});

server.listen(PORT, HOST, () => {
  console.log(hosted ? `IONOS migration tracker running at ${publicUrl} (sign-in through DevToolBox)` : `IONOS migration tracker running at http://localhost:${PORT}`);
  console.log(`Data: ${store.file}`);
  applyShare();
});
server.on('error', e => { console.error(e.code === 'EADDRINUSE' ? `Port ${PORT} is in use. Try PORT=4761 npm start` : e); process.exit(1); });
for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, () => { try { store.flush(); } catch {} process.exit(0); });
