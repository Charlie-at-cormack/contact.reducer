// Review lists: a set of domains that an agent checks on a password-protected page,
// with the admin recording a decision for each domain.
// Secrets (password hashes, session tokens) live in data.reviewAuth and never reach a browser.
import crypto from 'node:crypto';
import os from 'node:os';
import { health, SITE, SSL } from '../public/health.js';
import { REVIEW_TYPES, typeOf, verdictMeta, outcomeMeta } from '../public/reviewtypes.js';

const SESSION_MS = 30 * 864e5;
const FAIL_WINDOW = 15 * 60e3;
const FAIL_MAX = 10;

const now = () => new Date().toISOString();
const str = (v, max) => String(v ?? '').slice(0, max);
const sha = s => crypto.createHash('sha256').update(String(s)).digest('base64url');
const age = iso => Date.now() - Date.parse(iso || 0);

// ---------- Passwords ----------
function hashPw(pw) {
  const p = String(pw ?? '');
  if (p.length < 6) throw new Error('The password needs at least 6 characters');
  if (p.length > 200) throw new Error('The password is too long');
  const salt = crypto.randomBytes(16).toString('base64url');
  return { salt, hash: crypto.scryptSync(p, salt, 32).toString('base64url'), at: now() };
}
function pwMatches(pw, rec) {
  if (!rec?.salt || typeof pw !== 'string' || !pw || pw.length > 200) return false;
  const a = crypto.scryptSync(pw, rec.salt, 32);
  const b = Buffer.from(rec.hash, 'base64url');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

// What the admin's browser may see: everything except the secrets.
export const withoutSecrets = d => ({ ...d, reviewAuth: undefined });

export function lanUrls(port) {
  const out = [];
  for (const list of Object.values(os.networkInterfaces())) {
    for (const i of list || []) if ((i.family === 'IPv4' || i.family === 4) && !i.internal) out.push(`http://${i.address}:${port}`);
  }
  return out;
}

// Same rule as the browser: IONOS says SUB_DOMAIN, or a parent domain is in the same contract.
function subdomainTest(data) {
  const byContract = new Map();
  for (const d of Object.values(data.domains)) {
    if (!byContract.has(d.contractKey)) byContract.set(d.contractKey, new Set());
    byContract.get(d.contractKey).add(d.domain);
  }
  return d => {
    if (d.type === 'SUB_DOMAIN') return true;
    const names = byContract.get(d.contractKey);
    let p = d.domain;
    while (p.includes('.')) { p = p.slice(p.indexOf('.') + 1); if (names?.has(p)) return true; }
    return false;
  };
}

function snapshot(d, settings) {
  const h = health(d.scan, settings);
  return h ? { server: h.server, ip: h.ip || '', site: h.site, siteDetail: h.siteDetail || '', ssl: h.ssl || '', at: h.at || null } : null;
}

// ---------- Admin operations ----------
export function createList(store, body) {
  const data = store.data;
  const name = str(body.name, 120).trim();
  if (!name) throw new Error('Give the list a name');
  const keys = [...new Set(Array.isArray(body.keys) ? body.keys : [])].filter(k => typeof k === 'string' && data.domains[k]).slice(0, 2000);
  if (!keys.length) throw new Error('Choose at least one domain');
  const auth = data.reviewAuth;
  const pwMode = body.pwMode === 'own' ? 'own' : 'master';
  // Validate before changing anything. The first list that uses the master password sets it.
  const own = pwMode === 'own' ? hashPw(body.password) : null;
  const master = pwMode === 'master' && !auth.master ? hashPw(body.password) : null;
  if (master) auth.master = master;
  const id = crypto.randomBytes(12).toString('base64url');
  const isSub = subdomainTest(data);
  const list = {
    id, name, type: REVIEW_TYPES[body.type] ? body.type : 'down', from: str(body.from, 300), createdAt: now(), closed: false, closedAt: null, pwMode, people: [],
    items: keys.map(k => {
      const d = data.domains[k];
      return { key: k, domain: d.domain, contractKey: d.contractKey || null, contract: data.contracts[d.contractKey]?.number || '', sub: isSub(d), snap: snapshot(d, data.settings), agent: null, admin: null };
    }),
  };
  data.reviews[id] = list;
  auth.lists[id] = { own, sessions: [] };
  store.bump(list);
  return list;
}

export function updateList(store, id, p) {
  const data = store.data;
  const list = data.reviews[id];
  if (!list) throw new Error('Review list not found');
  if (!data.reviewAuth.lists[id]) data.reviewAuth.lists[id] = { own: null, sessions: [] };
  const a = data.reviewAuth.lists[id];
  if ('name' in p) {
    const n = str(p.name, 120).trim();
    if (!n) throw new Error('The name cannot be empty');
    list.name = n;
  }
  if ('closed' in p) { list.closed = !!p.closed; list.closedAt = list.closed ? now() : null; }
  // A password change signs everyone out of this list.
  if (p.pwMode === 'own') { a.own = hashPw(p.password); list.pwMode = 'own'; a.sessions = []; }
  else if (p.pwMode === 'master') {
    if (!data.reviewAuth.master) throw new Error('Set a master password first');
    a.own = null; list.pwMode = 'master'; a.sessions = [];
  }
  store.bump(list);
}

export function setMaster(store, pw) {
  const data = store.data;
  data.reviewAuth.master = hashPw(pw);
  // Everyone on a list that uses the master password signs in again with the new one.
  for (const [id, l] of Object.entries(data.reviews)) if (l.pwMode === 'master' && data.reviewAuth.lists[id]) data.reviewAuth.lists[id].sessions = [];
  store.bump();
}

export function deleteList(store, id) {
  if (!store.data.reviews[id]) throw new Error('Review list not found');
  delete store.data.reviews[id];
  delete store.data.reviewAuth.lists[id];
  store.markReset();
}

export function decide(store, id, keys, p, logDomain) {
  const data = store.data;
  const list = data.reviews[id];
  if (!list) throw new Error('Review list not found');
  const type = typeOf(list);
  if ('outcome' in p && p.outcome && !type.outcomes(data.settings).some(o => o.k === p.outcome)) throw new Error('Unknown decision for this type of list');
  const want = new Set(keys);
  let n = 0;
  for (const it of list.items) {
    if (!want.has(it.key)) continue;
    it.admin ||= {};
    const ad = it.admin;
    if ('outcome' in p && (ad.outcome || null) !== (p.outcome || null)) {
      ad.outcome = p.outcome || null;
      ad.outcomeAt = now();
      const d = data.domains[it.key];
      if (d) logDomain(d, `Review “${list.name}”: ${p.outcome ? `you marked ${outcomeMeta(type, p.outcome, data.settings).l}` : 'decision cleared'}`);
    }
    if ('note' in p) {
      const t = str(p.note, 4000).trim();
      if (t !== (ad.note || '')) { ad.note = t; ad.noteAt = now(); }
    }
    n++;
  }
  store.bump(list);
  return n;
}

// ---------- Agent page ----------
const fails = new Map();
function tooMany(k) {
  const f = fails.get(k);
  if (f && Date.now() - f.first > FAIL_WINDOW) { fails.delete(k); return false; }
  return !!f && f.n >= FAIL_MAX;
}
function noteFail(k) {
  const f = fails.get(k);
  if (!f || Date.now() - f.first > FAIL_WINDOW) fails.set(k, { n: 1, first: Date.now() });
  else f.n++;
}

function sessionOf(store, id, req) {
  const m = /(?:^|;\s*)rv=([A-Za-z0-9_-]{20,})/.exec(req.headers.cookie || '');
  const a = store.data.reviewAuth.lists[id];
  if (!m || !a) return null;
  const h = sha(m[1]);
  const s = a.sessions.find(x => x.h === h);
  if (!s || age(s.lastAt) > SESSION_MS) return null;
  if (age(s.lastAt) > 3600e3) { s.lastAt = now(); store.save(); }
  return s;
}

function touch(list, name) {
  list.people ||= [];
  const p = list.people.find(x => x.name === name);
  if (p) p.lastAt = now();
  else list.people.push({ name, firstAt: now(), lastAt: now() });
}

// One domain as the agent sees it: the current scan when there is one, else the snapshot taken
// when the list was made. Notes, blockers and other tracker data are never included.
function agentItem(data, it, type) {
  const d = data.domains[it.key];
  const s = (d && health(d.scan, data.settings)) || it.snap;
  const site = s?.site ? { k: s.site, l: SITE[s.site]?.l || s.site, c: SITE[s.site]?.c || 'none', detail: s.siteDetail || '' } : null;
  const ssl = s?.ssl ? { k: s.ssl, l: SSL[s.ssl]?.l || s.ssl, c: SSL[s.ssl]?.c || 'none' } : null;
  const ad = it.admin;
  const om = outcomeMeta(type, ad?.outcome, data.settings);
  return {
    key: it.key, domain: it.domain, sub: !!it.sub, contract: it.contract, contractLabel: data.contracts[it.contractKey]?.label || '',
    server: s?.server || '', ip: s?.ip || '', site, ssl, checkedAt: s?.at || null, agent: it.agent || null,
    admin: ad && (ad.outcome || ad.note) ? { outcome: ad.outcome || null, label: om?.l || '', c: om?.c || 'none', note: ad.note || '', at: ad.outcomeAt || ad.noteAt || null } : null,
  };
}

const ROUTE = /^\/r\/([A-Za-z0-9_-]{8,40})(?:\/api\/(state|login|logout|item))?\/?$/;

export function reviewRoute({ store, send, readBody, sendPage, logDomain }) {
  return async function handle(req, res, url) {
    const m = ROUTE.exec(url.pathname);
    if (!m) return send(res, 404, { error: 'Not found' });
    const [, id, action] = m;
    if (!action) return req.method === 'GET' ? sendPage(res) : send(res, 405, { error: 'Method not allowed' });
    const data = store.data;
    const list = data.reviews[id];
    if (!list) return send(res, 404, { error: 'This review list does not exist or was deleted.' });
    const type = typeOf(list);

    if (action === 'state') {
      if (req.method !== 'GET') return send(res, 405, { error: 'Method not allowed' });
      const s = sessionOf(store, id, req);
      if (!s) return send(res, 401, { error: 'Sign in to open this list' });
      return send(res, 200, {
        list: { name: list.name, from: list.from, createdAt: list.createdAt, closed: !!list.closed },
        type: { k: type.k, l: type.l, howto: type.howto, verdicts: type.verdicts },
        me: { name: s.name }, items: list.items.map(it => agentItem(data, it, type)),
      });
    }
    if (req.method !== 'POST') return send(res, 405, { error: 'Method not allowed' });
    const body = await readBody(req, 64e3);

    if (action === 'login') {
      const key = `${req.socket.remoteAddress || ''}|${id}`;
      if (tooMany(key)) return send(res, 429, { error: 'Too many wrong passwords. Try again in 15 minutes.' });
      if (!data.reviewAuth.lists[id]) data.reviewAuth.lists[id] = { own: null, sessions: [] };
      const a = data.reviewAuth.lists[id];
      const rec = list.pwMode === 'own' ? a.own : data.reviewAuth.master;
      if (!rec) return send(res, 403, { error: 'No password is set for this list yet. Ask the person who shared it.' });
      if (!pwMatches(body.password, rec)) { noteFail(key); return send(res, 401, { error: 'Wrong password' }); }
      fails.delete(key);
      const name = str(body.name, 60).replace(/\s+/g, ' ').trim();
      if (!name) return send(res, 400, { error: 'Enter your name' });
      const tok = crypto.randomBytes(24).toString('base64url');
      a.sessions = [{ h: sha(tok), name, at: now(), lastAt: now() }, ...a.sessions.filter(x => age(x.lastAt) < SESSION_MS)].slice(0, 50);
      touch(list, name);
      store.bump(list);
      return send(res, 200, { ok: true }, { 'Set-Cookie': `rv=${tok}; Path=/r/${id}; HttpOnly; SameSite=Strict; Max-Age=${SESSION_MS / 1000}` });
    }

    const s = sessionOf(store, id, req);
    if (!s) return send(res, 401, { error: 'Your session ended. Sign in again.' });

    if (action === 'logout') {
      const a = data.reviewAuth.lists[id];
      a.sessions = a.sessions.filter(x => x !== s);
      store.save();
      return send(res, 200, { ok: true }, { 'Set-Cookie': `rv=; Path=/r/${id}; HttpOnly; SameSite=Strict; Max-Age=0` });
    }

    // action === 'item'
    if (list.closed) return send(res, 409, { error: 'This list is closed, so answers can no longer be changed.' });
    const it = list.items.find(x => x.key === body.key);
    if (!it) return send(res, 404, { error: 'That domain is not in this list' });
    it.agent ||= {};
    const ag = it.agent;
    const d = data.domains[it.key];
    if ('verdict' in body) {
      const v = body.verdict || null;
      if (v && !type.verdicts.some(x => x.k === v)) return send(res, 400, { error: 'Unknown answer for this list' });
      if ((ag.verdict || null) !== v) {
        ag.verdict = v; ag.verdictAt = now(); ag.by = s.name;
        if (d) logDomain(d, `Review “${list.name}”: ${s.name} ${v ? `says ${verdictMeta(type, v).l}` : 'cleared their answer'}`);
      }
    }
    if ('note' in body) {
      const t = str(body.note, 4000).trim();
      if (t !== (ag.note || '')) {
        ag.note = t; ag.noteAt = now(); ag.by = s.name;
        if (d && t) logDomain(d, `Review “${list.name}”: note from ${s.name}`);
      }
    }
    if (body.opened) { ag.openedAt = now(); ag.openedBy = s.name; }
    touch(list, s.name);
    store.bump(list);
    return send(res, 200, { ok: true, item: agentItem(data, it, type) });
  };
}
