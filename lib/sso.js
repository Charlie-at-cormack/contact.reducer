// Hosted mode: sign-in through Cormack DevToolBox (cormackdeveloper.co.uk).
//
// Turned on by IMT_PUBLIC_URL (for example https://ionos.cormackdeveloper.co.uk). Then every page and API call
// needs a session, except review links (/r/...) and the files the review page loads, which keep their own
// review passwords. A visitor without a session goes to DevToolBox /sso, which sends them back to /_sso with a
// 60-second ticket signed with the shared secret (IMT_SSO_SECRET here, DTB_SSO_SECRET there). We check it,
// refuse reuse, and set our own signed session cookie. Locally (no IMT_PUBLIC_URL) nothing changes.
import crypto from 'node:crypto';

const env = k => String(process.env[k] || '').trim();

const PUBLIC_URL = env('IMT_PUBLIC_URL').replace(/\/+$/, '');
const SECRET = env('IMT_SSO_SECRET');
const SESSION_HOURS = Math.min(72, Math.max(1, Number(env('IMT_SESSION_HOURS')) || 12));
const COOKIE = 'imt_sid';

export const hosted = !!PUBLIC_URL;
export const publicUrl = PUBLIC_URL;
export const publicHost = hosted ? new URL(PUBLIC_URL).host : '';
const loginUrl = env('IMT_SSO_URL') || (hosted ? `https://${publicHost.split('.').slice(1).join('.')}/sso` : '');

/** Hosted mode must never start without sign-in: returns an error message, or '' when the settings are usable. */
export function configProblem() {
  if (!hosted) return '';
  try {
    const u = new URL(PUBLIC_URL);
    const local = u.hostname === 'localhost' || u.hostname === '127.0.0.1';   // http only for testing on this machine
    if (u.protocol !== 'https:' && !(local && u.protocol === 'http:')) return 'IMT_PUBLIC_URL must start with https://';
    if (u.pathname !== '/' || u.search) return 'IMT_PUBLIC_URL must be just the address, e.g. https://ionos.cormackdeveloper.co.uk';
  } catch { return 'IMT_PUBLIC_URL is not a valid address'; }
  if (SECRET.length < 32) return 'IMT_SSO_SECRET is missing or shorter than 32 characters (use the same value as DTB_SSO_SECRET in DevToolBox)';
  try { new URL(loginUrl); } catch { return 'IMT_SSO_URL is not a valid address'; }
  return '';
}

const hmac = (purpose, data) => crypto.createHmac('sha256', SECRET).update(`${purpose}.${data}`).digest('base64url');
function sameSig(a, b) {
  const x = Buffer.from(String(a)), y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}
/** "<base64url json>.<signature>" → the parsed payload, or null if the signature or format is wrong. */
function open(token, purpose) {
  const parts = String(token || '').split('.');
  if (parts.length !== 2 || parts[0].length > 4000 || !sameSig(parts[1], hmac(purpose, parts[0]))) return null;
  try { return JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8')); } catch { return null; }
}
const seal = (obj, purpose) => {
  const data = Buffer.from(JSON.stringify(obj)).toString('base64url');
  return `${data}.${hmac(purpose, data)}`;
};

// Ticket ids already used, until they expire (a ticket works once).
const usedTickets = new Map();
function burn(jti, exp) {
  const now = Date.now() / 1000;
  for (const [k, e] of usedTickets) if (e < now) usedTickets.delete(k);
  if (usedTickets.has(jti)) return false;
  usedTickets.set(jti, exp);
  return true;
}

function cookieValue(req, name) {
  for (const part of String(req.headers.cookie || '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0 && part.slice(0, i).trim() === name) return part.slice(i + 1).trim();
  }
  return '';
}

/** The signed-in user ({ sub, email, name, role }) or null. */
export function sessionUser(req) {
  const s = open(cookieValue(req, COOKIE), 'imt-session');
  if (!s || s.v !== 1 || typeof s.exp !== 'number' || s.exp < Date.now() / 1000) return null;
  return { sub: s.sub, email: s.email, name: s.name, role: s.role };
}

const cookie = (value, maxAge) => `${COOKIE}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
const safeNext = n => (typeof n === 'string' && /^\/(?![/\\])[^\s]*$/.test(n) && n.length < 2000 ? n : '/');

/** Where a visitor without a session goes: DevToolBox, which sends them back here signed in. */
export const loginRedirect = url => `${loginUrl}?to=${encodeURIComponent(PUBLIC_URL + url.pathname + url.search)}`;

/** GET /_sso?t=<ticket>&next=<path>: check the ticket, start a session, go to next. */
export function handleCallback(req, res, url, headers) {
  const t = open(url.searchParams.get('t'), 'dtb-sso-ticket');
  const now = Math.floor(Date.now() / 1000);
  const ok = t && t.v === 1 && t.aud === publicHost && typeof t.exp === 'number' && t.exp >= now && t.iat <= now + 30
    && typeof t.jti === 'string' && burn(t.jti, t.exp);
  if (!ok) {
    res.writeHead(403, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', ...headers });
    return res.end(`<!doctype html><meta charset="utf-8"><title>Sign-in link expired</title>
<p style="font:15px system-ui;margin:40px">This sign-in link has expired or was already used. <a href="/">Try again</a>.</p>`);
  }
  const exp = now + SESSION_HOURS * 3600;
  const value = seal({ v: 1, sub: t.sub, email: t.email, name: t.name, role: t.role, exp }, 'imt-session');
  console.log(`Signed in through DevToolBox: ${t.email}`);
  res.writeHead(302, { Location: safeNext(url.searchParams.get('next')), 'Set-Cookie': cookie(value, SESSION_HOURS * 3600),
    'Cache-Control': 'no-store', ...headers });
  res.end();
}

/** GET /_sso/logout: end this app's session and go back to the dashboard. */
export function handleLogout(res, headers) {
  res.writeHead(302, { Location: new URL('/', loginUrl).toString(), 'Set-Cookie': cookie('', 0), 'Cache-Control': 'no-store', ...headers });
  res.end();
}
