// Network helpers: IP normalisation, CIDR matching, DNS via chosen resolvers,
// and HTTP requests that expose the connected IP, TLS validity and each redirect hop.
import http from 'node:http';
import https from 'node:https';
import zlib from 'node:zlib';
import dns from 'node:dns';
import net from 'node:net';

export const UA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36 MigrationCheck/1.0';

// ---------- IP utilities ----------
export function expandV6(ip) {
  ip = String(ip).toLowerCase().split('%')[0].trim();
  if (ip.includes('.')) {
    const i = ip.lastIndexOf(':');
    const p = ip.slice(i + 1).split('.').map(Number);
    ip = ip.slice(0, i + 1) + ((p[0] << 8) | p[1]).toString(16) + ':' + ((p[2] << 8) | p[3]).toString(16);
  }
  const parts = ip.split('::');
  const head = parts[0] ? parts[0].split(':') : [];
  let groups = head;
  if (parts.length > 1) {
    const tail = parts[1] ? parts[1].split(':') : [];
    groups = [...head, ...Array(Math.max(0, 8 - head.length - tail.length)).fill('0'), ...tail];
  }
  return groups.map(g => g.padStart(4, '0')).join(':');
}

export function normIp(ip) {
  ip = String(ip || '').trim();
  return net.isIPv6(ip) ? expandV6(ip) : ip;
}

function ipToBig(ip) {
  if (net.isIPv4(ip)) return { v: 4, n: ip.split('.').reduce((a, o) => (a << 8n) + BigInt(+o), 0n), bits: 32 };
  if (net.isIPv6(ip)) return { v: 6, n: BigInt('0x' + expandV6(ip).replace(/:/g, '')), bits: 128 };
  return null;
}

export function ipMatches(ip, rule) {
  rule = String(rule || '').trim();
  if (!rule) return false;
  if (!rule.includes('/')) return normIp(ip) === normIp(rule);
  const [base, lenStr] = rule.split('/');
  const a = ipToBig(ip), b = ipToBig(base);
  if (!a || !b || a.v !== b.v) return false;
  const len = Math.min(a.bits, Math.max(0, parseInt(lenStr, 10) || 0));
  const shift = BigInt(a.bits - len);
  return (a.n >> shift) === (b.n >> shift);
}

// Published Cloudflare ranges, used to recognise proxied DNS records.
const CLOUDFLARE = ['173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22', '141.101.64.0/18', '108.162.192.0/18',
  '190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13', '104.24.0.0/14',
  '172.64.0.0/13', '131.0.72.0/22', '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32', '2405:8100::/32',
  '2a06:98c0::/29', '2c0f:f248::/32'];

export function cdnForIp(ip) {
  return CLOUDFLARE.some(r => ipMatches(ip, r)) ? 'Cloudflare' : null;
}

// Header-based CDN / proxy / platform recognition.
export function cdnFromHeaders(h = {}) {
  const server = String(h.server || '').toLowerCase();
  const via = String(h.via || '').toLowerCase();
  if (h['cf-ray'] || server === 'cloudflare') return 'Cloudflare';
  if (h['x-amz-cf-id'] || h['x-amz-cf-pop'] || via.includes('cloudfront')) return 'Amazon CloudFront';
  if (h['x-sucuri-id'] || server.includes('sucuri')) return 'Sucuri';
  if (h['x-fastly-request-id'] || (String(h['x-served-by'] || '').startsWith('cache-') && via.includes('varnish'))) return 'Fastly';
  if (server.includes('akamai') || h['x-akamai-transformed']) return 'Akamai';
  if (h['x-azure-ref']) return 'Azure Front Door';
  if (h['x-cdn']) return `CDN (${String(h['x-cdn']).slice(0, 30)})`;
  return null;
}

export function platformFromHeaders(h = {}) {
  const server = String(h.server || '').toLowerCase();
  if (h['x-vercel-id'] || server === 'vercel') return 'Vercel';
  if (h['x-nf-request-id'] || server === 'netlify') return 'Netlify';
  if (h['x-github-request-id'] || server === 'github.com') return 'GitHub Pages';
  if (h['x-wix-request-id']) return 'Wix';
  if (server.includes('squarespace')) return 'Squarespace';
  if (h['x-shopify-stage'] || h['x-shopid']) return 'Shopify';
  return null;
}

// ---------- DNS ----------
export function makeResolver(settings) {
  const r = new dns.promises.Resolver({ timeout: 4000, tries: 2 });
  const servers = (settings?.resolvers || []).filter(s => net.isIP(String(s).trim()));
  if (servers.length) { try { r.setServers(servers); } catch {} }
  return r;
}

export async function dnsQuery(resolver, fn, name) {
  try { return { ok: true, v: await resolver[fn](name) }; }
  catch (e) { return { ok: false, code: e.code || e.message }; }
}

export async function resolveHost(resolver, host) {
  const [a, aaaa, cname] = await Promise.all([
    dnsQuery(resolver, 'resolve4', host),
    dnsQuery(resolver, 'resolve6', host),
    dnsQuery(resolver, 'resolveCname', host),
  ]);
  const out = { host, a: a.ok ? a.v : [], aaaa: aaaa.ok ? aaaa.v : [], cname: cname.ok ? cname.v : [], error: null };
  if (!out.a.length && !out.aaaa.length) {
    const code = a.code || aaaa.code;
    out.error = code === 'ENOTFOUND' ? 'NXDOMAIN (name does not exist)' : code === 'ENODATA' ? 'No A or AAAA record' : String(code || 'No records');
  }
  return out;
}

// Custom lookup so HTTP connects to the IPs we resolved (IPv4 preferred).
export function makeLookup(map) {
  return (hostname, options, cb) => {
    if (typeof options === 'function') { cb = options; options = {}; }
    const ips = map[String(hostname).toLowerCase()];
    if (ips && ips.length) {
      const list = ips.map(address => ({ address, family: address.includes(':') ? 6 : 4 }));
      const v4 = list.filter(x => x.family === 4);
      const chosen = v4.length ? v4 : list;
      if (options && options.all) return cb(null, chosen);
      return cb(null, chosen[0].address, chosen[0].family);
    }
    return dns.lookup(hostname, options, cb);
  };
}

// ---------- HTTP ----------
function friendlyError(e) {
  const map = {
    ENOTFOUND: 'DNS lookup failed', ECONNREFUSED: 'Connection refused', ECONNRESET: 'Connection reset',
    ETIMEDOUT: 'Timed out', EHOSTUNREACH: 'Host unreachable', ENETUNREACH: 'Network unreachable',
    EPROTO: 'TLS handshake failed', ERR_SSL_WRONG_VERSION_NUMBER: 'TLS not available on this port',
  };
  const code = e.code || '';
  return map[code] ? `${map[code]}${code ? ` (${code})` : ''}` : String(e.message || code || 'Request failed').slice(0, 160);
}

export function request(urlStr, o = {}) {
  return new Promise(resolve => {
    let u;
    try { u = new URL(urlStr); } catch { return resolve({ url: urlStr, error: 'Invalid URL', ms: 0 }); }
    const isHttps = u.protocol === 'https:';
    const mod = isHttps ? https : http;
    const t0 = Date.now();
    const timeout = o.timeout || 10000;
    const headers = {
      'User-Agent': UA,
      Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      'Accept-Language': 'en-GB,en;q=0.9',
      'Accept-Encoding': 'gzip, deflate, br',
      Host: u.host,
      ...(o.headers || {}),
    };
    const opts = {
      method: o.method || 'GET',
      host: o.connectIp || u.hostname.replace(/^\[|\]$/g, ''),
      port: u.port || (isHttps ? 443 : 80),
      path: (u.pathname || '/') + u.search,
      headers,
      agent: false,
      timeout,
    };
    if (isHttps) {
      if (!net.isIP(u.hostname)) opts.servername = u.hostname;
      opts.rejectUnauthorized = false; // we record validity instead of failing
    }
    if (!o.connectIp && o.lookup) opts.lookup = o.lookup;

    let done = false;
    const finish = r => {
      if (done) return;
      done = true;
      clearTimeout(hard);
      r.url = urlStr;
      r.ms = Date.now() - t0;
      resolve(r);
    };
    const hard = setTimeout(() => { req.destroy(new Error(`Timed out after ${Math.round(timeout / 1000)}s`)); }, timeout + 2000);

    const req = mod.request(opts, res => {
      const sock = res.socket;
      const out = { status: res.statusCode, headers: res.headers, ip: sock?.remoteAddress || null };
      if (isHttps && sock) {
        out.tls = { authorized: !!sock.authorized, error: sock.authorizationError ? String(sock.authorizationError) : null };
        try {
          const c = sock.getPeerCertificate();
          if (c && c.subject) {
            out.tls.cert = {
              subject: c.subject.CN || '',
              issuer: (c.issuer && (c.issuer.O || c.issuer.CN)) || '',
              validTo: c.valid_to || '',
              san: String(c.subjectaltname || '').slice(0, 400),
            };
          }
        } catch {}
      }
      const isRedirect = res.statusCode >= 300 && res.statusCode < 400;
      if (o.noBody || isRedirect || opts.method === 'HEAD') {
        res.resume();
        out.body = '';
        finish(out);
        req.destroy();
        return;
      }
      const enc = String(res.headers['content-encoding'] || '').toLowerCase();
      let stream = res;
      try {
        if (enc === 'gzip' || enc === 'x-gzip') stream = res.pipe(zlib.createGunzip());
        else if (enc === 'br') stream = res.pipe(zlib.createBrotliDecompress());
        else if (enc === 'deflate') stream = res.pipe(zlib.createInflate());
      } catch {}
      const max = o.maxBody ?? 600000;
      const chunks = [];
      let len = 0;
      const end = () => {
        if (done) return;
        out.body = Buffer.concat(chunks).toString('utf8');
        finish(out);
        req.destroy();
      };
      stream.on('data', c => {
        chunks.push(c);
        len += c.length;
        if (len >= max) { out.truncated = true; end(); }
      });
      stream.on('end', end);
      stream.on('error', end);
      res.on('error', end);
    });
    req.on('timeout', () => req.destroy(Object.assign(new Error(`Timed out after ${Math.round(timeout / 1000)}s`), { code: 'ETIMEDOUT' })));
    req.on('error', e => finish({ error: friendlyError(e), code: e.code || null }));
    req.end();
  });
}

// Follows redirects one hop at a time and records each hop.
export async function fetchChain(startUrl, o = {}) {
  const hops = [];
  const seen = new Set();
  let url = startUrl;
  let last = null;
  const maxHops = o.maxHops ?? 8;
  for (let i = 0; i <= maxHops; i++) {
    if (seen.has(url)) { return { hops, final: last, finalUrl: url, error: 'Redirect loop' }; }
    seen.add(url);
    const r = await request(url, o);
    last = r;
    hops.push({
      url,
      status: r.status || null,
      location: r.headers?.location || null,
      ip: r.ip || null,
      ms: r.ms,
      server: r.headers?.server || null,
      error: r.error || null,
      tls: r.tls || null,
    });
    if (r.error) return { hops, final: r, finalUrl: url, error: r.error };
    if ([301, 302, 303, 307, 308].includes(r.status) && r.headers.location) {
      let next;
      try { next = new URL(r.headers.location, url).href; } catch { return { hops, final: r, finalUrl: url, error: 'Bad redirect location' }; }
      if (o.allowHosts && !o.allowHosts.includes(new URL(next).hostname.toLowerCase())) {
        return { hops, final: r, finalUrl: next, offsite: true };
      }
      url = next;
      continue;
    }
    return { hops, final: r, finalUrl: url };
  }
  return { hops, final: last, finalUrl: url, error: 'Too many redirects' };
}

export function chainSummary(c) {
  if (!c) return null;
  return {
    hops: c.hops,
    finalUrl: c.finalUrl,
    finalStatus: c.final?.status || null,
    error: c.error || null,
  };
}

export function isIonosMx(host) {
  return /(^|\.)(ionos\.(co\.uk|com|de|es|fr|it|mx|ca)|1and1\.(co\.uk|com|de)|kundenserver\.de|perfora\.net)\.?$/i.test(String(host || '').trim());
}

export function isIonosNs(host) {
  return /(^|\.)ui-dns\.(com|de|org|biz)\.?$/i.test(String(host || '').trim());
}
