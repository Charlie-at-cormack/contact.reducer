// Plain-language website health from the last verification scan:
// which server answers, whether the site is up, and whether HTTPS is valid.
// Shared by the server (scan log tallies) and the browser, so no Node or DOM APIs here.

const PROVIDERS = [
  [/kundenserver\.de|(^|\.)ionos\.|1and1|perfora\.net|schlund|onlinehome-server|ui-r\.com/i, 'IONOS'],
  [/cloudflare/i, 'Cloudflare'],
  [/amazonaws\.com|cloudfront\.net|awsglobalaccelerator/i, 'Amazon AWS'],
  [/googleusercontent\.com|1e100\.net/i, 'Google Cloud'],
  [/cloudapp\.(net|azure\.com)|azurewebsites/i, 'Microsoft Azure'],
  [/digitalocean/i, 'DigitalOcean'],
  [/hetzner|your-server\.de/i, 'Hetzner'],
  [/(^|\.)ovh\.|kimsufi|soyoustart/i, 'OVH'],
  [/linode|akamai/i, 'Akamai / Linode'],
  [/vultr/i, 'Vultr'],
  [/wix(dns)?\.|wixsite/i, 'Wix'],
  [/squarespace/i, 'Squarespace'],
  [/shopify/i, 'Shopify'],
  [/secureserver\.net|godaddy/i, 'GoDaddy'],
  [/fasthosts/i, 'Fasthosts'],
  [/123-reg|webfusion/i, '123 Reg'],
  [/heartinternet/i, 'Heart Internet'],
  [/krystal/i, 'Krystal'],
  [/names\.co\.uk|namesco/i, 'Namesco'],
  [/siteground|sgvps/i, 'SiteGround'],
  [/hostinger/i, 'Hostinger'],
  [/netlify/i, 'Netlify'],
  [/vercel/i, 'Vercel'],
  [/github\./i, 'GitHub Pages'],
  [/wpengine/i, 'WP Engine'],
  [/kinsta/i, 'Kinsta'],
  [/zen\.(net|co)\.uk/i, 'Zen Internet'],
  [/btcentralplus|\.bt\.net/i, 'BT'],
  [/virginm\.net|virginmedia/i, 'Virgin Media'],
];
// IONOS address blocks, used to name the provider when reverse DNS gives nothing.
const IONOS_V4 = ['217.160.', '82.165.', '212.227.', '74.208.', '87.106.', '77.68.'];

export function providerOf(ip, ptr) {
  if (ptr) for (const [re, name] of PROVIDERS) if (re.test(ptr)) return name;
  if (ip && IONOS_V4.some(p => ip.startsWith(p))) return 'IONOS';
  if (ip && /^2001:8d8:/i.test(ip)) return 'IONOS';
  return '';
}

export const shortVps = name => String(name || '').replace(/\s*\([^)]*\)/g, '').trim() || String(name || '');

export function bucketList(settings) {
  return [
    ...(settings?.vps || []).map(v => ({ k: `vps:${v.id}`, l: shortVps(v.name), c: 'ok' })),
    { k: 'mixed', l: 'Partly moved', c: 'warn' },
    { k: 'old', l: 'IONOS shared', c: 'old' },
    { k: 'other', l: 'Other server', c: 'other' },
    { k: 'cdn', l: 'Behind CDN', c: 'cdn' },
    { k: 'none', l: 'No DNS', c: 'none' },
  ];
}
export const SITE = { up: { l: 'Up', c: 'ok' }, redirect: { l: 'Redirects', c: 'muted' }, parked: { l: 'Not set up', c: 'warn' }, down: { l: 'Down', c: 'bad' }, nodns: { l: 'No DNS', c: 'none' } };
export const SSL = { ok: { l: 'Valid', c: 'ok' }, fail: { l: 'Invalid', c: 'bad' }, none: { l: 'No HTTPS', c: 'warn' } };

const hostOf = u => { try { return new URL(u).hostname.toLowerCase(); } catch { return ''; } };
const bare = h => String(h || '').toLowerCase().replace(/^www\./, '');
const keyOf = ip => (ip.cls === 'vps' ? `vps:${ip.vps}` : ip.cls);

export function shortErr(e) {
  const s = String(e || '');
  if (!s) return 'No response';
  if (/ENOTFOUND|DNS lookup failed|NXDOMAIN/i.test(s)) return 'Name does not resolve';
  if (/ECONNREFUSED|refused/i.test(s)) return 'Connection refused';
  if (/timed? ?out|ETIMEDOUT/i.test(s)) return 'Timed out';
  if (/ECONNRESET|reset/i.test(s)) return 'Connection reset';
  if (/unreachable/i.test(s)) return 'Server unreachable';
  if (/TLS not available/i.test(s)) return 'No TLS on port 443';
  if (/TLS handshake|EPROTO/i.test(s)) return 'No certificate (TLS handshake failed)';
  if (/loop/i.test(s)) return 'Redirect loop';
  return s.slice(0, 70);
}

function dnsText(e) {
  const s = String(e || '');
  if (!s || /ENODATA|No A or AAAA/i.test(s)) return 'No A or AAAA record';
  if (/NXDOMAIN|ENOTFOUND/i.test(s)) return 'Name does not exist';
  if (/SERVFAIL/i.test(s)) return 'DNS server failure (SERVFAIL)';
  if (/REFUSED/i.test(s)) return 'DNS query refused';
  if (/TIMEOUT/i.test(s)) return 'DNS timed out';
  return s;
}

function tlsReason(err, cert) {
  const s = String(err || '');
  if (/ALTNAME|does not match|altnames/i.test(s)) return `Certificate is for ${cert?.subject || 'another name'}`;
  if (/EXPIRED|expired/i.test(s)) return 'Certificate expired';
  if (/SELF_SIGNED|self[- ]signed/i.test(s)) return 'Self-signed certificate';
  if (/UNABLE_TO_VERIFY|unable to verify|ISSUER/i.test(s)) return 'Incomplete certificate chain';
  return s ? s.slice(0, 70) : 'Untrusted certificate';
}

export function ipLabel(i, settings) {
  if (i.cls === 'vps') return shortVps((settings?.vps || []).find(v => v.id === i.vps)?.name || i.label);
  if (i.cls === 'old') return 'IONOS shared';
  if (i.cls === 'cdn') return String(i.label || 'CDN').replace(/ proxy$/, '');
  return i.provider || providerOf(i.ip, i.ptr) || 'Other server';
}

function sslOf(h) {
  const first = h?.http?.https?.hops?.[0];
  if (!first) return null;
  if (first.tls) {
    const cert = first.tls.cert || null;
    const t = cert?.validTo ? Date.parse(cert.validTo) : NaN;
    const days = Number.isFinite(t) ? Math.floor((t - Date.now()) / 864e5) : null;
    if (first.tls.authorized && (days == null || days >= 0)) return { state: 'ok', days, cert, detail: days != null ? `${days} days left` : '' };
    return { state: 'fail', days, cert, detail: first.tls.authorized ? 'Certificate expired' : tlsReason(first.tls.error, cert) };
  }
  // No certificate presented at all (handshake refused, nothing on 443): the name has no working HTTPS.
  if (first.error) return { state: 'none', detail: shortErr(first.error) };
  return null;
}
const SSL_RANK = { ok: 0, none: 1, fail: 2 };

export function health(scan, settings) {
  if (!scan || !Array.isArray(scan.hosts)) return null;
  const root = scan.hosts.find(h => h.role === 'root') || scan.hosts[0];
  const www = scan.hosts.find(h => h.role === 'www');
  const all = scan.hosts.flatMap(h => (h.ips || []).map(i => ({ ...i, role: h.role, host: h.host })));
  const lead = root?.ips?.length ? root : www?.ips?.length ? www : root;
  const primary = lead?.ips?.find(i => i.family === 4) || lead?.ips?.[0] || null;
  const out = { at: scan.at, verdict: scan.verdict, summary: scan.summary, marker: !!scan.flags?.markerMatched, ips: all, odd: [], ip: '', provider: '' };

  // Server
  if (!primary) { out.bucket = 'none'; out.server = 'No DNS'; }
  else {
    const pk = keyOf(primary);
    const odd = all.filter(i => keyOf(i) !== pk);
    out.ip = primary.ip;
    out.ptr = primary.ptr || '';
    out.provider = primary.cls === 'old' ? 'IONOS' : primary.cls === 'vps' ? '' : ipLabel(primary, settings);
    out.bucket = pk.startsWith('vps:') ? (odd.length ? 'mixed' : pk) : primary.cls;
    out.server = primary.cls === 'other' && out.provider === 'IONOS' ? 'IONOS server' : ipLabel(primary, settings);
    out.odd = odd.map(i => ({ text: `${i.role === 'www' ? 'www ' : ''}${i.family === 6 ? 'AAAA' : 'A'} ${i.ip}`, label: ipLabel(i, settings), cls: i.cls }));
    if (odd.length) {
      const v6 = odd.every(i => i.family === 6);
      const lbl = [...new Set(out.odd.map(o => o.label))].join(', ');
      out.oddShort = `${v6 ? 'IPv6' : odd.every(i => i.role === 'www') ? 'www' : 'also'} on ${lbl}`;
    }
  }

  // Site
  if (!primary) { out.site = 'nodns'; out.siteDetail = dnsText(root?.error); }
  else {
    const sec = lead.http?.https, pl = lead.http?.http;
    const pick = sec?.finalStatus ? sec : pl?.finalStatus ? pl : null;
    if (!pick) {
      out.site = 'down';
      const viaHttps = pl?.hops?.length > 1 && /^https:/i.test(pl.finalUrl || '');
      out.siteDetail = viaHttps ? 'HTTP redirects to HTTPS, which fails' : shortErr(sec?.error || pl?.error);
      out.siteError = [sec?.error && `HTTPS: ${sec.error}`, pl?.error && `HTTP: ${pl.error}`].filter(Boolean).join(' · ');
    }
    else {
      out.code = pick.finalStatus;
      out.finalUrl = pick.finalUrl;
      const fh = hostOf(pick.finalUrl);
      if (out.code >= 400) { out.site = 'down'; out.siteDetail = `HTTP ${out.code}`; }
      else if (fh && bare(fh) !== bare(root.host)) { out.site = 'redirect'; out.siteDetail = `to ${fh}`; }
      else if (lead.http?.placeholder) { out.site = 'parked'; out.siteDetail = lead.http.placeholder; }
      else { out.site = 'up'; out.siteDetail = `HTTP ${out.code}${pick === pl ? ', HTTP only' : ''}`; }
    }
    if (www && www !== lead && www.ips?.length) {
      const w = www.http?.https?.finalStatus || www.http?.http?.finalStatus;
      if (!w || w >= 400) out.wwwIssue = w ? `www gives HTTP ${w}` : `www: ${shortErr(www.http?.https?.error || www.http?.http?.error)}`;
    }
  }

  // SSL
  if (primary) {
    let s = sslOf(lead);
    // Nothing answers at all (timeout, refused): report it as down only. A refused TLS handshake still counts as no HTTPS.
    const tlsRefused = /TLS|EPROTO|handshake/i.test(lead.http?.https?.hops?.[0]?.error || '');
    if (s?.state === 'none' && out.site === 'down' && !out.code && !tlsRefused) s = null;
    const wwwDead = out.wwwIssue && !www?.http?.https?.hops?.[0]?.tls; // www fails entirely: reported as wwwIssue
    if (s && www && www !== lead && www.ips?.length && !wwwDead) {
      const sw = sslOf(www);
      if (sw && (!s || SSL_RANK[sw.state] > SSL_RANK[s.state])) s = { ...sw, detail: `www: ${sw.detail}` };
    }
    if (s) {
      out.ssl = s.state;
      out.sslDetail = s.detail;
      out.sslDays = s.days ?? null;
      out.cert = s.cert || null;
      out.sslSoon = s.state === 'ok' && s.days != null && s.days < 14;
    }
  }

  out.onVps = out.bucket.startsWith('vps:');
  out.ok = out.onVps && (out.site === 'up' || out.site === 'redirect') && out.ssl === 'ok';
  return out;
}

// Compact signature used by the scan log to spot changes between scans.
export const sig = h => (h ? `${h.bucket}|${h.site}|${h.ssl || '-'}` : '');

export function tally(domains, settings) {
  const c = { total: domains.length, scanned: 0, bucket: {}, site: {}, ssl: {}, healthy: 0, marker: 0 };
  for (const d of domains) {
    const h = health(d.scan, settings);
    if (!h) continue;
    c.scanned++;
    c.bucket[h.bucket] = (c.bucket[h.bucket] || 0) + 1;
    c.site[h.site] = (c.site[h.site] || 0) + 1;
    if (h.ssl) c.ssl[h.ssl] = (c.ssl[h.ssl] || 0) + 1;
    if (h.ok) c.healthy++;
    if (h.marker) c.marker++;
  }
  return c;
}
