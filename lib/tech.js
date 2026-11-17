// Technology detection for one website.
// Every finding carries conf: 'detected' (direct evidence: header, generator, cookie, file, config)
// or 'inferred' (implied by another finding, a heuristic, or the IONOS product type),
// and src: 'public' | 'source' | 'ionos'. Anything undetermined is flagged for manual review.
import { makeResolver, resolveHost, makeLookup, fetchChain, request, cdnFromHeaders, platformFromHeaders } from './net.js';
import { readSource, analyzeSource, dbHostInfo } from './source.js';

const CMS_DB = {
  WordPress: ['MySQL / MariaDB', 'WordPress requires MySQL or MariaDB'],
  Joomla: ['MySQL / MariaDB', 'Joomla normally runs on MySQL/MariaDB (PostgreSQL is possible)'],
  Drupal: ['MySQL / MariaDB', 'Drupal needs a SQL database, usually MySQL/MariaDB'],
  ExpressionEngine: ['MySQL / MariaDB', 'ExpressionEngine requires MySQL'],
  'Craft CMS': ['MySQL / MariaDB', 'Craft needs MySQL or PostgreSQL'],
  TYPO3: ['MySQL / MariaDB', 'TYPO3 needs a SQL database'],
  Magento: ['MySQL / MariaDB', 'Magento requires MySQL/MariaDB'],
  PrestaShop: ['MySQL / MariaDB', 'PrestaShop requires MySQL'],
  OpenCart: ['MySQL / MariaDB', 'OpenCart requires MySQL'],
  'Concrete CMS': ['MySQL / MariaDB', 'Concrete CMS requires MySQL'],
  Ghost: ['MySQL / MariaDB', 'Ghost uses MySQL in production'],
};
const PHP_CMS = new Set(['WordPress', 'Joomla', 'Drupal', 'ExpressionEngine', 'Craft CMS', 'TYPO3', 'Magento', 'PrestaShop', 'OpenCart', 'Concrete CMS']);
const PHP_FW = new Set(['Laravel', 'Symfony', 'CodeIgniter']);

const GENERATORS = [
  [/^WordPress\s*([\d.]+)?/i, 'cms', 'WordPress'],
  [/^Joomla!?\s*([\d.]+)?/i, 'cms', 'Joomla'],
  [/^Drupal\s*([\d.]+)?/i, 'cms', 'Drupal'],
  [/^TYPO3\s*(?:CMS)?\s*([\d.]+)?/i, 'cms', 'TYPO3'],
  [/^concrete(?:5| CMS)\s*-?\s*(?:Version\s*)?([\d.]+)?/i, 'cms', 'Concrete CMS'],
  [/^Ghost\s*([\d.]+)?/i, 'cms', 'Ghost'],
  [/^ExpressionEngine/i, 'cms', 'ExpressionEngine'],
  [/^Craft CMS/i, 'cms', 'Craft CMS'],
  [/^Wix\.com/i, 'builder', 'Wix'],
  [/^Squarespace/i, 'builder', 'Squarespace'],
  [/^Shopify/i, 'builder', 'Shopify'],
  [/^Webflow/i, 'builder', 'Webflow'],
  [/MyWebsite|cm4all/i, 'builder', 'IONOS MyWebsite'],
  [/^Hugo\s*([\d.]+)?/i, 'ssg', 'Hugo'],
  [/^Jekyll\s*v?([\d.]+)?/i, 'ssg', 'Jekyll'],
  [/^Eleventy\s*v?([\d.]+)?/i, 'ssg', 'Eleventy'],
  [/^Gatsby\s*([\d.]+)?/i, 'framework', 'Gatsby'],
  [/^Astro\s*v?([\d.]+)?/i, 'framework', 'Astro'],
  [/^Next\.js/i, 'framework', 'Next.js'],
  [/^Nuxt/i, 'framework', 'Nuxt'],
  [/^Elementor\s*([\d.]+)?/i, 'pagebuilder', 'Elementor'],
  [/^WooCommerce\s*([\d.]+)?/i, 'ecommerce', 'WooCommerce'],
  [/WPBakery/i, 'pagebuilder', 'WPBakery'],
  [/^Site Kit by Google\s*([\d.]+)?/i, 'plugin', 'Site Kit by Google'],
  [/Slider Revolution/i, 'plugin', 'Slider Revolution'],
  [/^Divi/i, 'theme', 'Divi'],
  [/^Adobe Muse/i, 'export', 'Adobe Muse export'],
];

function F(cat, name, ver, conf, src, ev) { return { cat, name, ver: ver || null, conf, src, ev }; }

function metaGenerators(html) {
  const out = [];
  const re = /<meta\b[^>]*>/gi;
  let m;
  while ((m = re.exec(html))) {
    const tag = m[0];
    if (!/name\s*=\s*["']?generator/i.test(tag)) continue;
    const c = tag.match(/content\s*=\s*"([^"]*)"|content\s*=\s*'([^']*)'/i);
    if (c) out.push((c[1] ?? c[2]).trim());
  }
  return out;
}

function titleOf(html) {
  const m = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  return m ? m[1].replace(/\s+/g, ' ').trim().slice(0, 140) : '';
}

function analyzePublic(page, origin) {
  const out = [];
  const add = (cat, name, ver, conf, ev) => out.push(F(cat, name, ver, conf, 'public', ev));
  const h = page.headers || {};
  const html = String(page.body || '');
  const low = html.toLowerCase();
  const xpb = String(h['x-powered-by'] || '');
  const server = String(h.server || '');
  const cookies = [].concat(h['set-cookie'] || []).map(c => String(c).split('=')[0].trim());

  // Headers
  let m;
  if ((m = xpb.match(/PHP\/?([\d.]+)?/i))) add('language', 'PHP', m[1], 'detected', `X-Powered-By: ${xpb}`);
  if (/PleskLin|PleskWin/i.test(xpb)) add('panel', 'Plesk', null, 'detected', `X-Powered-By: ${xpb}`);
  if (/Express/i.test(xpb)) { add('framework', 'Express', null, 'detected', `X-Powered-By: ${xpb}`); add('language', 'Node.js', null, 'inferred', 'Express runs on Node.js'); }
  if (/Next\.js/i.test(xpb)) add('framework', 'Next.js', null, 'detected', `X-Powered-By: ${xpb}`);
  if (/ASP\.NET/i.test(xpb) || h['x-aspnet-version']) add('language', 'ASP.NET', h['x-aspnet-version'] || null, 'detected', `X-Powered-By: ${xpb || 'X-AspNet-Version'}`);
  if (/Phusion Passenger/i.test(xpb + server)) add('server', 'Phusion Passenger', null, 'detected', 'Passenger app server (Node.js/Ruby/Python app)');
  if (/WP Engine/i.test(xpb)) add('host', 'WP Engine', null, 'detected', `X-Powered-By: ${xpb}`);
  for (const [re, name] of [[/^Apache(?:\/([\d.]+))?/i, 'Apache'], [/^nginx(?:\/([\d.]+))?/i, 'nginx'], [/^LiteSpeed/i, 'LiteSpeed'], [/^Microsoft-IIS(?:\/([\d.]+))?/i, 'IIS'], [/^openresty/i, 'OpenResty'], [/^Caddy/i, 'Caddy']]) {
    if ((m = server.match(re))) add('server', name, m[1], 'detected', `Server: ${server}`);
  }
  if (/AmazonS3/i.test(server)) add('host', 'Amazon S3 (static hosting)', null, 'detected', `Server: ${server}`);
  if ((m = String(h['x-generator'] || '').match(/Drupal\s*(\d+)?/i))) add('cms', 'Drupal', m[1], 'detected', `X-Generator: ${h['x-generator']}`);
  if (h['x-drupal-cache'] || h['x-drupal-dynamic-cache']) add('cms', 'Drupal', null, 'detected', 'X-Drupal-Cache header');
  if (/xmlrpc\.php/i.test(String(h['x-pingback'] || ''))) add('cms', 'WordPress', null, 'detected', 'X-Pingback: xmlrpc.php');
  if (/api\.w\.org/i.test(String(h.link || ''))) add('cms', 'WordPress', null, 'detected', 'Link header rel="https://api.w.org/"');
  if (h['x-litespeed-cache']) add('server', 'LiteSpeed Cache', null, 'detected', 'X-LiteSpeed-Cache header');
  if (h['x-nextjs-cache'] || h['x-nextjs-prerender']) add('framework', 'Next.js', null, 'detected', 'X-Nextjs-* header');
  const cdn = cdnFromHeaders(h);
  if (cdn) add('cdn', cdn, null, 'detected', 'CDN/proxy response headers');
  const platform = platformFromHeaders(h);
  if (platform) add(['Wix', 'Squarespace', 'Shopify'].includes(platform) ? 'builder' : 'host', platform, null, 'detected', 'Platform response headers');

  // Cookies
  const ck = (re, cat, name, ev) => { const c = cookies.find(n => re.test(n)); if (c) add(cat, name, null, 'detected', `${ev || 'Cookie'}: ${c}`); };
  ck(/^PHPSESSID$/i, 'language', 'PHP');
  ck(/^laravel_session$/i, 'framework', 'Laravel');
  ck(/^(wordpress_|wp-settings|wp_lang|wp-wpml)/i, 'cms', 'WordPress');
  ck(/^woocommerce_/i, 'ecommerce', 'WooCommerce');
  ck(/^ci_session$/i, 'framework', 'CodeIgniter');
  ck(/^(CRAFT_CSRF_TOKEN|CraftSessionId)$/i, 'cms', 'Craft CMS');
  ck(/^exp_(last_visit|last_activity|csrf_token|tracker|sessionid)$/i, 'cms', 'ExpressionEngine');
  ck(/^S?SESS[a-f0-9]{32}$/i, 'cms', 'Drupal');
  ck(/^JSESSIONID$/i, 'language', 'Java');
  ck(/^(ASP\.NET_SessionId|\.AspNetCore\.)/i, 'language', 'ASP.NET');
  ck(/^connect\.sid$/i, 'framework', 'Express');
  ck(/^_shopify_/i, 'builder', 'Shopify');
  ck(/^PrestaShop-/i, 'cms', 'PrestaShop');
  ck(/^OCSESSID$/i, 'cms', 'OpenCart');
  ck(/^(mage-|frontend$)/i, 'cms', 'Magento');

  // Generators
  for (const g of metaGenerators(html)) {
    const hit = GENERATORS.find(([re]) => re.test(g));
    if (hit) { const v = g.match(hit[0]); add(hit[1], hit[2], v && v[1], 'detected', `meta generator "${g.slice(0, 80)}"`); }
    else add('other', `Generator: ${g.slice(0, 60)}`, null, 'detected', 'meta generator');
  }

  // Markup
  if (/\/wp-content\/|\/wp-includes\//i.test(html)) add('cms', 'WordPress', null, 'detected', '/wp-content/ or /wp-includes/ asset paths');
  const themes = new Set(), plugins = new Set();
  for (const x of html.matchAll(/\/wp-content\/themes\/([^/'"?\s]+)\//gi)) themes.add(decodeURIComponent(x[1]));
  for (const x of html.matchAll(/\/wp-content\/plugins\/([^/'"?\s]+)\//gi)) plugins.add(decodeURIComponent(x[1]));
  for (const t of themes) add('theme', t, null, 'detected', 'theme asset path');
  for (const p of [...plugins].slice(0, 30)) add('plugin', p, null, 'detected', 'plugin asset path');
  if (plugins.has('elementor') || /elementor-kit-|class="elementor/i.test(html)) add('pagebuilder', 'Elementor', null, 'detected', 'Elementor markup');
  if (plugins.has('woocommerce')) add('ecommerce', 'WooCommerce', null, 'detected', 'WooCommerce assets');
  if (/drupal-settings-json|Drupal\.settings|\/sites\/default\/files\/|\/core\/misc\/drupal\.js/i.test(html)) add('cms', 'Drupal', null, 'detected', 'Drupal markup/asset paths');
  if (/\/media\/jui\/|\/media\/system\/js\/|joomla-script-options|\/components\/com_/i.test(html)) add('cms', 'Joomla', null, 'detected', 'Joomla asset paths');
  if (/\/cpresources\//i.test(html)) add('cms', 'Craft CMS', null, 'detected', '/cpresources/ assets');
  if (/\/typo3conf\/|\/typo3temp\//i.test(html)) add('cms', 'TYPO3', null, 'detected', 'TYPO3 asset paths');
  if (/[?&]ACT=\d+/i.test(html) && /exp_|expressionengine/i.test(html)) add('cms', 'ExpressionEngine', null, 'detected', 'ExpressionEngine ACT form/markup');
  if (/Mage\.Cookies|\/static\/version\d+\/frontend\//i.test(html)) add('cms', 'Magento', null, 'detected', 'Magento static paths');
  if (/var\s+prestashop\s*=|prestashop\./i.test(html)) add('cms', 'PrestaShop', null, 'detected', 'PrestaShop JS object');
  if (/catalog\/view\/theme\//i.test(html)) add('cms', 'OpenCart', null, 'detected', 'OpenCart theme path');
  if (/cdn\.shopify\.com|Shopify\.theme/i.test(html)) add('builder', 'Shopify', null, 'detected', 'Shopify CDN/theme object');
  if (/static\.wixstatic\.com|wix-warmup-data|_wixCssImports/i.test(html)) add('builder', 'Wix', null, 'detected', 'Wix assets');
  if (/Static\.SQUARESPACE_CONTEXT|<!-- This is Squarespace\. -->/i.test(html)) add('builder', 'Squarespace', null, 'detected', 'Squarespace page context');
  else if (/squarespace-cdn\.com|static1\.squarespace\.com/i.test(html)) add('other', 'Squarespace-hosted images (hotlinked)', null, 'detected', 'Images load from Squarespace CDN; not proof of Squarespace hosting');
  if (/data-wf-site=|data-wf-page=/i.test(html)) add('export', 'Webflow markup', null, 'detected', 'data-wf-site/page attributes (Webflow export or Webflow hosting)');
  if (/\/\.cm4all\/|cm4all/i.test(html)) add('builder', 'IONOS MyWebsite', null, 'detected', 'CM4all builder assets');
  if (/__NEXT_DATA__|\/_next\/static\//.test(html)) add('framework', 'Next.js', null, 'detected', '__NEXT_DATA__ / _next/static');
  if (/__NUXT__|\/_nuxt\//.test(html)) add('framework', 'Nuxt', null, 'detected', '__NUXT__ / _nuxt assets');
  if (/id="___gatsby"/.test(html)) add('framework', 'Gatsby', null, 'detected', '___gatsby root');
  if (/astro-island|data-astro-cid/i.test(html)) add('framework', 'Astro', null, 'detected', 'Astro islands');
  if (/ng-version="/.test(html)) add('frontend', 'Angular', (html.match(/ng-version="([\d.]+)"/) || [])[1], 'detected', 'ng-version attribute');
  if (/data-reactroot|react-dom(\.production)?(\.min)?\.js/i.test(html)) add('frontend', 'React', null, 'detected', 'React markers');
  if (/data-v-[a-f0-9]{8}|vue(\.min)?\.js/i.test(html)) add('frontend', 'Vue', null, 'inferred', 'Vue markers');
  if (/\bx-data=/.test(html)) add('frontend', 'Alpine.js', null, 'inferred', 'x-data attributes');
  if ((m = html.match(/jquery(?:[.-]([\d.]+))?(?:\.min)?\.js/i))) add('frontend', 'jQuery', m[1] && /\d/.test(m[1]) ? m[1] : null, 'detected', 'jQuery script');
  if (/bootstrap(?:\.bundle)?(?:\.min)?\.(css|js)/i.test(html)) add('frontend', 'Bootstrap', null, 'detected', 'Bootstrap asset');
  if (/gsap(?:\.min)?\.js|ScrollTrigger/i.test(html)) add('frontend', 'GSAP', null, 'detected', 'GSAP script');
  if (/\/livewire\/livewire/i.test(html)) add('framework', 'Laravel', null, 'detected', 'Livewire assets');
  if (/<meta[^>]+name=["']csrf-token["']/i.test(html) && cookies.includes('XSRF-TOKEN')) add('framework', 'Laravel', null, 'inferred', 'csrf-token meta + XSRF-TOKEN cookie');

  // PHP URLs
  try {
    const p = new URL(page.url).pathname;
    if (/\.php$/i.test(p)) add('language', 'PHP', null, 'detected', `Page served from ${p}`);
  } catch {}
  const phpLinks = [...html.matchAll(/(?:href|action|src)\s*=\s*["']([^"'#?]*\.php)(?:[?#][^"']*)?["']/gi)]
    .map(x => x[1]).filter(u => !/^https?:/i.test(u) || u.startsWith(origin));
  if (phpLinks.length) add('language', 'PHP', null, 'inferred', `Links to .php URLs, e.g. ${phpLinks[0].slice(0, 60)}`);

  // Redirect-only pages
  const refresh = html.match(/<meta[^>]+http-equiv=["']?refresh["']?[^>]*content=["']?\s*\d+\s*;\s*url=([^"'>\s]+)/i);
  if (refresh && html.length < 4000) add('redirect', `Meta refresh to ${refresh[1].slice(0, 80)}`, null, 'detected', 'meta refresh page');
  if (/<frameset/i.test(low) || (/<iframe[^>]+src=/i.test(html) && html.replace(/<[^>]+>/g, '').trim().length < 200 && html.length < 4000)) add('redirect', 'Frame redirect (page wraps another site)', null, 'detected', 'frameset/iframe wrapper page');

  // Infrastructure default / parking pages
  const title = titleOf(html);
  if (/Domain Default page/i.test(title) || /plesk-default-page|This page is generated by Plesk/i.test(html)) add('parked', 'Plesk default page (site not set up)', null, 'detected', `title "${title}"`);
  if (/login_up\.php/i.test(page.url || '') || /^Plesk Obsidian/i.test(title)) add('parked', 'Redirects to Plesk login (site not set up)', null, 'detected', 'Plesk login page');
  if (/This domain (name )?(has just been|was recently|is) registered|domain is parked|parkingcrew|sedoparking|bodis\.com/i.test(html) && html.length < 60000) add('parked', 'Parking page', null, 'detected', 'parking page text');
  if (/^(It works!|Welcome to nginx!|Apache2 (Ubuntu|Debian) Default Page|Test Page for the (Apache|nginx))/i.test(title)) add('parked', 'Web server default page', null, 'detected', `title "${title}"`);
  if (/defaultwebpage\.cgi|cPanel/i.test(title)) add('parked', 'Hosting control panel default page', null, 'detected', `title "${title}"`);
  if (/^IONOS|1&1 IONOS|ionos\.(co\.uk|com)\/?.*parking/i.test(title)) add('parked', 'IONOS placeholder page', null, 'inferred', `title "${title}"`);

  return { findings: out, title, cookies };
}

function ionosHints(d) {
  const out = [];
  const add = (cat, name, conf, ev) => out.push(F(cat, name, null, conf, 'ionos', ev));
  const dest = d.destination || '';
  const t = d.target || '';
  if (dest === 'CLICK_AND_BUILD') { add('host', 'IONOS Click & Build app', 'detected', `IONOS destination CLICK_AND_BUILD (${t})`); add('cms', 'WordPress', 'inferred', 'IONOS Click & Build installs are usually WordPress'); }
  if (dest === 'DNS_TEMPLATE_INTERNAL' && /click/i.test(t)) add('host', 'IONOS Click & Build (DNS template)', 'detected', `IONOS DNS template "${t}"`);
  if (dest === 'DNS_TEMPLATE_INTERNAL' && /webhosting/i.test(t)) add('host', 'IONOS webhosting (DNS template)', 'detected', `IONOS DNS template "${t}"`);
  if (dest === 'DNS_WEBSITE_TEMPLATE') add('builder', 'IONOS MyWebsite', 'detected', `IONOS destination DNS_WEBSITE_TEMPLATE ("${t}")`);
  if (dest === 'WEBSPACE' || dest === 'WEBSPACE_ROOT') add('host', 'IONOS webspace', 'detected', `IONOS webspace path ${t}`);
  if (/REDIRECT/.test(dest)) add('redirect', `IONOS redirect to ${t}`, 'detected', `IONOS destination ${dest}`);
  return out;
}

function mergeFindings(list) {
  const map = new Map();
  for (const f of list) {
    const k = `${f.cat}|${f.name.toLowerCase()}`;
    const cur = map.get(k);
    if (!cur) { map.set(k, { ...f, srcs: [f.src], evs: [f.ev] }); continue; }
    if (f.conf === 'detected' && cur.conf !== 'detected') { cur.conf = 'detected'; cur.src = f.src; }
    if (!cur.ver && f.ver) cur.ver = f.ver;
    if (f.src === 'source' && f.ver) cur.ver = f.ver;
    if (!cur.srcs.includes(f.src)) cur.srcs.push(f.src);
    if (cur.evs.length < 4 && !cur.evs.includes(f.ev)) cur.evs.push(f.ev);
  }
  return [...map.values()].map(f => ({ cat: f.cat, name: f.name, ver: f.ver, conf: f.conf, src: f.src, srcs: f.srcs, ev: f.evs.join(' · ') }));
}

function classify(findings, ctx) {
  const bySrc = s => findings.filter(f => f.srcs.some(x => s.includes(x)));
  const tiers = [
    findings.filter(f => f.conf === 'detected' && f.srcs.some(s => s !== 'ionos')),
    findings.filter(f => f.conf === 'inferred' && f.srcs.some(s => s !== 'ionos')),
    bySrc(['ionos']),
  ];
  const label = f => `${f.name}${f.ver ? ` ${f.ver}` : ''}`;
  if (ctx.offsite) return { key: 'redirect', label: `Redirect → ${ctx.offsite}`, conf: 'detected', ev: `Homepage redirects to ${ctx.offsite}` };
  for (const tier of tiers) {
    const one = (cat, fn) => tier.find(f => f.cat === cat && (!fn || fn(f)));
    let f;
    if ((f = one('redirect'))) return { key: 'redirect', label: f.name, conf: f.conf, ev: f.ev, src: f.src };
    if ((f = one('parked'))) return { key: 'parked', label: f.name, conf: f.conf, ev: f.ev, src: f.src };
    if ((f = one('builder'))) return { key: 'builder', label: label(f), conf: f.conf, ev: f.ev, src: f.src };
    if ((f = one('cms', x => x.name === 'WordPress'))) return { key: 'wordpress', label: label(f), conf: f.conf, ev: f.ev, src: f.src };
    if ((f = one('cms'))) return { key: 'cms', label: label(f), conf: f.conf, ev: f.ev, src: f.src };
    if ((f = one('framework'))) return { key: 'framework', label: label(f), conf: f.conf, ev: f.ev, src: f.src };
    if ((f = one('language', x => x.name === 'PHP'))) return { key: 'php', label: `Custom PHP${f.ver ? ` (${f.ver})` : ''}`, conf: f.conf, ev: f.ev, src: f.src };
    if ((f = one('language'))) return { key: 'framework', label: `Custom ${f.name} app`, conf: f.conf, ev: f.ev, src: f.src };
    if ((f = one('ssg'))) return { key: 'static', label: `Static (${f.name})`, conf: f.conf, ev: f.ev, src: f.src };
    if ((f = one('static'))) return { key: 'static', label: f.name, conf: f.conf, ev: f.ev, src: f.src };
  }
  return { key: 'unknown', label: 'Unknown', conf: 'unknown', ev: 'No CMS, framework, server-side language or static-site evidence found' };
}

function phpEolNote(findings, notes) {
  const php = findings.find(f => f.cat === 'language' && f.name === 'PHP' && f.ver);
  if (!php) return;
  const [maj, min] = php.ver.split('.').map(Number);
  if (maj < 8 || (maj === 8 && min < 2)) notes.push(`PHP ${php.ver} is past end of life. Check the code runs on the VPS PHP version.`);
}

export async function techScan(d, ctx) {
  const settings = ctx.settings;
  const timeout = settings.timeoutMs || 10000;
  const t0 = Date.now();
  const root = String(d.domain).toLowerCase();
  const res = { at: new Date().toISOString(), findings: [], notes: [], reviewReasons: [], probes: [], source: null, page: null };
  const all = [...ionosHints(d)];

  // ---- Public website ----
  const resolver = makeResolver(settings);
  const hosts = await Promise.all([root, `www.${root}`].map(h => resolveHost(resolver, h)));
  const map = {};
  for (const h of hosts) map[h.host] = [...h.a, ...h.aaaa];
  const lookup = makeLookup(map);
  let chain = null;
  for (const url of [`https://${root}/`, `http://${root}/`, `https://www.${root}/`, `http://www.${root}/`]) {
    const host = new URL(url).hostname;
    if (!map[host]?.length) continue;
    const c = await fetchChain(url, { lookup, timeout, maxBody: 800000 });
    if (c.final?.status) { chain = c; break; }
    chain = chain || c;
  }
  let offsite = null;
  if (chain?.final?.status) {
    const page = { ...chain.final, url: chain.finalUrl };
    const finalHost = new URL(chain.finalUrl).hostname.toLowerCase();
    if (finalHost.replace(/^www\./, '') !== root.replace(/^www\./, '')) offsite = finalHost;
    res.page = {
      url: chain.finalUrl, status: page.status, title: '', server: page.headers?.server || null,
      poweredBy: page.headers?.['x-powered-by'] || null, hops: chain.hops.map(h => `${h.status || 'ERR'} ${h.url}`),
      lastModified: page.headers?.['last-modified'] || null, etag: page.headers?.etag || null,
    };
    if (!offsite) {
      const origin = new URL(chain.finalUrl).origin;
      const pub = analyzePublic(page, origin);
      res.page.title = pub.title;
      all.push(...pub.findings);
      const probe = async (path, test) => {
        const r = await request(origin + path, { lookup, timeout, maxBody: 120000 });
        const row = { path, status: r.status || null, error: r.error || null, result: '' };
        if (!r.error && test) row.result = test(r) || '';
        res.probes.push(row);
        return r;
      };
      const soft = await probe(`/mig-probe-${Date.now().toString(36)}.html`);
      const soft200 = soft.status === 200;
      if (soft200) res.notes.push('The server answers 200 for missing pages, so path probes are unreliable.');
      await probe('/robots.txt', r => {
        if (r.status !== 200 || /<html/i.test(r.body || '')) return '';
        const b = r.body || '';
        if (/wp-sitemap\.xml|Disallow:\s*\/wp-admin\//i.test(b)) { all.push(F('cms', 'WordPress', null, 'inferred', 'public', 'robots.txt mentions wp-admin / wp-sitemap')); return 'WordPress hints'; }
        if (/Disallow:\s*\/administrator\//i.test(b)) { all.push(F('cms', 'Joomla', null, 'inferred', 'public', 'robots.txt disallows /administrator/')); return 'Joomla hints'; }
        if (/Disallow:\s*\/core\//i.test(b) && /Disallow:\s*\/profiles\//i.test(b)) { all.push(F('cms', 'Drupal', null, 'inferred', 'public', 'robots.txt disallows /core/ and /profiles/')); return 'Drupal hints'; }
        return '';
      });
      const merged0 = mergeFindings(all);
      const hasCms = merged0.some(f => ['cms', 'builder', 'framework'].includes(f.cat) && f.src !== 'ionos');
      const hasLang = merged0.some(f => f.cat === 'language' && f.src !== 'ionos');
      if (!hasCms) {
        await probe('/wp-login.php', r => {
          if (r.status === 200 && /wp-login|user_login|wp-submit/i.test(r.body || '')) { all.push(F('cms', 'WordPress', null, 'detected', 'public', '/wp-login.php serves the WordPress login form')); return 'WordPress login form'; }
          return '';
        });
      }
      const merged1 = mergeFindings(all);
      const serverSide = merged1.some(f => (['cms', 'builder', 'framework'].includes(f.cat) || (f.cat === 'language')) && f.src !== 'ionos');
      if (!serverSide && !soft200 && page.status < 300) {
        const ev = [];
        const ip = await probe('/index.php', r => (r.status === 200 ? 'responds 200' : r.status ? `HTTP ${r.status}` : ''));
        const ih = await probe('/index.html', r => (r.status === 200 ? 'responds 200' : r.status ? `HTTP ${r.status}` : ''));
        if (ip.status === 200) all.push(F('language', 'PHP', null, 'inferred', 'public', '/index.php responds 200'));
        else {
          if (ih.status === 200 && ip.status === 404) ev.push('index.html exists and index.php returns 404');
          if (page.headers?.['last-modified']) ev.push('HTML served with Last-Modified (file-based response)');
          if (page.headers?.etag && /^"?[0-9a-f]+-[0-9a-f]+(-[0-9a-f]+)?"?$/i.test(String(page.headers.etag).replace(/^W\//, ''))) ev.push('Apache-style file ETag');
          // Needs at least one file-serving signal; absence of server-side signals alone is not enough.
          if (ev.length) {
            if (!pub.cookies.length) ev.push('no cookies set');
            all.push(F('static', 'Static HTML/CSS/JS', null, 'inferred', 'public', `No server-side signals; ${ev.join('; ')}`));
          }
        }
      }
      if (!hasLang && merged1.some(f => f.cat === 'export' && f.name === 'Webflow markup') && !merged1.some(f => f.cat === 'builder')) {
        all.push(F('static', 'Static HTML/CSS/JS', null, 'inferred', 'public', 'Webflow export markup and no server-side signals'));
      }
      if (merged1.some(f => f.cat === 'export' && f.name === 'Adobe Muse export')) all.push(F('static', 'Static HTML/CSS/JS', null, 'inferred', 'public', 'Adobe Muse export'));
      if (merged1.some(f => f.cat === 'cdn')) res.notes.push('Responses come through a CDN/proxy, so server headers may describe the CDN rather than the origin.');
    }
  } else {
    res.page = { error: chain?.error || 'No DNS address for root or www', status: null };
    res.reviewReasons.push(`Website could not be fetched: ${res.page.error}`);
  }

  // ---- Source access ----
  if (ctx.source) {
    res.source = { spec: ctx.source.spec || null, kind: ctx.source.kind || null, from: ctx.source.from || null, ok: false };
    const s = await readSource(ctx.source);
    if (s?.error) { res.source.error = s.error; res.reviewReasons.push(`Source access failed: ${s.error}`); }
    else if (s) {
      const a = analyzeSource(s);
      res.source.ok = true;
      res.source.root = s.root;
      res.source.files = a.fileCount;
      res.source.dirs = a.dirCount;
      all.push(...a.findings);
      res.notes.push(...a.notes);
      res._dbs = a.dbs;
    }
  }

  // ---- Implications ----
  let findings = mergeFindings(all);
  const cmsNames = findings.filter(f => f.cat === 'cms').map(f => f.name);
  const hasPhp = findings.some(f => f.cat === 'language' && f.name === 'PHP');
  if (!hasPhp) {
    const why = findings.find(f => (f.cat === 'cms' && PHP_CMS.has(f.name)) || (f.cat === 'framework' && PHP_FW.has(f.name)));
    if (why) findings.push({ cat: 'language', name: 'PHP', ver: null, conf: 'inferred', src: why.src, srcs: [why.src], ev: `${why.name} runs on PHP` });
  }
  if (cmsNames.includes('Ghost') && !findings.some(f => f.name === 'Node.js')) findings.push({ cat: 'language', name: 'Node.js', ver: null, conf: 'inferred', src: 'public', srcs: ['public'], ev: 'Ghost runs on Node.js' });
  phpEolNote(findings, res.notes);

  const stack = classify(findings, { offsite });
  res.stack = stack;
  if (stack.key === 'unknown') res.reviewReasons.push('Stack unknown: no CMS, framework, language or static-site evidence.');
  if (stack.src === 'ionos') res.reviewReasons.push('Stack comes only from the IONOS export; confirm with a public or source scan.');

  // ---- Database ----
  const dbs = res._dbs || [];
  delete res._dbs;
  const detectedDb = dbs.find(x => x.conf === 'detected' && x.type) || dbs.find(x => x.type);
  let db;
  if (detectedDb) {
    db = { uses: 'yes', type: detectedDb.type, conf: detectedDb.conf, ev: detectedDb.ev, host: detectedDb.host, name: detectedDb.name, where: detectedDb.where, whereLabel: detectedDb.whereLabel, src: 'source' };
    if (dbs.length > 1) db.others = dbs.filter(x => x !== detectedDb).slice(0, 5).map(x => `${x.type} (${x.ev})`);
  } else if (stack.key === 'builder') db = { uses: 'platform', type: 'Managed by the platform', conf: stack.conf, ev: `${stack.label} stores content on its own platform` };
  else if (stack.key === 'redirect' || stack.key === 'parked') db = { uses: 'no', type: null, conf: 'inferred', ev: stack.key === 'redirect' ? 'Redirect only, no site content' : 'Placeholder page, no site content' };
  else {
    const cms = findings.find(f => f.cat === 'cms' && CMS_DB[f.name] && f.conf === 'detected') || findings.find(f => f.cat === 'cms' && CMS_DB[f.name]);
    if (cms) {
      db = { uses: 'yes', type: CMS_DB[cms.name][0], conf: 'inferred', ev: CMS_DB[cms.name][1], src: cms.src };
      if (['WEBSPACE', 'WEBSPACE_ROOT', 'CLICK_AND_BUILD'].includes(d.destination)) { db.where = 'ionos'; db.whereLabel = 'Probably an IONOS MySQL database (site is on IONOS webspace)'; db.whereConf = 'inferred'; }
    } else if (stack.key === 'static') db = { uses: 'no', type: null, conf: stack.conf, ev: stack.conf === 'detected' ? 'Static files only; no server-side code found' : 'Static site signals; a static site cannot use a server-side database' };
    else db = { uses: 'unknown', type: null, conf: 'unknown', ev: res.source?.ok ? 'No database configuration found in the source files read' : 'Cannot be confirmed from public signals; provide source access' };
  }
  if (db.uses === 'unknown') res.reviewReasons.push('Database use unknown.');
  if (db.where === 'ionos' && db.conf === 'detected') res.notes.push(`Database host ${db.host} is hosted by IONOS. Migrate it before cancelling the contract.`);
  res.db = db;

  res.findings = findings.sort((a, b) => catOrder(a.cat) - catOrder(b.cat));
  res.offsite = offsite;
  res.review = res.reviewReasons.length > 0;
  res.ms = Date.now() - t0;
  return res;
}

const ORDER = ['redirect', 'parked', 'builder', 'cms', 'framework', 'language', 'static', 'ssg', 'export', 'pagebuilder', 'ecommerce', 'theme', 'plugin', 'frontend', 'server', 'panel', 'host', 'cdn', 'other'];
function catOrder(c) { const i = ORDER.indexOf(c); return i < 0 ? 99 : i; }

export { dbHostInfo };
