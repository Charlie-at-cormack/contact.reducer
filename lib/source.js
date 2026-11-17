// Source access for deeper technology detection.
// Spec formats:
//   /absolute/local/folder   or   ~/folder           (read directly)
//   user@host:/path/to/docroot  or  sshalias:/path    (key-based SSH, BatchMode; never asks for passwords)
// Templates may use {domain} and {path} (the IONOS webspace path).
// Only a directory listing and a fixed set of known files are read. File contents are
// analysed in memory and never stored; database passwords and users are never extracted.
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { spawn } from 'node:child_process';

export const KNOWN_FILES = [
  'wp-config.php', 'wp-includes/version.php', 'composer.json', 'package.json', '.env', 'artisan',
  'configuration.php', 'administrator/manifests/files/joomla.xml', 'sites/default/settings.php', 'core/lib/Drupal.php',
  'system/user/config/config.php', 'system/ee/ExpressionEngine/Boot/boot.constants.php', 'system/expressionengine/config/database.php',
  'config/db.php', 'typo3conf/LocalConfiguration.php', 'config/system/settings.php', 'app/etc/env.php',
  'app/config/parameters.php', 'config.php', 'index.php', 'index.html', 'index.htm', '.htaccess', 'web.config',
  'next.config.js', 'next.config.mjs', 'nuxt.config.js', 'nuxt.config.ts', 'gatsby-config.js', 'astro.config.mjs',
  'vite.config.js', 'svelte.config.js', 'hugo.toml', 'config.toml', '_config.yml', 'prisma/schema.prisma',
  'requirements.txt', 'manage.py', 'Gemfile', 'server.js', 'app.js', 'ecosystem.config.js', 'docker-compose.yml',
];
const PRUNE = new Set(['node_modules', '.git', 'uploads', 'cache', 'vendor', '.cache', '.next', 'bower_components', '.svn', 'logs']);
const MAX_ENTRIES = 8000;

export function fillTemplate(tpl, d) {
  const p = String(d.webspacePath || '');
  const clean = p === '/.' || p === '.' ? '' : p.replace(/\/+$/, '');
  return String(tpl).replace(/\{domain\}/g, d.domain).replace(/\{path\}/g, clean);
}

export function parseSpec(spec) {
  spec = String(spec || '').trim();
  if (!spec) return null;
  const m = spec.match(/^([A-Za-z0-9._-]+@)?([A-Za-z0-9._-]+):(\/.*|~.*)?$/);
  if (m && !spec.startsWith('/') && !spec.startsWith('~')) {
    const target = (m[1] || '') + m[2];
    if (target.startsWith('-')) return { error: 'Invalid SSH target' };
    return { kind: 'ssh', target, path: m[3] || '.', spec };
  }
  if (spec.startsWith('~')) spec = path.join(os.homedir(), spec.slice(1));
  if (!path.isAbsolute(spec)) return { error: 'Use an absolute folder path or user@host:/path' };
  return { kind: 'local', path: path.normalize(spec), spec };
}

// Which source to use for a domain: domain override, then account template (webspace sites),
// then VPS template (domains that point to that VPS).
export function resolveSource(d, account, settings) {
  if (d.source?.spec) return { ...parseSpec(d.source.spec), from: 'domain override' };
  const tpl = account?.sourceTemplate;
  if (tpl && (!tpl.includes('{path}') || d.webspacePath)) return { ...parseSpec(fillTemplate(tpl, d)), from: `account template (${account.name})` };
  const ips = new Set([
    ...(d.scan?.hosts?.[0]?.ips || []).filter(i => i.cls === 'vps').map(i => i.vps),
  ]);
  for (const v of settings.vps || []) {
    const onVps = ips.has(v.id) || (d.exportIps?.v4 || []).some(ip => (v.ipv4 || []).includes(ip));
    if (v.sourceTemplate && onVps) return { ...parseSpec(fillTemplate(v.sourceTemplate, d)), from: `${v.name} template` };
  }
  return null;
}

// ---------- Readers ----------
async function readLocal(root) {
  const st = await fs.stat(root).catch(() => null);
  if (!st || !st.isDirectory()) return { error: `Folder not found: ${root}` };
  const list = [];
  const walk = async (dir, rel, depth) => {
    if (list.length >= MAX_ENTRIES) return;
    let entries;
    try { entries = await fs.readdir(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (list.length >= MAX_ENTRIES) return;
      if (e.name.startsWith('._') || e.name === '.DS_Store') continue;
      const r = rel ? `${rel}/${e.name}` : e.name;
      if (e.isDirectory()) {
        list.push({ t: 'd', p: r });
        if (depth < 3 && !PRUNE.has(e.name)) await walk(path.join(dir, e.name), r, depth + 1);
      } else if (e.isFile()) list.push({ t: 'f', p: r });
    }
  };
  await walk(root, '', 1);
  const files = new Map();
  const read = async (rel, max) => {
    try {
      const fh = await fs.open(path.join(root, rel), 'r');
      try {
        const buf = Buffer.alloc(max);
        const { bytesRead } = await fh.read(buf, 0, max, 0);
        files.set(rel, buf.subarray(0, bytesRead).toString('utf8'));
      } finally { await fh.close(); }
    } catch {}
  };
  for (const k of KNOWN_FILES) await read(k, 262144);
  for (const rel of phpSample(list)) if (!files.has(rel)) await read(rel, 65536);
  return { list, files, root };
}

function phpSample(list) {
  return list
    .filter(e => e.t === 'f' && /\.php$/i.test(e.p) && e.p.split('/').length <= 2 && !/^wp-(admin|includes)\//.test(e.p))
    .slice(0, 30)
    .map(e => e.p);
}

const shq = s => `'${String(s).replace(/'/g, `'\\''`)}'`;

function sshScript(p) {
  const prune = [...PRUNE].map(n => `-name ${shq(n)}`).join(' -o ');
  const known = KNOWN_FILES.map(shq).join(' ');
  return `P=${shq(p)}
case "$P" in "~"*) P="$HOME\${P#\\~}";; esac
cd "$P" 2>/dev/null || { echo "@@ERR cannot open $P"; exit 0; }
echo "@@PWD $(pwd)"
echo "@@LIST"
find . -maxdepth 3 \\( ${prune} \\) -prune -o -type d -print 2>/dev/null | head -n 3000 | sed 's/^/d /'
find . -maxdepth 3 \\( ${prune} \\) -prune -o -type f -print 2>/dev/null | head -n 5000 | sed 's/^/f /'
echo "@@ENDLIST"
emit() { echo "@@FILE $1"; head -c "$2" "$1" | base64; echo "@@END"; }
for f in ${known}; do [ -f "$f" ] && emit "$f" 262144; done
find . -maxdepth 2 -type f -name '*.php' 2>/dev/null | grep -v -E '^\\./wp-(admin|includes)/' | head -n 30 | while read -r f; do emit "\${f#./}" 65536; done
exit 0
`;
}

function readSsh(target, p, timeoutMs = 60000) {
  return new Promise(resolve => {
    const args = ['-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', '-T', target, 'sh', '-s'];
    let out = '', err = '';
    let child;
    try { child = spawn('ssh', args, { stdio: ['pipe', 'pipe', 'pipe'] }); } catch (e) { return resolve({ error: `ssh unavailable: ${e.message}` }); }
    const timer = setTimeout(() => { child.kill('SIGKILL'); }, timeoutMs);
    child.stdout.on('data', c => { if (out.length < 30e6) out += c; });
    child.stderr.on('data', c => { if (err.length < 10000) err += c; });
    child.on('error', e => { clearTimeout(timer); resolve({ error: `ssh failed: ${e.message}` }); });
    child.on('close', code => {
      clearTimeout(timer);
      if (!out.includes('@@')) {
        const hint = /permission denied|host key|publickey|password/i.test(err) ? ` Key-based login is required: run "ssh ${target}" once in Terminal to accept the host key and check your key.` : '';
        return resolve({ error: `SSH ${code === 255 ? 'connection failed' : `exit ${code}`}: ${err.trim().split('\n').slice(-2).join(' ').slice(0, 300) || 'no output'}.${hint}` });
      }
      const errLine = out.match(/^@@ERR (.*)$/m);
      if (errLine) return resolve({ error: errLine[1] });
      const list = [];
      const files = new Map();
      const lines = out.split('\n');
      let mode = '', cur = null, buf = [];
      for (const line of lines) {
        if (line === '@@LIST') { mode = 'list'; continue; }
        if (line === '@@ENDLIST') { mode = ''; continue; }
        if (line.startsWith('@@FILE ')) { cur = line.slice(7).replace(/^\.\//, ''); buf = []; mode = 'file'; continue; }
        if (line === '@@END' && mode === 'file') {
          try { files.set(cur, Buffer.from(buf.join(''), 'base64').toString('utf8')); } catch {}
          mode = ''; cur = null; continue;
        }
        if (mode === 'list') {
          const m = line.match(/^([df]) \.\/?(.*)$/);
          if (m && m[2]) list.push({ t: m[1], p: m[2] });
        } else if (mode === 'file') buf.push(line.trim());
      }
      const pwd = (out.match(/^@@PWD (.*)$/m) || [])[1] || p;
      resolve({ list, files, root: `${target}:${pwd}` });
    });
    child.stdin.end(sshScript(p));
  });
}

export async function readSource(src) {
  if (!src) return null;
  if (src.error) return { error: src.error };
  if (src.kind === 'local') return readLocal(src.path);
  if (src.kind === 'ssh') return readSsh(src.target, src.path);
  return { error: 'Unknown source type' };
}

// ---------- Analysis ----------
export function dbHostInfo(host) {
  const h = String(host || '').toLowerCase().trim().replace(/:\d+$/, '');
  if (!h) return null;
  if (/^(localhost|127\.0\.0\.1|::1)$/.test(h) || h.startsWith('localhost:') || h.startsWith('/')) return { where: 'local', label: 'Same server (localhost)' };
  if (/(^|\.)(hosting-data\.io|1and1\.(com|co\.uk|de)|ionos\.(com|co\.uk|de)|db\.1and1\.com)$/.test(h)) return { where: 'ionos', label: 'IONOS-hosted database' };
  return { where: 'external', label: 'External database server' };
}

const pick = (txt, re) => { const m = re.exec(txt || ''); return m ? m[1] : null; };
const phpDefine = (txt, name) => pick(txt, new RegExp(`define\\(\\s*['"]${name}['"]\\s*,\\s*['"]([^'"]*)['"]`, 'i'));
const envVal = (txt, name) => pick(txt, new RegExp(`^\\s*${name}\\s*=\\s*["']?([^"'\\r\\n#]*)`, 'mi'));
const arrVal = (txt, key) => pick(txt, new RegExp(`['"]${key}['"]\\s*=>\\s*['"]([^'"]*)['"]`, 'i'));
function safeJson(t) { try { return JSON.parse(t); } catch { return null; } }

function dbTypeFromDriver(drv) {
  const v = String(drv || '').toLowerCase();
  if (!v) return null;
  if (/maria/.test(v)) return 'MariaDB';
  if (/mysql|mysqli/.test(v)) return 'MySQL / MariaDB';
  if (/pgsql|postgres/.test(v)) return 'PostgreSQL';
  if (/sqlite/.test(v)) return 'SQLite';
  if (/sqlsrv|mssql/.test(v)) return 'Microsoft SQL Server';
  if (/mongo/.test(v)) return 'MongoDB';
  return v;
}

export function analyzeSource(src) {
  const findings = [];
  const dbs = [];
  const notes = [];
  const add = (cat, name, ver, ev) => findings.push({ cat, name, ver: ver || null, conf: 'detected', src: 'source', ev });
  const addDb = (type, ev, host, name, conf = 'detected') => {
    const info = dbHostInfo(host);
    dbs.push({ type, ev, host: host || null, name: name || null, conf, where: info?.where || null, whereLabel: info?.label || null });
  };
  const F = p => src.files.get(p);
  const paths = src.list.map(e => e.p);
  const dirs = new Set(src.list.filter(e => e.t === 'd').map(e => e.p));
  const has = p => paths.includes(p);
  const composer = safeJson(F('composer.json') || '');
  const creq = { ...(composer?.require || {}), ...(composer?.['require-dev'] || {}) };
  const pkg = safeJson(F('package.json') || '');
  const deps = { ...(pkg?.dependencies || {}), ...(pkg?.devDependencies || {}) };
  const env = F('.env') || '';

  // WordPress
  const wpv = pick(F('wp-includes/version.php'), /\$wp_version\s*=\s*'([^']+)'/);
  if (wpv) add('cms', 'WordPress', wpv, 'wp-includes/version.php');
  else if (has('wp-config.php') || dirs.has('wp-content')) add('cms', 'WordPress', null, has('wp-config.php') ? 'wp-config.php present' : 'wp-content/ present');
  const wpc = F('wp-config.php');
  if (wpc) {
    const host = phpDefine(wpc, 'DB_HOST');
    addDb('MySQL / MariaDB', 'wp-config.php (DB_HOST / DB_NAME)', host, phpDefine(wpc, 'DB_NAME'));
  }
  for (const e of src.list) {
    let m;
    if (e.t === 'd' && (m = e.p.match(/^wp-content\/themes\/([^/]+)$/))) add('theme', m[1], null, 'wp-content/themes/');
  }
  const plugins = src.list.filter(e => e.t === 'd' && /^wp-content\/plugins\/[^/]+$/.test(e.p)).map(e => e.p.split('/')[2]);
  for (const p of plugins.slice(0, 40)) add('plugin', p, null, 'wp-content/plugins/');
  if (plugins.includes('elementor')) add('pagebuilder', 'Elementor', null, 'wp-content/plugins/elementor');
  if (plugins.includes('woocommerce')) add('ecommerce', 'WooCommerce', null, 'wp-content/plugins/woocommerce');

  // Joomla
  const jc = F('configuration.php');
  if (jc && /class\s+JConfig/.test(jc)) {
    add('cms', 'Joomla', pick(F('administrator/manifests/files/joomla.xml'), /<version>([^<]+)<\/version>/), 'configuration.php (JConfig)');
    addDb(dbTypeFromDriver(pick(jc, /\$dbtype\s*=\s*'([^']*)'/)) || 'MySQL / MariaDB', 'configuration.php ($dbtype / $host)', pick(jc, /\$host\s*=\s*'([^']*)'/), pick(jc, /\$db\s*=\s*'([^']*)'/));
  }
  // Drupal
  const ds = F('sites/default/settings.php');
  if (ds || F('core/lib/Drupal.php')) {
    add('cms', 'Drupal', pick(F('core/lib/Drupal.php'), /const\s+VERSION\s*=\s*'([^']+)'/), ds ? 'sites/default/settings.php' : 'core/lib/Drupal.php');
    const drv = ds && pick(ds, /['"]driver['"]\s*=>\s*['"]([^'"]+)['"]/);
    if (drv) addDb(dbTypeFromDriver(drv), 'settings.php $databases driver', arrVal(ds, 'host'), arrVal(ds, 'database'));
  }
  // ExpressionEngine
  const eec = F('system/user/config/config.php');
  if (eec || dirs.has('system/ee') || F('system/expressionengine/config/database.php')) {
    add('cms', 'ExpressionEngine', pick(F('system/ee/ExpressionEngine/Boot/boot.constants.php'), /APP_VER['"]\s*,\s*['"]([^'"]+)/), eec ? 'system/user/config/config.php' : 'system/ee/');
    const cfg = eec || F('system/expressionengine/config/database.php') || '';
    const drv = arrVal(cfg, 'dbdriver');
    if (drv || arrVal(cfg, 'hostname')) addDb(dbTypeFromDriver(drv) || 'MySQL / MariaDB', 'ExpressionEngine database config', arrVal(cfg, 'hostname'), arrVal(cfg, 'database'));
  }
  // Craft
  if (creq['craftcms/cms'] || (dirs.has('craft') && env.includes('CRAFT'))) {
    add('cms', 'Craft CMS', creq['craftcms/cms'] || null, 'composer.json craftcms/cms');
    const drv = envVal(env, 'CRAFT_DB_DRIVER') || envVal(env, 'DB_DRIVER');
    if (drv) addDb(dbTypeFromDriver(drv), '.env DB driver', envVal(env, 'CRAFT_DB_SERVER') || envVal(env, 'DB_SERVER'), envVal(env, 'CRAFT_DB_DATABASE') || envVal(env, 'DB_DATABASE'));
  }
  // TYPO3
  const t3 = F('typo3conf/LocalConfiguration.php') || F('config/system/settings.php');
  if (t3 && /TYPO3|'DB'\s*=>/.test(t3)) {
    add('cms', 'TYPO3', null, 'TYPO3 configuration');
    const drv = arrVal(t3, 'driver');
    addDb(dbTypeFromDriver(drv) || 'SQL database', 'TYPO3 DB connection', arrVal(t3, 'host'), arrVal(t3, 'dbname'));
  }
  // Magento / PrestaShop / OpenCart / Concrete
  const mg = F('app/etc/env.php');
  if (mg && /'db'\s*=>/.test(mg)) { add('cms', 'Magento', null, 'app/etc/env.php'); addDb('MySQL / MariaDB', 'app/etc/env.php', arrVal(mg, 'host'), arrVal(mg, 'dbname')); }
  const ps = F('app/config/parameters.php');
  if (ps && /database_host/.test(ps)) { add('cms', 'PrestaShop', null, 'app/config/parameters.php'); addDb('MySQL / MariaDB', 'parameters.php', arrVal(ps, 'database_host'), arrVal(ps, 'database_name')); }
  const cfgphp = F('config.php') || '';
  if (/DIR_APPLICATION/.test(cfgphp) && /DB_DRIVER/.test(cfgphp)) { add('cms', 'OpenCart', null, 'config.php (DIR_APPLICATION)'); addDb(dbTypeFromDriver(phpDefine(cfgphp, 'DB_DRIVER')), 'config.php DB_DRIVER', phpDefine(cfgphp, 'DB_HOSTNAME'), phpDefine(cfgphp, 'DB_DATABASE')); }
  if (dirs.has('concrete') && dirs.has('application')) add('cms', 'Concrete CMS', null, 'concrete/ + application/');

  // PHP frameworks
  if (has('artisan') || creq['laravel/framework']) add('framework', 'Laravel', creq['laravel/framework'] || null, has('artisan') ? 'artisan + composer.json' : 'composer.json');
  else if (creq['symfony/framework-bundle']) add('framework', 'Symfony', creq['symfony/framework-bundle'], 'composer.json');
  if (creq['codeigniter4/framework'] || dirs.has('system/core')) add('framework', 'CodeIgniter', creq['codeigniter4/framework'] || null, creq['codeigniter4/framework'] ? 'composer.json' : 'system/core/');
  if (creq.php) notes.push(`composer.json requires PHP ${creq.php}`);
  const envConn = envVal(env, 'DB_CONNECTION');
  if (envConn) addDb(dbTypeFromDriver(envConn), '.env DB_CONNECTION', envVal(env, 'DB_HOST'), envVal(env, 'DB_DATABASE'));
  const dbUrl = envVal(env, 'DATABASE_URL') || envVal(env, 'MONGODB_URI');
  if (dbUrl) {
    const scheme = (dbUrl.match(/^([a-z0-9+]+):/i) || [])[1] || '';
    let host = null;
    try { host = new URL(dbUrl.replace(/^[a-z0-9+]+:/i, 'http:')).hostname || null; } catch {}
    addDb(dbTypeFromDriver(scheme) || scheme, '.env DATABASE_URL (scheme and host only)', host, null);
  }

  // Node / JS
  if (pkg) {
    const fw = [['next', 'Next.js'], ['nuxt', 'Nuxt'], ['gatsby', 'Gatsby'], ['astro', 'Astro'], ['@sveltejs/kit', 'SvelteKit'], ['express', 'Express'], ['fastify', 'Fastify'], ['@nestjs/core', 'NestJS']];
    for (const [k, n] of fw) if (deps[k]) add('framework', n, deps[k], 'package.json');
    for (const [k, n] of [['react', 'React'], ['vue', 'Vue'], ['svelte', 'Svelte'], ['vite', 'Vite']]) if (deps[k]) add('frontend', n, deps[k], 'package.json');
    if (deps.express || deps.fastify || deps['@nestjs/core'] || deps.next || deps.nuxt || has('server.js')) add('language', 'Node.js', pkg.engines?.node || null, 'package.json');
    const drivers = [['pg', 'PostgreSQL'], ['mysql2', 'MySQL / MariaDB'], ['mysql', 'MySQL / MariaDB'], ['mongoose', 'MongoDB'], ['mongodb', 'MongoDB'], ['sqlite3', 'SQLite'], ['better-sqlite3', 'SQLite']];
    for (const [k, n] of drivers) if (deps[k]) addDb(n, `package.json dependency "${k}"`, null, null, 'inferred');
  }
  const prisma = F('prisma/schema.prisma');
  if (prisma) { const prov = pick(prisma, /provider\s*=\s*"(postgresql|mysql|sqlite|mongodb|sqlserver|cockroachdb)"/); if (prov) addDb(dbTypeFromDriver(prov) || prov, 'prisma/schema.prisma provider', null, null); }
  // Python / Ruby
  if (has('manage.py')) add('framework', 'Django', null, 'manage.py');
  const req = F('requirements.txt') || '';
  if (/^flask/im.test(req)) add('framework', 'Flask', null, 'requirements.txt');
  if (/psycopg/i.test(req)) addDb('PostgreSQL', 'requirements.txt psycopg', null, null, 'inferred');
  if (/mysqlclient|pymysql/i.test(req)) addDb('MySQL / MariaDB', 'requirements.txt MySQL driver', null, null, 'inferred');
  if (has('manage.py') || req) add('language', 'Python', null, has('manage.py') ? 'manage.py' : 'requirements.txt');
  if (/gem ['"]rails['"]/.test(F('Gemfile') || '')) { add('framework', 'Ruby on Rails', null, 'Gemfile'); add('language', 'Ruby', null, 'Gemfile'); }
  // Static site generators
  if (F('hugo.toml') || /baseURL/i.test(F('config.toml') || '')) add('ssg', 'Hugo', null, F('hugo.toml') ? 'hugo.toml' : 'config.toml');
  if (F('_config.yml') && (has('Gemfile') || dirs.has('_posts') || dirs.has('_layouts'))) add('ssg', 'Jekyll', null, '_config.yml');

  // File-type census
  const filesOnly = src.list.filter(e => e.t === 'f');
  const ext = p => (p.match(/\.([a-z0-9]+)$/i) || [])[1]?.toLowerCase() || '';
  const count = exts => filesOnly.filter(e => exts.includes(ext(e.p))).length;
  const php = count(['php', 'phtml', 'php5', 'php7', 'inc']);
  const asp = count(['asp', 'aspx', 'ashx', 'cshtml']);
  const cgi = count(['cgi', 'pl', 'py', 'rb']);
  const html = count(['html', 'htm']);
  if (php) add('language', 'PHP', null, `${php} PHP file${php > 1 ? 's' : ''} in the top 3 levels`);
  if (asp) add('language', 'ASP.NET', null, `${asp} ASP/ASP.NET files`);

  // Database use in PHP code
  for (const [p, txt] of src.files) {
    if (!/\.php$/i.test(p) || p === 'wp-config.php') continue;
    let m;
    if ((m = txt.match(/new\s+PDO\s*\(\s*["'](mysql|pgsql|sqlite|sqlsrv)[:"']/i))) addDb(dbTypeFromDriver(m[1]), `PDO DSN in ${p}`, pick(txt, /host=([a-z0-9._-]+)/i), pick(txt, /dbname=([a-z0-9_]+)/i));
    else if (/mysqli_connect\s*\(|new\s+mysqli\s*\(/i.test(txt)) addDb('MySQL / MariaDB', `mysqli connection in ${p}`, pick(txt, /mysqli(?:_connect)?\s*\(\s*['"]([^'"]+)['"]/i), null);
    if (/\bmysql_connect\s*\(/i.test(txt)) {
      addDb('MySQL / MariaDB', `mysql_connect() in ${p}`, pick(txt, /mysql_connect\s*\(\s*['"]([^'"]+)['"]/i), null);
      notes.push(`${p} uses mysql_connect(), which was removed in PHP 7. The site needs code changes or PHP 5.6.`);
    }
  }
  const generic = cfgphp && !/DIR_APPLICATION/.test(cfgphp) ? (phpDefine(cfgphp, 'DB_HOST') || phpDefine(cfgphp, 'DB_SERVER')) : null;
  if (generic) addDb(dbTypeFromDriver(phpDefine(cfgphp, 'DB_DRIVER')) || 'MySQL / MariaDB', 'config.php DB_HOST', generic, phpDefine(cfgphp, 'DB_NAME') || phpDefine(cfgphp, 'DB_DATABASE'), 'inferred');
  const sqlite = filesOnly.filter(e => /\.(sqlite3?|db)$/i.test(e.p) && !/thumbs\.db$/i.test(e.p));
  if (sqlite.length) addDb('SQLite', `database file ${sqlite[0].p}`, null, null);

  // Static: only client-side files and no server-side code or app config
  const serverSide = php || asp || cgi || findings.some(f => ['cms', 'framework'].includes(f.cat)) || has('server.js');
  const hasIndex = has('index.html') || has('index.htm');
  if (!serverSide && hasIndex) add('static', 'Static HTML/CSS/JS', null, `index.html present; ${html} HTML file${html === 1 ? '' : 's'} and no server-side code in the top 3 levels`);
  else if (!serverSide && !hasIndex && filesOnly.length) notes.push('No index.html and no server-side code found at this path. Check the source path is the document root.');
  if (!filesOnly.length) notes.push('The source folder is empty or unreadable.');

  return { findings, dbs, notes, fileCount: filesOnly.length, dirCount: dirs.size };
}
