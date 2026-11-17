// JSON file store with a revision counter so the browser can fetch only what changed.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

export function makeToken(id) {
  return `migration-check:${id}:${crypto.randomBytes(9).toString('base64url')}`;
}

export function defaultSettings() {
  return {
    vps: [
      { id: 'vps114', name: 'VPS 114 (Plesk)', ipv4: ['194.164.91.114'], ipv6: [], token: makeToken('vps114'), sourceTemplate: '' },
      { id: 'vps212', name: 'VPS 212 (Plesk)', ipv4: ['185.132.36.212'], ipv6: [], token: makeToken('vps212'), sourceTemplate: '' },
    ],
    oldRanges: ['217.160.0.0/16', '2001:8d8::/32'],
    markerPath: '/.well-known/migration-check.txt',
    resolvers: ['1.1.1.1', '8.8.8.8'],
    concurrency: 10,
    timeoutMs: 10000,
    rev: 1,
  };
}

export class Store {
  constructor(dir) {
    this.dir = dir;
    this.file = path.join(dir, 'store.json');
    fs.mkdirSync(dir, { recursive: true });
    this.data = this.load();
    this.timer = null;
  }

  load() {
    try {
      return this.migrate(JSON.parse(fs.readFileSync(this.file, 'utf8')));
    } catch (e) {
      if (e.code !== 'ENOENT') {
        console.error('store.json could not be read, starting empty. A copy was kept.', e.message);
        try { fs.copyFileSync(this.file, `${this.file}.unreadable-${Date.now()}`); } catch {}
      }
      return this.migrate({});
    }
  }

  migrate(d) {
    d.version = 1;
    d.rev ??= 1;
    d.resetRev ??= 0;
    d.accounts ??= {};
    d.contracts ??= {};
    d.domains ??= {};
    d.emails ??= {};
    d.scanRuns ??= [];
    // A run left unfinished by a restart can never finish: close it.
    for (const r of d.scanRuns) if (!r.finishedAt) { r.finishedAt = new Date().toISOString(); r.interrupted = true; }
    // Review lists. reviewAuth holds password hashes and sessions and is never sent to a browser.
    d.reviews ??= {};
    d.reviewAuth ??= {};
    d.reviewAuth.master ??= null;
    d.reviewAuth.lists ??= {};
    d.reviewConfig = { share: false, baseUrl: '', ...(d.reviewConfig || {}) };
    d.settings = { ...defaultSettings(), ...(d.settings || {}) };
    return d;
  }

  bump(obj) {
    this.data.rev++;
    if (obj) obj.rev = this.data.rev;
    this.save();
    return this.data.rev;
  }

  // Signals that something was deleted, so clients should reload everything.
  markReset() {
    this.data.rev++;
    this.data.resetRev = this.data.rev;
    this.save();
  }

  // Throttled: at most one write per second, even while a scan changes data constantly.
  save() {
    if (this.timer) return;
    this.timer = setTimeout(() => this.flush(), 1000);
  }

  flush() {
    clearTimeout(this.timer);
    this.timer = null;
    const tmp = `${this.file}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(this.data));
    fs.renameSync(tmp, this.file);
  }

  backup(label) {
    if (!fs.existsSync(this.file) && !Object.keys(this.data.domains).length) return null;
    this.flush();
    const bdir = path.join(this.dir, 'backups');
    fs.mkdirSync(bdir, { recursive: true });
    const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
    const name = `store-${stamp}-${String(label || 'manual').replace(/[^a-z0-9-]+/gi, '-').slice(0, 40)}.json`;
    fs.copyFileSync(this.file, path.join(bdir, name));
    const all = fs.readdirSync(bdir).filter(f => f.startsWith('store-')).sort();
    for (const f of all.slice(0, Math.max(0, all.length - 30))) {
      try { fs.unlinkSync(path.join(bdir, f)); } catch {}
    }
    return name;
  }

  changes(since) {
    const d = this.data;
    if (!since || since < d.resetRev) return { full: true, rev: d.rev, data: d };
    const pick = obj => Object.values(obj).filter(x => (x.rev || 0) > since);
    return {
      full: false,
      rev: d.rev,
      accounts: pick(d.accounts),
      contracts: pick(d.contracts),
      domains: pick(d.domains),
      emails: pick(d.emails),
      reviews: pick(d.reviews),
      settings: (d.settings.rev || 0) > since ? d.settings : null,
      emailImports: d.emailImports || [],
      runs: d.scanRuns.filter(r => (r.rev || 0) > since),
    };
  }
}
