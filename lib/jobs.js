// Background scan jobs with a concurrency limit. A domain is never scanned twice at once.
export class Jobs {
  constructor() {
    this.list = [];
    this.seq = 0;
    this.running = new Map();
  }

  start(kind, keys, worker, concurrency = 4, onDone = null) {
    const id = `job${++this.seq}`;
    const fresh = [...new Set(keys)].filter(k => !this.running.has(`${kind}:${k}`));
    const job = {
      id, kind, total: fresh.length, done: 0, errors: 0, skipped: keys.length - fresh.length,
      startedAt: new Date().toISOString(), finishedAt: null, cancelled: false, current: [], lastError: null,
    };
    this.list.unshift(job);
    this.list = this.list.slice(0, 15);
    for (const k of fresh) this.running.set(`${kind}:${k}`, id);
    const queue = [...fresh];
    const runOne = async () => {
      while (queue.length && !job.cancelled) {
        const k = queue.shift();
        job.current.push(k);
        try { await worker(k); }
        catch (e) { job.errors++; job.lastError = `${k}: ${e.message}`; console.error(`[${kind}] ${k}:`, e); }
        finally {
          job.done++;
          job.current = job.current.filter(x => x !== k);
          this.running.delete(`${kind}:${k}`);
        }
      }
    };
    const n = Math.max(1, Math.min(concurrency, fresh.length));
    Promise.all(Array.from({ length: fresh.length ? n : 0 }, runOne)).then(() => {
      for (const k of queue) this.running.delete(`${kind}:${k}`);
      job.finishedAt = new Date().toISOString();
      if (onDone) { try { onDone(job); } catch (e) { console.error('[jobs] onDone', e); } }
    });
    if (!fresh.length) job.finishedAt = job.startedAt;
    return job;
  }

  cancel(id) {
    const j = this.list.find(x => x.id === id);
    if (j) j.cancelled = true;
    return !!j;
  }

  summary() {
    return this.list.map(j => ({ ...j, current: j.current.slice(0, 16) }));
  }
}
