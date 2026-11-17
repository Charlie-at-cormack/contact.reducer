// Review list types: what the agent can answer, and what you can decide, for each type of list.
// Shared by the server (validation, agent page) and the browser (admin UI), so no Node or DOM APIs here.
import { shortVps } from './health.js';

export const REVIEW_TYPES = {
  down: {
    k: 'down',
    l: 'Website down',
    d: 'Sites that do not answer properly. The agent says whether each one should be live or can be removed.',
    howto: 'For each domain: <b>Open</b> it and look at it. Then choose <b>Should be live</b> if it is a real site that must work, or <b>To be removed</b> if it is no longer needed. Add a note when something needs explaining.',
    verdicts: [
      { k: 'remove', l: 'To be removed', c: 'bad' },
      { k: 'live', l: 'Should be live', c: 'ok' },
    ],
    // l = full label (lists, logs, agent page); s + ic = the compact button on your decision row.
    outcomes: () => [
      { k: 'fixed', l: 'Fixed', s: 'Fixed', ic: 'check-line', c: 'ok', done: true },
      { k: 'remove', l: 'Remove', s: 'Remove', ic: 'delete-bin-line', c: 'bad', done: true },
      { k: 'issue', l: 'Issue to resolve', s: 'Issue', ic: 'error-warning-line', c: 'other' },
    ],
  },
  live: {
    k: 'live',
    l: 'Website live on IONOS shared',
    d: 'Working sites still on IONOS shared hosting. The agent says whether each one moves to the new server or goes, and whether the domain is kept.',
    howto: 'For each domain: <b>Open</b> it and look at it. Choose <b>Migrate</b> if the site must keep working on the new server, <b>Remove + keep domain</b> if the site can go but the domain name stays, or <b>Remove + cancel domain</b> if neither is needed any more. Add a note when something needs explaining.',
    verdicts: [
      { k: 'migrate', l: 'Migrate', c: 'ok' },
      { k: 'remove_keep', l: 'Remove + keep domain', c: 'warn' },
      { k: 'remove_cancel', l: 'Remove + cancel domain', c: 'bad' },
    ],
    // "Moved to" offers every destination VPS from Settings.
    outcomes: settings => [
      ...(settings?.vps || []).map(v => ({ k: `moved:${v.id}`, l: `Moved to ${shortVps(v.name)}`, s: shortVps(v.name), g: 'Moved to', c: 'ok', done: true })),
      { k: 'removed_kept', l: 'Removed, domain kept', s: 'Kept', ic: 'delete-bin-line', g: 'Removed', c: 'warn', done: true },
      { k: 'removed_cancelled', l: 'Removed + domain cancelled', s: 'Cancelled', ic: 'delete-bin-line', g: 'Removed', c: 'bad', done: true },
      { k: 'issue', l: 'Issue to resolve', s: 'Issue', ic: 'error-warning-line', c: 'other' },
    ],
  },
};

export const typeOf = list => REVIEW_TYPES[list?.type] || REVIEW_TYPES.down;

export function verdictMeta(type, k) {
  if (!k) return null;
  return type.verdicts.find(v => v.k === k) || { k, l: k, c: 'none' };
}

export function outcomeMeta(type, k, settings) {
  if (!k) return null;
  const o = type.outcomes(settings).find(x => x.k === k);
  if (o) return o;
  if (k.startsWith('moved:')) return { k, l: `Moved to ${k.slice(6)}`, c: 'ok', done: true }; // a VPS since removed from Settings
  return { k, l: k, c: 'none' };
}
