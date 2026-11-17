// Agent review page: sign in with the list password, then answer for each domain.
const $ = (s, el = document) => el.querySelector(s);
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const plural = (n, w) => `${n} ${n === 1 ? w : `${w}s`}`;
const LS = {
  get(k, d) { try { const v = localStorage.getItem(`rv:${k}`); return v ? JSON.parse(v) : d; } catch { return d; } },
  set(k, v) { try { localStorage.setItem(`rv:${k}`, JSON.stringify(v)); } catch {} },
};
function ago(iso) {
  if (!iso) return '';
  const s = (Date.now() - Date.parse(iso)) / 1000;
  if (s < 60) return 'just now';
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86400) return `${Math.round(s / 3600)} h ago`;
  return `${Math.round(s / 86400)} days ago`;
}
// Cormack logo, swapped for light and dark by CSS.
const LOGO = '<img src="/brand/cormack-light.svg" alt="Cormack" class="logo logo-light"><img src="/brand/cormack-dark.svg" alt="Cormack" class="logo logo-dark">';
const isDark = () => document.documentElement.getAttribute("data-theme") === "dark";
const themeBtn = () => `<button class="hdr-btn" type="button" data-act="theme" title="${isDark() ? "Switch to light mode" : "Switch to dark mode"}"><i class="${isDark() ? "ri-sun-line" : "ri-moon-line"}"></i></button>`;

const ID = decodeURIComponent(location.pathname.split('/')[2] || '');
const BASE = `/r/${encodeURIComponent(ID)}/api`;
const R = { st: null, tab: 'todo', q: '', edit: null, stick: new Set() };
const TABS = [
  { k: 'todo', l: 'To review', fn: i => !i.agent?.verdict },
  { k: 'done', l: 'Reviewed', fn: i => !!i.agent?.verdict },
  { k: 'reply', l: 'Admin replies', fn: i => !!i.admin },
  { k: 'all', l: 'All', fn: () => true },
];

async function call(path, body) {
  const opt = body === undefined ? { cache: 'no-store' } : { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) };
  const r = await fetch(`${BASE}/${path}`, opt);
  let j = {};
  try { j = await r.json(); } catch {}
  if (!r.ok) { const e = new Error(j.error || `${r.status} ${r.statusText}`); e.status = r.status; throw e; }
  return j;
}
function toast(msg, err) {
  const el = document.createElement('div');
  el.className = `toast${err ? ' err' : ''}`;
  el.textContent = msg;
  $('#toasts').appendChild(el);
  setTimeout(() => el.remove(), err ? 6000 : 3000);
}

async function load(quiet) {
  try {
    R.st = await call('state');
    document.title = `${R.st.list.name} · Domain review`;
    render();
  } catch (e) {
    if (e.status === 401) return login();
    if (e.status === 404) return message('Review list not found', 'This link does not point to a review list. It may have been deleted. Ask the person who shared it with you.');
    if (!quiet) message('Cannot reach the review server', `${e.message}. The computer sharing this list may be off or no longer sharing.`);
  }
}

function message(title, text) {
  R.st = null;
  $('#app').innerHTML = `<div class="card center-card"><div class="brand">${LOGO}<span class="app-pill">Domain review</span><span class="grow"></span>${themeBtn()}</div><h1>${esc(title)}</h1><p class="muted">${esc(text)}</p></div>`;
}

function login(err = '') {
  R.st = null;
  $('#app').innerHTML = `<form class="card center-card" id="login">
    <div class="brand">${LOGO}<span class="app-pill">Domain review</span><span class="grow"></span>${themeBtn()}</div>
    <div><h1>Sign in</h1><p class="muted">to open this review list</p></div>
    <label class="field"><span>Your name</span><input class="in" id="lname" required maxlength="60" autocomplete="name" value="${esc(LS.get('name', ''))}"></label>
    <label class="field"><span>Password</span><input class="in" id="lpw" type="password" required autocomplete="current-password"></label>
    ${err ? `<div class="err">${esc(err)}</div>` : ''}
    <button class="btn primary wide" type="submit">Open list</button>
    <p class="hint">Your name is shown next to your answers. You get the password from the person who shared this link.</p></form>`;
  (LS.get('name', '') ? $('#lpw') : $('#lname')).focus();
  $('#login').addEventListener('submit', async e => {
    e.preventDefault();
    const name = $('#lname').value.trim();
    const btn = $('#login button');
    btn.disabled = true;
    try {
      await call('login', { name, password: $('#lpw').value });
      LS.set('name', name);
      await load();
    } catch (ex) { login(ex.message); }
  });
}

// ---------- List ----------
function render() {
  const st = R.st;
  if (!st) return;
  const items = st.items;
  const n = items.length;
  const per = st.type.verdicts.map(v => ({ ...v, n: items.filter(i => i.agent?.verdict === v.k).length }));
  const done = per.reduce((s, v) => s + v.n, 0);
  const counts = Object.fromEntries(TABS.map(t => [t.k, items.filter(t.fn).length]));
  $('#app').innerHTML = `
    <header class="top">
      <div class="brand">${LOGO}<span class="app-pill">Domain review</span></div>
      <span class="grow"></span><span class="muted who-name"><i class="ri-user-line"></i> ${esc(st.me.name)}</span>${themeBtn()}<button class="btn sm" data-act="logout"><i class="ri-logout-box-r-line"></i> Sign out</button>
    </header>
    <section class="card head">
      <div class="type">${esc(st.type.l)}</div>
      <h1>${esc(st.list.name)}</h1>
      <div class="muted">${plural(n, 'domain')}${st.list.from ? ` · ${esc(st.list.from)}` : ''}</div>
      ${st.list.closed ? '<div class="banner">This list is closed. You can still read it, but answers can no longer be changed.</div>' : ''}
      <div class="prog"><div class="sbar">${n ? per.map(v => `<i class="c-${v.c}" style="width:${(v.n / n) * 100}%"></i>`).join('') : ''}</div>
        <span><b>${done} of ${n}</b> reviewed</span>${per.map(v => `<span class="key"><i class="c-${v.c}"></i>${esc(v.l)} ${v.n}</span>`).join('')}</div>
      <p class="howto">${st.type.howto}</p>
    </section>
    <div class="toolbar">
      <span class="seg">${TABS.map(t => `<button class="${t.k === R.tab ? 'on' : ''}" data-act="tab" data-v="${t.k}">${t.l}<span class="cnt">${counts[t.k]}</span></button>`).join('')}</span>
      <span class="grow"></span>
      <input class="in search" id="q" type="search" placeholder="Search domains" value="${esc(R.q)}" autocomplete="off" spellcheck="false">
    </div>
    <div class="items" id="items"></div>`;
  renderList();
}

function renderList() {
  const st = R.st;
  const tab = TABS.find(t => t.k === R.tab) || TABS[0];
  const words = R.q.toLowerCase().split(/\s+/).filter(Boolean);
  // Items answered in this tab stay in place until the tab changes, so nothing jumps under the cursor.
  const list = st.items.filter(i => (tab.fn(i) || R.stick.has(i.key)) && words.every(w => `${i.domain} ${i.contract} ${i.server} ${i.ip}`.toLowerCase().includes(w)));
  const empty = R.tab === 'todo' && !words.length ? 'All done: every domain in this list has an answer.' : 'Nothing here.';
  $('#items').innerHTML = list.map(row).join('') || `<div class="card empty">${empty}</div>`;
}

function row(i) {
  const closed = R.st.list.closed;
  const v = i.agent?.verdict;
  const editing = R.edit === i.key;
  const site = i.site ? `<span class="hs c-${i.site.c}"><i></i>${esc(i.site.l)}</span>${i.site.detail ? ` <span class="muted">${esc(i.site.detail)}</span>` : ''}` : '<span class="muted">Not checked yet</span>';
  const ssl = i.ssl ? ` <span class="sep">·</span> SSL <span class="hs c-${i.ssl.c}"><i></i>${esc(i.ssl.l)}</span>` : '';
  const dis = closed ? 'disabled' : '';
  const vc = R.st.type.verdicts.find(x => x.k === v)?.c;
  return `<article class="it card${vc ? ` answered c-${vc}` : ''}" data-key="${esc(i.key)}">
    <div class="it-l">
      <div class="it-d"><b>${esc(i.domain)}</b>${i.sub ? '<span class="tag">Sub</span>' : ''}</div>
      <div class="it-m">${i.contract ? `Contract ${esc(i.contract)}` : 'No contract number'}${i.contractLabel ? ` · ${esc(i.contractLabel)}` : ''}</div>
      <div class="it-m">Server: ${esc(i.server || '—')}${i.ip ? ` <span class="mono">${esc(i.ip)}</span>` : ''}</div>
      <div class="it-m">Site ${site}${ssl}</div>
      ${i.agent?.note && !editing ? `<div class="it-note"><b>Your note</b> ${esc(i.agent.note)}</div>` : ''}
      ${i.admin ? `<div class="it-admin c-${esc(i.admin.c || 'none')}"><i></i><div><b>Admin${i.admin.label ? `: ${esc(i.admin.label)}` : ''}</b>${i.admin.note ? ` · ${esc(i.admin.note)}` : ''}</div></div>` : ''}
    </div>
    <div class="it-r">
      <a class="btn" href="http://${esc(i.domain)}" target="_blank" rel="noopener noreferrer" data-open="${esc(i.key)}">Open ↗</a>
      ${R.st.type.verdicts.map(x => `<button class="btn vb c-${x.c}${v === x.k ? ' on' : ''}" data-act="verdict" data-v="${x.k}" ${dis} aria-pressed="${v === x.k}">${esc(x.l)}</button>`).join('')}
      <button class="btn" data-act="note" ${dis}>${i.agent?.note ? 'Edit note' : 'Add note'}</button>
      ${i.agent?.openedAt ? `<span class="hint">Opened ${esc(ago(i.agent.openedAt))}</span>` : ''}
    </div>
    ${editing ? `<div class="it-edit"><textarea class="in" rows="3" maxlength="4000" placeholder="What did you find? For example: shows a login page, belongs to a client that left, needs the shop back">${esc(i.agent?.note || '')}</textarea>
      <div class="it-edit-b"><button class="btn primary sm" data-act="note-save">Save note</button><button class="btn sm ghost" data-act="note-cancel">Cancel</button></div></div>` : ''}
  </article>`;
}

const find = key => R.st.items.find(i => i.key === key);
function update(item) {
  const i = R.st.items.findIndex(x => x.key === item.key);
  if (i >= 0) R.st.items[i] = item;
  render();
}
async function save(key, patch) {
  try { const r = await call('item', { key, ...patch }); update(r.item); }
  catch (e) {
    if (e.status === 401) return login('Your session ended. Sign in again.');
    toast(e.message, true);
  }
}

document.addEventListener('click', async e => {
  const op = e.target.closest('[data-open]');
  if (op) { // the link opens normally; record that it was opened
    if (!R.st.list.closed) call('item', { key: op.dataset.open, opened: true }).then(r => update(r.item)).catch(() => {});
    return;
  }
  const t = e.target.closest('[data-act]');
  if (!t || t.disabled) return;
  const key = t.closest('[data-key]')?.dataset.key;
  switch (t.dataset.act) {
    case 'theme': {
      const next = isDark() ? "light" : "dark";
      document.documentElement.setAttribute("data-theme", next);
      try { localStorage.setItem("cmk-theme", next); } catch {}
      t.outerHTML = themeBtn();
      break;
    }
    case 'tab': R.tab = t.dataset.v; R.stick.clear(); R.edit = null; render(); break;
    case 'logout': await call('logout', {}).catch(() => {}); login(); break;
    case 'verdict': {
      const it = find(key);
      R.stick.add(key);
      await save(key, { verdict: it.agent?.verdict === t.dataset.v ? null : t.dataset.v });
      break;
    }
    case 'note': R.edit = key; render(); $('.it-edit textarea')?.focus(); break;
    case 'note-cancel': R.edit = null; render(); break;
    case 'note-save': {
      const val = $('.it-edit textarea').value;
      R.edit = null;
      R.stick.add(key);
      await save(key, { note: val });
      break;
    }
  }
});
document.addEventListener('input', e => {
  if (e.target.id === 'q') { R.q = e.target.value; renderList(); }
});
document.addEventListener('keydown', e => {
  if (e.target.matches?.('.it-edit textarea') && e.key === 'Enter' && (e.metaKey || e.ctrlKey)) $('[data-act="note-save"]')?.click();
  if (e.key === 'Escape' && R.edit) { R.edit = null; render(); }
});

// Pick up the admin's replies without a reload, but never while typing.
const busy = () => !R.st || R.edit || /INPUT|TEXTAREA/.test(document.activeElement?.tagName || '') && document.activeElement.id !== 'q';
setInterval(() => { if (!busy() && document.visibilityState === 'visible') load(true); }, 20000);
document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'visible' && !busy()) load(true); });

load();
