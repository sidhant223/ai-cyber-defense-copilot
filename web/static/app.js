/* Defense Copilot web UI: state, API, shell, Home and Scan.
   report.js and tools.js add the other screens to SCREENS. Every value that
   comes from a scanned repository goes through esc() before it reaches HTML. */
'use strict';

const S = {
  screen: 'home', theme: store('theme') || 'light', menu: !isNarrow() && store('menu') !== 'closed', meta: null, history: [], report: null,
  sel: null, minSev: 'all', statusFilter: 'all', fileFilter: 'all', detailTab: 'diff', showSat: false, query: '', reveal: false, showSkipped: false,
  showCalcDetails: false,
  source: 'sample', sample: 'flask-notes-app', path: '', zip: null, scope: [], useConfig: true,
  scanning: false, error: null, rules: null, ruleId: 'AUTH-001', ruleCat: 'all',
  routes: null, unprot: false, routeQuery: '', routeFilter: 'all', split: 'dev', evals: {}, evalView: null, truth: null,
  form: { control: '', reason: '', expires: '', where: 'config' }, toast: '',
};
const SCREENS = {};
const TITLES = { guide: 'Guide', home: 'Home', scan: 'Scan', report: 'Posture report', routes: 'Route inventory',
  accepted: 'Accepted findings', rules: 'Controls', eval: 'Evaluation', how: 'How it works' };
const CATS = [['authentication', 'Authentication'], ['input_validation', 'Input validation'],
  ['rate_limiting', 'Rate limiting'], ['secret_management', 'Secret management'], ['access_control', 'Access control']];
const CATT = Object.fromEntries(CATS);
const W = { critical: 5, high: 3, medium: 2, low: 1 };
const CR = { present: 1, partial: 0.5, absent: 0 };
const SEVR = { critical: 0, high: 1, medium: 2, low: 3 };
const STR = { absent: 0, partial: 1, present: 2, not_applicable: 3 };
const SL = { absent: 'ABSENT', partial: 'PARTIAL', present: 'PRESENT', not_applicable: 'N/A' };
const SC = { absent: 'var(--absent)', partial: 'var(--partial)', present: 'var(--present)', not_applicable: 'var(--na)' };
const ACTIONS = {};

// ---------------------------------------------------------------- helpers
function isNarrow() { return window.matchMedia('(max-width: 900px)').matches; }
function store(k, v) {
  try { if (v === undefined) return localStorage.getItem(k); localStorage.setItem(k, v); } catch (e) { return null; }
}
function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
const scoreColor = s => s >= 80 ? 'var(--present)' : s >= 50 ? 'var(--partial)' : 'var(--absent)';
const gradeText = r => r.summary.grade ? 'grade ' + r.summary.grade : 'grade withheld';
const fColor = f => f.suppressed ? 'var(--na)' : SC[f.status];
const fLabel = f => f.suppressed ? 'ACCEPTED' : SL[f.status];
const plural = (n, w) => `${n} ${w}${n === 1 ? '' : 's'}`;
function set(patch) { Object.assign(S, patch); render(); }
function flash(t) { set({ toast: t }); clearTimeout(flash.t); flash.t = setTimeout(() => set({ toast: '' }), 2400); }
function tabs(opts, cur, act, cls = 'seg') {
  return `<div class="${cls}">${opts.map(([v, l]) =>
    `<button class="${cur === v ? 'on' : ''}" data-act="${act}" data-v="${esc(v)}" aria-pressed="${cur === v}">${esc(l)}</button>`).join('')}</div>`;
}
function check(on, act, label) {
  return `<button class="check ${on ? 'on' : ''}" data-act="${act}" role="checkbox" aria-checked="${on}"><span class="box"><i></i></span>${esc(label)}</button>`;
}

async function api(path, opts = {}) {
  const res = await fetch(path, opts);
  const data = await res.json().catch(() => ({ error: `Server returned ${res.status}` }));
  if (!res.ok) throw new Error(data.error || `Server returned ${res.status}`);
  return data;
}

// ---------------------------------------------------------------- shell
function sidebar() {
  const r = S.report, m = S.meta;
  const gaps = r ? r.findings.filter(f => f.is_gap).length : '';
  const nav = [['home', 'Home', ''], ['scan', 'Scan', '', 'Target'], ['report', 'Report', gaps],
    ['routes', 'Routes', ''], ['accepted', 'Accepted', r && r.summary.controls_suppressed ? r.summary.controls_suppressed : ''],
    ['rules', 'Rules', m ? m.controls : '', 'Tool'], ['eval', 'Evaluation', ''], ['how', 'How it works', ''], ['guide', 'Guide', '', 'Help']];
  return `<aside class="side" id="side" aria-label="Main menu" ${S.menu ? '' : 'inert'}>
  <button class="brand" data-act="go" data-v="home"><div class="logo"><i></i></div>
    <div><b>Defense Copilot</b><span>v${esc(m ? m.version : '')} · rules ${m ? m.controls : ''}</span></div></button>
  <div class="target"><span class="eyebrow">Target</span>
    ${r ? `<span class="name">${esc(r.source)}</span>
    <div class="line"><b style="color:${scoreColor(r.summary.posture_score)}">${r.summary.posture_score}</b><span>${gradeText(r)}</span><span>·</span><span>${plural(gaps, 'gap')}</span></div>`
      : '<span class="small mute">No scan yet</span>'}</div>
  <nav aria-label="Screens">${nav.map(([k, l, b, h]) => `${h ? `<div class="navhead">${h}</div>` : ''}
    <button class="navbtn ${S.screen === k ? 'on' : ''}" data-act="go" data-v="${k}" ${S.screen === k ? 'aria-current="page"' : ''}>
      <span>${l}</span><span class="badge">${esc(b)}</span></button>`).join('')}</nav>
  <div class="sidefoot"><span>static analysis · no network · runs nothing</span><span>rule-based guidance · no AI model</span></div>
</aside>`;
}

function topbar() {
  const r = S.report;
  const cli = { report: r && cliFor(r), routes: r && `copilot routes ${r.source}`, accepted: '.copilot.yaml',
    rules: 'copilot rules list', eval: evalView() === 'project' ? (r && `copilot scan ${r.source} --format json`) : `copilot evaluate --split ${S.split}` }[S.screen];
  const dl = S.screen === 'report' && r ? `<div class="dl">${[['html', 'HTML'], ['json', 'JSON'], ['sarif', 'SARIF'], ['md', 'Markdown']]
    .map(([f, l]) => `<a href="/api/export/${esc(r.id)}?format=${f}" download>${l}</a>`).join('')}</div>` : '';
  const themes = `<div class="pilltabs" role="group" aria-label="Theme">${[['light', 'Light'], ['dark', 'Dark']].map(([v, l]) =>
    `<button class="${S.theme === v ? 'on' : ''}" data-act="theme" data-v="${v}" aria-pressed="${S.theme === v}"><span class="dot ${v === 'dark' ? 'fill' : ''}"></span>${l}</button>`).join('')}</div>`;
  const burger = `<button class="burger" data-act="menu" aria-controls="side" aria-expanded="${S.menu}" aria-label="${S.menu ? 'Close' : 'Open'} menu"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true">${S.menu && isNarrow() ? '<path d="M6 6l12 12M18 6L6 18"/>' : '<path d="M4 7h16M4 12h16M4 17h16"/>'}</svg></button>`;
  const cliBtn = cli ? `<button class="click-copy" data-act="copyCli" data-v="${esc(cli)}" title="Click to copy CLI command" style="font:12px var(--mono);color:var(--mute);padding:3px 6px;border-radius:5px;display:inline-flex;align-items:center;gap:6px">$ ${esc(cli)} <span style="font-size:10px;opacity:.65">📋</span></button>` : '';
  return `<header class="top"><div class="title">${burger}<b>${TITLES[S.screen]}</b>${cliBtn}</div>
    <div class="actions">${dl}${themes}</div></header>`;
}

function cliFor(r) {
  const s = r.summary;
  return `copilot scan ${r.source}` + (s.scope === 'partial' ? ` --category ${s.categories_scanned.join(',')}` : '');
}

function render() {
  document.documentElement.dataset.theme = S.theme;
  const focus = document.activeElement && document.activeElement.dataset && document.activeElement.dataset.bind;
  const caret = focus ? document.activeElement.selectionStart : null;
  const body = (SCREENS[S.screen] || SCREENS.home)();
  const app = document.getElementById('app');
  app.className = 'shell ' + (S.menu ? 'menu-open' : 'menu-closed');
  app.innerHTML = sidebar() + (S.menu && isNarrow() ? '<div class="scrim" data-act="menu"></div>' : '') +
    `<main>${topbar()}${body}</main>` + (S.toast ? `<div class="toast" role="status">${esc(S.toast)}</div>` : '');
  if (focus) {   // keep typing position across re-renders
    const el = document.querySelector(`[data-bind="${focus}"]`);
    if (el) { el.focus(); if (caret !== null && el.setSelectionRange) el.setSelectionRange(caret, caret); }
  }
}

// ---------------------------------------------------------------- Home
SCREENS.home = () => {
  const r = S.report;
  const gaps = r ? r.findings.filter(f => f.is_gap)
    .sort((a, b) => SEVR[a.severity] - SEVR[b.severity] || STR[a.status] - STR[b.status] || a.control_id.localeCompare(b.control_id)).slice(0, 5) : [];
  const trend = r && r.diff ? `
    <span class="score-trend ${r.diff.scoreDelta > 0 ? 'up' : r.diff.scoreDelta < 0 ? 'down' : 'same'}" title="Previous score: ${r.diff.prevScore}">
      ${r.diff.scoreDelta > 0 ? '▲ +' : r.diff.scoreDelta < 0 ? '▼ ' : '= '}${r.diff.scoreDelta} pts vs previous scan
    </span>` : '';
  const latest = r ? `
    <div class="row" style="gap:18px"><span class="bignum" style="color:${scoreColor(r.summary.posture_score)}">${r.summary.posture_score}</span>
      <div class="stack g6"><div class="row" style="gap:8px;align-items:center"><span class="mono" style="font-weight:500">${gradeText(r)}</span>${trend}</div>
      <span class="mute" style="font-size:12.5px">${plural(gaps.length ? r.findings.filter(f => f.is_gap).length : 0, 'gap')} · ${r.summary.controls_scored} of ${r.summary.controls_evaluated} controls scored</span></div></div>
    ${chips(r)}
    <div class="stack" style="border-top:1px solid var(--line)"><span class="eyebrow" style="padding:12px 0 4px">Fix first</span>
      ${gaps.map(f => `<button class="listrow" style="grid-template-columns:70px 84px minmax(0,1fr);padding:8px 0" data-act="open" data-v="${esc(f.control_id)}">
        <span class="tag" style="color:${fColor(f)}">${fLabel(f)}</span><span class="mono small ink2">${esc(f.control_id)}</span>
        <span class="clip">${esc(f.control_name)}</span></button>`).join('') || '<span class="small mute" style="padding:8px 0">No open gaps.</span>'}
    </div>` : `<p class="mute">No scan yet this session. Pick a bundled sample, a folder on this machine, or a .zip.</p>`;
  const recent = S.history.length ? S.history.map(h => `
    <button class="listrow" style="grid-template-columns:minmax(0,1fr) 80px 40px;padding:9px 18px;${r && h.id === r.id ? 'background:var(--sunk)' : ''}" data-act="load" data-v="${esc(h.id)}">
      <div class="stack" style="min-width:0"><span class="mono clip" style="font-size:12.5px">${esc(h.source)}</span>
        <span class="mute xs">${esc(h.framework || 'unknown')} · ${plural(h.gaps, 'gap')} · ${new Date(h.scanned_at).toLocaleTimeString()}</span></div>
      <div class="bar"><i style="width:${h.score}%;background:${scoreColor(h.score)}"></i></div>
      <span class="mono" style="font-weight:600;font-size:12px;text-align:right;color:${scoreColor(h.score)}">${h.score}</span></button>`).join('')
    : '<p class="mute small" style="padding:0 18px 16px">Nothing yet. Scans stay here until the server stops; download a report to keep one.</p>';
  const places = [['CLI', 'copilot scan ./repo --fail-on critical'], ['GitHub Action', 'uses: sidhant223/ai-cyber-defense-copilot@main'],
    ['Pre-commit', 'hooks: [{id: copilot-scan}]'], ['Docker', 'docker run --rm -v "$PWD:/repo:ro" copilot scan .']];
  return `<div class="page w1180" style="padding-top:36px;gap:28px">
  <div class="stack g10 hero" style="max-width:720px">
    <h1>Which security controls are missing from your code?</h1>
    <p>A linter finds bad code that exists. This finds good code that should exist and doesn't: no auth on a route, no rate limit on a login endpoint, a secret sitting in plaintext.</p>
    <div class="row" style="margin-top:6px"><button class="btn primary" data-act="go" data-v="scan">New scan</button>
      <button class="btn" data-act="go" data-v="report" ${r ? '' : 'disabled'}>Open latest report</button>
      <button class="btn" data-act="go" data-v="guide">How to use</button></div>
  </div>
  <div class="grid2s">
    <section class="panel pad stack g16"><div class="between"><span class="eyebrow">Latest scan</span><span class="mono small mute">${esc(r ? r.source : '')}</span></div>${latest}</section>
    <section class="panel flush"><div class="between" style="padding:14px 18px"><span class="eyebrow">Recent scans</span>${S.history.length ? '<button class="xs mute click-copy" data-act="clearHistory">Clear history</button>' : '<span class="small mute">this session</span>'}</div>${recent}</section>
  </div>
  <section class="stack g10"><span class="eyebrow">Same engine, other places</span><div class="cards">
    ${places.map(([t, c]) => `<div class="panel stack g8" style="padding:14px"><span style="font-weight:600">${t}</span><span class="mono small ink2" style="word-break:break-all;line-height:1.5">${esc(c)}</span></div>`).join('')}
  </div></section></div>`;
};

function chips(r) {
  const c = r.summary.by_status, sev = r.summary.gaps_by_severity;
  const out = [[c.absent + ' absent', SC.absent], [c.partial + ' partial', SC.partial], [c.present + ' present', SC.present], [c.not_applicable + ' n/a', 'var(--na)']]
    .concat(['critical', 'high', 'medium', 'low'].filter(k => sev[k]).map(k => [plural(sev[k], k + ' gap'), 'var(--mute)']));
  if (r.summary.controls_suppressed) out.push([r.summary.controls_suppressed + ' accepted', 'var(--mute)']);
  return `<div class="row g6">${out.map(([l, col]) => `<span class="chip" style="color:${col}">${esc(l)}</span>`).join('')}</div>`;
}

// ---------------------------------------------------------------- Scan
SCREENS.scan = () => {
  const m = S.meta;
  let left = '';
  if (S.source === 'sample') {
    left = `<p class="mute" style="font-size:12.5px">Eight labelled samples with known ground truth. <span class="mono">fastapi-secure-tasks</span> and <span class="mono">express-secure-notes</span> are the negative controls.</p>
    <div class="samples">${(m ? m.samples : []).map(s => `
      <button class="sample ${s.name === S.sample ? 'on' : ''}" data-act="sample" data-v="${esc(s.name)}" aria-pressed="${s.name === S.sample}">
        <div class="between" style="align-items:flex-start"><span class="mono sample-name">${esc(s.name)}</span>
          <span class="mono" style="font-weight:600;font-size:12px;color:${scoreColor(s.score)}">${s.score} ${esc(s.grade || '—')}</span></div>
        <span class="mute xs">${esc(s.framework || 'unknown')} · ${esc(s.language)} · ${esc(s.kind)}</span>
        <div class="bar" style="height:4px"><i style="width:${s.score}%;background:${scoreColor(s.score)}"></i></div></button>`).join('')}</div>`;
  } else if (S.source === 'folder') {
    left = `<label class="stack g8"><span class="small mute">Absolute path to a repository</span>
      <input class="field mono" data-bind="path" value="${esc(S.path)}" placeholder="C:\\Users\\you\\projects\\my-api" spellcheck="false"></label>
      <span class="small mute">Read-only. The folder is walked, indexed and matched; nothing in it is executed. Paths with spaces are fine.</span>`;
  } else {
    left = `<label class="drop" id="drop"><span style="font-weight:500">${S.zip ? esc(S.zip.name) : 'Drop a zipped project, or click to choose'}</span>
      <span class="small mute">A single top-level folder is unwrapped so relative paths stay correct. Extracted to a temporary folder and deleted after the scan.</span>
      <span class="mono xs mute">.zip only · up to 60 MB</span><input type="file" accept=".zip" data-bind="zip" hidden></label>`;
  }
  const where = S.source === 'sample' ? `corpus/samples/${S.sample}` : S.source === 'folder' ? (S.path ? `"${S.path}"` : '<path>') : (S.zip ? S.zip.name : '<zip>');
  const cli = `copilot scan ${where}` + (S.scope.length ? ` --category ${S.scope.join(',')}` : '') + (S.useConfig ? '' : ' --no-config');
  const ready = S.source === 'sample' || (S.source === 'folder' && S.path.trim()) || (S.source === 'zip' && S.zip);

  const scanBanner = S.scanning ? `
    <div class="scan-banner stack g12" role="status" aria-live="polite">
      <div class="between" style="align-items:center">
        <div class="row" style="gap:10px;align-items:center">
          <div class="scan-logo-anim"><i></i></div>
          <div class="stack" style="gap:2px">
            <div class="row" style="gap:8px;align-items:center">
              <span style="font-weight:600;font-size:14px">Scanning repository…</span>
              <span class="scan-step-dot"></span>
            </div>
            <span class="mono xs mute">${esc(where)}</span>
          </div>
        </div>
        <span class="mono xs" style="color:var(--accent);letter-spacing:.06em">SCANNING · 28 CONTROLS</span>
      </div>
      <div class="scan-progress-bar"></div>
      <div class="between mono xs mute" style="font-size:11px">
        <span>[1/3] indexing framework & routes</span>
        <span>[2/3] evaluating absent controls</span>
        <span>[3/3] computing posture score</span>
      </div>
    </div>` : '';

  return `<div class="page w1240"><div class="scangrid">
  <div class="stack g18" style="min-width:0">
    ${scanBanner}
    ${tabs([['sample', 'Corpus sample'], ['folder', 'Local folder'], ['zip', 'Upload a .zip']], S.source, 'source')}
    <div class="stack g10">${left}</div>
    ${S.error ? `<div class="error"><b>Scan failed.</b> ${esc(S.error)}${S.report ? ` The previous report (${esc(S.report.source)}) is kept.` : ''}</div>` : ''}
  </div>
  <div class="panel stack g16 sticky" style="padding:18px">
    <div class="stack g8"><span class="eyebrow">Scope · changes what is scored</span>
      <div class="row g6">${CATS.map(([c, t]) => `<button class="scopechip ${S.scope.includes(c) ? 'on' : ''}" data-act="scope" data-v="${c}" aria-pressed="${S.scope.includes(c)}">${t}</button>`).join('')}</div>
      <span class="xs mute">${S.scope.length ? `Grade withheld: ${S.scope.length} of 5 categories.` : 'Empty means all five, or the project .copilot.yaml. Narrowing withholds the grade.'}</span>
      ${check(S.useConfig, 'useConfig', 'Apply the project .copilot.yaml')}</div>
    <div class="stack g8"><span class="eyebrow">Display · never moves the score</span>
      ${tabs([['all', 'All'], ['critical', 'Critical'], ['high', 'High+'], ['medium', 'Medium+'], ['low', 'Low+']], S.minSev, 'minSev', 'seg fill')}
      ${check(S.showSat, 'showSat', 'Show satisfied controls')}</div>
    <div class="code">$ ${esc(cli)}</div>
    <button class="btn primary block" data-act="scan" ${ready && !S.scanning ? '' : 'disabled'}>${S.scanning ? '<span class="btn-spinner"></span>Scanning…' : 'Scan'}</button>
  </div></div></div>`;
};

// ---------------------------------------------------------------- persistence & actions
const LOCAL_SCANS = 'copilot_saved_reports';
function getSavedReports() {
  try { return JSON.parse(localStorage.getItem(LOCAL_SCANS) || '{}'); } catch(e) { return {}; }
}
function saveReport(r) {
  try {
    const all = getSavedReports();
    all[r.id] = r;
    const keys = Object.keys(all);
    if (keys.length > 20) delete all[keys[0]];
    localStorage.setItem(LOCAL_SCANS, JSON.stringify(all));
  } catch(e) {}
}

Object.assign(ACTIONS, {
  go: v => navigate(v),
  menu: () => { const open = !S.menu; if (!isNarrow()) store('menu', open ? 'open' : 'closed'); set({ menu: open }); },
  theme: v => { store('theme', v); set({ theme: v }); },
  source: v => set({ source: v, error: null }),
  sample: v => set({ sample: v, error: null }),
  scope: v => set({ scope: S.scope.includes(v) ? S.scope.filter(x => x !== v) : [...S.scope, v] }),
  useConfig: () => set({ useConfig: !S.useConfig }),
  minSev: v => set({ minSev: v }),
  statusFilter: v => set({ statusFilter: v }),
  fileFilter: v => set({ fileFilter: v }),
  detailTab: v => set({ detailTab: v }),
  routeFilter: v => set({ routeFilter: v }),
  showSat: () => set({ showSat: !S.showSat }),
  open: v => { set({ sel: v, query: '' }); navigate('report'); },
  copyCli: v => {
    navigator.clipboard.writeText(v).then(() => flash('CLI command copied'), () => flash('Copy failed'));
  },
  copyText: v => {
    navigator.clipboard.writeText(v).then(() => flash('Copied: ' + v), () => flash('Copy failed'));
  },
  clearHistory: () => {
    try { localStorage.removeItem(LOCAL_SCANS); } catch(e) {}
    set({ history: [] });
    flash('Session history cleared');
  },
  load: async v => {
    try {
      let rep;
      try { rep = await api('/api/report/' + v); } catch(err) {
        rep = getSavedReports()[v];
        if (!rep) throw err;
      }
      set({ report: rep, sel: null, routes: null, query: '', statusFilter: 'all', fileFilter: 'all' });
      navigate('report');
    } catch (e) { flash(e.message); }
  },
  scan: runScan,
});

async function runScan() {
  if (S.scanning) return;
  set({ scanning: true, error: null });
  const minDelay = new Promise(resolve => setTimeout(resolve, 500));
  try {
    const targetSource = S.source === 'sample' ? S.sample : S.source === 'folder' ? S.path : (S.zip ? S.zip.name : '');
    const prev = S.history.find(h => h.source === targetSource || (targetSource && h.source.endsWith(targetSource)));

    let scanPromise;
    if (S.source === 'zip') {
      const q = new URLSearchParams({ name: S.zip.name, categories: S.scope.join(','), use_config: S.useConfig ? '1' : '0' });
      scanPromise = api('/api/scan-zip?' + q, { method: 'POST', body: S.zip });
    } else {
      scanPromise = api('/api/scan', { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ kind: S.source === 'sample' ? 'sample' : 'folder', name: S.sample, path: S.path,
          categories: S.scope, use_config: S.useConfig }) });
    }
    const [report] = await Promise.all([scanPromise, minDelay]);
    if (prev) {
      const curGaps = report.findings.filter(f => f.is_gap).length;
      report.diff = {
        scoreDelta: report.summary.posture_score - prev.score,
        gapsDelta: prev.gaps - curGaps,
        prevScore: prev.score,
        prevGaps: prev.gaps
      };
    }
    saveReport(report);
    S.history = await api('/api/history');
    set({ report, sel: null, routes: null, scanning: false, screen: 'report', query: '', statusFilter: 'all', fileFilter: 'all' });
  } catch (e) {
    set({ scanning: false, error: e.message });
  }
}

async function navigate(screen) {
  set({ screen, menu: isNarrow() ? false : S.menu });
  window.scrollTo(0, 0);
  try {
    if (screen === 'rules' && !S.rules) set({ rules: await api('/api/rules') });
    if (screen === 'routes' && S.report && (!S.routes || S.routes.id !== S.report.id))
      set({ routes: Object.assign(await api('/api/routes/' + S.report.id), { id: S.report.id }) });
    if (screen === 'eval') await loadEval();
  } catch (e) { flash(e.message); }
}

document.addEventListener('click', e => {
  const el = e.target.closest('[data-act]');
  if (!el || el.disabled) return;
  const fn = ACTIONS[el.dataset.act];
  if (fn) { e.preventDefault(); fn(el.dataset.v); }
});
document.addEventListener('input', e => {
  const key = e.target.dataset && e.target.dataset.bind;
  if (!key || key === 'zip') return;
  if (key.startsWith('form.')) S.form[key.slice(5)] = e.target.value; else S[key] = e.target.value;
  render();
});
document.addEventListener('change', e => {
  if (e.target.dataset && e.target.dataset.bind === 'zip') set({ zip: e.target.files[0] || null, error: null });
  else if (e.target.dataset && e.target.dataset.bind === 'form.control') set({ form: { ...S.form, control: e.target.value } });
  else if (e.target.dataset && e.target.dataset.act === 'fileFilter') set({ fileFilter: e.target.value });
});
document.addEventListener('dragover', e => { if (e.target.closest('#drop')) { e.preventDefault(); e.target.closest('#drop').classList.add('over'); } });
document.addEventListener('drop', e => {
  if (!e.target.closest('#drop')) return;
  e.preventDefault();
  const f = e.dataTransfer.files[0];
  if (f && f.name.toLowerCase().endsWith('.zip')) set({ zip: f, error: null }); else flash('Only .zip files can be scanned.');
});

document.addEventListener('keydown', e => {
  if (e.key === 'Escape') {
    if (S.menu && isNarrow()) { set({ menu: false }); return; }
    if (S.query) { set({ query: '' }); return; }
  }
  const tag = (e.target && e.target.tagName) || '';
  if (tag === 'INPUT' || tag === 'SELECT' || tag === 'TEXTAREA') return;

  if (e.key === '/' && S.screen === 'report') {
    e.preventDefault();
    const qEl = document.querySelector('input[data-bind="query"]');
    if (qEl) qEl.focus();
    return;
  }

  if ((e.key === 'j' || e.key === 'ArrowDown' || e.key === 'k' || e.key === 'ArrowUp') && S.screen === 'report' && S.report && typeof shownFindings === 'function') {
    const list = shownFindings(S.report);
    if (!list.length) return;
    e.preventDefault();
    const curIdx = list.findIndex(f => f.control_id === S.sel);
    let nextIdx = 0;
    if (e.key === 'j' || e.key === 'ArrowDown') {
      nextIdx = curIdx >= 0 ? Math.min(list.length - 1, curIdx + 1) : 0;
    } else {
      nextIdx = curIdx > 0 ? curIdx - 1 : 0;
    }
    const nextId = list[nextIdx].control_id;
    ACTIONS.pick(nextId);
    const btn = document.querySelector(`button[data-act="pick"][data-v="${nextId}"]`);
    if (btn) btn.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
  }
});

window.matchMedia('(max-width: 900px)').addEventListener('change', e => set({ menu: !e.matches && store('menu') !== 'closed' }));
window.addEventListener('DOMContentLoaded', async () => {
  render();
  try {
    const [meta, history] = await Promise.all([api('/api/meta'), api('/api/history')]);
    set({ meta, history });
    if (history.length) {
      let rep;
      try { rep = await api('/api/report/' + history[0].id); }
      catch(e) { rep = getSavedReports()[history[0].id]; }
      if (rep) set({ report: rep });
    }
  } catch (e) { flash('Could not reach the local server: ' + e.message); }
});

