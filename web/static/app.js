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
  <button class="brand" data-act="go" data-v="home">
    <div><b>Defense Copilot</b><span style="display:block;margin-top:2px">v${esc(m ? m.version : '')} · ${m ? m.controls : ''} controls</span></div>
  </button>
  <nav aria-label="Screens">${nav.map(([k, l, b, h]) => `${h ? `<div class="navhead">${h}</div>` : ''}
    <button class="navbtn ${S.screen === k ? 'on' : ''}" data-act="go" data-v="${k}" ${S.screen === k ? 'aria-current="page"' : ''}>
      <span>${l}</span><span class="badge">${esc(b)}</span></button>`).join('')}</nav>
  <div class="sidefoot"><span>static analysis · no network · runs nothing · rule-based guidance</span></div>
</aside>`;
}

function topbar() {
  const r = S.report;
  const gaps = r ? r.findings.filter(f => f.is_gap).length : 0;
  const cli = { report: r && cliFor(r), routes: r && `copilot routes ${r.source}`, accepted: '.copilot.yaml',
    rules: 'copilot rules list', eval: evalView() === 'project' ? (r && `copilot scan ${r.source} --format json`) : `copilot evaluate --split ${S.split}` }[S.screen];
  const dl = S.screen === 'report' && r ? `<div class="dl">${[['html', 'HTML'], ['json', 'JSON'], ['sarif', 'SARIF'], ['md', 'Markdown']]
    .map(([f, l]) => `<a href="/api/export/${esc(r.id)}?format=${f}" download>${l}</a>`).join('')}</div>` : '';
  const themes = `<div class="theme-text-toggle" role="group" aria-label="Theme">
    <button class="${S.theme === 'light' ? 'on' : ''}" data-act="theme" data-v="light">Light</button>
    <span class="mute">/</span>
    <button class="${S.theme === 'dark' ? 'on' : ''}" data-act="theme" data-v="dark">Dark</button>
  </div>`;
  const burger = `<button class="burger" data-act="menu" aria-controls="side" aria-expanded="${S.menu}" aria-label="${S.menu ? 'Close' : 'Open'} menu"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true">${S.menu && isNarrow() ? '<path d="M6 6l12 12M18 6L6 18"/>' : '<path d="M4 7h16M4 12h16M4 17h16"/>'}</svg></button>`;
  const cliBtn = cli ? `<button class="click-copy" data-act="copyCli" data-v="${esc(cli)}" title="Click to copy CLI command" style="font:12px var(--mono);color:var(--mute);padding:3px 0;display:inline-flex;align-items:center;gap:6px">$ ${esc(cli)}</button>` : '';
  const targetMeta = r ? `<span class="target-meta">Target: <span class="highlight">${esc(r.source)}</span> · <span class="highlight">${r.summary.posture_score} ${gradeText(r)}</span>${gaps ? ` · <span class="gaps-flag">${plural(gaps, 'gap')}</span>` : ''}</span>` : '';

  return `<header class="top">
    <div class="title">
      ${burger}<b>${TITLES[S.screen]}</b>
      ${targetMeta}
      ${cliBtn}
    </div>
    <div class="actions">${dl}${themes}</div>
  </header>`;
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
    <span class="mono xs ${r.diff.scoreDelta > 0 ? 'mute' : 'gaps-flag'}" title="Previous score: ${r.diff.prevScore}">
      ${r.diff.scoreDelta > 0 ? '+' : ''}${r.diff.scoreDelta} pts vs prev
    </span>` : '';
  const latest = r ? `
    <div class="score-editorial">
      <span class="score-num">${r.summary.posture_score}</span>
      <div class="score-meta">
        <div class="row g8" style="align-items:center"><span class="grade-label">${gradeText(r)}</span>${trend}</div>
        <span class="mute xs">${plural(gaps.length ? r.findings.filter(f => f.is_gap).length : 0, 'gap')} · ${r.summary.controls_scored} of ${r.summary.controls_evaluated} scored</span>
      </div>
    </div>
    ${chips(r)}
    <div class="hairline-list" style="margin-top:var(--s-16)">
      <div class="section-title" style="padding-bottom:var(--s-8)">Fix first</div>
      ${gaps.map(f => `<button class="hairline-row" data-act="open" data-v="${esc(f.control_id)}">
        <div class="row g8" style="min-width:0;flex:1">
          <span class="status-dot ${f.status}"></span>
          <span class="mono xs mute">${esc(f.control_id)}</span>
          <span class="clip ink">${esc(f.control_name)}</span>
        </div>
        <span class="xs mute ${f.severity === 'critical' ? 'gaps-flag' : ''}">${esc(f.severity)}</span>
      </button>`).join('') || '<span class="small mute" style="padding:var(--s-8) 0">No open gaps.</span>'}
    </div>` : `<p class="mute">No scan yet this session. Pick a bundled sample, a folder on this machine, or a .zip.</p>`;
  const recent = S.history.length ? `
    <div class="hairline-list">
      ${S.history.map(h => `
        <button class="hairline-row" data-act="load" data-v="${esc(h.id)}" style="${r && h.id === r.id ? 'font-weight:600' : ''}">
          <div class="stack" style="min-width:0">
            <span class="mono clip" style="font-size:13px">${esc(h.source)}</span>
            <span class="mute xs">${esc(h.framework || 'unknown')} · ${plural(h.gaps, 'gap')} · ${new Date(h.scanned_at).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})}</span>
          </div>
          <span class="mono" style="font-size:13px">${h.score}</span>
        </button>`).join('')}
    </div>` : '<p class="mute small">Nothing yet. Scans stay here until the server stops; download a report to keep one.</p>';
  const places = [['CLI', 'copilot scan ./repo --fail-on critical'], ['GitHub Action', 'uses: sidhant223/ai-cyber-defense-copilot@main'],
    ['Pre-commit', 'hooks: [{id: copilot-scan}]'], ['Docker', 'docker run --rm -v "$PWD:/repo:ro" copilot scan .']];
  return `<div class="page w1100">
  <div class="stack g16 hero">
    <h1 class="home-headline">Which security controls are missing from your code?</h1>
    <p class="home-sub">A linter finds bad code that exists. This finds good code that should exist and doesn’t: no auth on a route, no rate limit on a login endpoint, a secret sitting in plaintext.</p>
    <div class="home-actions">
      <button class="btn-solid" data-act="go" data-v="scan">New scan</button>
      <button class="btn-text" data-act="go" data-v="report" ${r ? '' : 'disabled'}>Open latest report</button>
      <button class="btn-text" data-act="go" data-v="guide">How to use</button>
    </div>
  </div>
  <div class="home-grid">
    <section class="editorial-section">
      <div class="section-title">Latest scan</div>
      <div class="hairline"></div>
      ${latest}
    </section>
    <section class="editorial-section">
      <div class="between" style="align-items:center">
        <span class="section-title">Recent scans</span>
        ${S.history.length ? '<button class="btn-text xs mute" data-act="clearHistory">Clear history</button>' : '<span class="xs mute">this session</span>'}
      </div>
      <div class="hairline"></div>
      ${recent}
    </section>
  </div>
  <section class="editorial-section" style="margin-top:var(--s-24)">
    <div class="section-title">Same engine, other places</div>
    <div class="hairline"></div>
    <div class="places-list">
      ${places.map(([t, c]) => `
        <div class="place-row">
          <span class="place-name">${esc(t)}</span>
          <span class="place-cmd mono">${esc(c)}</span>
        </div>
      `).join('')}
    </div>
  </section></div>`;
};

function chips(r) {
  const c = r.summary.by_status;
  const gapCount = (c.absent || 0) + (c.partial || 0);
  return `<div class="chips-line" style="margin-top:var(--s-8)">
    ${gapCount ? `<span class="gap-count">${plural(gapCount, 'gap')}</span>` : '0 gaps'} ·
    ${c.absent ? `<span class="gap-count">${c.absent} absent</span>` : '0 absent'} ·
    ${c.partial ? `<span class="gap-count">${c.partial} partial</span>` : '0 partial'} ·
    <b>${c.present}</b> present ·
    ${c.not_applicable} n/a
    ${r.summary.controls_suppressed ? ` · ${r.summary.controls_suppressed} accepted` : ''}
  </div>`;
}

// ---------------------------------------------------------------- Scan
SCREENS.scan = () => {
  const m = S.meta;
  let left = '';
  if (S.source === 'sample') {
    left = `<p class="mute small" style="margin-bottom:var(--s-8)">Eight labelled samples with known ground truth. <span class="mono">fastapi-secure-tasks</span> and <span class="mono">express-secure-notes</span> are the negative controls.</p>
    <div class="samples-table">${(m ? m.samples : []).map(s => `
      <button class="sample-row ${s.name === S.sample ? 'on' : ''}" data-act="sample" data-v="${esc(s.name)}" aria-pressed="${s.name === S.sample}">
        <div class="stack" style="min-width:0;flex:1">
          <span class="mono" style="font-weight:500;font-size:13.5px">${esc(s.name)}</span>
          <span class="sample-meta">${esc(s.framework || 'unknown')} · ${esc(s.language)} · ${esc(s.kind)}</span>
        </div>
        <div class="row g16" style="align-items:baseline">
          <span class="mono" style="font-size:13px;font-weight:600">${s.score}</span>
          <span class="serif mute" style="font-style:italic;font-size:15px;min-width:20px;text-align:right">${esc(s.grade || '—')}</span>
        </div>
      </button>`).join('')}</div>`;
  } else if (S.source === 'folder') {
    left = `<div class="stack g16">
      <label class="stack g8">
        <span class="section-title">Absolute path to repository</span>
        <input class="field mono" data-bind="path" value="${esc(S.path)}" placeholder="C:\\Users\\you\\projects\\my-api" spellcheck="false">
      </label>
      <span class="small mute">Read-only. The folder is walked, indexed and matched; nothing in it is executed. Paths with spaces are fine.</span>
    </div>`;
  } else {
    left = `<label class="drop" id="drop">
      <span style="font-weight:500;font-size:14px">${S.zip ? esc(S.zip.name) : 'Drop a zipped project, or click to choose'}</span>
      <span class="small mute">A single top-level folder is unwrapped so relative paths stay correct. Extracted to a temporary folder and deleted after the scan.</span>
      <span class="mono xs mute">.zip only · up to 60 MB</span>
      <input type="file" accept=".zip" data-bind="zip" hidden>
    </label>`;
  }
  const where = S.source === 'sample' ? `corpus/samples/${S.sample}` : S.source === 'folder' ? (S.path ? `"${S.path}"` : '<path>') : (S.zip ? S.zip.name : '<zip>');
  const cli = `copilot scan ${where}` + (S.scope.length ? ` --category ${S.scope.join(',')}` : '') + (S.useConfig ? '' : ' --no-config');
  const ready = S.source === 'sample' || (S.source === 'folder' && S.path.trim()) || (S.source === 'zip' && S.zip);

  const scanBanner = S.scanning ? `
    <div class="scan-banner stack g8" role="status" aria-live="polite">
      <div class="between" style="align-items:baseline">
        <span style="font-family:var(--serif);font-size:18px">Scanning repository…</span>
        <span class="mono xs mute">${esc(where)}</span>
      </div>
      <div class="hairline-progress"><div class="hairline-progress-fill" style="width:70%"></div></div>
      <div class="between mono xs mute">
        <span>[1/3] indexing framework & routes</span>
        <span>[2/3] evaluating absent controls</span>
        <span>[3/3] computing posture score</span>
      </div>
    </div>` : '';

  return `<div class="page w1100">
  <div class="between" style="align-items:baseline">
    <h1 class="serif" style="font-size:32px;margin:0">Scan a Repository</h1>
    <span class="mono xs mute">28 controls · static AST + regex</span>
  </div>
  <div class="hairline"></div>
  <div class="scangrid">
    <div class="stack g24" style="min-width:0">
      ${scanBanner}
      ${tabs([['sample', 'Corpus sample'], ['folder', 'Local folder'], ['zip', 'Upload a .zip']], S.source, 'source')}
      <div class="stack g16">${left}</div>
      ${S.error ? `<div class="error"><b>Scan failed.</b> ${esc(S.error)}${S.report ? ` The previous report (${esc(S.report.source)}) is kept.` : ''}</div>` : ''}
    </div>
    <div class="editorial-section sticky" style="gap:var(--s-24)">
      <div class="stack g8">
        <span class="section-title">Scope · changes what is scored</span>
        <div class="row g6">${CATS.map(([c, t]) => `<button class="scopechip ${S.scope.includes(c) ? 'on' : ''}" data-act="scope" data-v="${c}" aria-pressed="${S.scope.includes(c)}">${t}</button>`).join('')}</div>
        <span class="xs mute">${S.scope.length ? `Grade withheld: ${S.scope.length} of 5 categories.` : 'Empty means all five, or the project .copilot.yaml. Narrowing withholds the grade.'}</span>
        ${check(S.useConfig, 'useConfig', 'Apply the project .copilot.yaml')}
      </div>
      <div class="stack g8">
        <span class="section-title">Display · never moves the score</span>
        ${tabs([['all', 'All'], ['critical', 'Critical'], ['high', 'High+'], ['medium', 'Medium+'], ['low', 'Low+']], S.minSev, 'minSev')}
        ${check(S.showSat, 'showSat', 'Show satisfied controls')}
      </div>
      <div class="code">$ ${esc(cli)}</div>
      <button class="btn-solid block" data-act="scan" ${ready && !S.scanning ? '' : 'disabled'}>${S.scanning ? 'Scanning…' : 'Scan'}</button>
    </div>
  </div></div>`;
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

