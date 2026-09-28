/* Defense Copilot web UI: state, API, shell, Home and Scan.
   report.js and tools.js add the other screens to SCREENS. Every value that
   comes from a scanned repository goes through esc() before it reaches HTML. */
'use strict';

const S = {
  screen: 'home', theme: store('theme') || 'light', menu: !isNarrow() || store('menu') === 'open',
  rail: store('rail') === 'true', meta: null, history: [], report: null,
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

function logoMark(size = 24) {
  return `<svg viewBox="0 0 32 32" fill="none" width="${size}" height="${size}" aria-hidden="true">
    <rect x="2" y="2" width="8" height="8" rx="2" fill="currentColor" fill-opacity="0.85"/>
    <rect x="12" y="2" width="8" height="8" rx="2" fill="currentColor" fill-opacity="0.85"/>
    <rect x="22" y="2" width="8" height="8" rx="2" fill="currentColor" fill-opacity="0.85"/>
    <rect x="2" y="12" width="8" height="8" rx="2" fill="currentColor" fill-opacity="0.85"/>
    <rect x="12" y="12" width="8" height="8" rx="2" fill="currentColor" fill-opacity="0.85"/>
    <rect x="22.75" y="12.75" width="6.5" height="6.5" rx="1.6" fill="var(--absent-tint)" stroke="var(--absent)" stroke-width="1.3" stroke-dasharray="2.5 1.5"/>
    <rect x="2" y="22" width="8" height="8" rx="2" fill="currentColor" fill-opacity="0.85"/>
    <rect x="12" y="22" width="8" height="8" rx="2" fill="currentColor" fill-opacity="0.85"/>
    <rect x="22" y="22" width="8" height="8" rx="2" fill="currentColor" fill-opacity="0.85"/>
  </svg>`;
}

const NAV_ICONS = {
  home: '<svg viewBox="0 0 24 24" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg>',
  scan: '<svg viewBox="0 0 24 24" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/><line x1="11" y1="8" x2="11" y2="14"/><line x1="8" y1="11" x2="14" y2="11"/></svg>',
  report: '<svg viewBox="0 0 24 24" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>',
  routes: '<svg viewBox="0 0 24 24" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="6" cy="18" r="3"/><circle cx="6" cy="6" r="3"/><circle cx="18" cy="6" r="3"/><path d="M6 9v6"/><path d="M9 6h6"/></svg>',
  accepted: '<svg viewBox="0 0 24 24" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/></svg>',
  rules: '<svg viewBox="0 0 24 24" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><line x1="4" y1="21" x2="4" y2="14"/><line x1="4" y1="10" x2="4" y2="3"/><line x1="12" y1="21" x2="12" y2="12"/><line x1="12" y1="8" x2="12" y2="3"/><line x1="20" y1="21" x2="20" y2="16"/><line x1="20" y1="12" x2="20" y2="3"/><line x1="1" y1="14" x2="7" y2="14"/><line x1="9" y1="8" x2="15" y2="8"/><line x1="17" y1="16" x2="23" y2="16"/></svg>',
  eval: '<svg viewBox="0 0 24 24" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>',
  how: '<svg viewBox="0 0 24 24" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>',
  guide: '<svg viewBox="0 0 24 24" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M2 3h6a4 4 0 0 1 4 4v14a3 3 0 0 0-3-3H2z"/><path d="M22 3h-6a4 4 0 0 0-4 4v14a3 3 0 0 1 3-3h7z"/></svg>',
};

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
  const nav = [
    ['home', 'Home', '', ''],
    ['scan', 'Scan', '', 'Target'],
    ['report', 'Report', gaps, ''],
    ['routes', 'Routes', '', ''],
    ['accepted', 'Accepted', r && r.summary.controls_suppressed ? r.summary.controls_suppressed : '', ''],
    ['rules', 'Rules', m ? m.controls : '', 'Tool'],
    ['eval', 'Evaluation', '', ''],
    ['how', 'How it works', '', ''],
    ['guide', 'Guide', '', 'Help']
  ];

  const latestCard = r ? `
    <button class="side-latest" data-act="go" data-v="report" title="Open latest report: ${esc(r.source)}">
      <div class="side-latest-full stack g4">
        <div class="side-latest-header">
          <span class="side-latest-target">${esc(r.source)}</span>
          <span class="side-latest-score mono" style="color:${scoreColor(r.summary.posture_score)}">${r.summary.posture_score} <span class="xs mute">${r.summary.grade || '—'}</span></span>
        </div>
        <div class="side-mini-bar"><i style="width:${r.summary.posture_score}%;background:${scoreColor(r.summary.posture_score)}"></i></div>
        <div class="side-latest-meta">
          <span>${plural(gaps, 'gap')}</span>
          <span>${r.summary.controls_scored} scored</span>
        </div>
      </div>
      <div class="side-latest-compact">
        <span class="mono xs" style="font-weight:500;color:${scoreColor(r.summary.posture_score)}">${r.summary.posture_score}</span>
        <span class="mono xs mute">${r.summary.grade || '—'}</span>
      </div>
    </button>` : `
    <div class="side-latest" style="cursor:default">
      <div class="side-latest-full">
        <span class="side-latest-empty">No scan yet</span>
      </div>
      <div class="side-latest-compact">
        <span class="mono xs mute">—</span>
      </div>
    </div>`;

  return `<aside class="side" id="side" aria-label="Main menu"${isNarrow() && !S.menu ? ' inert' : ''}>
  <div class="side-header">
    <button class="brand" data-act="go" data-v="home" title="Defense Copilot">
      <span class="brand-mark">${logoMark(26)}</span>
      <div class="brand-text">
        <b>Defense Copilot</b>
        <span>v${esc(m ? m.version : '0.1.0')} · ${m ? m.controls : '28'} controls</span>
      </div>
    </button>
    <button class="rail-toggle" data-act="toggleRail" aria-label="${S.rail ? 'Expand sidebar' : 'Collapse to rail'}" title="${S.rail ? 'Expand sidebar' : 'Collapse to rail'}">
      ${S.rail ?
        '<svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" fill="none" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2"/><line x1="9" y1="3" x2="9" y2="21"/><path d="M14 10l2 2-2 2"/></svg>' :
        '<svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" fill="none" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2"/><line x1="9" y1="3" x2="9" y2="21"/><path d="M16 10l-2 2 2 2"/></svg>'
      }
    </button>
  </div>
  <nav aria-label="Screens">${nav.map(([k, l, b, h]) => `${h ? `<div class="navhead">${h}</div>` : ''}
    <button class="navbtn ${S.screen === k ? 'on' : ''}" data-act="go" data-v="${k}" ${S.screen === k ? 'aria-current="page"' : ''} title="${l}">
      <span class="navbtn-main">
        <span class="nav-icon">${NAV_ICONS[k] || ''}</span>
        <span class="nav-label">${l}</span>
      </span>
      <span class="badge">${esc(b)}</span>
    </button>`).join('')}</nav>
  ${latestCard}
  <div class="sidefoot">
    <button class="rail-btn" data-act="toggleRail" aria-label="${S.rail ? 'Expand sidebar' : 'Collapse sidebar'}" title="${S.rail ? 'Expand sidebar' : 'Collapse sidebar'}">
      <span class="rail-icon">
        ${S.rail ?
          '<svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" fill="none" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2"/><line x1="9" y1="3" x2="9" y2="21"/><path d="M14 10l2 2-2 2"/></svg>' :
          '<svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" fill="none" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2"/><line x1="9" y1="3" x2="9" y2="21"/><path d="M16 10l-2 2 2 2"/></svg>'
        }
      </span>
      <span class="rail-text">${S.rail ? 'Expand' : 'Collapse sidebar'}</span>
    </button>
    <span class="sidefoot-note">static analysis · offline</span>
  </div>
</aside>`;
}

function topbar() {
  const r = S.report;
  const dl = S.screen === 'report' && r ? `<div class="dl">${[['html', 'HTML'], ['json', 'JSON'], ['sarif', 'SARIF'], ['md', 'Markdown']]
    .map(([f, l]) => `<a href="/api/export/${esc(r.id)}?format=${f}" download>${l}</a>`).join('')}</div>` : '';
  const themes = `<div class="theme-toggle" role="group" aria-label="Theme">
    <button class="${S.theme === 'light' ? 'on' : ''}" data-act="theme" data-v="light">Light</button>
    <span class="mute">/</span>
    <button class="${S.theme === 'dark' ? 'on' : ''}" data-act="theme" data-v="dark">Dark</button>
  </div>`;
  const burger = `<button class="burger" data-act="menu" aria-controls="side" aria-expanded="${S.menu}" aria-label="${S.menu ? 'Close' : 'Open'} menu"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true">${S.menu && isNarrow() ? '<path d="M6 6l12 12M18 6L6 18"/>' : '<path d="M4 7h16M4 12h16M4 17h16"/>'}</svg></button>`;

  return `<header class="top">
    <div class="title">${burger}<b>${TITLES[S.screen]}</b></div>
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
  app.className = 'shell ' + (S.menu ? 'menu-open' : 'menu-closed') + (S.rail ? ' rail' : '');
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
      ${r.diff.scoreDelta > 0 ? '▲ +' : r.diff.scoreDelta < 0 ? '▼ ' : '= '}${r.diff.scoreDelta} pts vs prev
    </span>` : '';
  const latest = r ? `
    <div class="row" style="gap:16px;align-items:baseline">
      <span class="score-num" style="font-size:64px;color:${scoreColor(r.summary.posture_score)}">${r.summary.posture_score}</span>
      <div class="stack g4">
        <div class="row g8" style="align-items:center"><span class="score-grade" style="font-size:16px">${gradeText(r)}</span>${trend}</div>
        <span class="mute xs">${plural(gaps.length ? r.findings.filter(f => f.is_gap).length : 0, 'gap')} · ${r.summary.controls_scored} of ${r.summary.controls_evaluated} controls scored</span>
      </div>
    </div>
    ${chips(r)}
    <div class="stack g4" style="border-top:1px solid var(--line);padding-top:var(--s-12);margin-top:var(--s-8)">
      <span class="lbl">Fix first</span>
      ${gaps.map(f => `<button class="listrow" style="grid-template-columns:16px 84px minmax(0,1fr) 60px;padding:8px 0" data-act="open" data-v="${esc(f.control_id)}">
        <span class="status-dot ${f.status}"></span>
        <span class="mono xs mute">${esc(f.control_id)}</span>
        <span class="clip">${esc(f.control_name)}</span>
        <span class="xs mute" style="text-align:right;${f.severity === 'critical' ? 'color:var(--absent);font-weight:500' : ''}">${esc(f.severity)}</span>
      </button>`).join('') || '<span class="xs mute" style="padding:var(--s-8) 0">No open gaps.</span>'}
    </div>` : `<p class="mute" style="font-size:13.5px">No scan yet this session. Pick a bundled sample, a folder on this machine, or a .zip.</p>`;

  const recent = S.history.length ? `
    <div class="stack">
      ${S.history.map(h => `
        <button class="listrow" style="grid-template-columns:minmax(0,1fr) 70px 40px;padding:10px 16px;${r && h.id === r.id ? 'background:var(--sunk)' : ''}" data-act="load" data-v="${esc(h.id)}">
          <div class="stack" style="min-width:0">
            <span class="mono clip" style="font-size:12.5px">${esc(h.source)}</span>
            <span class="mute xs">${esc(h.framework || 'unknown')} · ${plural(h.gaps, 'gap')} · ${new Date(h.scanned_at).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})}</span>
          </div>
          <div class="bar"><i style="width:${h.score}%;background:${scoreColor(h.score)}"></i></div>
          <span class="mono" style="font-size:12.5px;font-weight:500;text-align:right;color:${scoreColor(h.score)}">${h.score}</span>
        </button>`).join('')}
    </div>` : '<p class="mute xs" style="padding:16px">Nothing yet. Scans stay here until the server stops; download a report to keep one.</p>';

  const previewSegs = [
    'absent', 'absent', 'absent', 'absent', 'absent', 'absent', 'absent', 'absent', 'absent', 'absent', 'absent', 'absent', 'absent',
    'partial', 'partial',
    'present', 'present', 'present', 'present', 'present', 'present', 'present',
    'na', 'na', 'na', 'na', 'na', 'na'
  ];

  const places = [
    {
      title: 'CLI',
      cmd: 'copilot scan ./repo --fail-on critical',
      tileClass: 'tile-cli',
      icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="4 17 10 12 4 7"/><line x1="12" y1="19" x2="20" y2="19"/></svg>'
    },
    {
      title: 'GitHub Action',
      cmd: 'uses: sidhant223/ai-cyber-defense-copilot@main',
      tileClass: 'tile-gh',
      icon: '<svg viewBox="0 0 24 24" fill="currentColor"><path fill-rule="evenodd" clip-rule="evenodd" d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.53 1.032 1.53 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z"/></svg>'
    },
    {
      title: 'Pre-commit',
      cmd: 'hooks: [{id: copilot-scan}]',
      tileClass: 'tile-pre',
      icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="3"/><line x1="3" y1="12" x2="9" y2="12"/><line x1="15" y1="12" x2="21" y2="12"/><circle cx="3" cy="12" r="1" fill="currentColor"/><circle cx="21" cy="12" r="1" fill="currentColor"/></svg>'
    },
    {
      title: 'Docker',
      cmd: 'docker run --rm -v "$PWD:/repo:ro" copilot scan .',
      tileClass: 'tile-docker',
      icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="7" width="2" height="2"/><rect x="5" y="7" width="2" height="2"/><rect x="8" y="7" width="2" height="2"/><rect x="5" y="4" width="2" height="2"/><rect x="8" y="4" width="2" height="2"/><rect x="11" y="4" width="2" height="2"/><rect x="11" y="7" width="2" height="2"/><rect x="14" y="7" width="2" height="2"/><path d="M1 10.5h18c.5 0 2.5 0 3.5-1.5 0 0 .5 3.5-3 5-2 1-4.5 1-7.5 1-4 0-7.5-1-9-3l-2-1.5z"/></svg>'
    }
  ];

  return `<div class="page w1140">
  <div class="hero-wrap">
    <div class="stack g12 hero">
      <div class="hero-pill">Static analysis · runs offline · 28 controls</div>
      <h1 class="hero-headline">Which security controls are <span class="hero-hl">missing</span> from your code?</h1>
      <p class="hero-sub">A linter finds bad code that exists. This finds good code that should exist and doesn’t: no auth on a route, no rate limit on a login endpoint, a secret sitting in plaintext.</p>
      <div class="hero-actions">
        <button class="btn primary btn-hero" data-act="go" data-v="scan">New scan <span class="arrow">→</span></button>
        <button class="btn btn-hero" data-act="go" data-v="report" ${r ? '' : 'disabled'}>Open latest report</button>
        <button class="btn-text btn-hero-link" data-act="go" data-v="guide">How to use</button>
      </div>
    </div>
    <div class="hero-preview-container">
      <div class="hero-dot-bg"></div>
      <div class="hero-glow"></div>
      <div class="hero-preview-card" data-act="sample" data-v="flask-notes-app" title="Inspect sample repository: flask-notes-app">
        <div class="hero-preview-top">
          <div class="stack g4">
            <span class="lbl">Live preview</span>
            <span class="hero-preview-target">flask-notes-app</span>
          </div>
          <div>
            <span class="hero-preview-score">46</span>
            <span class="hero-preview-grade">F</span>
          </div>
        </div>
        <div class="preview-bar" aria-label="Segmented score bar preview" title="13 absent, 2 partial, 7 present, 6 n/a">
          ${previewSegs.map((st, i) => `<span class="preview-seg ${st}" style="--i:${i}"></span>`).join('')}
        </div>
        <div class="hero-preview-findings">
          <div class="hero-preview-row">
            <span class="status-dot absent"></span>
            <span class="clip"><b class="mono xs">AUTH-001</b> No auth on write routes</span>
            <span class="hero-preview-badge" style="color:var(--absent)">critical</span>
          </div>
          <div class="hero-preview-row">
            <span class="status-dot absent"></span>
            <span class="clip"><b class="mono xs">RATE-001</b> No rate limit on login endpoint</span>
            <span class="hero-preview-badge" style="color:var(--partial)">high</span>
          </div>
          <div class="hero-preview-row">
            <span class="status-dot partial"></span>
            <span class="clip"><b class="mono xs">SEC-002</b> Plaintext credentials in config</span>
            <span class="hero-preview-badge mute">medium</span>
          </div>
        </div>
      </div>
    </div>
  </div>

  <div class="grid2s">
    <section class="panel stack g16">
      <div class="between"><span class="lbl">Latest scan</span><span class="mono xs mute">${esc(r ? r.source : '')}</span></div>
      ${latest}
    </section>
    <section class="panel flush stack">
      <div class="between" style="padding:16px;border-bottom:1px solid var(--line)">
        <span class="lbl">Recent scans</span>
        ${S.history.length ? '<button class="click-copy xs mute" data-act="clearHistory">Clear history</button>' : '<span class="xs mute">this session</span>'}
      </div>
      ${recent}
    </section>
  </div>

  <section class="stack g12">
    <span class="lbl">Same engine, other places</span>
    <div class="cards">
      ${places.map(p => `
        <div class="place-card">
          <div class="place-card-head">
            <div class="place-icon-tile ${p.tileClass}">${p.icon}</div>
            <span class="place-title">${esc(p.title)}</span>
          </div>
          <div class="place-cmd-wrap">
            <span class="place-cmd-text mono">${esc(p.cmd)}</span>
            <button class="cmd-copy-btn" data-act="copyCmd" data-v="${esc(p.cmd)}" title="Copy command">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
              <span>Copy</span>
            </button>
          </div>
        </div>
      `).join('')}
    </div>
  </section></div>`;
};

function chips(r) {
  const c = r.summary.by_status, sev = r.summary.gaps_by_severity;
  const out = [
    [c.absent + ' absent', 'absent'],
    [c.partial + ' partial', 'partial'],
    [c.present + ' present', 'present'],
    [c.not_applicable + ' n/a', 'na']
  ].concat(['critical', 'high', 'medium', 'low'].filter(k => sev[k]).map(k => [plural(sev[k], k + ' gap'), k]));
  if (r.summary.controls_suppressed) out.push([r.summary.controls_suppressed + ' accepted', 'accepted']);
  return `<div class="row g8">${out.map(([l, cls]) => `<span class="chip ${cls}">${esc(l)}</span>`).join('')}</div>`;
}

// ---------------------------------------------------------------- Scan
SCREENS.scan = () => {
  const m = S.meta;
  let left = '';
  if (S.source === 'sample') {
    left = `<p class="mute" style="font-size:13px;margin-bottom:var(--s-12)">Eight labelled samples with known ground truth. <span class="mono">fastapi-secure-tasks</span> and <span class="mono">express-secure-notes</span> are the negative controls.</p>
    <div class="samples">${(m ? m.samples : []).map(s => `
      <button class="sample ${s.name === S.sample ? 'on' : ''}" data-act="sample" data-v="${esc(s.name)}" aria-pressed="${s.name === S.sample}">
        <div class="between" style="align-items:flex-start">
          <span class="mono sample-name">${esc(s.name)}</span>
          <span class="mono" style="font-weight:500;font-size:12.5px;color:${scoreColor(s.score)}">${s.score} ${esc(s.grade || '—')}</span>
        </div>
        <span class="mute xs">${esc(s.framework || 'unknown')} · ${esc(s.language)} · ${esc(s.kind)}</span>
        <div class="bar"><i style="width:${s.score}%;background:${scoreColor(s.score)}"></i></div>
      </button>`).join('')}</div>`;
  } else if (S.source === 'folder') {
    left = `<div class="stack g16">
      <label class="stack g8">
        <span style="font-size:13px;font-weight:500">Absolute path to repository</span>
        <input class="field mono" data-bind="path" value="${esc(S.path)}" placeholder="C:\\Users\\you\\projects\\my-api" spellcheck="false">
      </label>
      <span class="xs mute">Read-only. The folder is walked, indexed and matched; nothing in it is executed. Paths with spaces are fine.</span>
    </div>`;
  } else {
    left = `<label class="drop" id="drop">
      <span style="font-weight:500;font-size:14px">${S.zip ? esc(S.zip.name) : 'Drop a zipped project, or click to choose'}</span>
      <span class="xs mute">A single top-level folder is unwrapped so relative paths stay correct. Extracted to a temporary folder and deleted after the scan.</span>
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
        <span style="font-size:16px;font-weight:500">Scanning repository…</span>
        <span class="mono xs mute">${esc(where)}</span>
      </div>
      <div class="bar"><i style="width:70%"></i></div>
      <div class="between mono xs mute">
        <span>[1/3] indexing framework & routes</span>
        <span>[2/3] evaluating absent controls</span>
        <span>[3/3] computing posture score</span>
      </div>
    </div>` : '';

  return `<div class="page w1100">
  <div class="between" style="align-items:baseline">
    <h1 style="font-size:28px;font-weight:500;margin:0">Scan a Repository</h1>
    <span class="mono xs mute">28 controls · static AST + regex</span>
  </div>
  <div class="scangrid">
    <div class="stack g20" style="min-width:0">
      ${scanBanner}
      ${tabs([['sample', 'Corpus sample'], ['folder', 'Local folder'], ['zip', 'Upload a .zip']], S.source, 'source')}
      <div class="stack g16">${left}</div>
      ${S.error ? `<div class="error"><b>Scan failed.</b> ${esc(S.error)}${S.report ? ` The previous report (${esc(S.report.source)}) is kept.` : ''}</div>` : ''}
    </div>
    <div class="panel sticky stack g20">
      <div class="stack g8">
        <span class="lbl">Scope · changes what is scored</span>
        <div class="row g6">${CATS.map(([c, t]) => `<button class="scopechip ${S.scope.includes(c) ? 'on' : ''}" data-act="scope" data-v="${c}" aria-pressed="${S.scope.includes(c)}">${t}</button>`).join('')}</div>
        <span class="xs mute">${S.scope.length ? `Grade withheld: ${S.scope.length} of 5 categories.` : 'Empty means all five, or the project .copilot.yaml. Narrowing withholds the grade.'}</span>
        ${check(S.useConfig, 'useConfig', 'Apply the project .copilot.yaml')}
      </div>
      <div class="stack g8">
        <span class="lbl">Display · never moves the score</span>
        ${tabs([['all', 'All'], ['critical', 'Critical'], ['high', 'High+'], ['medium', 'Medium+'], ['low', 'Low+']], S.minSev, 'minSev')}
        ${check(S.showSat, 'showSat', 'Show satisfied controls')}
      </div>
      <div class="code">$ ${esc(cli)}</div>
      <div><button class="btn primary" data-act="scan" ${ready && !S.scanning ? '' : 'disabled'}>${S.scanning ? 'Scanning…' : 'Scan repository'}</button></div>
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
  menu: () => {
    if (isNarrow()) {
      const open = !S.menu;
      store('menu', open ? 'open' : 'closed');
      set({ menu: open });
    } else {
      const next = !S.rail;
      store('rail', next);
      set({ rail: next });
    }
  },
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
  toggleRail: () => {
    const next = !S.rail;
    store('rail', next);
    set({ rail: next });
  },
  copyCmd: (v, btnEl) => {
    navigator.clipboard.writeText(v).then(() => {
      flash('Copied: ' + v);
      if (btnEl) {
        btnEl.classList.add('copied');
        const span = btnEl.querySelector('span');
        if (span) span.textContent = 'Copied';
        setTimeout(() => {
          btnEl.classList.remove('copied');
          if (span) span.textContent = 'Copy';
        }, 1500);
      }
    }, () => flash('Copy failed'));
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
  set({ screen, menu: isNarrow() ? false : true });
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
  if (fn) { e.preventDefault(); fn(el.dataset.v, el); }
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

