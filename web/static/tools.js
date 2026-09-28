/* Routes, Accepted, Rules, Evaluation, How it works. */
'use strict';

// ---------------------------------------------------------------- Routes
SCREENS.routes = () => {
  const r = S.report;
  if (!r) return emptyNeedScan('The route inventory reads the current scan.');
  if (!S.routes || S.routes.id !== r.id) return '<div class="page"><span class="mute">Loading routes…</span></div>';
  const { columns, rows } = S.routes;
  if (!rows.length) return `<div class="page w1100"><div class="dashed"><span style="font-weight:500">No route handlers found</span>
    <span class="mute" style="font-size:12.5px">The route-shaped controls found no subjects in ${esc(r.source)}, so there is no attack surface table to show.</span></div></div>`;

  const count = (col, v) => rows.filter(x => x.columns[col] === v).length;
  const unprotCount = rows.filter(x => x.unprotected).length;
  const noAuthCount = count('auth', 'no');
  const noRoleCount = count('role check', 'no');
  const noRateCount = count('rate limit', 'no');

  const stats = [
    ['routes found', rows.length, 'var(--ink)'],
    ['unprotected', unprotCount, unprotCount ? 'var(--accent)' : 'var(--mute)'],
    ['unauthenticated', noAuthCount, noAuthCount ? 'var(--accent)' : 'var(--mute)'],
    ['admin without role check', noRoleCount, noRoleCount ? 'var(--accent)' : 'var(--mute)'],
    ['credential routes rate limited', count('rate limit', 'yes'), 'var(--ink)']
  ];

  const q = (S.routeQuery || '').trim().toLowerCase();
  const shown = rows.filter(x => {
    if (S.routeFilter === 'unprot' && !x.unprotected) return false;
    if (S.routeFilter === 'no-auth' && x.columns['auth'] !== 'no') return false;
    if (S.routeFilter === 'no-role' && x.columns['role check'] !== 'no') return false;
    if (S.routeFilter === 'no-rate' && x.columns['rate limit'] !== 'no') return false;
    if (q && !(x.file_path.toLowerCase().includes(q) || x.snippet.toLowerCase().includes(q))) return false;
    return true;
  });

  const filterTabs = [
    ['all', `All (${rows.length})`],
    ['unprot', `Unprotected (${unprotCount})`],
    ['no-auth', `Missing auth (${noAuthCount})`],
    ['no-rate', `Missing rate limit (${noRateCount})`],
    ['no-role', `Missing role check (${noRoleCount})`]
  ];

  const tpl = `grid-template-columns:120px minmax(220px,1.6fr) ${columns.map(() => '1fr').join(' ')}`;
  const cell = v => `<span class="mono small" style="color:${v === 'yes' ? 'var(--mute)' : v === 'no' ? 'var(--accent)' : 'var(--line2)'}">${esc(v)}</span>`;

  return `<div class="page w1100">
    <div class="between" style="align-items:baseline">
      <h1 class="serif" style="font-size:32px;margin:0">Route Inventory</h1>
      <span class="mono xs mute">${rows.length} endpoints detected in ${esc(r.source)}</span>
    </div>
    <div class="hairline"></div>

    <div class="stat-grid">
      ${stats.map(([k, v, c]) => `
        <div class="stat-col">
          <span class="stat-val" style="color:${c}">${v}</span>
          <span class="stat-lbl">${esc(k)}</span>
        </div>
      `).join('')}
    </div>

    <div class="between" style="align-items:center;gap:var(--s-16)">
      <input class="field mono" data-bind="routeQuery" value="${esc(S.routeQuery)}" placeholder="Search endpoints or paths (e.g. /login, POST, admin)..." style="flex:1;max-width:380px" aria-label="Search routes">
      <div class="row g16" style="align-items:center">
        ${tabs(filterTabs, S.routeFilter || 'all', 'routeFilter')}
        <button class="btn-text xs mute" data-act="copyRouteTable">Copy Markdown Table</button>
      </div>
    </div>

    <div style="overflow-x:auto;width:100%"><div class="table">
      <div class="trow head" style="${tpl}"><span>Location</span><span>Route</span>${columns.map(c => `<span>${esc(c)}</span>`).join('')}</div>
      ${shown.length ? shown.map(x => `<div class="trow ${x.unprotected ? 'hot' : ''}" style="${tpl}">
        <button class="mono small mute click-copy" data-act="copyText" data-v="${esc(x.file_path)}:${x.line}" title="Click to copy location" style="text-align:left">${esc(x.file_path)}:${x.line}</button>
        <span class="mono small clip" title="${esc(x.snippet.trim())}">${highlightLine(x.snippet.trim(), x.file_path.split('.').pop())}</span>
        ${columns.map(c => cell(x.columns[c])).join('')}</div>`).join('')
        : '<div class="mute small" style="padding:var(--s-16) 0">No routes match the current filter.</div>'}
    </div></div>
    <span class="small mute">A dash means that control did not consider the line a subject: a listing endpoint has no credential rate limit to miss. Login, register, logout, health and similar paths are unauthenticated by design and never counted as gaps.</span>
  </div>`;
};

// ---------------------------------------------------------------- Accepted
function scoreIf(findings, control) {
  const scored = scoredOf(findings.map(f => f.control_id === control ? { ...f, suppressed: true } : f));
  if (!scored.length) return 100;
  const total = scored.reduce((a, f) => a + W[f.severity], 0);
  const earned = scored.reduce((a, f) => a + W[f.severity] * CR[f.status], 0);
  return Math.round(100 * earned / total);
}

SCREENS.accepted = () => {
  const r = S.report;
  if (!r) return emptyNeedScan('Accepted findings belong to a scan.');
  const items = r.suppressions_applied.map(a => ['APPLIED', 'var(--mute)', a])
    .concat(r.problems.map(p => ['NOT APPLIED', 'var(--accent)', p]))
    .concat(r.findings.filter(f => f.suppressed).map(f => ['ACCEPTED', 'var(--line2)', `${f.control_id} · ${f.suppression_reason || 'no reason recorded'}`]));
  const gaps = r.findings.filter(f => f.status === 'absent' || f.status === 'partial');
  const fm = S.form;
  if (!gaps.some(f => f.control_id === fm.control) && gaps.length) fm.control = gaps[0].control_id;
  const snippet = fm.where === 'inline'
    ? `# copilot: ignore ${fm.control} -- ${fm.reason || '<reason>'}`
    : `suppress:\n  - control: ${fm.control}\n    reason: ${fm.reason}${fm.expires ? `\n    expires: ${fm.expires}` : ''}`;
  const today = new Date().toISOString().slice(0, 10);
  const f = gaps.find(g => g.control_id === fm.control);
  let impact, ok = false;
  if (!fm.reason.trim()) impact = 'Will not apply: no reason given.';
  else if (fm.expires && fm.expires < today) impact = `Will not apply: expired ${fm.expires}.`;
  else if (f && f.suppressed) impact = 'Already accepted in this report.';
  else { ok = true; impact = `Would move the score ${r.summary.posture_score} → ${scoreIf(r.findings, fm.control)} and remove 1 gap.`; }
  return `<div class="page w1100">
    <div class="between" style="align-items:baseline">
      <h1 class="serif" style="font-size:32px;margin:0">Accepted Risks</h1>
      <span class="mono xs mute">suppressions & in-house guards</span>
    </div>
    <div class="hairline"></div>

    <div class="grid2">
      <div class="stack g24" style="min-width:0">
        <p class="mute small">An accepted finding stays in the report and leaves the gap list, the posture score and the exit code. An entry with no reason, or past its expiry, does not apply.</p>
        <div class="hairline-list">
          <div class="section-title" style="padding-bottom:var(--s-8)">Active suppressions</div>
          ${items.length ? items.map(([st, col, text]) => `
            <div class="hairline-row">
              <span class="tag inline" style="color:${col}">${st}</span>
              <span class="mono small" style="word-break:break-word;flex:1">${esc(text)}</span>
            </div>`).join('')
            : '<div class="mute small" style="padding:var(--s-8) 0">No suppressions recorded for this target.</div>'}
        </div>
        <div class="editorial-section">
          <div class="section-title">In-house guards</div>
          <p class="mute small">Protections this codebase writes its own way. Without them, every route behind an in-house decorator reads as unauthenticated.</p>
          <div class="code pre">guards:\n  AUTH-001: ['@require_api_key']</div>
        </div>
      </div>

      <div class="editorial-section sticky" style="gap:var(--s-16)">
        <span class="section-title">Accept a finding</span>
        ${gaps.length ? `
        <label class="stack g6">
          <span class="xs mute">Control</span>
          <select class="field mono" data-bind="form.control">${gaps.map(g => `<option value="${esc(g.control_id)}" ${g.control_id === fm.control ? 'selected' : ''}>${esc(g.control_id)} · ${esc(g.control_name)}</option>`).join('')}</select>
        </label>
        <label class="stack g6">
          <span class="xs mute">Reason · required</span>
          <input class="field" data-bind="form.reason" value="${esc(fm.reason)}" placeholder="rate limiting is enforced at API gateway">
        </label>
        <div class="row g16" style="align-items:flex-end">
          <label class="stack g6" style="flex:1">
            <span class="xs mute">Expires · optional</span>
            <input type="date" class="field mono" data-bind="form.expires" value="${esc(fm.expires)}">
          </label>
          <div class="stack g6">
            <span class="xs mute">Where</span>
            ${tabs([['config', '.copilot.yaml'], ['inline', 'inline']], fm.where, 'where')}
          </div>
        </div>
        <div class="code pre">${esc(snippet)}</div>
        <span class="xs" style="color:${ok ? 'var(--ink)' : 'var(--accent)'}">${esc(impact)}</span>
        <button class="btn-solid block" data-act="copySnippet">Copy snippet</button>
        <span class="xs mute">Paste into your project and scan again. This page never edits your files.</span>`
        : '<span class="small mute">This report has no open gaps to accept.</span>'}
      </div>
    </div>
  </div>`;
};

// ---------------------------------------------------------------- Rules
const MODE_TEXT = {
  subject_guard: 'Subject/guard. Finds the thing that should be protected, then looks for evidence that it is. It can only report an unprotected route because it first found the route.',
  presence: 'Presence. Matches patterns across file contents or paths; an inverted rule treats a match as the control being absent.',
};

SCREENS.rules = () => {
  if (!S.rules) return '<div class="page"><span class="mute">Loading controls…</span></div>';
  const r = S.report;
  const byId = r ? Object.fromEntries(r.findings.map(f => [f.control_id, f])) : {};
  const skipped = r ? Object.fromEntries(r.skipped_controls.map(k => [k.control_id, k.reason])) : {};
  const status = id => byId[id] ? [byId[id].status, fLabel(byId[id]), fColor(byId[id])] : skipped[id] ? ['na', 'SKIPPED', 'var(--mute)'] : ['na', '—', 'var(--mute)'];
  const list = S.rules.filter(c => S.ruleCat === 'all' || c.category === S.ruleCat);
  const c = S.rules.find(x => x.id === S.ruleId) || list[0];
  const [stKey, st, col] = status(c.id);
  const f = byId[c.id];
  return `<div class="page w1100">
    <div class="between" style="align-items:baseline">
      <h1 class="serif" style="font-size:32px;margin:0">Detection Rules</h1>
      <span class="mono xs mute">${S.rules.length} rules catalogue · YAML</span>
    </div>
    <div class="hairline"></div>

    <div class="grid2">
      <div class="stack g16" style="min-width:0">
        ${tabs([['all', 'All']].concat(CATS), S.ruleCat, 'ruleCat')}
        <div class="hairline-list">
          ${list.map(x => { const [sk, s2, c2] = status(x.id); return `
            <button class="control-row ${x.id === c.id ? 'on' : ''}" data-act="rule" data-v="${esc(x.id)}">
              <span class="status-dot ${sk}"></span>
              <span class="id">${esc(x.id)}</span>
              <span class="name">${esc(x.name)}</span>
              <span class="sev ${x.severity === 'critical' ? 'critical' : ''}">${esc(x.severity)}</span>
            </button>`; }).join('')}
        </div>
        <span class="mono xs mute">YAML under src/copilot/rules/ · copilot rules validate</span>
      </div>

      <article class="detail-panel sticky">
        <div class="stack g6">
          <div class="row g16" style="align-items:baseline">
            <span class="status-dot ${stKey}"></span>
            <span class="mono xs mute">${esc(c.id)}</span>
            <span class="caps">${c.severity} · ${c.mode}</span>
          </div>
          <h2>${esc(c.name)}</h2>
          <span class="mono xs mute">${esc([CATT[c.category], c.cwe, c.owasp, 'src/copilot/rules/' + c.source_file].filter(Boolean).join(' · '))}</span>
        </div>
        <div class="row" style="align-items:center;gap:10px;font-size:12.5px">
          <span class="tag inline" style="color:${col}">${st}</span>
          <span class="mute">in ${esc(r ? r.source : 'no scan yet')}</span>
          ${f && f.status !== 'not_applicable' ? `<button class="btn-text xs" style="margin-left:auto;color:var(--accent)" data-act="openRule" data-v="${esc(c.id)}">Open finding →</button>` : ''}
        </div>
        ${c.description ? `<div class="stack g6"><span class="section-title">What it checks</span><span class="ink2 small">${esc(c.description)}</span></div>` : ''}
        <div class="stack g6"><span class="section-title">Mode</span><span class="ink2 small">${esc(MODE_TEXT[c.mode] || 'Custom computation in detector.')}</span></div>
        ${c.yaml ? `<div class="code pre" style="max-height:300px;overflow:auto">${esc(c.yaml)}</div>` : ''}
        ${Object.keys(c.verdict).length ? `<div class="stack g6"><span class="section-title">Verdict mapping</span>
          <div class="mono xs" style="display:grid;grid-template-columns:auto 1fr;gap:4px 14px">${Object.entries(c.verdict).map(([k, v]) =>
            `<span class="mute">${esc(k)}</span><span style="color:${SC[v] || 'var(--mute)'}">${esc(v)}</span>`).join('')}</div></div>` : ''}
        <div class="stack g6"><span class="section-title">Remediation</span><span class="ink2 small">${esc(c.remediation)}</span></div>
      </article>
    </div>
  </div>`;
};

// ---------------------------------------------------------------- How it works
SCREENS.how = () => {
  const r = S.report;
  const outcomes = [
    ['PRESENT', 'present', 'Every subject is guarded'],
    ['PARTIAL', 'partial', 'Some guarded, some not'],
    ['ABSENT', 'absent', 'Subjects exist, none guarded'],
    ['N/A', 'na', 'No subjects, nothing to judge']
  ];
  return `<div class="page w1100">
    <div class="between" style="align-items:baseline">
      <h1 class="serif" style="font-size:32px;margin:0">How It Works</h1>
      <span class="mono xs mute">pipeline, scoring model & limitations</span>
    </div>
    <div class="hairline"></div>

    <section class="editorial-section">
      <div class="section-title">What this reports</div>
      <p class="desc">A linter finds bad code that exists. This finds good code that should exist and does not: no auth on a route, no rate limit on a login endpoint, a secret sitting in plaintext.</p>
      <div class="flowline">
        <span>repo path</span>
        <span class="mute">→</span>
        <span>SCANNER <i class="mute" style="font-style:normal">what's there</i></span>
        <span class="mute">→</span>
        <span>DETECTORS ×5 <i class="mute" style="font-style:normal">what's missing</i></span>
        <span class="mute">→</span>
        <span>REPORTER <i class="mute" style="font-style:normal">how it reads</i></span>
      </div>
    </section>

    <section class="editorial-section">
      <div class="section-title">Four outcomes</div>
      <div class="stat-grid">
        ${outcomes.map(([k, v, d]) => `
          <div class="stat-col">
            <div class="row g8" style="align-items:center">
              <span class="status-dot ${v}"></span>
              <span class="stat-val" style="font-size:20px">${k}</span>
            </div>
            <span class="stat-lbl">${d}</span>
          </div>
        `).join('')}
      </div>
      <p class="mute small">PARTIAL is the interesting one. Authentication applied to most routes and forgotten on two is far more common than authentication missing entirely, and a binary scanner calls that present.</p>
    </section>

    <section class="editorial-section">
      <div class="section-title">Posture score</div>
      <div class="code" style="font-size:13.5px">score = 100 × Σ(weight × credit) / Σ(weight)</div>
      <div class="row g48" style="padding:var(--s-8) 0">
        <div class="stack g4"><span class="section-title">Weight</span><span class="mono xs">critical 5 · high 3 · medium 2 · low 1</span></div>
        <div class="stack g4"><span class="section-title">Credit</span><span class="mono xs">present 1.0 · partial 0.5 · absent 0</span></div>
      </div>
      ${r ? `<div class="notice"><b>For ${esc(r.source)}:</b> ${r.weights.earned.toFixed(1)} earned / ${r.weights.total} weight across ${r.summary.controls_scored} scored controls = ${r.summary.posture_score}</div>` : ''}
      <p class="mute small">Grade bands A 90 · B 80 · C 70 · D 60. Capped at D while any critical control is absent. Withheld entirely when a run is narrowed to some categories. N/A and accepted findings are excluded from both sums, and display filters never move the number.</p>
    </section>

    <section class="editorial-section">
      <div class="section-title">Limits worth knowing</div>
      <div class="hairline-list">
        <div class="hairline-row"><b style="width:180px;flex:none">Static analysis only</b><span class="mute small" style="flex:1">Nothing is executed, no network calls are made.</span></div>
        <div class="hairline-row"><b style="width:180px;flex:none">Regex, not a parser</b><span class="mute small" style="flex:1">Whole-line comments are stripped, but multi-line constructs can defeat proximity windows.</span></div>
        <div class="hairline-row"><b style="width:180px;flex:none">No cross-module dataflow</b><span class="mute small" style="flex:1">Express middleware mounted in another file cannot be tied to a specific router.</span></div>
        <div class="hairline-row"><b style="width:180px;flex:none">Rule-based guidance</b><span class="mute small" style="flex:1">Explanations come from the rule catalogue and the scan's own evidence; no AI model is needed or read.</span></div>
        <div class="hairline-row"><b style="width:180px;flex:none">Exports are not redacted</b><span class="mute small" style="flex:1">Evidence can quote secrets; treat downloaded reports as sensitive.</span></div>
      </div>
    </section>
  </div>`;
};

Object.assign(ACTIONS, {
  unprot: () => set({ unprot: !S.unprot }),
  where: v => set({ form: { ...S.form, where: v } }),
  copySnippet: () => {
    const el = document.querySelector('.sticky .code.pre');
    navigator.clipboard.writeText(el ? el.textContent : '').then(() => flash('Snippet copied'), () => flash('Copy failed; select the text instead'));
  },
  copyRouteTable: () => {
    if (!S.routes || !S.routes.rows.length) return;
    const { columns, rows } = S.routes;
    const q = (S.routeQuery || '').trim().toLowerCase();
    const shown = rows.filter(x => {
      if (S.routeFilter === 'unprot' && !x.unprotected) return false;
      if (S.routeFilter === 'no-auth' && x.columns['auth'] !== 'no') return false;
      if (S.routeFilter === 'no-role' && x.columns['role check'] !== 'no') return false;
      if (S.routeFilter === 'no-rate' && x.columns['rate limit'] !== 'no') return false;
      if (q && !(x.file_path.toLowerCase().includes(q) || x.snippet.toLowerCase().includes(q))) return false;
      return true;
    });
    const header = '| Location | Route | ' + columns.join(' | ') + ' |\n| --- | --- | ' + columns.map(() => '---').join(' | ') + ' |';
    const lines = shown.map(x => `| ${x.file_path}:${x.line} | \`${x.snippet.trim().replace(/\|/g, '\\|')}\` | ` + columns.map(c => x.columns[c] || '-').join(' | ') + ' |');
    const tableMd = header + '\n' + lines.join('\n');
    navigator.clipboard.writeText(tableMd).then(() => flash('Route table copied to clipboard'), () => flash('Copy failed'));
  },
  rule: v => set({ ruleId: v }),
  ruleCat: v => set({ ruleCat: v, ruleId: (S.rules.find(x => v === 'all' || x.category === v) || {}).id || S.ruleId }),
  openRule: v => { set({ sel: v, query: '', showSat: true }); navigate('report'); },
});
