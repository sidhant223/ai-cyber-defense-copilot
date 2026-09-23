/* Routes, Accepted, Rules, Evaluation, How it works. */
'use strict';

// ---------------------------------------------------------------- Routes
SCREENS.routes = () => {
  const r = S.report;
  if (!r) return emptyNeedScan('The route inventory reads the current scan.');
  if (!S.routes || S.routes.id !== r.id) return '<div class="page"><span class="mute">Loading routes…</span></div>';
  const { columns, rows } = S.routes;
  if (!rows.length) return `<div class="page w1240"><div class="dashed"><span style="font-weight:500">No route handlers found</span>
    <span class="mute" style="font-size:12.5px">The route-shaped controls found no subjects in ${esc(r.source)}, so there is no attack surface table to show.</span></div></div>`;
  const count = (col, v) => rows.filter(x => x.columns[col] === v).length;
  const stats = [['routes found', rows.length, 'var(--ink)'], ['unprotected', rows.filter(x => x.unprotected).length, 'var(--absent)'],
    ['unauthenticated', count('auth', 'no'), 'var(--absent)'], ['admin without role check', count('role check', 'no'), 'var(--absent)'],
    ['credential routes rate limited', count('rate limit', 'yes'), 'var(--present)']];
  const shown = S.unprot ? rows.filter(x => x.unprotected) : rows;
  const tpl = `grid-template-columns:110px minmax(220px,1.6fr) ${columns.map(() => '1fr').join(' ')}`;
  const cell = v => `<span class="mono small" style="color:${v === 'yes' ? 'var(--present)' : v === 'no' ? 'var(--absent)' : 'var(--mute)'}">${esc(v)}</span>`;
  return `<div class="page w1240">
    <div class="row" style="gap:10px">${stats.map(([k, v, c]) => `<div class="panel stat"><b style="color:${c}">${v}</b><span class="small mute">${k}</span></div>`).join('')}</div>
    <div class="row">${check(S.unprot, 'unprot', 'Unprotected only')}</div>
    <div class="panel" style="overflow-x:auto"><div class="table">
      <div class="trow head" style="${tpl}"><span>Location</span><span>Route</span>${columns.map(c => `<span>${esc(c)}</span>`).join('')}</div>
      ${shown.map(x => `<div class="trow ${x.unprotected ? 'hot' : ''}" style="${tpl}">
        <span class="mono small mute">${esc(x.file_path)}:${x.line}</span><span class="mono small clip" title="${esc(x.snippet.trim())}">${esc(x.snippet.trim())}</span>
        ${columns.map(c => cell(x.columns[c])).join('')}</div>`).join('')}
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
  const items = r.suppressions_applied.map(a => ['APPLIED', 'var(--present)', a])
    .concat(r.problems.map(p => ['NOT APPLIED', 'var(--absent)', p]))
    .concat(r.findings.filter(f => f.suppressed).map(f => ['ACCEPTED', 'var(--na)', `${f.control_id} · ${f.suppression_reason || 'no reason recorded'}`]));
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
  return `<div class="page w1240"><div class="grid-accept">
    <div class="stack g12" style="min-width:0">
      <span class="mute" style="font-size:12.5px">An accepted finding stays in the report and leaves the gap list, the posture score and the exit code. An entry with no reason, or past its expiry, does not apply.</span>
      ${items.length ? items.map(([st, col, text]) => `<div class="panel pad-s row" style="gap:10px;flex-wrap:nowrap">
        <span class="tag inline" style="color:${col}">${st}</span><span class="mono small" style="word-break:break-word">${esc(text)}</span></div>`).join('')
        : '<div class="dashed" style="padding:24px"><span class="mute">No suppressions for this target.</span></div>'}
      <div class="panel pad-s stack g8"><span style="font-weight:600">guards</span>
        <span class="mute" style="font-size:12.5px">Protections this codebase writes its own way. Without them, every route behind an in-house decorator reads as unauthenticated.</span>
        <div class="code pre">guards:\n  AUTH-001: ['@require_api_key']</div></div>
    </div>
    <div class="panel stack g14 sticky" style="padding:18px">
      <span style="font-weight:600;font-size:14px">Accept a finding</span>
      ${gaps.length ? `
      <label class="stack g6"><span class="small mute">Control</span>
        <select class="field mono" data-bind="form.control">${gaps.map(g => `<option value="${esc(g.control_id)}" ${g.control_id === fm.control ? 'selected' : ''}>${esc(g.control_id)} · ${esc(g.control_name)}</option>`).join('')}</select></label>
      <label class="stack g6"><span class="small mute">Reason · required</span>
        <input class="field" data-bind="form.reason" value="${esc(fm.reason)}" placeholder="rate limiting is enforced at the API gateway"></label>
      <div class="row" style="gap:10px;align-items:flex-end;flex-wrap:nowrap">
        <label class="stack g6" style="flex:1"><span class="small mute">Expires · optional</span>
          <input type="date" class="field mono" data-bind="form.expires" value="${esc(fm.expires)}"></label>
        <div class="stack g6"><span class="small mute">Where</span>${tabs([['config', '.copilot.yaml'], ['inline', 'inline']], fm.where, 'where')}</div>
      </div>
      <div class="code pre">${esc(snippet)}</div>
      <span style="font-size:12.5px;color:${ok ? 'var(--present)' : 'var(--absent)'}">${esc(impact)}</span>
      <button class="btn primary block" data-act="copySnippet">Copy snippet</button>
      <span class="xs mute">Paste it into the project and scan again. This page never edits your files.</span>`
      : '<span class="small mute">This report has no open gaps to accept.</span>'}
    </div></div></div>`;
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
  const status = id => byId[id] ? [fLabel(byId[id]), fColor(byId[id])] : skipped[id] ? ['SKIPPED', 'var(--na)'] : ['—', 'var(--na)'];
  const list = S.rules.filter(c => S.ruleCat === 'all' || c.category === S.ruleCat);
  const c = S.rules.find(x => x.id === S.ruleId) || list[0];
  const [st, col] = status(c.id);
  const f = byId[c.id];
  return `<div class="page w1360"><div class="grid2">
    <div class="stack g12" style="min-width:0">
      ${tabs([['all', 'All']].concat(CATS), S.ruleCat, 'ruleCat')}
      <div class="panel flush">${list.map(x => { const [s2, c2] = status(x.id); return `
        <button class="listrow ${x.id === c.id ? 'on' : ''}" style="grid-template-columns:82px minmax(0,1fr) 70px 70px;padding:8px 14px" data-act="rule" data-v="${esc(x.id)}">
          <span class="mono small">${esc(x.id)}</span><span class="clip">${esc(x.name)}</span>
          <span class="caps">${x.severity}</span><span class="mono" style="font-weight:600;font-size:10px;color:${c2};text-align:right">${s2}</span></button>`; }).join('')}</div>
      <span class="mono xs mute">${S.rules.length} controls · YAML under src/copilot/rules/ · copilot rules validate / rules test</span>
    </div>
    <article class="panel pad stack g14 sticky">
      <div class="stack g6"><span class="mono mute" style="font-size:12.5px">${esc(c.id)}</span>
        <h2 style="font-size:20px;font-weight:600">${esc(c.name)}</h2>
        <span class="mono xs mute">${esc([CATT[c.category], c.severity, c.mode, c.cwe, c.owasp, 'src/copilot/rules/' + c.source_file].filter(Boolean).join(' · '))}</span></div>
      <div class="row soft" style="flex-direction:row;align-items:center;gap:10px;font-size:12.5px">
        <span class="tag inline" style="color:${col}">${st}</span><span>in ${esc(r ? r.source : 'no scan yet')}</span>
        ${f && f.status !== 'not_applicable' ? `<button style="margin-left:auto;color:var(--accent);font-weight:500" data-act="openRule" data-v="${esc(c.id)}">Open finding →</button>` : ''}</div>
      ${c.description ? `<div class="stack g6"><span class="eyebrow">What it checks</span><span>${esc(c.description)}</span></div>` : ''}
      <div class="stack g6"><span class="eyebrow">Mode</span><span>${esc(MODE_TEXT[c.mode] || 'Custom. Implemented in the category detector because the check is a computation, not a match. The YAML still carries id, severity and remediation.')}</span></div>
      ${c.yaml ? `<div class="code pre" style="max-height:340px;overflow:auto">${esc(c.yaml)}</div>` : ''}
      ${Object.keys(c.verdict).length ? `<div class="stack g6"><span class="eyebrow">Verdict mapping</span>
        <div class="mono small" style="display:grid;grid-template-columns:auto 1fr;gap:4px 14px">${Object.entries(c.verdict).map(([k, v]) =>
          `<span class="mute">${esc(k)}</span><span style="color:${SC[v] || 'var(--na)'}">${esc(v)}</span>`).join('')}</div></div>` : ''}
      <div class="soft"><span class="eyebrow">Remediation</span><span>${esc(c.remediation)}</span></div>
    </article></div></div>`;
};

// ---------------------------------------------------------------- How it works
SCREENS.how = () => {
  const r = S.report;
  const outcomes = [['PRESENT', 'present', 'Every subject is guarded'], ['PARTIAL', 'partial', 'Some guarded, some not'],
    ['ABSENT', 'absent', 'Subjects exist, none guarded'], ['N/A', 'na', 'No subjects, nothing to judge']];
  return `<div class="page w880" style="padding-top:28px;gap:28px">
  <section class="stack g12"><h2 style="font-size:22px;font-weight:600">What this reports</h2>
    <p style="font-size:15px" class="ink2">A linter finds bad code that exists. This finds good code that should exist and does not: no auth on a route, no rate limit on a login endpoint, a secret sitting in plaintext.</p>
    <div class="flowline"><span>repo path</span><span class="mute" style="border:0;padding:0;background:none">→</span><span>SCANNER <i class="mute" style="font-style:normal">what's there</i></span>
      <span class="mute" style="border:0;padding:0;background:none">→</span><span>DETECTORS ×5 <i class="mute" style="font-style:normal">what's missing</i></span>
      <span class="mute" style="border:0;padding:0;background:none">→</span><span>REPORTER <i class="mute" style="font-style:normal">how it reads</i></span></div></section>
  <section class="stack g12"><h3 style="font-size:16px;font-weight:600">Four outcomes</h3>
    <div class="grid-180">${outcomes.map(([k, v, d]) =>
      `<div class="panel stack g6" style="padding:14px"><span class="mono" style="font-weight:600;font-size:11px;color:var(--${v})">${k}</span><span>${d}</span></div>`).join('')}</div>
    <p class="mute">PARTIAL is the interesting one. Authentication applied to most routes and forgotten on two is far more common than authentication missing entirely, and a binary scanner calls that present.</p></section>
  <section class="stack g12"><h3 style="font-size:16px;font-weight:600">Posture score</h3>
    <div class="code" style="font-size:15px;padding:14px 16px;border-radius:8px">score = 100 × Σ(weight × credit) / Σ(weight)</div>
    <div class="grid-200">
      <div class="stack g6"><span class="eyebrow">Weight</span><span class="mono">critical 5 · high 3 · medium 2 · low 1</span></div>
      <div class="stack g6"><span class="eyebrow">Credit</span><span class="mono">present 1.0 · partial 0.5 · absent 0</span></div></div>
    ${r ? `<div class="soft"><span class="eyebrow">For ${esc(r.source)}</span><span class="mono">${r.weights.earned.toFixed(1)} earned / ${r.weights.total} weight across ${r.summary.controls_scored} scored controls = ${r.summary.posture_score}</span></div>` : ''}
    <p class="mute">Grade bands A 90 · B 80 · C 70 · D 60. Capped at D while any critical control is absent. Withheld entirely when a run is narrowed to some categories. N/A and accepted findings are excluded from both sums, and display filters never move the number.</p></section>
  <section class="stack g10"><h3 style="font-size:16px;font-weight:600">Limits worth knowing</h3>
    <div class="stack g8 ink2">
      <span><b style="color:var(--ink)">Static analysis only.</b> Nothing is executed, no network calls are made.</span>
      <span><b style="color:var(--ink)">Regex, not a parser.</b> Whole-line comments are stripped, but multi-line constructs can defeat proximity windows.</span>
      <span><b style="color:var(--ink)">No cross-module dataflow.</b> Express middleware mounted in another file cannot be tied to a specific router.</span>
      <span><b style="color:var(--ink)">Rule-based guidance, no AI model.</b> Explanations come from the rule catalogue and the scan's own evidence; no API key is needed or read.</span>
      <span><b style="color:var(--ink)">Exports are not redacted.</b> Evidence can quote secrets; treat downloaded reports as sensitive.</span>
    </div></section></div>`;
};

Object.assign(ACTIONS, {
  unprot: () => set({ unprot: !S.unprot }),
  where: v => set({ form: { ...S.form, where: v } }),
  copySnippet: () => {
    const el = document.querySelector('.sticky .code.pre');
    navigator.clipboard.writeText(el ? el.textContent : '').then(() => flash('Snippet copied'), () => flash('Copy failed; select the text instead'));
  },
  rule: v => set({ ruleId: v }),
  ruleCat: v => set({ ruleCat: v, ruleId: (S.rules.find(x => v === 'all' || x.category === v) || {}).id || S.ruleId }),
  openRule: v => { set({ sel: v, query: '', showSat: true }); navigate('report'); },
});
