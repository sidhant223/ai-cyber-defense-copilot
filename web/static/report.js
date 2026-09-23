/* Posture report: score, weight bar, grouped findings, detail with real source evidence. */
'use strict';

function emptyNeedScan(what) {
  return `<div class="page w1240"><div class="dashed"><span style="font-weight:500">No scan yet</span>
    <span class="mute" style="font-size:12.5px">${what} Run a scan first.</span>
    <div class="row" style="margin-top:8px"><button class="btn primary sm" data-act="go" data-v="scan">New scan</button></div></div></div>`;
}

function scoredOf(findings) {
  return findings.filter(f => f.status !== 'not_applicable' && !f.suppressed);
}

function shownFindings(r) {
  const q = S.query.trim().toLowerCase();
  return r.findings.filter(f => {
    if (S.minSev !== 'all' && f.is_gap && SEVR[f.severity] > SEVR[S.minSev]) return false;
    if (!S.showSat && !f.is_gap) return false;
    if (q && !(f.control_id.toLowerCase().includes(q) || f.control_name.toLowerCase().includes(q) ||
               f.evidence.some(e => (e.file_path || '').toLowerCase().includes(q)))) return false;
    return true;
  });
}

function scoreSection(r) {
  const s = r.summary, scan = r.scan;
  const facts = [['Framework', scan.framework || 'unknown'], ['Language', scan.language], ['Files scanned', scan.files_scanned],
    ['Files skipped', scan.skipped_files], ['Controls scored', `${s.controls_scored} of ${s.controls_evaluated}`], ['Scan time', scan.scan_duration_ms + ' ms']];
  const segs = scoredOf(r.findings).sort((a, b) => W[b.severity] - W[a.severity] || STR[a.status] - STR[b.status] || a.control_id.localeCompare(b.control_id));
  let notice = '';
  if (s.grade_capped_by) notice = `Grade capped at ${s.grade}: ${s.grade_capped_by}. A weighted average can sit high while a critical control is missing entirely.`;
  else if (s.scope === 'partial') notice = `Grade withheld: this run covered ${s.categories_scanned.length} of ${r.categories_available} categories. The score describes that slice only.`;
  else if (!scan.framework) notice = 'No framework identified with confidence, so framework-specific controls were not evaluated.';
  return `<section class="panel pad stack g18">
    <div class="row" style="gap:28px">
      <div class="row" style="gap:10px;align-items:baseline"><span class="score48" style="color:${scoreColor(s.posture_score)}">${s.posture_score}</span>
        <span class="mono mute" style="font-weight:500;font-size:14px">${gradeText(r)}</span></div>
      <div class="facts">${facts.map(([k, v]) => `<div class="stack" style="gap:2px"><span class="eyebrow">${k}</span><span style="font-weight:500">${esc(v)}</span></div>`).join('')}</div>
    </div>
    <div class="stack g6">
      <div class="weights">${segs.map(f => `<button style="flex:${W[f.severity]}" class="${S.sel === f.control_id ? 'on' : ''}" data-act="pick" data-v="${esc(f.control_id)}"
        title="${esc(f.control_id)} · ${f.severity} ${W[f.severity]} · ${f.status}" aria-label="${esc(f.control_id)} ${f.status}"><i style="width:${CR[f.status] * 100}%"></i></button>`).join('')}</div>
      <span class="mono xs mute">${r.weights.earned.toFixed(1)} earned / ${r.weights.total} weight across ${s.controls_scored} scored controls = ${s.posture_score}</span>
    </div>
    ${chips(r)}
    ${notice ? `<div class="notice">${esc(notice)}</div>` : ''}
  </section>`;
}

function evidenceHtml(f) {
  const hide = f.category === 'secret_management' && !S.reveal;   // may quote the credential itself
  return f.evidence.map(e => {
    if (!e.file_path) {
      return `<div class="dashed" style="padding:12px 14px"><span class="eyebrow">Negative evidence · searched, not found</span>
        <span style="font-size:13px">${esc(e.note || f.message)}</span></div>`;
    }
    const loc = e.line_number ? `${e.file_path}:${e.line_number}` : e.file_path;
    const note = hide ? 'excerpt hidden · enable “Reveal secret excerpts”' : (e.note || '');
    const head = `<div class="evhead"><span>${esc(loc)}</span><span title="${esc(note)}">${esc(note)}</span></div>`;
    if (hide) return `<div class="evbox">${head}</div>`;
    if (e.context && e.context.length) {
      return `<div class="evbox">${head}<div class="src">${e.context.map(([n, t]) =>
        `<div class="ln ${n === e.line_number ? 'hit' : ''}"><span class="n">${n}</span><span class="t">${esc(t) || ' '}</span></div>`).join('')}</div>
        <div class="legend"><span><i></i>matched line · ${e.context.length} lines of context</span></div></div>`;
    }
    return `<div class="evbox">${head}${e.snippet ? `<div class="src"><div class="ln hit"><span class="n">${e.line_number || ''}</span><span class="t">${esc(e.snippet)}</span></div></div>` : ''}</div>`;
  }).join('');
}

function detailHtml(f) {
  const ev = evidenceHtml(f);
  return `<article class="panel pad stack g16 sticky">
    <div class="row">
      <span class="tag inline" style="color:${fColor(f)}">${fLabel(f)}</span>
      <span class="mono" style="font-size:12.5px">${esc(f.control_id)}</span>
      <span class="caps">${f.severity} · weight ${f.weight}</span><span class="caps">· confidence ${esc(f.confidence)}</span>
    </div>
    <div class="stack g6"><h2 style="font-size:20px;font-weight:600">${esc(f.control_name)}</h2>
      <div class="row mono xs mute" style="gap:12px">${f.cwe ? `<span>${esc(f.cwe)}</span>` : ''}${f.owasp ? `<span>OWASP ${esc(f.owasp)}</span>` : ''}<span>fp ${esc((f.fingerprint || '').slice(0, 16))}</span></div></div>
    <p style="font-size:15px;line-height:1.5">${esc(f.message)}</p>
    ${f.suppressed ? `<div class="soft" style="font-size:12.5px">Accepted: ${esc(f.suppression_reason)}</div>` : ''}
    ${ev ? `<div class="stack g10"><span class="eyebrow">Evidence · ${f.evidence.length}</span>${ev}</div>` : ''}
    <div class="soft"><span class="eyebrow">Remediation</span><span>${esc(f.remediation_hint)}</span></div>
    ${f.fix_prompt ? `<details class="soft"><summary class="eyebrow" style="cursor:pointer">Fix prompt · paste into your editor or coding assistant</summary>
      <div class="code" style="margin-top:8px">${esc(f.fix_prompt)}</div>
      <div class="row" style="margin-top:8px"><button class="btn sm" data-act="copyFix" data-v="${esc(f.control_id)}">Copy</button></div></details>` : ''}
    <div class="row">
      ${f.is_gap ? `<button class="btn sm" data-act="accept" data-v="${esc(f.control_id)}">Accept with a reason…</button>` : ''}
      <button class="btn sm" data-act="explain" data-v="${esc(f.control_id)}">Explain rule</button>
      <span class="mono xs mute">$ copilot rules explain ${esc(f.control_id)}</span>
    </div>
  </article>`;
}

SCREENS.report = () => {
  const r = S.report;
  if (!r) return emptyNeedScan('The posture report opens here after a scan.');
  const shown = shownFindings(r);
  const selId = shown.some(f => f.control_id === S.sel) ? S.sel : (shown[0] && shown[0].control_id);
  const groups = CATS.map(([c, t]) => {
    const all = r.findings.filter(f => f.category === c);
    const rows = shown.filter(f => f.category === c)
      .sort((a, b) => STR[a.status] - STR[b.status] || SEVR[a.severity] - SEVR[b.severity] || a.control_id.localeCompare(b.control_id));
    const gaps = all.filter(f => f.is_gap).length;
    return { t, rows, all, gaps, rank: rows.length ? Math.min(...rows.map(f => STR[f.status] * 10 + SEVR[f.severity])) : 99 };
  }).filter(g => g.rows.length).sort((a, b) => a.rank - b.rank);
  const sel = r.findings.find(f => f.control_id === selId);
  const noRows = shown.length === 0
    ? `<div class="panel" style="padding:28px;${r.findings.some(f => f.is_gap) ? '' : 'color:var(--present);font-weight:500'}">${
      r.findings.some(f => f.is_gap) ? 'No findings match the current filters. The score is unchanged.'
        : 'No gaps found in the controls that applied. That is not proof the project is secure; check coverage above.'}</div>` : '';
  const skipped = r.skipped_controls.length ? `<div class="panel">
    <button class="between" style="width:100%;padding:11px 14px;font-size:12.5px;color:var(--ink2)" data-act="skipped" aria-expanded="${S.showSkipped}">
      <span>${plural(r.skipped_controls.length, 'control')} not evaluated</span><span class="mono">${S.showSkipped ? '−' : '+'}</span></button>
    ${S.showSkipped ? r.skipped_controls.map(k => `<div class="row" style="padding:8px 14px;border-top:1px solid var(--line);font-size:12.5px;flex-wrap:nowrap">
      <span class="mono small" style="width:84px;flex:none">${esc(k.control_id)}</span><span class="mute">${esc(k.reason)}</span></div>`).join('') : ''}</div>` : '';
  const problems = r.problems.length ? `<div class="notice">${r.problems.map(esc).join('<br>')}</div>` : '';
  return `<div class="page w1360">
  ${scoreSection(r)}
  <div class="row" style="gap:12px">
    <input class="field" data-bind="query" value="${esc(S.query)}" placeholder="Filter by id, name or file" style="flex:1;min-width:200px;max-width:320px" aria-label="Filter findings">
    ${tabs([['all', 'All'], ['critical', 'Critical'], ['high', 'High+'], ['medium', 'Medium+'], ['low', 'Low+']], S.minSev, 'minSev')}
    ${check(S.showSat, 'showSat', 'Show satisfied')}
    ${check(S.reveal, 'reveal', 'Reveal secret excerpts')}
    <span class="small mute" style="margin-left:auto">Showing ${shown.length} of ${r.findings.length} · score uses all ${r.summary.controls_scored} scored</span>
  </div>
  <div class="grid2">
    <div class="stack g14" style="min-width:0">
      ${noRows}
      ${groups.map(g => `<div class="panel flush">
        <div class="gh"><span style="font-weight:600">${g.t}</span><span class="small mute">${plural(g.gaps, 'gap')} of ${plural(g.all.length, 'control')}</span></div>
        ${g.rows.map(f => `<button class="listrow frow ${f.control_id === selId ? 'on' : ''}" data-act="pick" data-v="${esc(f.control_id)}" aria-pressed="${f.control_id === selId}">
          <span class="tag" style="color:${fColor(f)}">${fLabel(f)}</span><span class="mono small ink2">${esc(f.control_id)}</span>
          <span class="clip">${esc(f.control_name)}</span><span class="caps">${f.severity}</span></button>`).join('')}</div>`).join('')}
      ${skipped}${problems}
    </div>
    ${sel ? detailHtml(sel) : ''}
  </div></div>`;
};

Object.assign(ACTIONS, {
  pick: v => {
    set({ sel: v, showSat: S.showSat || !(S.report.findings.find(f => f.control_id === v) || {}).is_gap });
    const detail = isNarrow() && document.querySelector('article.sticky');   // details sit below the list here
    if (detail) detail.scrollIntoView({ behavior: 'smooth', block: 'start' });
  },
  reveal: () => set({ reveal: !S.reveal }),
  skipped: () => set({ showSkipped: !S.showSkipped }),
  accept: v => { S.form = { ...S.form, control: v, reason: '' }; navigate('accepted'); },
  explain: v => { S.ruleId = v; S.ruleCat = 'all'; navigate('rules'); },
  copyFix: v => {
    const f = S.report.findings.find(x => x.control_id === v);
    navigator.clipboard.writeText(f.fix_prompt).then(() => flash('Fix prompt copied'), () => flash('Copy failed; select the text instead'));
  },
});
