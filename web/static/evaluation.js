/* Evaluation: statistics for the most recently scanned project, and the corpus evaluation. */
'use strict';

const evalView = () => S.evalView || (S.report ? 'project' : 'corpus');

async function loadEval() {
  try {
    if (evalView() === 'project' && S.report && (!S.truth || S.truth.id !== S.report.id)) {
      S.truth = Object.assign(await api('/api/truth/' + S.report.id), { id: S.report.id });
      render();
    }
    if (evalView() === 'corpus' && !S.evals[S.split]) {
      S.evals[S.split] = await api('/api/eval?split=' + S.split);
      render();
    }
  } catch (e) { flash(e.message); }
}

// Per-category numbers computed from the report the server returned.
function categoryStats(r) {
  return CATS.filter(([c]) => r.summary.categories_scanned.includes(c)).map(([c, t]) => {
    const all = r.findings.filter(f => f.category === c);
    const count = st => all.filter(f => f.status === st).length;
    const scored = scoredOf(all);
    const total = scored.reduce((a, f) => a + W[f.severity], 0);
    const earned = scored.reduce((a, f) => a + W[f.severity] * CR[f.status], 0);
    return { c, t, n: all.length, present: count('present'), partial: count('partial'), absent: count('absent'),
             na: count('not_applicable'), gaps: all.filter(f => f.is_gap).length,
             score: total ? Math.round(100 * earned / total) : null, total, earned };
  });
}

function projectView() {
  const r = S.report;
  if (!r) return emptyNeedScan('Evaluation statistics describe your most recent scan.');
  const s = r.summary;
  const gaps = r.findings.filter(f => f.is_gap);
  const cats = categoryStats(r);
  const evidence = r.findings.reduce((a, f) => a + f.evidence.length, 0);
  const files = new Set(gaps.flatMap(f => f.evidence.map(e => e.file_path).filter(Boolean)));
  const conf = ['high', 'medium', 'low'].map(k => [k, gaps.filter(f => f.confidence === k).length]);
  const samples = (S.meta ? S.meta.samples : []).filter(x => x.name !== r.source).sort((a, b) => b.score - a.score);
  const better = samples.filter(x => x.score > s.posture_score).length;
  const tiles = [
    ['Posture score', s.posture_score, 'var(--ink)', gradeText(r)],
    ['Controls evaluated', s.controls_evaluated, 'var(--ink)', `${s.controls_scored} scored · ${r.skipped_controls.length} not evaluated`],
    ['Open gaps', gaps.length, gaps.length ? 'var(--accent)' : 'var(--mute)', ['critical', 'high', 'medium', 'low'].filter(k => s.gaps_by_severity[k]).map(k => `${s.gaps_by_severity[k]} ${k}`).join(' · ') || 'none'],
    ['Coverage', `${s.categories_scanned.length}/${r.categories_available}`, 'var(--ink)', s.scope === 'partial' ? 'categories · grade withheld' : 'categories · full scope'],
  ];
  const t = S.truth && S.truth.id === r.id ? S.truth : null;
  let truth;
  if (!t) truth = '<span class="mute small">Checking for ground-truth labels…</span>';
  else if (!t.labelled) truth = `<div class="notice">No ground-truth labels exist for <span class="mono">${esc(r.source)}</span>, so accuracy (false positives, missed gaps) cannot be measured for it. The numbers on this page describe what the scanner found and how it scored it. Scan a bundled corpus sample to see a labelled comparison.</div>`;
  else {
    const q = [['TP', t.tp, 'gap labelled, gap reported', 'var(--ink)'], ['FP', t.fp, 'reported, not labelled', t.fp ? 'var(--accent)' : 'var(--mute)'],
      ['FN', t.fn, 'labelled, missed', t.fn ? 'var(--accent)' : 'var(--mute)'], ['TN', t.tn, 'no gap, none reported', 'var(--ink)']];
    truth = `<div class="confusion">${q.map(([k, v, d, col]) => `<div class="confusion-col"><b style="color:${col}">${v}</b><span class="mono xs" style="font-weight:600">${k}</span><span class="xs mute">${d}</span></div>`).join('')}</div>
      ${t.disagreements.length ? `<div class="hairline-list">${t.disagreements.map(d => `<div class="trow" style="grid-template-columns:90px 1fr 1fr 80px">
        <span class="mono small">${esc(d.control_id)}</span><span class="small">labelled <b>${esc(d.expected)}</b></span><span class="small">reported <b>${esc(d.reported)}</b></span>
        <span class="mono xs" style="color:var(--accent)">${esc(d.outcome.toUpperCase())}</span></div>`).join('')}</div>`
        : `<div class="mute small" style="padding:var(--s-8) 0">Every labelled control in the scanned categories matches the manifest for <span class="mono">${esc(t.sample)}</span>.</div>`}
      <span class="xs mute">Labels come from corpus/manifest.yaml (${esc(t.split)} split). The rules were tuned on these samples, so this is a regression check, not an accuracy claim.</span>`;
  }
  const catTpl = 'grid-template-columns:minmax(140px,1.3fr) repeat(5,56px) minmax(120px,1fr) 60px';
  return `<div class="page w1100">
    <div class="between" style="align-items:baseline">
      <div>
        <h1 class="serif" style="font-size:32px;margin:0">Evaluation & Accuracy</h1>
        <span class="mono xs mute">${esc(r.source)} · ${esc(r.scan.framework || 'unknown framework')} · ${r.scan.files_scanned} files</span>
      </div>
      ${tabs([['project', 'This project'], ['corpus', 'Corpus']], 'project', 'evalView')}
    </div>
    <div class="hairline"></div>

    <div class="stat-grid">
      ${tiles.map(([k, v, col, sub]) => `
        <div class="stat-col">
          <span class="stat-val" style="color:${col}">${esc(v)}</span>
          <span class="stat-lbl">${k} · ${esc(sub)}</span>
        </div>
      `).join('')}
    </div>

    <section class="editorial-section">
      <div class="section-title">By category</div>
      <div style="overflow-x:auto;width:100%"><div class="table" style="min-width:720px">
        <div class="trow head" style="${catTpl}"><span>Category</span><span>Present</span><span>Partial</span><span>Absent</span><span>N/A</span><span>Gaps</span><span>Weighted score</span><span></span></div>
        ${cats.map(x => `<div class="trow" style="${catTpl}">
          <span>${x.t}</span><span class="mono">${x.present}</span><span class="mono ${x.partial ? 'gaps-flag' : ''}">${x.partial}</span>
          <span class="mono ${x.absent ? 'gaps-flag' : ''}">${x.absent}</span><span class="mono mute">${x.na}</span><span class="mono">${x.gaps}</span>
          <div class="hairline-progress" title="${x.earned.toFixed(1)} of ${x.total} weight"><div class="hairline-progress-fill" style="width:${x.score ?? 0}%"></div></div>
          <span class="mono" style="font-weight:600">${x.score ?? '—'}</span></div>`).join('')}
      </div></div>
      <span class="xs mute">Score per category uses the same weights as overall score (critical 5, high 3, medium 2, low 1; present 1, partial 0.5). A dash means nothing in that category applied.</span>
    </section>

    <div class="grid2">
      <section class="editorial-section">
        <div class="section-title">Gaps and evidence</div>
        <div class="hairline-list">${conf.map(([k, n]) => `
          <div class="hairline-row">
            <span class="caps" style="width:120px">${k} confidence</span>
            <div class="hairline-progress" style="flex:1"><div class="hairline-progress-fill" style="width:${gaps.length ? 100 * n / gaps.length : 0}%"></div></div>
            <span class="mono small" style="width:24px;text-align:right">${n}</span>
          </div>`).join('')}</div>
        <span class="small mute">${evidence} evidence item${evidence === 1 ? '' : 's'} across all controls; gaps point at ${files.size} file${files.size === 1 ? '' : 's'}.</span>
        <span class="mono xs mute">${r.weights.earned.toFixed(1)} earned / ${r.weights.total} weight across ${s.controls_scored} scored controls = ${s.posture_score}</span>
      </section>

      <section class="editorial-section">
        <div class="section-title">Compared with bundled samples</div>
        ${samples.length ? `
          <div class="hairline-list">${[{ name: r.source, score: s.posture_score, me: true }].concat(samples).sort((a, b) => b.score - a.score).map(x => `
            <div class="hairline-row">
              <span class="mono small clip" style="width:170px;${x.me ? 'font-weight:600;color:var(--ink)' : 'color:var(--mute)'}">${esc(x.name)}${x.me ? ' ◂' : ''}</span>
              <div class="hairline-progress" style="flex:1"><div class="hairline-progress-fill" style="width:${x.score}%"></div></div>
              <span class="mono small" style="width:28px;text-align:right">${x.score}</span>
            </div>`).join('')}</div>` : '<span class="mute small">Sample scores unavailable.</span>'}
      </section>
    </div>

    <section class="editorial-section">
      <div class="section-title">Against ground truth</div>
      ${truth}
    </section>
  </div>`;
}

function corpusView() {
  const d = S.evals[S.split];
  const head = `<div class="between" style="align-items:baseline">
    <div class="row g16" style="align-items:baseline">
      <h1 class="serif" style="font-size:32px;margin:0">Corpus Evaluation</h1>
      ${tabs([['dev', 'dev · 8 samples'], ['holdout', 'holdout']], S.split, 'split')}
    </div>
    ${tabs([['project', 'This project'], ['corpus', 'Corpus']], 'corpus', 'evalView')}
  </div>
  <div class="hairline"></div>`;

  if (!d) return `<div class="page w1100">${head}<span class="mute">Scanning corpus…</span></div>`;
  if (d.error) return `<div class="page w1100">${head}<div class="dashed" style="max-width:620px;padding:36px">
    <span style="font-weight:600;font-size:15px">No ${esc(S.split)} split yet</span>
    <span class="mute">Holdout samples are labelled by hand before the scanner ever sees them and are never used to change a rule. This is the only split whose numbers are reportable as accuracy.</span>
    <span class="mono small" style="margin-top:6px">$ copilot evaluate --split holdout</span></div></div>`;

  const tiles = [['TP', d.tp, 'gap labelled, gap reported', 'var(--ink)'], ['FP', d.fp, 'reported, not labelled', d.fp ? 'var(--accent)' : 'var(--mute)'],
    ['FN', d.fn, 'labelled, missed', d.fn ? 'var(--accent)' : 'var(--mute)'], ['TN', d.tn, 'no gap, none reported', 'var(--ink)']];
  const bySample = Object.fromEntries((S.meta ? S.meta.samples : []).map(s => [s.name, s]));
  const tpl = 'grid-template-columns:minmax(170px,1.3fr) 90px 110px minmax(120px,1fr) 60px 60px 100px';

  return `<div class="page w1100">
    ${head}
    <div class="confusion">${tiles.map(([k, v, dsc, col]) => `<div class="confusion-col"><b style="color:${col}">${v}</b><span class="mono xs" style="font-weight:600">${k}</span><span class="xs mute">${dsc}</span></div>`).join('')}</div>
    <div class="notice">Regression signal only. Rules were tuned until they matched these samples, so precision and recall here are circular by construction. No accuracy figure is claimed.</div>
    <div style="overflow-x:auto;width:100%"><div class="table" style="min-width:760px">
      <div class="trow head" style="${tpl}"><span>Sample</span><span>Framework</span><span>Kind</span><span>Score</span><span>Grade</span><span>Gaps</span><span>Manifest</span></div>
      ${d.samples.map(x => { const s = bySample[x.name] || {}; return `<div class="trow" style="${tpl}">
        <span class="mono small">${esc(x.name)}</span><span class="ink2">${esc(x.framework || 'unknown')}</span><span class="mute">${esc(s.kind || '')}</span>
        <div class="row" style="flex-wrap:nowrap"><span class="mono" style="font-weight:600;font-size:12px;width:26px">${s.score ?? '—'}</span>
          <div class="hairline-progress" style="flex:1"><div class="hairline-progress-fill" style="width:${s.score || 0}%"></div></div></div>
        <span class="mono" style="font-weight:600;font-size:12px">${esc(s.grade || '—')}</span><span class="mono">${s.gaps ?? '—'}</span>
        <span class="mono xs" style="color:${x.disagreements ? 'var(--accent)' : 'var(--mute)'}">${x.disagreements ? plural(x.disagreements, 'disagreement') : 'matches'}</span></div>`; }).join('')}
    </div></div>
  </div>`;
}

SCREENS.eval = () => evalView() === 'project' ? projectView() : corpusView();

Object.assign(ACTIONS, {
  evalView: v => { set({ evalView: v }); loadEval(); },
  split: v => { set({ split: v }); loadEval(); },
});
