/* Posture report: score, weight bar, grouped findings, detail with syntax-highlighted source evidence & diffs. */
'use strict';

const PY_KW = new Set([
  'and', 'as', 'assert', 'async', 'await', 'break', 'class', 'continue', 'def',
  'del', 'elif', 'else', 'except', 'finally', 'for', 'from', 'global', 'if',
  'import', 'in', 'is', 'lambda', 'nonlocal', 'not', 'or', 'pass', 'raise',
  'return', 'try', 'while', 'with', 'yield', 'True', 'False', 'None'
]);
const JS_KW = new Set([
  'async', 'await', 'break', 'case', 'catch', 'class', 'const', 'continue', 'debugger',
  'default', 'delete', 'do', 'else', 'export', 'extends', 'finally', 'for', 'function',
  'if', 'import', 'in', 'instanceof', 'let', 'new', 'return', 'super', 'switch',
  'this', 'throw', 'try', 'typeof', 'var', 'void', 'while', 'with', 'yield',
  'true', 'false', 'null', 'undefined'
]);

function highlightLine(line, ext = 'py') {
  if (!line) return ' ';
  const isJs = ext === 'js' || ext === 'ts' || (typeof ext === 'string' && (ext.endsWith('.js') || ext.endsWith('.ts')));
  const kw = isJs ? JS_KW : PY_KW;

  const regex = isJs
    ? /(\/\/[^\n]*)|("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`)|(\b\d+(?:\.\d+)?\b)|(\b[a-zA-Z_$][a-zA-Z0-9_$]*\b)|([^\s\w"'/`]+)/g
    : /(#[^\n]*)|(f?"""[\s\S]*?"""|f?'''[\s\S]*?'''|f?"(?:\\.|[^"\\])*"|f?'(?:\\.|[^'\\])*')|(@[a-zA-Z_][\w\.]*)|(\b\d+(?:\.\d+)?\b)|(\b[a-zA-Z_]\w*\b)|([^\s\w#"']+)/g;

  let lastIndex = 0;
  let result = '';
  let match;

  while ((match = regex.exec(line)) !== null) {
    if (match.index > lastIndex) {
      result += esc(line.slice(lastIndex, match.index));
    }
    const [full, com, str, decOrNum, numOrId, idOrOp] = match;
    if (com) {
      result += `<span class="syn-com">${esc(com)}</span>`;
    } else if (str) {
      result += `<span class="syn-str">${esc(str)}</span>`;
    } else if (decOrNum && decOrNum.startsWith('@')) {
      result += `<span class="syn-dec">${esc(decOrNum)}</span>`;
    } else if (decOrNum && /^\d/.test(decOrNum)) {
      result += `<span class="syn-num">${esc(decOrNum)}</span>`;
    } else if (numOrId && /^\d/.test(numOrId)) {
      result += `<span class="syn-num">${esc(numOrId)}</span>`;
    } else if (numOrId && kw.has(numOrId)) {
      result += `<span class="syn-kw">${esc(numOrId)}</span>`;
    } else if (idOrOp && kw.has(idOrOp)) {
      result += `<span class="syn-kw">${esc(idOrOp)}</span>`;
    } else {
      result += esc(full);
    }
    lastIndex = regex.lastIndex;
  }
  if (lastIndex < line.length) {
    result += esc(line.slice(lastIndex));
  }
  return result;
}

function emptyNeedScan(what) {
  return `<div class="page w1240"><div class="dashed"><span style="font-weight:500">No scan yet</span>
    <span class="mute" style="font-size:12.5px">${what} Run a scan first.</span>
    <div class="row" style="margin-top:8px"><button class="btn primary sm" data-act="go" data-v="scan">New scan</button></div></div></div>`;
}

function scoredOf(findings) {
  return findings.filter(f => f.status !== 'not_applicable' && !f.suppressed);
}

function uniqueFilesOf(findings) {
  const set = new Set();
  findings.forEach(f => f.evidence.forEach(e => { if (e.file_path) set.add(e.file_path); }));
  return Array.from(set).sort();
}

function shownFindings(r) {
  const q = S.query.trim().toLowerCase();
  return r.findings.filter(f => {
    if (S.minSev !== 'all' && f.is_gap && SEVR[f.severity] > SEVR[S.minSev]) return false;
    if (S.statusFilter === 'gaps' && !f.is_gap) return false;
    if (S.statusFilter === 'absent' && f.status !== 'absent') return false;
    if (S.statusFilter === 'partial' && f.status !== 'partial') return false;
    if (S.statusFilter === 'present' && f.status !== 'present') return false;
    if (!S.showSat && S.statusFilter === 'all' && !f.is_gap) return false;
    if (S.fileFilter && S.fileFilter !== 'all' && !f.evidence.some(e => e.file_path === S.fileFilter)) return false;
    if (q && !(f.control_id.toLowerCase().includes(q) || f.control_name.toLowerCase().includes(q) ||
               f.category.toLowerCase().includes(q) ||
               f.evidence.some(e => (e.file_path || '').toLowerCase().includes(q)))) return false;
    return true;
  });
}

function generateDiffLines(f, r) {
  const fw = (r && r.scan && r.scan.framework) || 'flask';
  const ev = f.evidence && (f.evidence.find(e => e.file_path && e.line_number) || f.evidence[0]);
  const filePath = (ev && ev.file_path) ? ev.file_path : (fw === 'express' ? 'server.js' : 'app.py');
  const snippet = (ev && (ev.snippet || (ev.context && ev.context.find(([n]) => n === ev.line_number)?.[1]))) || '';

  switch (f.control_id) {
    case 'AUTH-001':
      if (fw === 'flask') {
        return {
          file: filePath,
          lines: [
            { type: 'ctx', text: 'from flask import Flask, request, jsonify' },
            { type: 'add', text: 'from flask_login import login_required  # protect endpoint' },
            { type: 'ctx', text: '...' },
            { type: 'add', text: '@login_required' },
            { type: 'ctx', text: snippet.trim() || '@app.route("/endpoint", methods=["POST"])' },
            { type: 'ctx', text: 'def handle_request():' },
          ]
        };
      } else if (fw === 'fastapi') {
        return {
          file: filePath,
          lines: [
            { type: 'ctx', text: 'from fastapi import FastAPI, Depends' },
            { type: 'add', text: 'from .auth import get_current_user, User' },
            { type: 'ctx', text: '...' },
            { type: 'del', text: snippet.trim() || '@app.get("/endpoint")' },
            { type: 'add', text: '@app.get("/endpoint")' },
            { type: 'add', text: 'async def handle_request(current_user: User = Depends(get_current_user)):' },
          ]
        };
      } else if (fw === 'express') {
        return {
          file: filePath,
          lines: [
            { type: 'ctx', text: 'const express = require("express");' },
            { type: 'add', text: 'const { requireAuth } = require("../middleware/auth");' },
            { type: 'ctx', text: '...' },
            { type: 'del', text: snippet.trim() || "app.get('/endpoint', (req, res) => {" },
            { type: 'add', text: (snippet.trim() || "app.get('/endpoint', (req, res) => {").replace(/\((req,\s*res)/, 'requireAuth, ($1') },
          ]
        };
      }
      break;

    case 'RATE-001':
    case 'RATE-003':
      if (fw === 'flask') {
        return {
          file: filePath,
          lines: [
            { type: 'ctx', text: 'from flask import Flask, request' },
            { type: 'add', text: 'from flask_limiter import Limiter' },
            { type: 'add', text: 'from flask_limiter.util import get_remote_address' },
            { type: 'add', text: 'limiter = Limiter(get_remote_address, app=app, default_limits=["200/day", "50/hour"])' },
            { type: 'ctx', text: '...' },
            { type: 'add', text: '@limiter.limit("5 per minute")  # throttle sensitive route' },
            { type: 'ctx', text: snippet.trim() || '@app.route("/login", methods=["POST"])' },
          ]
        };
      } else if (fw === 'express') {
        return {
          file: filePath,
          lines: [
            { type: 'add', text: 'const rateLimit = require("express-rate-limit");' },
            { type: 'add', text: 'const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5 });' },
            { type: 'ctx', text: '...' },
            { type: 'del', text: snippet.trim() || "app.post('/login', (req, res) => {" },
            { type: 'add', text: (snippet.trim() || "app.post('/login', (req, res) => {").replace(/\((req,\s*res)/, 'authLimiter, ($1') },
          ]
        };
      }
      break;

    case 'INPUT-002':
      return {
        file: filePath,
        lines: [
          { type: 'ctx', text: '# Before: raw query concatenation or f-string susceptible to SQL injection' },
          { type: 'del', text: snippet.trim() || 'query = f"SELECT * FROM items WHERE id = {user_id}"' },
          { type: 'del', text: 'cursor.execute(query)' },
          { type: 'ctx', text: '# After: parameterized query with placeholders' },
          { type: 'add', text: 'query = "SELECT * FROM items WHERE id = ?"' },
          { type: 'add', text: 'cursor.execute(query, (user_id,))' },
        ]
      };

    case 'SECRET-001':
      return {
        file: filePath,
        lines: [
          { type: 'del', text: snippet.trim() || 'SECRET_KEY = "hardcoded-secret-key"' },
          { type: 'add', text: 'import os' },
          { type: 'add', text: 'SECRET_KEY = os.environ.get("SECRET_KEY")' },
          { type: 'add', text: 'if not SECRET_KEY:' },
          { type: 'add', text: '    raise RuntimeError("SECRET_KEY environment variable is required")' },
        ]
      };

    case 'AUTH-006':
      return {
        file: filePath,
        lines: [
          { type: 'ctx', text: 'from datetime import timedelta' },
          { type: 'add', text: 'app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=1)' },
          { type: 'add', text: 'app.config["SESSION_COOKIE_HTTPONLY"] = True' },
          { type: 'add', text: 'app.config["SESSION_COOKIE_SECURE"] = True' },
          { type: 'add', text: 'app.config["SESSION_COOKIE_SAMESITE"] = "Lax"' },
        ]
      };

    case 'AC-001':
      return {
        file: filePath,
        lines: [
          { type: 'add', text: 'from flask_wtf.csrf import CSRFProtect' },
          { type: 'add', text: 'csrf = CSRFProtect(app)' },
          { type: 'ctx', text: '...' },
          { type: 'ctx', text: '# Ensure HTML forms include <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>' },
        ]
      };

    case 'AC-003':
      return {
        file: filePath,
        lines: [
          { type: 'add', text: 'from flask_talisman import Talisman' },
          { type: 'add', text: '# Enforces HTTPS, HSTS, X-Content-Type-Options, X-Frame-Options' },
          { type: 'add', text: 'Talisman(app, content_security_policy=None)' },
        ]
      };

    case 'AUTH-010':
      return {
        file: filePath,
        lines: [
          { type: 'ctx', text: snippet.trim() || 'def register():' },
          { type: 'add', text: '    if len(password) < 12 or not any(c.isdigit() for c in password):' },
          { type: 'add', text: '        return jsonify({"error": "Password must be at least 12 chars with numbers"}), 400' },
        ]
      };

    default:
      return {
        file: filePath,
        lines: [
          { type: 'ctx', text: `# Remediation for ${f.control_id} (${f.control_name}):` },
          ...(snippet ? [{ type: 'ctx', text: snippet.trim() }] : []),
          { type: 'add', text: `# Apply required guard: ${f.remediation_hint}` },
        ]
      };
  }
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

  let trendHtml = '';
  if (r.diff) {
    const d = r.diff;
    const sign = d.scoreDelta > 0 ? '+' : '';
    const cls = d.scoreDelta > 0 ? 'up' : d.scoreDelta < 0 ? 'down' : 'same';
    const arrow = d.scoreDelta > 0 ? '▲' : d.scoreDelta < 0 ? '▼' : '=';
    trendHtml = `<span class="score-trend ${cls}" title="Score moved from ${d.prevScore} in previous scan">${arrow} ${sign}${d.scoreDelta} pts</span>`;
  }

  return `<section class="panel pad stack g18">
    <div class="row" style="gap:28px">
      <div class="row" style="gap:10px;align-items:baseline">
        <span class="score48" style="color:${scoreColor(s.posture_score)}">${s.posture_score}</span>
        <span class="mono mute" style="font-weight:500;font-size:14px">${gradeText(r)}</span>
        ${trendHtml}
      </div>
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
  const hide = f.category === 'secret_management' && !S.reveal;
  return f.evidence.map(e => {
    if (!e.file_path) {
      return `<div class="dashed" style="padding:12px 14px"><span class="eyebrow">Negative evidence · searched, not found</span>
        <span style="font-size:13px">${esc(e.note || f.message)}</span></div>`;
    }
    const loc = e.line_number ? `${e.file_path}:${e.line_number}` : e.file_path;
    const note = hide ? 'excerpt hidden · enable “Reveal secret excerpts”' : (e.note || '');
    const head = `<div class="evhead">
      <button class="click-copy mono" data-act="copyText" data-v="${esc(loc)}" title="Click to copy file location" style="color:inherit;font:inherit">${esc(loc)} <span style="font-size:10px;opacity:.6">📋</span></button>
      <span title="${esc(note)}">${esc(note)}</span>
    </div>`;
    if (hide) return `<div class="evbox">${head}</div>`;
    const ext = e.file_path.split('.').pop() || 'py';
    if (e.context && e.context.length) {
      return `<div class="evbox">${head}<div class="src">${e.context.map(([n, t]) =>
        `<div class="ln ${n === e.line_number ? 'hit' : ''}"><span class="n">${n}</span><span class="t">${highlightLine(t, ext)}</span></div>`).join('')}</div>
        <div class="legend"><span><i></i>matched line · ${e.context.length} lines of context</span></div></div>`;
    }
    return `<div class="evbox">${head}${e.snippet ? `<div class="src"><div class="ln hit"><span class="n">${e.line_number || ''}</span><span class="t">${highlightLine(e.snippet, ext)}</span></div></div>` : ''}</div>`;
  }).join('');
}

function detailHtml(f, r) {
  const ev = evidenceHtml(f);
  const diff = generateDiffLines(f, r);
  const ext = diff ? (diff.file.split('.').pop() || 'py') : 'py';
  const diffBox = diff ? `<div class="diff-box">
    <div class="diff-head">
      <span class="mono">${esc(diff.file)}</span>
      <button class="btn sm" data-act="copyDiff" data-v="${esc(f.control_id)}">Copy diff</button>
    </div>
    <div class="diff-body">${diff.lines.map(l => `<div class="diff-ln ${l.type}"><span class="sign">${l.type === 'add' ? '+' : l.type === 'del' ? '−' : ' '}</span><span class="text">${highlightLine(l.text, ext)}</span></div>`).join('')}</div>
  </div>` : '';

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

    ${f.is_gap ? `
      <div class="stack g8">
        <div class="between" style="align-items:center">
          <span class="eyebrow">Suggested fix</span>
          ${tabs([['diff', 'Unified Diff'], ['prompt', 'Fix Prompt']], S.detailTab, 'detailTab')}
        </div>
        ${S.detailTab === 'diff' ? diffBox : `
          <div class="soft">
            <div class="code">${esc(f.fix_prompt)}</div>
            <div class="row" style="margin-top:8px"><button class="btn sm" data-act="copyFix" data-v="${esc(f.control_id)}">Copy prompt</button></div>
          </div>
        `}
      </div>
    ` : ''}

    <div class="row" style="margin-top:4px">
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

  const files = uniqueFilesOf(r.findings);
  const isFiltered = S.query || S.minSev !== 'all' || S.statusFilter !== 'all' || S.fileFilter !== 'all';

  return `<div class="page w1360">
  ${scoreSection(r)}
  <div class="stack g10">
    <div class="row" style="gap:10px">
      <input class="field" data-bind="query" value="${esc(S.query)}" placeholder="Filter by id, name, category, or file (/ to focus)" style="flex:1;min-width:220px;max-width:340px" aria-label="Filter findings">
      ${tabs([['all', 'All'], ['gaps', 'Gaps only'], ['absent', 'Absent'], ['partial', 'Partial'], ['present', 'Satisfied']], S.statusFilter, 'statusFilter')}
      ${tabs([['all', 'All severities'], ['critical', 'Critical'], ['high', 'High+'], ['medium', 'Medium+'], ['low', 'Low+']], S.minSev, 'minSev')}
      ${files.length > 1 ? `
        <select class="field mono" data-act="fileFilter" style="width:auto;min-width:140px;max-width:200px" aria-label="Filter by file">
          <option value="all" ${S.fileFilter === 'all' ? 'selected' : ''}>All files (${files.length})</option>
          ${files.map(f => `<option value="${esc(f)}" ${S.fileFilter === f ? 'selected' : ''}>${esc(f)}</option>`).join('')}
        </select>` : ''}
      ${check(S.reveal, 'reveal', 'Reveal secret excerpts')}
      ${isFiltered ? `<button class="xs mute click-copy" data-act="clearFilters" style="margin-left:4px">Clear filters</button>` : ''}
      <span class="small mute" style="margin-left:auto">Showing ${shown.length} of ${r.findings.length} · <span class="kbd">J</span>/<span class="kbd">K</span> navigate</span>
    </div>
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
    ${sel ? detailHtml(sel, r) : ''}
  </div></div>`;
};

Object.assign(ACTIONS, {
  pick: v => {
    set({ sel: v });
    const detail = isNarrow() && document.querySelector('article.sticky');
    if (detail) detail.scrollIntoView({ behavior: 'smooth', block: 'start' });
  },
  reveal: () => set({ reveal: !S.reveal }),
  skipped: () => set({ showSkipped: !S.showSkipped }),
  accept: v => { S.form = { ...S.form, control: v, reason: '' }; navigate('accepted'); },
  explain: v => { S.ruleId = v; S.ruleCat = 'all'; navigate('rules'); },
  clearFilters: () => set({ query: '', minSev: 'all', statusFilter: 'all', fileFilter: 'all', showSat: false }),
  copyFix: v => {
    const f = S.report.findings.find(x => x.control_id === v);
    if (!f) return;
    navigator.clipboard.writeText(f.fix_prompt).then(() => flash('Fix prompt copied to clipboard'), () => flash('Copy failed; select text instead'));
  },
  copyDiff: v => {
    const f = S.report.findings.find(x => x.control_id === v);
    if (!f) return;
    const diff = generateDiffLines(f, S.report);
    if (!diff) return;
    const txt = `--- a/${diff.file}\n+++ b/${diff.file}\n` + diff.lines.map(l => (l.type === 'add' ? '+ ' : l.type === 'del' ? '- ' : '  ') + l.text).join('\n');
    navigator.clipboard.writeText(txt).then(() => flash('Remediation diff copied to clipboard'), () => flash('Copy failed; select text instead'));
  },
});
