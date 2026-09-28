/* Guide: how to run the app, then how to use it, step by step. */
'use strict';

const RUN = {
  windows: [
    ['Install Python 3.11 or newer', 'From python.org. During setup, tick "Add python.exe to PATH". Check it in PowerShell:', 'py -3 --version'],
    ['Get the code', 'Clone the repository and open its folder:', 'git clone https://github.com/sidhant223/ai-cyber-defense-copilot.git\ncd ai-cyber-defense-copilot'],
    ['Create a virtual environment and install', 'Once per machine. This installs the scanner; the web UI needs nothing extra.', 'py -3 -m venv .venv\n.\\.venv\\Scripts\\python.exe -m pip install -e ".[dev]"'],
    ['Start the app', 'Your browser opens http://127.0.0.1:8000 by itself. Leave this window running.', '.\\.venv\\Scripts\\python.exe web\\server.py'],
    ['Stop it when you are done', 'Press Ctrl+C in the same window. Next time, repeat only step 4.', ''],
  ],
  unix: [
    ['Install Python 3.11 or newer', 'Use your package manager or python.org. Check it:', 'python3 --version'],
    ['Get the code', 'Clone the repository and open its folder:', 'git clone https://github.com/sidhant223/ai-cyber-defense-copilot.git\ncd ai-cyber-defense-copilot'],
    ['Create a virtual environment and install', 'Once per machine. This installs the scanner; the web UI needs nothing extra.', 'python3 -m venv .venv\nsource .venv/bin/activate\npython -m pip install -e ".[dev]"'],
    ['Start the app', 'Your browser opens http://127.0.0.1:8000 by itself. Leave this terminal running.', 'python web/server.py'],
    ['Stop it when you are done', 'Press Ctrl+C in the same terminal. Next time, activate .venv and repeat only step 4.', ''],
  ],
};

const USE = [
  ['Open Scan', 'Click Scan in the menu (☰ on small screens).', 'scan'],
  ['Choose what to scan', 'Corpus sample: eight ready-made projects, a good start is flask-notes-app. Local folder: paste the full path of a project on this computer. Upload a .zip: drop a zipped project. Nothing you scan is executed.', ''],
  ['Optionally narrow the scope', 'Scope chips limit which categories are scored (the grade is then withheld). Display filters only change what is listed, never the score.', ''],
  ['Press Scan', 'The report opens as soon as the scan finishes, usually in well under a second.', ''],
  ['Read the score', 'The number is 0–100 with a grade A–F. Each bar segment is one control, wider for more severe controls, green where it is satisfied.', 'report'],
  ['Open a finding', 'Findings are grouped by category. Click one to see the exact lines of code as evidence, what is missing, and how to fix it. "Fix prompt" gives a paragraph to paste into your editor or coding assistant.', ''],
  ['Check the routes', 'Routes lists every endpoint with whether it has authentication, a rate limit and a role check. Red rows need attention.', 'routes'],
  ['Accept a risk on purpose (optional)', 'Accepted builds a suppression entry with a reason and shows how the score would change. Copy it into your project; the app never edits your files.', 'accepted'],
  ['Export the report', 'On the report, the HTML, JSON, SARIF and Markdown buttons download it. Reports are kept only until the server stops, so download what you want to keep.', ''],
  ['Fix, then scan again', 'Change your code, return to Scan and press Scan. The new score appears at the top and on Home.', ''],
];

function steps(list, withCmd) {
  return list.map(([title, text, extra], i) => `<div class="guide-step">
    <span class="num">${i + 1}</span>
    <div style="min-width:0;flex:1" class="stack g6">
      <div style="font-weight:500">${esc(title)}</div>
      <div class="mute small">${esc(text)}</div>
      ${withCmd && extra ? `<div class="cmd"><div class="code" style="padding:var(--s-8) var(--s-16)">${esc(extra)}</div><button class="btn sm" data-act="copyCmd" data-v="${esc(extra)}">Copy</button></div>` : ''}
      ${!withCmd && extra ? `<div><button class="btn-text xs" data-act="go" data-v="${extra}">Go to ${esc(TITLES[extra])} →</button></div>` : ''}
    </div></div>`).join('');
}

SCREENS.guide = () => {
  const os = S.guideOs || (navigator.platform.toLowerCase().startsWith('win') ? 'windows' : 'unix');
  return `<div class="page w1100">
  <div class="between" style="align-items:baseline">
    <h1 style="font-size:28px;font-weight:500;margin:0">Documentation & Guide</h1>
    <span class="mono xs mute">installation, workflow & reading findings</span>
  </div>

  <p class="home-sub" style="margin-top:0">Run the app on your computer, then find which security controls are missing from a project. No account, API key or internet connection is needed.</p>

  <section class="panel stack g16">
    <div class="between" style="align-items:center">
      <span class="lbl">Part 1 · Run the application</span>
      ${tabs([['windows', 'Windows'], ['unix', 'macOS / Linux']], os, 'guideOs')}
    </div>
    <div class="stack">${steps(RUN[os], true)}</div>
    <span class="xs mute">Port 8000 busy? Add <span class="mono">--port 8001</span>. Prefer not to open a browser automatically? Add <span class="mono">--no-browser</span>.</span>
  </section>

  <section class="panel stack g16">
    <span class="lbl">Part 2 · Use it step by step</span>
    <div class="stack">${steps(USE, false)}</div>
  </section>

  <section class="panel stack g16">
    <span class="lbl">Reading a finding</span>
    <div class="stack">
      <div class="row g16" style="padding:10px 0;border-bottom:1px solid var(--line)">
        <div class="row g8" style="width:140px;flex:none"><span class="status-dot absent"></span><span class="chip absent">ABSENT</span></div>
        <span class="mute small">The protection is missing everywhere it is needed.</span>
      </div>
      <div class="row g16" style="padding:10px 0;border-bottom:1px solid var(--line)">
        <div class="row g8" style="width:140px;flex:none"><span class="status-dot partial"></span><span class="chip partial">PARTIAL</span></div>
        <span class="mute small">Present in some places, forgotten in others — usually the most useful finding.</span>
      </div>
      <div class="row g16" style="padding:10px 0;border-bottom:1px solid var(--line)">
        <div class="row g8" style="width:140px;flex:none"><span class="status-dot present"></span><span class="chip present">PRESENT</span></div>
        <span class="mute small">Every place that needs it has it.</span>
      </div>
      <div class="row g16" style="padding:10px 0">
        <div class="row g8" style="width:140px;flex:none"><span class="status-dot na"></span><span class="chip na">N/A</span></div>
        <span class="mute small">Nothing in the project needs this control.</span>
      </div>
    </div>
    <span class="xs mute">A clean report means none of the ${nControls()} checks found a gap. It is not proof that the project is secure.</span>
  </section>

  <section class="panel stack g12">
    <span class="lbl">Prefer the terminal?</span>
    <div class="row g8" style="align-items:stretch">
      <div class="code" style="flex:1;padding:var(--s-8) var(--s-16)">copilot scan corpus/samples/flask-notes-app\ncopilot scan ./my-project --format html -o report.html</div>
      <button class="btn sm" data-act="copyCmd" data-v="copilot scan ./my-project --format html -o report.html">Copy</button>
    </div>
  </section></div>`;
};

Object.assign(ACTIONS, {
  guideOs: v => set({ guideOs: v }),
  copyCmd: v => navigator.clipboard.writeText(v).then(() => flash('Copied'), () => flash('Copy failed; select the text instead')),
});
