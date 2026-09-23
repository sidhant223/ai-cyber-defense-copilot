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
    <div style="min-width:0"><b>${esc(title)}</b><span class="ink2">${esc(text)}</span>
      ${withCmd && extra ? `<div class="cmd"><div class="code">${esc(extra)}</div><button data-act="copyCmd" data-v="${esc(extra)}">Copy</button></div>` : ''}
      ${!withCmd && extra ? `<div style="margin-top:8px"><button class="btn sm" data-act="go" data-v="${extra}">Go to ${esc(TITLES[extra])} →</button></div>` : ''}
    </div></div>`).join('');
}

SCREENS.guide = () => {
  const os = S.guideOs || (navigator.platform.toLowerCase().startsWith('win') ? 'windows' : 'unix');
  return `<div class="page w880" style="padding-top:28px;gap:24px">
  <div class="stack g8"><h1 style="font-size:28px;font-weight:600;letter-spacing:-.02em">Guide</h1>
    <p class="ink2" style="font-size:15px">Run the app on your computer, then find which security controls are missing from a project. No account, API key or internet connection is needed.</p></div>
  <section class="stack g10">
    <div class="between"><h2 style="font-size:18px;font-weight:600">Part 1 · Run the application</h2>
      ${tabs([['windows', 'Windows'], ['unix', 'macOS / Linux']], os, 'guideOs')}</div>
    <div class="panel">${steps(RUN[os], true)}</div>
    <span class="small mute">Port 8000 busy? Add <span class="mono">--port 8001</span>. Prefer not to open a browser automatically? Add <span class="mono">--no-browser</span>.</span>
  </section>
  <section class="stack g10">
    <h2 style="font-size:18px;font-weight:600">Part 2 · Use it</h2>
    <div class="panel">${steps(USE, false)}</div>
  </section>
  <section class="stack g10">
    <h2 style="font-size:18px;font-weight:600">Reading a finding</h2>
    <div class="panel" style="padding:14px 18px;display:grid;grid-template-columns:auto 1fr;gap:10px 16px;align-items:center">
      <span class="tag inline" style="color:var(--absent)">ABSENT</span><span>The protection is missing everywhere it is needed.</span>
      <span class="tag inline" style="color:var(--partial)">PARTIAL</span><span>Present in some places, forgotten in others — usually the most useful finding.</span>
      <span class="tag inline" style="color:var(--present)">PRESENT</span><span>Every place that needs it has it.</span>
      <span class="tag inline" style="color:var(--na)">N/A</span><span>Nothing in the project needs this control.</span>
    </div>
    <span class="small mute">A clean report means none of the 28 checks found a gap. It is not proof that the project is secure.</span>
  </section>
  <section class="stack g10">
    <h2 style="font-size:18px;font-weight:600">Prefer the terminal?</h2>
    <div class="cmd"><div class="code">copilot scan corpus/samples/flask-notes-app\ncopilot scan ./my-project --format html -o report.html</div>
      <button data-act="copyCmd" data-v="copilot scan ./my-project --format html -o report.html">Copy</button></div>
  </section></div>`;
};

Object.assign(ACTIONS, {
  guideOs: v => set({ guideOs: v }),
  copyCmd: v => navigator.clipboard.writeText(v).then(() => flash('Copied'), () => flash('Copy failed; select the text instead')),
});
