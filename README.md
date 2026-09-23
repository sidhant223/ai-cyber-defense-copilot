# AI Cyber Defense Copilot

A command-line tool that scans a codebase and reports which **security
controls are absent** — not which lines are buggy.

That distinction is the whole project. A linter finds bad code that exists.
This finds good code that *should* exist and doesn't: no auth on a route, no
rate limit on a login endpoint, a secret sitting in plaintext.

```
repo path ─→ SCANNER ─→ DETECTORS (×5) ─→ REPORTER ─→ posture report
              what's       what's            how it
              there        missing           reads
```

## Quick start: launch the browser app

Requirements: **Python 3.11 or newer**, Git, and an internet connection for
the initial dependency installation. Python 3.12 is a good default.
Scanning runs locally: no API key, `.env` file, database, Node.js, or Ruflo
setup is required. The applications in `corpus/samples/` are scanner fixtures;
you do not need to install or start them.

Clone this repository, then follow the commands for your operating system:

```bash
git clone https://github.com/sidhant223/ai-cyber-defense-copilot.git
cd ai-cyber-defense-copilot
```

### Windows (PowerShell)

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -e ".[web,dev]"
.\.venv\Scripts\python.exe -m streamlit run web/streamlit_app.py --server.address 127.0.0.1
```

These commands use the virtual environment directly, so PowerShell script
activation and execution-policy changes are unnecessary.

### macOS / Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[web,dev]"
python -m streamlit run web/streamlit_app.py --server.address 127.0.0.1
```

Open **http://localhost:8501**. In the **Scan** tab, choose a bundled sample
and click **Scan**, or supply a local repository path or ZIP archive. Try
`fastapi-secure-tasks` for a sample with zero reported gaps, then
`flask-notes-app` to see missing controls. Stop the server with **Ctrl+C**.
To launch again later, return to this repository and rerun the Streamlit
command (activate `.venv` first on macOS/Linux).

## Command-line installation

If you only need the CLI, install `-e .` instead of `-e ".[web,dev]"` in the
virtual environment above. `[web]` adds the browser UI; `[dev]` adds pytest.

The examples below use `copilot` from an activated virtual environment.
On Windows, you can replace it with `.\.venv\Scripts\copilot.exe` without
activation. `python -m copilot.cli` is an equivalent entry point when `python`
refers to the virtual environment.

```bash
copilot scan corpus/samples/fastapi-secure-tasks --summary-only
copilot scan corpus/samples/flask-notes-app --format html -o report.html --exit-zero
```

The first command should report **0 gaps** and **score 100**. Open
`report.html` in a browser to view the second command's findings. A scan that
finds gaps normally exits with code `1`; that is a scan result, not a crash.

### Troubleshooting

| Problem | Fix |
|---|---|
| `py` or `python3` is not found | Install Python 3.11+ and reopen your terminal. On Windows, try `python` if the `py` launcher is unavailable. |
| Linux cannot create a virtual environment | Install your distribution's Python venv package, then rerun `python3 -m venv .venv`. |
| `No module named streamlit` or `copilot` | Run the install command with the same virtual-environment Python used to launch the app. |
| `copilot` is not recognized | Use the virtual environment's executable, or `python -m copilot.cli`. |
| `web/streamlit_app.py` cannot be found | Change into the cloned repository root before launching. |
| Port 8501 is in use | Add `--server.port 8502` and open http://localhost:8502. |
| A path contains spaces | Quote it, for example `copilot scan "C:/Projects/My App"`. |
| Clone fails for a private repository | Sign in to GitHub with an account that has access to this repository. |

## Use

```bash
copilot scan ./repo                                 # terminal output
copilot scan ./repo --format html -o report.html    # self-contained page
copilot scan ./repo --format json -o report.json    # the machine contract
copilot scan ./repo --format sarif -o out.sarif     # GitHub code scanning, IDEs
copilot scan ./repo --format markdown               # PR comment or job summary
copilot scan ./repo --category authentication,rate_limiting
copilot scan ./repo --min-severity high
copilot scan ./repo --show-present                  # include satisfied controls

copilot routes ./repo                               # every route and what protects it
copilot routes ./repo --unprotected-only

copilot rules list                                  # every loaded control
copilot rules explain AUTH-001                      # what it checks, and why
copilot rules validate                              # rule files are well formed
copilot rules test                                  # run every control's examples

copilot init                                        # write a .copilot.yaml

copilot evaluate --split dev                        # scanner vs corpus/manifest.yaml
copilot evaluate --split holdout                    # the only reportable accuracy
copilot evaluate --split all --format json -o eval.json
```

### Exit codes

| Code | Means |
|---|---|
| `0` | No gaps, or every gap accepted, or `--exit-zero` |
| `1` | A gap remains, or the score is below `--fail-under` |
| `2` | The scan could not run: bad path, bad config, bad rule file |

```bash
copilot scan ./repo --fail-on critical    # gate on severity, not on any finding
copilot scan ./repo --fail-under 70       # gate on the posture score
copilot scan ./repo --exit-zero           # report without gating
```

`routes`, `rules list`, `rules explain` and `evaluate` never gate: they exit
`0` whatever they find, and `2` only when they could not run.

## In CI

```yaml
# .github/workflows/security.yml in a repository you want to scan
name: Security controls
on: [push, pull_request]
permissions:
  contents: read
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - uses: sidhant223/ai-cyber-defense-copilot@main
        with:
          path: .
          fail-on: critical    # or fail-under: 70
```

The action writes `copilot.sarif`, appends the Markdown report to the job
summary, and exposes `score`, `grade` and `gaps` as step outputs. Pin a commit
SHA for a stable integration. If this repository is private, GitHub must
allow the consuming repository to access its action.

This repository's [CI workflow](.github/workflows/ci.yml) runs the tests,
rule examples, corpus evaluation, and a self-scan. It saves SARIF as a
downloadable workflow artifact. To also upload it to GitHub code scanning,
enable code scanning for the repository and set the Actions repository
variable `ENABLE_CODE_SCANNING` to `true`.

Also available as a pre-commit hook, which runs over the whole tree rather
than the staged files, because a limiter registered in one file protects
routes declared in another:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/sidhant223/ai-cyber-defense-copilot
    rev: main  # replace with a commit SHA to pin the hook
    hooks: [{id: copilot-scan}]
```

and as a container, mounted read-only because the tool reads code, runs
nothing and writes nothing:

```bash
docker build -t copilot .
docker run --rm -v "$PWD:/repo:ro" copilot scan .
```

## Accepting a finding

A scanner that cannot be told "yes, we know" gets switched off. Two ways to
say it, both requiring a reason:

```python
@app.route("/internal/metrics")   # copilot: ignore AUTH-001 -- behind the VPN
def metrics(): ...
```

```yaml
# .copilot.yaml
suppress:
  - control: RATE-001
    reason: rate limiting is enforced at the API gateway
    expires: 2026-12-31

guards:                       # protections this codebase writes its own way
  AUTH-001: ['@require_api_key']
```

An accepted finding stays in the report and leaves the gap list, the posture
score and the exit code. A suppression with no reason, or past its expiry,
does not apply and is reported as not applied -- a malformed date is an error
rather than an ignore that lasts forever.

`guards:` is the other half of the same problem: an in-house
`@require_api_key` is as good as `@login_required`, and without declaring it
the tool reports every route behind it as unauthenticated.

## Web UI

For a point-and-click version — pick a folder, hit Scan, read the findings in
the browser:

```bash
python -m pip install -e ".[web]"
python -m streamlit run web/streamlit_app.py --server.address 127.0.0.1
```

Opens on <http://localhost:8501>. Three tabs:

- **Scan** — choose a corpus sample, type a local path, or upload a `.zip`.
  Filter by category and severity, then download the HTML or JSON report.
- **Rules** — all 28 controls in a table; pick one to see its subject regex,
  guards, scopes, verdict mapping and remediation. This is `rules explain`
  with a mouse.
- **How it works** — the status vocabulary, the scoring formula, and the
  known limits.

Reports download as HTML, JSON, SARIF or Markdown. Everything the scanned
repository produced is HTML-escaped before it reaches the page: an evidence
note quotes a matched line, and a scanned file can contain anything.

It is a presentation layer only. It calls `scan()` and `run_all()` — the same
two functions `cli.py` calls — so there is no second implementation to drift.
Nothing about detection lives in `web/`.

## What it reports

Three outcomes, not two:

| Status | Meaning |
|---|---|
| `PRESENT` | Every subject is guarded |
| `PARTIAL` | Some guarded, some not |
| `ABSENT` | Subjects exist, none guarded |
| `NOT_APPLICABLE` | No subjects — nothing to judge |

`PARTIAL` is the interesting one. Authentication applied to most routes and
forgotten on two is far more common than authentication missing entirely, and
a binary scanner calls that "present".

Every finding also carries a CWE and an OWASP Top 10 (2021) reference, a
confidence, and a fingerprint that is built from the control, the file and
the subject text rather than the line number, so it survives edits above it.

Every finding cites evidence: a file and line, or an explicit statement of
what was searched and not found.

```
AUTH-001  partial  critical  4 of 6 HTTP route handler(s) are authenticated; 2 are not.
                             app.py:95  - no guard within 4 lines above or 8 below
                                 @app.route("/notes/<int:note_id>", methods=["PUT"])
                             app.py:107 - no guard within 4 lines above or 8 below
                                 @app.route("/notes/<int:note_id>", methods=["DELETE"])
```

## Controls

Twenty-eight across five categories. Full detail, including known
limitations, in [docs/controls.md](docs/controls.md).

| Category | Covers |
|---|---|
| Authentication | Route-level auth (Flask, FastAPI, Django, Express), CSRF on cookie sessions, session cookie flags, session and token expiry, password storage and strength |
| Input validation | Body schemas, query parameterisation, upload restrictions, shell execution |
| Rate limiting | Limiter registration, global default, credential endpoints |
| Secret management | Provider key formats, connection strings, entropy, `.env` handling, env-sourced config |
| Access control | CORS, debug mode, security headers, admin role checks, host allowlist, exception detail in responses |

Frameworks: Flask, FastAPI, Django, Express, Next.js. Languages: Python,
JavaScript, TypeScript. Anything else runs the framework-agnostic controls
and the report says which were skipped and why.

## Posture score

```
score = 100 × Σ(weight × credit) / Σ(weight)
```

Weights 5/3/2/1 for critical/high/medium/low; credit 1.0 present, 0.5 partial,
0.0 absent. `NOT_APPLICABLE` controls are excluded from both sums, and so are
accepted findings.

The score is always shown next to the number of controls actually scored,
because on its own it is misleading. Display filters never move it.

A letter grade sits next to it — A at 90, B at 80, C at 70, D at 60 — under
two rules that keep it from over-claiming:

- **Capped at D while any critical control is absent.** A weighted average
  can reach 90 with no authentication anywhere, and calling that an A would
  be the score lying by omission.
- **Withheld entirely when `--category` narrowed the run.** A grade reads as
  a verdict on the whole application; a run covering two categories cannot
  support one. The score is still shown, next to what it describes.

## Rules are data

Every detector is driven by a YAML file in `src/copilot/rules/`. Adding a
control means adding YAML, not editing Python — the five detector modules
together are under 100 lines.

```yaml
- id: AUTH-001
  name: Route-level authentication (Python)
  severity: critical
  applies_to:
    frameworks: [flask, fastapi]
    index_buckets: [routes]
  detection:
    subject:                     # the thing that should be protected
      pattern: '@(?:app|router)\.(?:route|get|post|put|delete|patch)\s*\('
      description: HTTP route handler
      exclude: ['["'']/?(?:login|health|metrics)']
    guard:                       # evidence that it is
      proximity_lines: 4
      proximity_lines_below: 8
      stop_at: '^\s*$'
      any_of:
        - '@(?:login_required|jwt_required)'
        - 'Depends\s*\(\s*[A-Za-z_.]*current_user'
  verdict:
    all_subjects_guarded: present
    some_subjects_guarded: partial
    no_subjects_guarded: absent
    no_subjects_found: not_applicable
```

The subject/guard split is what makes this an absence detector rather than a
grep: it can only report "unprotected route" because it first found the
route. See [docs/architecture.md](docs/architecture.md).

A guard can also carry `none_of`: lines that never count as protection,
however well they match. That is how a switched-off guard is caught —
`helmet({ contentSecurityPolicy: false })` names the middleware and disables
the part the control is about, and `Field(min_length=4)` is a password rule
below the floor both NIST and OWASP set.

### Rules carry their own tests

A regex rule breaks silently: a pattern that stops matching reports the
control absent everywhere and nothing crashes. So every control ships with
example code and the verdict it must reach, in
`src/copilot/rules/tests/<category>.yaml`, and each one needs at least one
example that is a gap and one that is not:

```yaml
AUTH-001:
  - name: decorated route is authenticated
    expect: present
    files:
      app.py: |
        from flask import Flask
        app = Flask(__name__)

        @login_required
        @app.route("/notes")
        def notes(): ...
```

```bash
copilot rules test                      # 82 examples, through the real pipeline
copilot rules test --control AUTH-001
```

Writing those examples is what found two live bugs in the shipped rules: a
control whose `PARTIAL` verdict was unreachable, and a subject pattern that
matched any function called `register`.

## Test corpus

Eight labelled dev samples in [corpus/](corpus/): six realistic applications
and two negative controls, each with the exact prompt that generated it and a
hand-written ground-truth entry in `manifest.yaml`.

Nothing is a planted flaw. Every gap recorded is something an AI coding tool
omitted on its own, given a prompt that never mentioned security. Method and
caveats in [corpus/README.md](corpus/README.md).

The negative controls exist because a scanner that flags everything is
useless: `fastapi-secure-tasks` scores 100 with zero gaps.

| Sample | Score | Grade |
|---|---|---|
| `fastapi-secure-tasks` (negative control) | 100 | A |
| `express-secure-notes` (negative control) | 94 | A |
| `express-admin-panel` | 60 | D |
| `flask-notes-app` | 46 | F |
| `django-blog` | 44 | F |
| `fastapi-bookstore` | 44 | F |
| `express-todo-api` | 42 | F |
| `flask-file-share` | 31 | F |

Not one of the eight has a CSRF defence, including both samples whose
prompts asked for security controls.

**No accuracy figure is claimed yet.** The eight samples are the `dev` split:
the rules were tuned until they matched them, so their precision and recall
are circular by construction and serve only as a regression signal
(currently TP 81 · FP 0 · FN 0 · TN 143). Accuracy will be `copilot evaluate
--split holdout`, run on samples labelled before the scanner ever saw them,
once that split exists.

The four controls added in September 2026 were labelled by a pass that read
only the sample code — never the rules or the scanner's output — and all 32
labels agreed with what the tool reports. That is a real signal and still not
accuracy, for the reason above; the method and the ten judgement calls are in
[corpus/README.md](corpus/README.md).

## Tests

Run from the repository root after installing `.[dev]` (included in the
quick-start installation):

```bash
python -m pytest -q
copilot rules test        # 82 rule examples
copilot rules validate    # every rule file is well formed
copilot evaluate --split dev
```

Unit tests per detector, all four verdict paths through the rule engine, CLI
exit codes and formats, suppression and grade rules, the route inventory, and
an integration pass asserting the full pipeline against the dev samples in
`corpus/manifest.yaml`. Every false positive found during development became a
permanent regression test.

The tool also scans itself in CI:

```bash
copilot scan . --config config/self-scan.copilot.yaml
# 28 checks · 11 applicable · 0 gaps · score 100 · 2 accepted
```

Two findings on its own source are accepted in that config, with reasons: a
pair of route decorators that live inside docstrings, and rate limiting for a
tool that has no HTTP server. Both are the documented cost of matching lines
with regexes instead of parsing them. Scanning itself is also how two rule
precision bugs were found — see `config/self-scan.copilot.yaml`.

## Constraints

1. **Static analysis only.** No LLM calls, no network, no code execution, no
   telemetry. Nothing this tool does needs a connection.
2. **Rules in data.** A new control category is a YAML file — including the
   Python side, since a category declared only in a rule file still runs.
3. **Detectors independent.** No cross-imports, no shared mutable state — and
   a test that checks it structurally.
4. **Three outcomes, not two.**
5. **Every finding cites evidence.**
6. **Every control carries examples**, and they run in CI.
7. **Python 3.11+, stdlib-first.** `pyyaml`, `rich`, `jinja2`, `pytest`.

## Not in scope

Fix generation, LLM integration, taint analysis, IDE plugins, languages beyond
Python and JavaScript/TypeScript. The missing dataflow analysis has a visible
cost — cross-module middleware cannot be resolved — which is documented as a
limitation rather than papered over.

## Layout

```
src/copilot/
├── cli.py              entry point
├── models.py           Finding, ScanResult, Report, score and grade
├── config.py           .copilot.yaml: filters, guards, suppressions
├── suppress.py         accepting a finding, inline and in config
├── routes.py           the route inventory
├── rules_test.py       running a control's examples
├── rules_validate.py   checking rule files without scanning
├── scanner/            walker, framework detection, indexer
├── detectors/          base + registry, rule engine, five detectors
├── rules/              the YAML rule set
│   └── tests/          each control's executable examples
└── reporter/           terminal, json, html, sarif, markdown
web/streamlit_app.py    optional browser UI over the same pipeline
corpus/                 labelled samples + ground truth
config/                 the self-scan config used in CI
docs/                   architecture, controls, phase-by-phase progress
tests/                  unit, engine, cli, suppression, routes, end-to-end
action.yml              GitHub Action
Dockerfile              container entry point
.pre-commit-hooks.yaml  pre-commit hook definitions
```
