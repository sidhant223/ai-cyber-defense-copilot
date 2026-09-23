# Architecture

## The problem this shape solves

A linter finds bad code that exists. This tool finds good code that should
exist and does not. That inversion is the reason the design looks the way it
does, and it shows up in one place above all: you cannot report a missing
control until you have found the thing the control was supposed to protect.

"No authentication anywhere" is not a finding. "Six route handlers, four of
them authenticated" is. Getting from the first sentence to the second is the
entire job, and it needs two separate passes over the code: one to find out
what is there, one to work out what is missing from it.

## Three modules

```
repo path ─→ SCANNER ─→ DETECTORS (×5) ─→ REPORTER ─→ posture report
              what's       what's            how it
              there        missing           reads
```

The split is not decorative. Each module has a different failure mode, and
keeping them apart means a failure in one is diagnosable without reading the
other two.

| Module | Answers | Fails by |
|---|---|---|
| Scanner | What is in this repository? | Missing files, or guessing the framework wrong |
| Detectors | What should be here and is not? | Wrong verdict on a control |
| Reporter | How does a person read this? | Being unreadable, or lying about the score |

### Scanner (`src/copilot/scanner/`)

Reads. Runs nothing, calls nothing.

- **`walker.py`** traverses the tree, skipping vendored, generated and
  oversized files, and reads what is left into memory once. Every file is
  read exactly once per scan; the detectors never touch the filesystem.
- **`framework.py`** fingerprints the framework from two signals in priority
  order: manifest declarations (`requirements.txt`, `package.json`), then
  import patterns. It returns `None` when the signals are weak or
  contradictory. A wrong framework makes every downstream detector wrong, so
  an honest unknown is worth more than a confident guess -- framework-gated
  rules simply do not fire, and the report says which ones and why.
- **`indexer.py`** maps files to the control categories they could bear on.
  This is a recall device, not a precision device: it exists so five
  detectors do not each re-walk the tree, and so a rule about route handlers
  is never run against a README. Narrowing further is the rule file's job.

Output is a `ScanResult`: framework, language, file count, the category
index, and the file contents.

### Detectors (`src/copilot/detectors/`)

Five modules, one per control category, each a subclass of `Detector` with a
`category` and a description. **They contain almost no logic.** All five
together are under 100 lines, because the logic lives in YAML and is executed
by a shared engine.

They are independent by construction: none imports another, none holds state
between runs, each takes a `ScanResult` and returns findings. A test asserts
the no-cross-imports property structurally rather than trusting the
convention.

The one exception is `secret_management.py`, which adds two checks the rule
language genuinely cannot express -- Shannon entropy scoring, and correlating
a committed `.env` against `.gitignore`. Those controls are still *declared*
in YAML with `detection.mode: custom`, so identifiers, severities and
remediation text have exactly one home and `copilot rules explain` works for
them like anything else.

### Reporter (`src/copilot/reporter/`)

Five formats over one `Report`:

- **JSON** is the contract. Versioned by `schema_version`; the evaluation
  harness consumes it.
- **HTML** is the artefact. One self-contained file, no external requests,
  print-friendly.
- **Terminal** is the feedback loop. `rich` table, gaps only by default.
- **SARIF** is the interchange format, and the mapping is unusually direct:
  `result.kind` is defined as `pass` / `fail` / `review` / `notApplicable`,
  which is exactly this tool's four verdicts. A finding with no line to point
  at anchors to the entry point with no region rather than inventing line 1,
  and what was searched travels in `relatedLocations`.
- **Markdown** is the pull request view: gaps first, each with a fix prompt
  assembled from the control's own remediation text. No model is called.

Display filters (`--min-severity`, `--show-present`) narrow what is
*rendered*. They never change `Report.findings`, so the posture score is the
same number regardless of how you look at it. A score that moved with a
display flag would be worse than no score.

## The rule engine

This is the part that has to be right, because every detector inherits its
behaviour: a flaw here is five flaws.

### Subject and guard

The core abstraction, and what makes this an absence detector rather than a
grep:

- A **subject** is a thing that ought to be protected -- a route handler, a
  SQL statement, an upload endpoint, a secret-named assignment.
- A **guard** is evidence of protection near that subject.

The engine finds subjects, checks each for a guard within a declared scope,
counts satisfied against total, and maps the ratio to a verdict. Because it
counts, `PARTIAL` falls out naturally, and `PARTIAL` is the interesting case:
authentication applied to most routes and forgotten on two is far more common
than authentication missing entirely, and a binary scanner reports it as
present.

A guard can `require` a pattern (protection is present) or `forbid` one
(protection is present when an unsafe marker is *absent*). The forbid form is
how "this query is parameterised" is expressed without the engine
understanding SQL: the subject is the SQL statement, and it is satisfied when
no interpolation marker sits on the same line.

### Guard scope

| Scope | Meaning | Used for |
|---|---|---|
| `same_line` | The subject's own line | SQL parameterisation, env lookups |
| `proximity` | N lines above and/or below | Decorators, middleware, dependencies |
| `file` | Anywhere in the same file | Schemas, router-wide middleware |
| `project` | Anywhere in the scan | "Does this app hash passwords at all" |

`proximity` also takes `stop_at`, a pattern that halts the scan in each
direction. Without it a five-line window reaches over the end of one function
into the next, and a decorator on the following handler gets credited to this
one. Every proximity guard in the shipped rule set stops at a blank line:
decorator stacks and function signatures never contain one, but functions are
separated by one, so the boundary is exactly where the scan should stop.

A control may declare several guards; a subject is satisfied when any one of
them matches. Express is why: the same protection can be written on the route,
on the router, or where the router is mounted, and recognising only the first
reports a fully authenticated API as having no authentication at all. When a
guard other than the first one is what satisfied a subject, the evidence says
so — "satisfied by a mount somewhere in the project" is a weaker statement
than "decorated here", and the report should not present them identically.

A guard may also declare `none_of`: lines that never count as a match,
however well they match `any_of`. This is the switched-off guard, and it is
a distinct failure from a missing one. `helmet({ contentSecurityPolicy:
false })` names the middleware and disables the part the control is about;
`Field(min_length=4)` is a password policy below the floor both NIST SP
800-63B and OWASP ASVS set. Both cases used to read as protection.

Config can add guards too, per control. An in-house `@require_api_key` is as
good as `@login_required`, and the alternative to declaring it is a report
that calls every route behind it unauthenticated — which is the fastest way
to make a scanner untrustworthy.

### Presence mode

The degenerate case: does a pattern occur anywhere in scope? The verdict
block decides what found and not-found *mean*, so one mode expresses both
"a rate limiter is registered" (found → present) and "CORS is wildcarded"
(found → absent). `none_of` is the per-line allowlist, which is where
placeholders and documented example credentials get filtered out.

### Why the rules are data

Adding a sixth control category has to mean adding a YAML file, not editing
Python. That claim is load-bearing, so it is worth saying exactly what was
tested: while building the corpus, the Django sample produced nothing at all
for route authentication, because AUTH-001 matches route decorators and
Django has none. The fix was AUTH-007 -- a new control in the existing
`authentication.yaml`, with no change to the engine.

The claim was also not quite true, which a test now prevents. Every category
needed a registered `Detector` subclass or its controls were loaded and never
run; a rule file introducing a sixth category would have been silently
inert. A category with no subclass now gets `YamlOnlyDetector`, and the file
index falls back to every file for a category the indexer does not know, so
the rule's own `applies_to` narrows it. `tests/test_rule_engine.py::
TestNewCategoryIsJustAFile` adds a `transport_security` category from YAML
alone and asserts it reports.

A category can also be spread over several files -- `authentication.yaml` and
`authentication_sessions.yaml` both hold authentication controls -- so a file
can stay short enough to read. The first file's description is the category's,
so a continuation file cannot quietly rename it.

### Rules carry their own tests

Rules-as-data has a failure mode that code does not: a regex that stops
matching raises nothing. The control simply reports `ABSENT` everywhere, the
scan looks healthy, and `rules validate` passes, because the rule is
well formed and merely wrong.

So each control ships examples -- a few lines of code and the verdict it must
reach -- in `rules/tests/<category>.yaml`, and `copilot rules test` runs them
through the real pipeline: framework detection, the file index, the category's
detector. The files are held in memory rather than written to disk, through
the same `scanner.scan_files` a real scan uses, so an example cannot pass by
taking a different path than a scan would.

Every control needs at least one example that is a gap and one that is not.
Writing them found two live bugs: SECRET-005's subject required a quoted
value, so an environment read was never a subject and its `PARTIAL` verdict
was unreachable; and AUTH-010's Django branch matched any `def register(...)`,
including a plugin registry's. Both are recorded in the example files rather
than quietly fixed.

Two engine changes *did* come out of the corpus, and both generalised the
rule language rather than special-casing a sample: multiple guards per
control, and `stop_at`. That is the right kind of change to make: it is
available to every rule, not just the one that needed it.

## Verdict mapping

The four outcomes and what produces them:

| Outcome | Meaning |
|---|---|
| `PRESENT` | Every subject is guarded, or the good pattern was found |
| `PARTIAL` | Some subjects guarded, some not |
| `ABSENT` | Subjects exist and none is guarded |
| `NOT_APPLICABLE` | No subjects at all -- nothing to judge |

`NOT_APPLICABLE` is excluded from scoring. A rate limit on a login route
cannot be missing from an app with no login route, and counting it as a
failure would punish small codebases for being small.

## Posture score

```
score = 100 × Σ(weight × credit) / Σ(weight)
```

Weights are 5/3/2/1 for critical/high/medium/low. Credit is 1.0 for
`PRESENT`, 0.5 for `PARTIAL`, 0.0 for `ABSENT`. `NOT_APPLICABLE` controls are
left out of both sums.

The number is always reported next to the count of controls actually scored,
because on its own it is misleading: a repo with two applicable controls and
a repo with twenty can both score 50.

### The grade, and when there isn't one

A letter (A at 90, B at 80, C at 70, D at 60, F below) is easier to read than
a number and easier to over-read, so it carries two limits:

- **Capped at D while any critical control is `ABSENT`.** The average is a
  ratio and does not know that one of its terms is load-bearing; an app can
  average 90 with no authentication at all. The cap is only announced where
  it bites -- a 44 is an F already, and saying it was "capped at D" would be
  noise.
- **Withheld when the run was narrowed.** `--category rate_limiting` produces
  a real score for a slice of the application and nothing that supports a
  verdict on the whole of it, so `grade` is null and the report says why.

Accepted findings (see below) are excluded from the score for the same reason
`NOT_APPLICABLE` is: an accepted risk is a decision, not a measurement, and a
score that moved when somebody wrote a comment would measure the comment.

## Accepting a finding

`src/copilot/suppress.py`. A scanner that cannot be told "yes, we know" gets
switched off, and the switched-off scanner has a recall of zero -- the same
argument as the entropy threshold, applied to the tool as a whole.

An inline comment (`# copilot: ignore AUTH-001 -- behind the VPN`) takes one
subject out of both the numerator and the denominator. A `suppress:` entry in
config accepts a whole control, which is what an absence finding needs: "no
rate limiter anywhere" has no line to annotate.

Three rules keep it honest:

1. **A reason is required.** Without one the suppression does not apply and
   is reported. "Someone silenced this once" is not reviewable.
2. **An expiry is respected, and a malformed one is an error.** Snyk's
   documented behaviour -- a malformed `expires` means the ignore persists
   indefinitely -- is the failure mode being avoided.
3. **The finding stays in the report.** It leaves the gap list, the score and
   the exit code, and appears with its reason. Suppression is disclosure, not
   deletion, which is also why SARIF carries it as `suppressions[]` rather
   than omitting the result.

## The route inventory

`copilot routes` answers the question a posture report provokes: not "is
authentication present" but "on which routes". It re-uses the subject pass
rather than detecting anything of its own -- `RuleEngine.subject_hits`
exposes the per-subject results that `evaluate` reduces to one verdict -- so
the table and the report can never disagree.

A raw body read is not a route, so INPUT-001's subjects are attributed to the
nearest route above them in the same file. That is a heuristic and is labelled
as one, in the module docstring and under the table. The first version of the
command listed body-read lines as routes and claimed 17 routes in an
application with 8.

## Constraints held throughout

1. **Static analysis only.** No LLM calls, no network, no code execution, no
   telemetry.
2. **Rules in data.** A new control category is a YAML file, and a test
   asserts it.
3. **Detectors independent.** No cross-imports, no shared mutable state.
4. **Three outcomes, not two.** `PARTIAL` is the point.
5. **Every finding cites evidence.** A file and line, or an explicit
   statement of what was searched and not found.
6. **Every control carries executable examples.**
7. **Python 3.11+, stdlib-first.** `pyyaml`, `rich`, `jinja2`, `pytest`.

## Scanning itself

The tool runs against its own source in CI
(`config/self-scan.copilot.yaml`), which is worth more than it sounds: it
found two rule precision bugs that the corpus could not. `def register(cls)`
in the detector registry read as a password endpoint, and
`{"secret_management": "Secret management"}` read as a hardcoded secret.
Neither shape exists in eight generated web applications, and both are
ordinary in a Python package.

Two findings there are accepted with reasons rather than excluded: route
decorators inside docstrings, which regex cannot distinguish from code, and
rate limiting for a local single-user server bound to 127.0.0.1, and the
browser UI displaying the server's fixed error messages.

## What is deliberately not here

Fix generation, LLM integration, taint analysis and dataflow, IDE plugins,
and languages beyond Python and JavaScript/TypeScript. The absence of
dataflow is the one with a visible cost: it is why cross-module middleware
mounting cannot be resolved, which is documented as a known limitation in
`controls.md` rather than papered over.
