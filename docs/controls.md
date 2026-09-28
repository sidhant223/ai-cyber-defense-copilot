# Controls

Forty-three controls across eight categories. Each one is defined in a YAML
file under `src/copilot/rules/` and can be interrogated live:

```bash
copilot rules list
copilot rules explain AUTH-001
copilot rules test --control AUTH-001   # run its examples
```

Every control carries a CWE and an OWASP Top 10 (2021) reference, so a
verdict can be checked against something other than this tool's opinion, and
at least two executable examples in `src/copilot/rules/tests/` -- one that
must come back a gap and one that must not.

This document covers what each control means, why it is worth checking, and
where it is known to be wrong.

---

## Authentication

Whether the application establishes *who* is calling.

| ID | Control | Severity | Mode |
|---|---|---|---|
| AUTH-001 | Route-level authentication (Flask, FastAPI) | critical | subject/guard |
| AUTH-002 | Route-level authentication (Express, Next.js) | critical | subject/guard |
| AUTH-003 | Password hashing | critical | subject/guard |
| AUTH-004 | Password hashing algorithm is not MD5 or SHA-1 | high | presence |
| AUTH-005 | Secure session cookie flags | high | subject/guard |
| AUTH-006 | Session expiry configured | medium | subject/guard |
| AUTH-007 | View-level authentication (Django) | critical | subject/guard |
| AUTH-008 | CSRF protection where a cookie session authenticates | high | subject/guard |
| AUTH-009 | Issued authentication tokens expire | high | subject/guard |
| AUTH-010 | Password strength enforced where a password is set | medium | subject/guard |

AUTH-008 to AUTH-010 live in `authentication_sessions.yaml` rather than
`authentication.yaml`. The engine merges rule files by category, so a second
file is a data change like any other; the split exists to keep both files
short.

**AUTH-001 / AUTH-002 / AUTH-007** are the same control in three dialects,
because the three frameworks put the check in three different places: a
decorator above the route, a middleware argument in the route call, and a
decorator above a plain view function. Each finds route handlers and checks
each for an authentication guard nearby.

Some endpoints are unauthenticated by design, and flagging them is the
fastest way to make a scanner untrustworthy. `login`, `register`, `token`,
`logout`, `health`, `metrics`, `docs` and static paths are excluded as
subjects. `/` is excluded in AUTH-001 (a Flask landing page) but *not* in
AUTH-002, because an Express router is mounted under a prefix and
`router.get('/')` is the collection endpoint.

**AUTH-003** is one of the few genuinely presence-shaped checks here, and
that is fine: if an application handles passwords and no hashing function
appears anywhere in it, they are stored in a recoverable form. The guard is
project-scoped because the hashing call is often in a different module from
the password handling. Django satisfies it through `django.contrib.auth`,
which is what actually does the hashing there.

**AUTH-005 / AUTH-006** only fire where real session machinery exists --
`app.secret_key`, `SessionMiddleware`, `express-session`, `session[...]`. An
earlier version also treated any `SECRET_KEY` as a session, which reported
missing cookie flags on stateless token APIs. A token-signing key is not a
session.

**AUTH-008** shares that subject, for the same reason: CSRF is a cookie
problem. A bearer token in an `Authorization` header is not attached by the
browser to a cross-site request, so a token API is `NOT_APPLICABLE` rather
than unprotected. A `SameSite` attribute on the cookie does not satisfy the
control -- OWASP treats it as defence in depth, not as a CSRF defence -- and
the guard is project-scoped because the middleware is registered once,
usually in a different file from the session it protects.

Known limitation: a global kill switch in another file (`WTF_CSRF_ENABLED =
False`, or a `@csrf_exempt` on one view) is not seen, so the control reports
`PRESENT` for an app that registered the middleware and then turned it off.
Line-level switch-offs *are* caught, through a guard's `none_of`.

**AUTH-009** is deliberately severity `high`, one step above session expiry:
a signed token has no server-side record to delete, so without an `exp` claim
there is no revocation path short of rotating the signing key.

**AUTH-010** counts a minimum length or a strength check, not a character-class
rule, and rejects a minimum below eight characters through the guard's
`none_of` -- eight is the floor in both NIST SP 800-63B and OWASP ASVS, so
`Field(min_length=4)` is a check that does not count. Login and token
endpoints are not subjects: a policy can only be applied where a password is
chosen.

---

## Input validation

Whether data crossing the trust boundary is constrained before use.

| ID | Control | Severity | Mode |
|---|---|---|---|
| INPUT-001 | Request body validated against a schema | high | subject/guard |
| INPUT-002 | Database queries are parameterised | critical | subject/guard |
| INPUT-003 | File uploads restricted by type and size | high | subject/guard |
| INPUT-004 | No shell execution on request-derived input | critical | presence |

**INPUT-001** finds raw body reads (`request.get_json()`, `req.body`,
`request.POST`) and looks for a schema in the same file: Pydantic,
marshmallow, a DRF serializer, zod, Joi, express-validator.

A FastAPI app that declares Pydantic models as handler parameters has *no
raw reads*, so this comes back `NOT_APPLICABLE` rather than `PRESENT`. That
is the honest answer: there was nothing to judge, because validation is
structural rather than a step someone remembered.

**INPUT-002** is the clearest use of the inverted guard. The subject is a SQL
statement in a string literal; the guard `forbid`s interpolation markers on
the same line -- f-string prefixes, `+` concatenation, `%` formatting,
`.format(`, `${}`. A statement with none of those is parameterised. The
engine never needs to understand SQL.

Making the SQL string the subject rather than the `execute()` call matters:
it catches `query = f"SELECT ..."` built on one line and executed on another.

**INPUT-004** is presence-shaped and inverted: finding `shell=True`,
`os.system`, `eval` on request data, or `pickle.loads` means the control is
absent. A `# nosec` annotation on the line suppresses it.

---

## Rate limiting

| ID | Control | Severity | Mode |
|---|---|---|---|
| RATE-001 | Rate limiting middleware registered | high | presence |
| RATE-002 | Credential endpoints rate limited | high | subject/guard |
| RATE-003 | Global default limit configured | medium | presence |

**RATE-001** is the cheapest check in the tool and it fails on most generated
applications. Without it the other two are moot.

**RATE-002** is the one that matters. Login, registration, password reset and
token endpoints are where credential stuffing lands, and a global default
sized for normal browsing is far too generous for them. This control is
separate from RATE-001 on purpose: an app can have a limiter and still leave
`/login` on the default.

**RATE-003** exists because a limiter with no default only protects the routes
someone remembered to decorate.

---

## Secret management

| ID | Control | Severity | Mode |
|---|---|---|---|
| SECRET-001 | No credentials in recognised provider formats | critical | presence |
| SECRET-002 | No credentials embedded in connection strings | critical | presence |
| SECRET-003 | No high-entropy literals in source | high | custom (Python) |
| SECRET-004 | Environment files excluded from version control | high | custom (Python) |
| SECRET-005 | Secret configuration read from the environment | high | subject/guard |

**SECRET-001** matches known key formats by prefix and length: AWS, Stripe,
GitHub, GitLab, Google, Slack, SendGrid, Twilio, DigitalOcean, npm, PEM
private key headers, JWTs. A match here is a near-certain live credential
rather than a heuristic, which is why it is critical. Documented example keys
(`AKIAIOSFODNN7EXAMPLE`) and obvious placeholders are allowlisted.

**SECRET-002** matches URLs carrying a password. Placeholder passwords
(`:password@`, `:changeme@`, `${VAR}`) are allowlisted.

### SECRET-003 and the entropy threshold

The threshold is **4.0 bits per character** over literals of at least 20
characters, and it is chosen against the alphabets rather than tuned against
a sample:

- Lowercase hex (`0-9a-f`) tops out at exactly log₂(16) = 4.0, so ordinary
  hashes, git SHAs and UUIDs sit just under the line and never fire.
- Base64 and mixed alphanumerics top out near log₂(64) = 6.0, and real random
  keys in those alphabets measure 4.5 to 5.5.

**This trades recall for precision, deliberately.** A bare 32-character hex
API key will not be caught by entropy alone. SECRET-001 catches the branded
ones by prefix, which is the higher-confidence signal anyway.

The reasoning: false positives destroy trust in a scanner faster than false
negatives do. An entropy check that fires on every checksum in a lockfile
gets switched off, and a switched-off check has a recall of zero. A check
that misses some unbranded keys but is believed when it does fire is worth
more.

To keep the recall loss bounded, the threshold is two-tier. A literal on a
line whose identifier looks credential-bearing (`api_key = "..."`) is flagged
at 4.0; a literal with no such context needs 4.5.

**Allowlists** — a literal is never reported when:

- its path is under `tests/`, `fixtures/`, `examples/`, `docs/`,
  `migrations/`, or is a lockfile or a `.md`
- it reads as a placeholder (`your-key`, `changeme`, `xxxxxx`, `<...>`)
- it is structurally not a secret: a URL, a filesystem path, a hostname, a
  UUID, a number
- it contains `{...}` — that is an f-string body, not a credential. This one
  came from the corpus: `f"{form.username}{datetime.now()}"` scores 4.03.
- it has fewer than 8 distinct characters (separators, padding)

Reported values are **redacted** to first four, last four and a length. A
posture report gets shared; it should not be a second copy of the secret.

**SECRET-004** correlates a `.env` in the tree against `.gitignore` rules.
`.env.example` and friends are meant to be committed and are excluded. No
`.env` at all is `NOT_APPLICABLE`, not `PRESENT`.

**SECRET-005** finds secret-named assignments and requires the value to come
from the environment on the same line. This is the control that produces
`PARTIAL` usefully: three secrets read from `os.environ` and one hardcoded is
exactly the state real codebases are in.

That claim used to be false, and writing the control's examples is what
showed it. The subject pattern required a quote after the separator, so
`SECRET_KEY = os.environ["SECRET_KEY"]` was not a subject at all and the
control could only report `ABSENT` or `NOT_APPLICABLE` -- never the `PARTIAL`
described above. The subject now matches a literal **or** an environment
read, which is what makes the ratio meaningful, and it moved both hardened
corpus samples from `NOT_APPLICABLE` to `PRESENT`: they do read their secrets
from the environment, and the control now says so.

---

## Access control configuration

| ID | Control | Severity | Mode |
|---|---|---|---|
| AC-001 | CORS policy is not wildcard or origin-reflecting | high | presence |
| AC-002 | Debug mode not enabled | medium | presence |
| AC-003 | Response security headers set | medium | presence |
| AC-004 | Administrative routes carry a role check | high | subject/guard |
| AC-005 | Host allowlist is not wildcard (Django) | medium | presence |
| AC-006 | Error responses do not carry exception detail | medium | presence |

**AC-001** catches `origins="*"`, reflected origins, and — importantly — the
bare `CORS(app)` and `cors()` calls, both of which default to allowing any
origin. The insecure state is the one you get by writing *less* code, which
is exactly the shape this tool exists to find.

**AC-004** is the classic broken-access-control shape: the admin route is
behind `login_required`, and any logged-in user can reach it. Authentication
is not authorisation. The guard list is deliberately disjoint from AUTH-001's
— `login_required` does not satisfy AC-004.

Note that `Depends(require_admin)` *does* satisfy AUTH-001, because a role
dependency authenticates before it authorises. AC-004 is what judges whether
the role check itself is there.

**AC-006** is inverted presence: finding `err.stack`, `str(e)` or
`traceback.format_exc()` on its way into a response body means the control is
absent. Lines that log rather than respond are allowlisted, because logging
the detail is the correct handling -- `console.error(err.stack)` next to a
generic `res.status(500)` is what present looks like. Debug mode is judged by
AC-002 instead, so the two do not double-count the same leak.

---

## Web security

The browser-facing protections that AC-003 only samples.

| ID | Control | Severity | Mode |
|---|---|---|---|
| WEB-001 | Content-Security-Policy defined | medium | presence |
| WEB-002 | HSTS enabled | medium | presence |
| WEB-003 | No open redirects | medium | subject/guard |
| WEB-004 | Outbound TLS verification not disabled | high | presence (inverted) |
| WEB-005 | CSRF protection not switched off | medium | presence (inverted) |

**WEB-001 / WEB-002** pass on any one security header in AC-003's terms, so
they ask for the two headers that matter most by name. `helmet()` and
`Talisman()` count, because both send a CSP and HSTS by default; switching
either off in the same call (`contentSecurityPolicy: false`) does not. Both
apply only to recognised web frameworks, and both carry medium confidence,
because a header set by a reverse proxy is invisible to a code scan. Accept
the control in `.copilot.yaml` when that is the case.

**WEB-003** takes a redirect whose argument comes from the request (or a
variable named `next…`) as its subject, and looks a few lines above for a
check that keeps the target on-site. `redirect(url_for(..., next=...))` is
excluded: `next` there is an argument, not the target.

**WEB-005** complements AUTH-008. AUTH-008 asks whether a CSRF defence exists;
WEB-005 asks whether it was then switched off (`@csrf_exempt`,
`WTF_CSRF_ENABLED = False`). A signed webhook is a legitimate exemption.
Accept it inline, with the reason.

---

## Logging & error handling

Whether the application leaves a trail and fails safely.

| ID | Control | Severity | Mode |
|---|---|---|---|
| LOG-001 | Application logging configured | low | presence |
| LOG-002 | Authentication events logged | medium | subject/guard |
| LOG-003 | Secrets not written to logs | high | presence (inverted) |
| LOG-004 | Central error handler registered (Express, Koa) | medium | presence |
| LOG-005 | Exceptions not silently swallowed | low | subject/guard (forbid) |

**LOG-002** reuses RATE-002's credential-endpoint subject and looks for a log
call in the handler body, up to the next route.

**LOG-003** matches a credential *interpolated into* or *passed to* a log call,
not a message that merely names one: `log.warning("invalid password for %s",
email)` is fine, while `log.info(f"... {password}")` is not. Identifiers of
something else (`token_id`, `password_reset`) are skipped.

**LOG-004** is judged for Express and Koa only. Their default error response
carries the stack trace unless `NODE_ENV` is production. Flask, FastAPI and
Django answer an unhandled error with a generic 500 when debug is off, and
debug mode is AC-002's job.

**LOG-005** takes an `except` or `catch` whose line ends at its opening colon or
brace, and flags an empty body (`pass`, `{}`, or a lone `}` on the next line).
A one-line handler with a body is not judged. A deliberate swallow should be
accepted with its reason, as this repository's own self-scan config does.

---

## Injection & unsafe code

Injection paths that INPUT-002 (SQL) and INPUT-004 (shell, `eval`,
`pickle.loads`) do not cover.

| ID | Control | Severity | Mode |
|---|---|---|---|
| INJ-001 | No NoSQL operator injection | high | presence (inverted) |
| INJ-002 | No unsafe deserializers | critical | presence (inverted) |
| INJ-003 | Outbound requests not built from request input (SSRF) | high | subject/guard |
| INJ-004 | File paths not built from request input | high | subject/guard |
| INJ-005 | User input not rendered as raw HTML | high | presence (inverted) |

**INJ-002** deliberately leaves out `pickle.loads` and a bare `yaml.load`,
which INPUT-004 already judges, so one line is never penalised twice. It
covers the rest of the family: `pickle.load`, `marshal`, `dill`, `joblib`,
`shelve`, `jsonpickle`, `yaml.load(..., Loader=yaml.Loader)` and
`node-serialize`.

**INJ-003 / INJ-004** only recognise request input on the line where it is
used. See *Request input is recognised per line* below. INJ-004 also takes
a client-supplied upload name (`file.filename`, multer's `originalname`) as
request input.

**INJ-005** lists the ways escaping is bypassed: `render_template_string` or
`Markup` over request data, `autoescape=False`, `dangerouslySetInnerHTML`,
`innerHTML`, `document.write`, `res.send` of request data, and raw template
output (`<%-`, `{{{`). It cannot tell whether the value was sanitised first,
which is why this repository accepts it for its own UI.

**Corpus coverage.** None of the eight labelled samples contains an injection
flaw of these kinds, so these five controls are measured only by their rule
examples until a holdout sample exercises them.

---

## Known limitations

Stated rather than hidden, because a scanner you cannot calibrate is a
scanner you cannot use.

### Cross-module middleware

Express mounts authentication where the router is attached:

```js
// server.js
app.use('/admin', requireLogin, adminRoutes);
```

Nothing in `routes/admin.js` says those routes are protected. Resolving which
router that mount refers to needs module-level dataflow analysis, which is
out of scope.

AUTH-002 handles this with a project-scoped third guard: a mount naming auth
middleware *anywhere* in the project satisfies every route. This is a real
precision loss — one such mount will mask a genuinely unprotected router — and
it is chosen over the alternative, which was reporting a fully authenticated
API as having none. `corpus/samples/express-admin-panel` records the case.

### Mount prefixes are not resolved

For the same reason, AC-004 reports `NOT_APPLICABLE` for
`express-admin-panel`: the admin prefix lives on the mount, so no route path
inside `routes/admin.js` contains `/admin`.

### Request input is recognised per line

WEB-003, INJ-003 and INJ-004 look for request input (`request.args`,
`req.query`, an upload's filename) on the same line as the redirect, fetch or
file call. A value copied into a variable first is missed:

```python
url = request.args["url"]
requests.get(url)          # not a subject
```

Following it would need dataflow analysis, the same limit as cross-module
middleware above. These controls therefore under-report rather than
over-report.

### Regex, not a parser

Line-level regex with comment stripping. Whole-line comments are blanked so
commented-out code is not counted, but trailing comments are left alone and
multi-line constructs can defeat proximity windows. A route decorator split
across four lines with a blank in the middle will be misjudged.

An AST pass would fix this for Python. It is not here because regex plus a
disciplined subject/guard split gets most of the value at a fraction of the
complexity, and the rule format would have to change to support it.

### Framework coverage

Flask, FastAPI, Django, Express and Next.js. Anything else scans with only
the framework-agnostic controls — every secret control, INPUT-002,
INPUT-004, AC-001 to AC-003. The report lists what was skipped and why rather
than silently returning a thin result.

### Only the first N pieces of evidence

Findings cap at 12 pieces of evidence. Counts in the message are complete; the
list is not.

### A guard can be switched off in another file

A guard's `none_of` catches a guard that is disabled *on its own line*
(`helmet({ contentSecurityPolicy: false })`, `Field(min_length=4)`). It
cannot catch a kill switch somewhere else in the project -- `WTF_CSRF_ENABLED
= False`, a `@csrf_exempt` on one view, `DEFAULT_PERMISSION_CLASSES` relaxed
in settings. Resolving those needs the same cross-module reasoning as
middleware mounting, so they are listed here rather than half-detected.

---

## Severity

| Severity | Weight | Meaning |
|---|---|---|
| critical | 5 | Directly exploitable, or a live credential |
| high | 3 | Materially widens the attack surface |
| medium | 2 | Defence in depth; exploitable in combination |
| low | 1 | Hardening |

Weights feed the posture score. They are judgement calls, and reasonable
people would move some of them: the point is that they are in one place, in
data, and changing one is a one-line edit to a YAML file.
