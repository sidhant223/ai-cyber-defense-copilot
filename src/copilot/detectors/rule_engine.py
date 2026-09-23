"""YAML-driven rule loading and evaluation.

Adding a sixth control category must mean adding a YAML file, not editing
Python. Everything in this module is generic: it knows about subjects,
guards, scopes and verdicts, and nothing about authentication or CORS.

Two evaluation modes cover every rule in the shipped rule set:

``subject_guard``
    Find the things that *should* be protected (subjects), then check each
    one for protection (a guard) within a declared scope. Count satisfied
    versus unsatisfied and map the ratio to a verdict. This is what makes
    the tool an absence detector rather than a grep: it can only report
    "unprotected route" because it first found the route.

    A guard may ``require`` a pattern (protection is present) or ``forbid``
    one (protection is present when an unsafe marker is *not* there). The
    forbid form is what expresses "this query is parameterised".

``presence``
    Does a pattern occur anywhere in scope, in file contents or in file
    paths? The verdict block decides what found and not-found *mean*, so
    the same mode expresses both "a rate limiter is registered" (found ->
    present) and "CORS is set to wildcard" (found -> absent).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

import yaml

from .. import suppress
from ..models import Confidence, Evidence, ScannedFile, ScanResult, Severity, Status

DEFAULT_RULES_DIR = Path(__file__).resolve().parent.parent / "rules"

MAX_EVIDENCE = 12
SNIPPET_LIMIT = 200

_STATUS_BY_NAME = {s.value: s for s in Status}
_SEVERITY_BY_NAME = {s.value: s for s in Severity}
_CONFIDENCE_BY_NAME = {c.value: c for c in Confidence}

_COMMENT_PREFIXES = ("#", "//", "*", "/*", '"""', "'''")

#: Standards reference formats. Checked at load time because a typo in a
#: reference is worse than a missing one: it points a reader at the wrong
#: weakness with the same authority as a correct one.
CWE_FORMAT = re.compile(r"^CWE-\d{1,4}$")
OWASP_FORMAT = re.compile(r"^A\d{2}:\d{4}$")


class RuleError(ValueError):
    """A rule file is malformed. Raised at load time, never at scan time."""


# --------------------------------------------------------------------------
# glob handling
# --------------------------------------------------------------------------

def glob_to_regex(pattern: str) -> re.Pattern[str]:
    """Translate a ``**``-aware glob into a regex anchored at both ends.

    ``fnmatch`` treats ``*`` as crossing directory separators, which makes
    ``**/routes/*.py`` and ``*/routes/*.py`` mean the same thing. They do not.
    """
    out: list[str] = ["^"]
    i = 0
    while i < len(pattern):
        ch = pattern[i]
        if pattern.startswith("**/", i):
            out.append("(?:[^/]+/)*")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif ch == "*":
            out.append("[^/]*")
            i += 1
        elif ch == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(ch))
            i += 1
    out.append("$")
    return re.compile("".join(out))


def path_matches(path: str, patterns: list[re.Pattern[str]]) -> bool:
    return any(p.search(path) for p in patterns)


# --------------------------------------------------------------------------
# rule model
# --------------------------------------------------------------------------

@dataclass
class AppliesTo:
    frameworks: list[str] = field(default_factory=list)
    languages: list[str] = field(default_factory=list)
    file_patterns: list[str] = field(default_factory=list)
    index_buckets: list[str] = field(default_factory=list)
    exclude_patterns: list[str] = field(default_factory=list)

    _compiled: list[re.Pattern[str]] = field(default_factory=list, repr=False)
    _excluded: list[re.Pattern[str]] = field(default_factory=list, repr=False)

    def __post_init__(self) -> None:
        self._compiled = [glob_to_regex(p) for p in self.file_patterns]
        self._excluded = [glob_to_regex(p) for p in self.exclude_patterns]

    def framework_ok(self, framework: str | None) -> bool:
        if not self.frameworks:
            return True
        return framework is not None and framework in self.frameworks

    def file_ok(self, f: ScannedFile) -> bool:
        if self.languages and f.language not in self.languages:
            return False
        if self._excluded and path_matches(f.path, self._excluded):
            return False
        if self._compiled and not path_matches(f.path, self._compiled):
            return False
        return True


@dataclass
class Subject:
    pattern: re.Pattern[str]
    description: str
    exclude: list[re.Pattern[str]] = field(default_factory=list)

    def matches(self, line: str) -> bool:
        if not self.pattern.search(line):
            return False
        return not any(x.search(line) for x in self.exclude)


@dataclass
class Guard:
    patterns: list[re.Pattern[str]]
    #: Lines that never count as a guard match, however well they match
    #: ``patterns``. This is how a switched-off guard is expressed:
    #: ``helmet({ contentSecurityPolicy: false })`` names the middleware and
    #: disables exactly the part the control is about.
    anti_patterns: list[re.Pattern[str]] = field(default_factory=list)
    mode: str = "require"          # require | forbid
    scope: str = "proximity"       # same_line | proximity | file | project
    lines_above: int = 5
    lines_below: int = 0
    description: str = ""
    #: Proximity scans stop when they reach a line matching this (the line is
    #: still checked). Without it a window of N lines reaches over the end of
    #: one function into the next, and a decorator on the following handler is
    #: credited to this one. Typically '^\s*$': decorator stacks and function
    #: signatures never contain a blank line, but functions are separated by
    #: one, so the boundary is exactly where the scan should stop.
    stop_at: re.Pattern[str] | None = None

    def window(self, lines: list[str], subject_line: int) -> tuple[int, int]:
        """0-based [start, end) slice of ``lines`` this guard may look at."""
        idx = subject_line - 1
        if self.scope == "same_line":
            return idx, idx + 1
        if self.scope == "file":
            return 0, len(lines)
        return max(0, idx - self.lines_above), min(len(lines), idx + self.lines_below + 1)


@dataclass
class ControlRule:
    id: str
    name: str
    category: str
    severity: Severity
    mode: str
    verdict: dict[str, Status]
    remediation_hint: str
    description: str = ""
    rationale: str = ""
    applies_to: AppliesTo = field(default_factory=AppliesTo)
    subject: Subject | None = None
    #: A subject is satisfied when ANY of these guards is satisfied. Several
    #: are needed because one protection can be written at more than one
    #: level -- a decorator on the route, a router-wide `router.use(...)`, or
    #: middleware named where the router is mounted.
    guards: list[Guard] = field(default_factory=list)
    patterns: list[re.Pattern[str]] = field(default_factory=list)
    anti_patterns: list[re.Pattern[str]] = field(default_factory=list)
    match_target: str = "content"   # content | path
    ignore_comments: bool = True
    partial_threshold: float = 1.0
    source_file: str = ""
    #: Declared in YAML; None means the evaluator's default applies.
    confidence: Confidence | None = None
    #: Standards references, e.g. ``CWE-306`` and ``A07:2021``. They give a
    #: reader somewhere to check the judgement other than this tool.
    cwe: str = ""
    owasp: str = ""

    def status_for(self, key: str, default: Status) -> Status:
        return self.verdict.get(key, default)

    @property
    def guard(self) -> Guard | None:
        """The primary guard. Used for messages and for `rules explain`."""
        return self.guards[0] if self.guards else None


# --------------------------------------------------------------------------
# parsing
# --------------------------------------------------------------------------

def _compile_all(patterns: Iterable[str], flags: int, where: str) -> list[re.Pattern[str]]:
    compiled = []
    for p in patterns:
        try:
            compiled.append(re.compile(p, flags))
        except re.error as exc:
            raise RuleError(f"{where}: bad regex {p!r}: {exc}") from exc
    return compiled


def _flags_from(spec: dict[str, Any]) -> int:
    flags = 0
    for name in spec.get("flags", []) or []:
        if name in ("i", "ignorecase"):
            flags |= re.IGNORECASE
        elif name in ("s", "dotall"):
            flags |= re.DOTALL
        elif name in ("m", "multiline"):
            flags |= re.MULTILINE
        else:
            raise RuleError(f"unknown regex flag {name!r}")
    return flags


def _parse_verdict(spec: dict[str, Any], control_id: str) -> dict[str, Status]:
    out: dict[str, Status] = {}
    for key, value in (spec or {}).items():
        if value not in _STATUS_BY_NAME:
            raise RuleError(f"{control_id}: unknown verdict status {value!r}")
        out[key] = _STATUS_BY_NAME[value]
    return out


def parse_control(spec: dict[str, Any], category: str, source_file: str) -> ControlRule:
    try:
        control_id = spec["id"]
        name = spec["name"]
        severity_name = spec["severity"]
    except KeyError as exc:
        raise RuleError(f"{source_file}: control missing required key {exc}") from exc

    if severity_name not in _SEVERITY_BY_NAME:
        raise RuleError(f"{control_id}: unknown severity {severity_name!r}")
    confidence_name = spec.get("confidence")
    if confidence_name is not None and str(confidence_name) not in _CONFIDENCE_BY_NAME:
        raise RuleError(f"{control_id}: unknown confidence {confidence_name!r}")

    cwe = str(spec.get("cwe") or "").strip()
    if cwe and not CWE_FORMAT.match(cwe):
        raise RuleError(f"{control_id}: cwe must look like 'CWE-306' (got {cwe!r})")
    owasp = str(spec.get("owasp") or "").strip()
    if owasp and not OWASP_FORMAT.match(owasp):
        raise RuleError(f"{control_id}: owasp must look like 'A07:2021' (got {owasp!r})")

    detection = spec.get("detection") or {}
    mode = detection.get("mode", "subject_guard")
    if mode not in ("subject_guard", "presence", "custom"):
        raise RuleError(f"{control_id}: unknown detection mode {mode!r}")

    applies = spec.get("applies_to") or {}
    applies_to = AppliesTo(
        frameworks=list(applies.get("frameworks") or []),
        languages=list(applies.get("languages") or []),
        file_patterns=list(applies.get("file_patterns") or []),
        index_buckets=list(applies.get("index_buckets") or []),
        exclude_patterns=list(applies.get("exclude_patterns") or []),
    )

    subject = None
    guards: list[Guard] = []
    patterns: list[re.Pattern[str]] = []
    anti_patterns: list[re.Pattern[str]] = []

    if mode == "custom":
        # Metadata-only. The owning detector implements the check in Python
        # because the rule language genuinely cannot express it (entropy
        # scoring, cross-file correlation). Keeping the id, severity and
        # remediation text here means `copilot rules explain` still works and
        # there is exactly one place that defines a control.
        pass
    elif mode == "subject_guard":
        subj_spec = detection.get("subject")
        if not subj_spec or "pattern" not in subj_spec:
            raise RuleError(f"{control_id}: subject_guard needs detection.subject.pattern")
        sflags = _flags_from(subj_spec)
        subject = Subject(
            pattern=_compile_all([subj_spec["pattern"]], sflags, control_id)[0],
            description=subj_spec.get("description", "subject"),
            exclude=_compile_all(subj_spec.get("exclude") or [], sflags, control_id),
        )
        # `guard:` is the single-guard shorthand; `guards:` is a list. A
        # subject is satisfied when any listed guard is satisfied.
        guard_specs = detection.get("guards")
        if guard_specs is None:
            guard_specs = [detection["guard"]] if detection.get("guard") else []
        if not guard_specs:
            raise RuleError(
                f"{control_id}: subject_guard needs detection.guard or detection.guards")
        for guard_spec in guard_specs:
            if not guard_spec.get("any_of"):
                raise RuleError(f"{control_id}: every guard needs any_of")
            gmode = guard_spec.get("mode", "require")
            if gmode not in ("require", "forbid"):
                raise RuleError(f"{control_id}: guard.mode must be require or forbid")
            scope = guard_spec.get("scope", "proximity")
            if scope not in ("same_line", "proximity", "file", "project"):
                raise RuleError(f"{control_id}: unknown guard.scope {scope!r}")
            guards.append(Guard(
                patterns=_compile_all(guard_spec["any_of"], _flags_from(guard_spec),
                                      control_id),
                anti_patterns=_compile_all(guard_spec.get("none_of") or [],
                                           _flags_from(guard_spec), control_id),
                mode=gmode,
                scope=scope,
                lines_above=int(guard_spec.get("proximity_lines", 5)),
                lines_below=int(guard_spec.get("proximity_lines_below", 0)),
                description=guard_spec.get("description", ""),
                stop_at=(_compile_all([guard_spec["stop_at"]], 0, control_id)[0]
                         if guard_spec.get("stop_at") else None),
            ))
        modes = {g.mode for g in guards}
        if len(modes) > 1:
            raise RuleError(
                f"{control_id}: all guards must share a mode; got {sorted(modes)}")
    else:
        pat_spec = detection.get("patterns")
        if not pat_spec or not pat_spec.get("any_of"):
            raise RuleError(f"{control_id}: presence needs detection.patterns.any_of")
        pflags = _flags_from(pat_spec)
        patterns = _compile_all(pat_spec["any_of"], pflags, control_id)
        anti_patterns = _compile_all(pat_spec.get("none_of") or [], pflags, control_id)

    match_target = (detection.get("patterns") or {}).get("match", "content")
    if match_target not in ("content", "path"):
        raise RuleError(f"{control_id}: patterns.match must be content or path")

    return ControlRule(
        id=control_id,
        name=name,
        category=category,
        severity=_SEVERITY_BY_NAME[severity_name],
        mode=mode,
        verdict=_parse_verdict(spec.get("verdict"), control_id),
        remediation_hint=(spec.get("remediation_hint") or "").strip(),
        description=(spec.get("description") or "").strip(),
        rationale=(spec.get("rationale") or "").strip(),
        applies_to=applies_to,
        subject=subject,
        guards=guards,
        patterns=patterns,
        anti_patterns=anti_patterns,
        match_target=match_target,
        ignore_comments=bool(detection.get("ignore_comments", True)),
        partial_threshold=float(spec.get("partial_threshold", 1.0)),
        source_file=source_file,
        confidence=_CONFIDENCE_BY_NAME.get(str(confidence_name)),
        cwe=cwe,
        owasp=owasp,
    )


def load_rule_file(path: Path) -> tuple[str, str, list[ControlRule]]:
    """Return ``(category, description, controls)`` for one YAML rule file."""
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise RuleError(f"{path.name}: invalid YAML: {exc}") from exc
    category = data.get("category")
    if not category:
        raise RuleError(f"{path.name}: missing top-level 'category'")
    controls = [parse_control(c, category, path.name) for c in (data.get("controls") or [])]
    return category, (data.get("description") or "").strip(), controls


# --------------------------------------------------------------------------
# evaluation
# --------------------------------------------------------------------------

def strip_comment_lines(lines: list[str]) -> list[str]:
    """Blank out whole-line comments.

    Commented-out code is the realistic false-positive source -- a
    ``# @app.route("/admin")`` left behind should not be counted as an
    unprotected route. Trailing comments are left alone; they almost never
    carry a route decorator, and parsing them properly needs a lexer.
    """
    out = []
    for line in lines:
        stripped = line.lstrip()
        out.append("" if stripped.startswith(_COMMENT_PREFIXES) else line)
    return out


@dataclass
class SubjectHit:
    file_path: str
    line_number: int
    snippet: str
    satisfied: bool
    guard_line: int | None = None
    guard_snippet: str | None = None
    #: Which guard matched, when it was not the control's first one. Naming it
    #: is what makes a loose guard visible: "satisfied by a mount somewhere in
    #: the project" is a weaker statement than "decorated here", and the
    #: report should not present them identically.
    guard_description: str = ""


class RuleEngine:
    """Loads rule files once and evaluates controls against a ScanResult."""

    def __init__(self, rules_dir: str | Path | None = None) -> None:
        self.rules_dir = Path(rules_dir) if rules_dir else DEFAULT_RULES_DIR
        self.categories: dict[str, str] = {}
        self._controls: list[ControlRule] = []
        self.load()

    # -- loading ---------------------------------------------------------

    def load(self) -> None:
        self.categories.clear()
        self._controls.clear()
        if not self.rules_dir.is_dir():
            raise RuleError(f"rules directory not found: {self.rules_dir}")
        seen: dict[str, str] = {}
        for path in sorted(self.rules_dir.glob("*.yaml")):
            category, description, controls = load_rule_file(path)
            # A category may be spread over several files -- authentication.yaml
            # and authentication_sessions.yaml both hold authentication
            # controls. The first file's description is the category's, so a
            # continuation file cannot quietly rename the category.
            if not self.categories.get(category):
                self.categories[category] = description
            for control in controls:
                if control.id in seen:
                    raise RuleError(
                        f"duplicate control id {control.id} in {path.name} "
                        f"(already defined in {seen[control.id]})"
                    )
                seen[control.id] = path.name
            self._controls.extend(controls)

    def add_guard_patterns(self, control_id: str, patterns: list[str]) -> None:
        """Register extra guard patterns for one control.

        This is how a codebase's own protection gets recognised: an in-house
        ``@require_api_key`` is as good as ``@login_required``, and without
        this the tool reports every route behind it as unauthenticated. The
        patterns arrive as one more guard, cloned from the control's first
        guard so they are searched in the same scope and direction -- a
        subject is satisfied when any guard matches.
        """
        control = self.get(control_id)
        if control is None:
            raise RuleError(f"guards: no such control: {control_id}")
        if control.mode != "subject_guard" or not control.guards:
            raise RuleError(f"guards: {control.id} is a {control.mode} control, which "
                            f"has no guards to extend")
        template = control.guards[0]
        control.guards.append(Guard(
            patterns=_compile_all(patterns, 0, f"guards: {control.id}"),
            mode=template.mode,
            scope=template.scope,
            lines_above=template.lines_above,
            lines_below=template.lines_below,
            description=f"{template.description or 'guarded'} (declared in config)",
            stop_at=template.stop_at,
        ))

    def controls(self, category: str | None = None) -> list[ControlRule]:
        if category is None:
            return list(self._controls)
        return [c for c in self._controls if c.category == category]

    def get(self, control_id: str) -> ControlRule | None:
        for c in self._controls:
            if c.id.lower() == control_id.lower():
                return c
        return None

    # -- file selection --------------------------------------------------

    def applicable_files(self, control: ControlRule, scan: ScanResult) -> list[ScannedFile]:
        """Files this control should look at: the category index, optionally
        narrowed to structural buckets, then filtered by the rule's globs.

        Buckets are a union, not an intersection: ``[source, config]`` means
        "source files or config files", which is what a rule author writing
        that list means. Intersecting them silently produced an empty set for
        every multi-bucket rule.
        """
        # A category the indexer does not know about (one declared only in a
        # rule file) has no index entry, so start from every file and let the
        # rule's own buckets and globs narrow it. An existing category always
        # has an entry, even when the list is empty, so this changes nothing
        # for the five shipped ones.
        candidates = (scan.files_for(control.category)
                      if control.category in scan.file_index else list(scan.files))
        buckets = control.applies_to.index_buckets
        if buckets:
            allowed: set[str] = set()
            for bucket in buckets:
                allowed.update(scan.file_index.get(bucket, []))
            candidates = [f for f in candidates if f.path in allowed]
        return [f for f in candidates if control.applies_to.file_ok(f)]

    def skip_reason(self, control: ControlRule, scan: ScanResult) -> str | None:
        """Why this control cannot be judged here, or None if it can be."""
        if not control.applies_to.framework_ok(scan.framework):
            wanted = ", ".join(control.applies_to.frameworks)
            actual = scan.framework or "unknown"
            return f"applies to {wanted}; detected framework is {actual}"
        if not self.applicable_files(control, scan):
            return "no files matched this control's file patterns"
        return None

    # -- evaluation ------------------------------------------------------

    def evaluate(self, control: ControlRule, scan: ScanResult):
        """Evaluate one control. Returns a Finding, or None if not judgeable."""
        from ..models import Finding

        if control.mode == "custom":
            raise RuleError(
                f"{control.id} is a custom control; its detector implements it")
        if self.skip_reason(control, scan) is not None:
            return None
        files = self.applicable_files(control, scan)
        if control.mode == "subject_guard":
            return self._eval_subject_guard(control, files, scan)
        return self._eval_presence(control, files, scan)

    # -- subject/guard ---------------------------------------------------

    def _lines_for(self, control: ControlRule, f: ScannedFile) -> list[str]:
        return strip_comment_lines(f.lines) if control.ignore_comments else f.lines

    def subject_hits(self, control: ControlRule,
                     scan: ScanResult) -> list[SubjectHit]:
        """Every subject this control found, guarded or not.

        ``evaluate`` reduces these to one verdict, which is the right summary
        and the wrong thing for "show me each route and what protects it".
        ``copilot routes`` uses this; nothing is re-detected for it.
        """
        if control.mode != "subject_guard" or self.skip_reason(control, scan):
            return []
        hits, _ = self._collect_hits(control, self.applicable_files(control, scan), scan)
        return hits

    def _collect_hits(self, control: ControlRule, files: list[ScannedFile],
                      scan: ScanResult | None = None
                      ) -> tuple[list[SubjectHit], list[Evidence]]:
        """``(hits, accepted)`` -- the subject pass, shared by both callers."""
        assert control.subject and control.guards
        guards = control.guards
        mode = guards[0].mode
        hits: list[SubjectHit] = []
        accepted: list[Evidence] = []
        suppressions = scan.inline_suppressions if scan is not None else {}

        # A project-scoped guard is resolved once, not per subject.
        project_hits: dict[int, tuple[int, str]] = {}
        for gi, guard in enumerate(guards):
            if guard.scope != "project":
                continue
            for f in files:
                lines = self._lines_for(control, f)
                found = _find_guard(guard, lines, 0, len(lines))
                if found:
                    project_hits[gi] = found
                    break

        for f in files:
            lines = self._lines_for(control, f)
            for i, line in enumerate(lines, start=1):
                if not control.subject.matches(line):
                    continue
                snippet = line.strip()[:SNIPPET_LIMIT]
                accepted_here = suppress.for_subject(suppressions, control.id, f.path, i)
                if accepted_here is not None:
                    # Out of both the numerator and the denominator: the reason
                    # travels with the report instead.
                    accepted.append(Evidence(
                        file_path=f.path, line_number=i, snippet=snippet,
                        note=f"accepted: {accepted_here.reason}"))
                    continue
                found: tuple[int, str] | None = None
                matched = 0
                for gi, guard in enumerate(guards):
                    if guard.scope == "project":
                        found = project_hits.get(gi)
                    else:
                        start, end = guard.window(lines, i)
                        found = _find_guard(guard, lines, start, end, subject_idx=i - 1)
                    if found is not None:
                        matched = gi
                        break
                # require: a guard must be found. forbid: none may be.
                satisfied = (found is not None) if mode == "require" else (found is None)
                hits.append(SubjectHit(
                    f.path, i, snippet, satisfied,
                    found[0] if found else None,
                    found[1] if found else None,
                    guards[matched].description if found and matched else "",
                ))
        return hits, accepted

    def _eval_subject_guard(self, control: ControlRule, files: list[ScannedFile],
                            scan: ScanResult | None = None):
        from ..models import Finding

        hits, accepted = self._collect_hits(control, files, scan)
        total = len(hits)
        satisfied_hits = [h for h in hits if h.satisfied]
        unsatisfied = [h for h in hits if not h.satisfied]
        searched_note = (f"searched {len(files)} indexed file(s) for "
                         f"{control.subject.description}")
        accepted_note = (f" {len(accepted)} accepted inline." if accepted else "")

        if total == 0 and accepted:
            status = control.status_for("no_subjects_found", Status.NOT_APPLICABLE)
            message = (f"Every {control.subject.description} found "
                       f"({len(accepted)}) was accepted inline, so there is nothing "
                       f"left to judge.")
            evidence = accepted
        elif total == 0:
            status = control.status_for("no_subjects_found", Status.NOT_APPLICABLE)
            message = (f"No {control.subject.description} found, so this control has "
                       f"nothing to protect.")
            evidence = [Evidence(file_path="", note=f"{searched_note}; 0 matched")]
        elif not satisfied_hits:
            status = control.status_for("no_subjects_guarded", Status.ABSENT)
            message = (f"{total} {control.subject.description}(s) found, none "
                       f"{_verb(control.guard)}.")
            evidence = _hit_evidence(unsatisfied, control, satisfied=False)
            evidence.append(Evidence(
                file_path="", note=f"{searched_note}; {total} matched, 0 satisfied"))
        elif len(satisfied_hits) == total:
            status = control.status_for("all_subjects_guarded", Status.PRESENT)
            message = (f"All {total} {control.subject.description}(s) are "
                       f"{_verb(control.guard)}.")
            evidence = _hit_evidence(satisfied_hits, control, satisfied=True)
        else:
            status = control.status_for("some_subjects_guarded", Status.PARTIAL)
            message = (f"{len(satisfied_hits)} of {total} "
                       f"{control.subject.description}(s) are {_verb(control.guard)}; "
                       f"{len(unsatisfied)} are not.")
            evidence = _hit_evidence(unsatisfied, control, satisfied=False)

        if accepted and total:
            # The counts above describe what was judged; this says what was
            # taken out of them, so the two add up.
            message += accepted_note
            evidence = evidence + accepted

        return Finding(
            control_id=control.id,
            control_name=control.name,
            category=control.category,
            status=status,
            severity=control.severity,
            message=message,
            evidence=evidence[:MAX_EVIDENCE],
            remediation_hint=control.remediation_hint,
            confidence=control.confidence or Confidence.MEDIUM,
        )

    # -- presence --------------------------------------------------------

    def _eval_presence(self, control: ControlRule, files: list[ScannedFile],
                       scan: ScanResult | None = None):
        from ..models import Finding

        matches: list[Evidence] = []
        suppressions = scan.inline_suppressions if scan is not None else {}
        for f in files:
            if control.match_target == "path":
                for pattern in control.patterns:
                    if pattern.search(f.path):
                        matches.append(Evidence(
                            file_path=f.path, line_number=None, snippet=None,
                            note=f"path matched {pattern.pattern}"))
                        break
                continue
            lines = self._lines_for(control, f)
            for i, line in enumerate(lines, start=1):
                # none_of is the allowlist: a line that trips it is never a
                # match, however well it matches any_of. This is where
                # placeholders and example credentials get filtered out.
                if any(a.search(line) for a in control.anti_patterns):
                    continue
                if suppress.for_subject(suppressions, control.id, f.path, i):
                    continue
                for pattern in control.patterns:
                    if pattern.search(line):
                        matches.append(Evidence(
                            file_path=f.path, line_number=i,
                            snippet=line.strip()[:SNIPPET_LIMIT],
                            note=f"matched {pattern.pattern}"))
                        break
                if len(matches) >= MAX_EVIDENCE:
                    break
            if len(matches) >= MAX_EVIDENCE:
                break

        target = "file paths" if control.match_target == "path" else "file contents"
        if matches:
            status = control.status_for("found", Status.PRESENT)
            message = f"{control.name}: matched in {len(matches)} location(s)."
            evidence = matches
        else:
            status = control.status_for("not_found", Status.ABSENT)
            message = f"{control.name}: no match anywhere in scope."
            evidence = [Evidence(
                file_path="",
                note=(f"searched {target} of {len(files)} indexed file(s) against "
                      f"{len(control.patterns)} pattern(s); found nothing"),
            )]

        return Finding(
            control_id=control.id,
            control_name=control.name,
            category=control.category,
            status=status,
            severity=control.severity,
            message=message,
            evidence=evidence[:MAX_EVIDENCE],
            remediation_hint=control.remediation_hint,
            confidence=control.confidence or Confidence.MEDIUM,
        )


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def _match_line(guard: Guard, lines: list[str], j: int) -> tuple[int, str] | None:
    if any(a.search(lines[j]) for a in guard.anti_patterns):
        return None          # named but switched off: not protection
    for pattern in guard.patterns:
        if pattern.search(lines[j]):
            return j + 1, lines[j].strip()[:SNIPPET_LIMIT]
    return None


def _find_guard(guard: Guard, lines: list[str], start: int, end: int,
                subject_idx: int | None = None) -> tuple[int, str] | None:
    """Search a guard's window for a match.

    Proximity scans walk outward from the subject rather than straight through
    the window, so that ``stop_at`` can cut them off at a boundary in each
    direction independently.
    """
    if subject_idx is None or guard.scope != "proximity" or guard.stop_at is None:
        for j in range(start, end):
            hit = _match_line(guard, lines, j)
            if hit:
                return hit
        return None

    hit = _match_line(guard, lines, subject_idx)
    if hit:
        return hit
    for direction, bound in ((-1, start - 1), (1, end)):
        j = subject_idx + direction
        while (j > bound) if direction < 0 else (j < bound):
            hit = _match_line(guard, lines, j)
            if hit:
                return hit
            if guard.stop_at.search(lines[j]):
                break
            j += direction
    return None


def _verb(guard: Guard) -> str:
    if guard.description:
        return guard.description
    return "guarded" if guard.mode == "require" else "free of the unsafe pattern"


def _scope_note(guard: Guard) -> str:
    if guard.scope == "same_line":
        return "on the same line"
    if guard.scope == "file":
        return "anywhere in the same file"
    if guard.scope == "project":
        return "anywhere in the project"
    below = f" or {guard.lines_below} below" if guard.lines_below else ""
    stop = ", not crossing a blank line" if guard.stop_at else ""
    return f"within {guard.lines_above} lines above{below}{stop}"


def _hit_evidence(hits: list[SubjectHit], control: ControlRule,
                  satisfied: bool) -> list[Evidence]:
    guards = control.guards
    assert guards
    mode = guards[0].mode
    # With several guards the negative evidence has to name every place that
    # was searched, otherwise "no guard within 4 lines" understates the work.
    where = " or ".join(dict.fromkeys(_scope_note(g) for g in guards))
    out = []
    for h in hits[:MAX_EVIDENCE]:
        if satisfied:
            note = (f"guard found {where}" if mode == "require"
                    else f"no unsafe marker {where}")
            if h.guard_description:
                note += f" [{h.guard_description}]"
            if h.guard_snippet and mode == "require":
                note += f": {h.guard_snippet}"
        else:
            note = (f"no guard {where}" if mode == "require"
                    else f"unsafe marker {where}"
                         + (f": {h.guard_snippet}" if h.guard_snippet else ""))
        out.append(Evidence(
            file_path=h.file_path,
            line_number=h.line_number,
            snippet=h.snippet,
            note=note,
        ))
    return out
