"""Accepting a finding on purpose.

A scanner that cannot be told "yes, we know" gets switched off. Two routes
exist here, because an absence finding often has no line to annotate:

**Inline**, on or just above the line being judged::

    @app.route("/internal/metrics")   # copilot: ignore AUTH-001 -- behind the VPN
    def metrics(): ...

**In config**, for a whole control::

    suppress:
      - control: RATE-001
        reason: rate limiting is enforced at the API gateway
        expires: 2026-12-31

Both require a reason. A suppression with no reason is not applied and is
reported, because "someone silenced this once" is not a decision anyone can
review later. An expired suppression is likewise not applied and is reported
-- the opposite of the Snyk behaviour where a malformed expiry means the
ignore lasts forever.

A suppressed finding is kept in the report and excluded from the gap list,
the posture score and the exit code. It is an accepted risk, not a
disappeared one.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import date

#: ``# copilot: ignore AUTH-001, AC-004 -- reason``, in any comment syntax the
#: scanned languages use. The reason runs to the end of the line.
SUPPRESS_RE = re.compile(
    r"(?:#|//|/\*|<!--|--)\s*copilot:\s*ignore\s+"
    r"(?P<ids>[A-Za-z][A-Za-z0-9-]*(?:\s*,\s*[A-Za-z][A-Za-z0-9-]*)*)"
    r"(?P<rest>.*)$"
)

#: What separates the control ids from the reason.
REASON_RE = re.compile(r"^\s*(?:--|:)\s*(?P<reason>\S.*?)\s*(?:\*/|-->)?\s*$")


@dataclass(frozen=True)
class InlineSuppression:
    file_path: str
    line: int
    control_ids: tuple[str, ...]
    reason: str
    problem: str = ""          # non-empty means it was not applied

    @property
    def valid(self) -> bool:
        return not self.problem

    def covers(self, control_id: str) -> bool:
        return self.valid and control_id.upper() in self.control_ids

    def describe(self) -> str:
        where = f"{self.file_path}:{self.line}"
        if self.problem:
            return f"{where}: {self.problem}"
        return f"{where}: {', '.join(self.control_ids)} -- {self.reason}"


@dataclass
class ConfigSuppression:
    """One ``suppress:`` entry from ``.copilot.yaml``."""

    control: str
    reason: str
    expires: date | None = None

    def active(self, today: date) -> bool:
        return self.expires is None or today <= self.expires

    def describe(self) -> str:
        until = f" (until {self.expires.isoformat()})" if self.expires else ""
        return f"{self.control}{until} -- {self.reason}"


@dataclass
class SuppressionReport:
    """What was accepted, and what was ignored rather than accepted."""

    applied: list[str] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)


def parse_line(file_path: str, line_no: int, text: str) -> InlineSuppression | None:
    """An inline suppression on this line, valid or not, or None."""
    match = SUPPRESS_RE.search(text)
    if match is None:
        return None
    ids = tuple(part.strip().upper() for part in match.group("ids").split(","))
    reason_match = REASON_RE.match(match.group("rest"))
    if reason_match is None:
        return InlineSuppression(
            file_path, line_no, ids, "",
            problem=(f"copilot: ignore {', '.join(ids)} has no reason, so it was not "
                     f"applied (write: copilot: ignore {ids[0]} -- why)"),
        )
    return InlineSuppression(file_path, line_no, ids, reason_match.group("reason"))


def build(files: list) -> dict[str, dict[int, InlineSuppression]]:
    """``{file path: {line number: suppression}}`` over already-read files.

    Parsed from the raw lines, before comment stripping: the comment *is* the
    instruction here.
    """
    out: dict[str, dict[int, InlineSuppression]] = {}
    for f in files:
        found: dict[int, InlineSuppression] = {}
        for i, line in enumerate(f.lines, start=1):
            if "copilot:" not in line:
                continue
            suppression = parse_line(f.path, i, line)
            if suppression is not None:
                found[i] = suppression
        if found:
            out[f.path] = found
    return out


def for_subject(index: dict[str, dict[int, InlineSuppression]], control_id: str,
                file_path: str, line: int) -> InlineSuppression | None:
    """The suppression covering a subject at ``file_path:line``, if any.

    The line itself or the line above it: a decorator stack leaves no room for
    a trailing comment on the line that matters, so both are accepted.
    """
    per_file = index.get(file_path)
    if not per_file:
        return None
    for candidate in (per_file.get(line), per_file.get(line - 1)):
        if candidate is not None and candidate.covers(control_id):
            return candidate
    return None


def problems(index: dict[str, dict[int, InlineSuppression]],
             known_ids: set[str]) -> list[str]:
    """Inline suppressions that were not applied, with the reason why."""
    out = []
    for per_file in index.values():
        for suppression in per_file.values():
            if not suppression.valid:
                out.append(suppression.describe())
                continue
            unknown = [cid for cid in suppression.control_ids if cid not in known_ids]
            if unknown:
                out.append(f"{suppression.file_path}:{suppression.line}: "
                           f"unknown control(s) {', '.join(unknown)} in a "
                           f"copilot: ignore comment")
    return sorted(out)


def apply_config(findings: list, suppressions: list[ConfigSuppression],
                 today: date | None = None) -> SuppressionReport:
    """Mark findings accepted by ``suppress:`` entries. Returns what happened."""
    today = today or date.today()
    report = SuppressionReport()
    by_control = {f.control_id.upper(): f for f in findings}
    for entry in suppressions:
        control = entry.control.upper()
        if control not in by_control:
            report.problems.append(f"suppress: {entry.control} was not evaluated here, "
                                   f"so the entry had no effect")
            continue
        if not entry.active(today):
            report.problems.append(
                f"suppress: {entry.control} expired on {entry.expires.isoformat()} "
                f"and was not applied")
            continue
        finding = by_control[control]
        finding.suppressed = True
        finding.suppression_reason = entry.reason
        report.applied.append(entry.describe())
    return report
