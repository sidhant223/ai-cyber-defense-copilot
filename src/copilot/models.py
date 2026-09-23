"""Core data types.

Everything downstream depends on these, so they are deliberately small
dataclasses with explicit serialisation.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

SCHEMA_VERSION = "1.4"


class Status(Enum):
    """Outcome of evaluating one control against one codebase.

    Three real outcomes rather than two: PARTIAL is the common and
    interesting case (auth on 3 of 5 routes). NOT_APPLICABLE means the
    control had nothing to judge -- no subjects were found at all.
    """

    PRESENT = "present"
    ABSENT = "absent"
    PARTIAL = "partial"
    NOT_APPLICABLE = "not_applicable"


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def weight(self) -> int:
        return _SEVERITY_WEIGHTS[self]

    @property
    def rank(self) -> int:
        """Sort key -- lower sorts first (most severe first)."""
        return _SEVERITY_ORDER.index(self)


_SEVERITY_WEIGHTS = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
}

_SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]


class Confidence(Enum):
    """How strongly the match supports the verdict. Display-only: never scored.

    HIGH is an exact keyword or known format, MEDIUM a regex that could match
    unrelated code, LOW a heuristic such as entropy scoring.
    """

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def rank(self) -> int:
        """Sort key -- lower sorts first (most confident first)."""
        return list(Confidence).index(self)

#: Status -> fraction of a control weight that counts as earned.
STATUS_CREDIT = {
    Status.PRESENT: 1.0,
    Status.PARTIAL: 0.5,
    Status.ABSENT: 0.0,
}

#: Score floor -> letter. A grade is easier to read than a number and harder
#: to over-read: nobody argues about the difference between 71 and 73.
GRADE_BANDS = ((90, "A"), (80, "B"), (70, "C"), (60, "D"), (0, "F"))

#: The worst grade an application can earn while a critical control is
#: missing entirely. A weighted average can reach 90 with no authentication
#: anywhere, and calling that an A would be the score lying by omission.
GRADE_CAP_CRITICAL_ABSENT = "D"


@dataclass
class Evidence:
    """A pointer at something the scanner actually saw.

    For an *absence* finding there is often no line to point at, so ``note``
    carries the negative evidence: what was searched, and what was not found.
    """

    file_path: str
    line_number: int | None = None
    snippet: str | None = None
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "file_path": self.file_path,
            "line_number": self.line_number,
            "snippet": self.snippet,
            "note": self.note,
        }


@dataclass
class Finding:
    control_id: str
    control_name: str
    category: str
    status: Status
    severity: Severity
    message: str
    evidence: list[Evidence] = field(default_factory=list)
    remediation_hint: str = ""
    confidence: Confidence = Confidence.MEDIUM
    #: Standards references, copied from the control that produced this
    #: finding. They are what lets a reader check the judgement against
    #: something other than this tool's own opinion.
    cwe: str = ""
    owasp: str = ""
    #: Accepted on purpose through a ``suppress:`` entry. The finding stays in
    #: the report and leaves the gap list, the score and the exit code.
    suppressed: bool = False
    suppression_reason: str = ""

    @property
    def fingerprint(self) -> str:
        """A stable id for this finding, deliberately not tied to a line.

        Line numbers move when code above them changes, so a fingerprint
        built from one would break every baseline and every suppression on the
        first unrelated edit. This uses the control, the file and the text of
        the subject instead.
        """
        anchor = ""
        for ev in self.evidence:
            if ev.file_path:
                subject = " ".join((ev.snippet or "").split())
                anchor = f"{ev.file_path}|{subject}"
                break
        digest = hashlib.sha256(f"{self.control_id}|{anchor}".encode("utf-8"))
        return digest.hexdigest()[:16]

    @property
    def is_gap(self) -> bool:
        """True when this finding represents a missing or incomplete control.

        A suppressed finding is not a gap: someone accepted it in writing, and
        the reason travels with the report.
        """
        return self.status in (Status.ABSENT, Status.PARTIAL) and not self.suppressed

    def to_dict(self) -> dict[str, Any]:
        return {
            "control_id": self.control_id,
            "control_name": self.control_name,
            "category": self.category,
            "status": self.status.value,
            "severity": self.severity.value,
            "message": self.message,
            "evidence": [e.to_dict() for e in self.evidence],
            "remediation_hint": self.remediation_hint,
            "confidence": self.confidence.value,
            "cwe": self.cwe,
            "owasp": self.owasp,
            "suppressed": self.suppressed,
            "suppression_reason": self.suppression_reason,
            "fingerprint": self.fingerprint,
        }


@dataclass
class ScannedFile:
    """One file the walker accepted.

    ``text`` is held in memory for the life of the scan so that detectors
    never re-read the tree. It is not serialised.
    """

    path: str          # repo-relative, forward slashes
    abs_path: str
    language: str      # python | javascript | typescript | config | other
    size_bytes: int
    text: str = field(default="", repr=False)

    _lines: list[str] | None = field(default=None, repr=False, compare=False)

    @property
    def lines(self) -> list[str]:
        if self._lines is None:
            self._lines = self.text.splitlines()
        return self._lines

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "language": self.language,
            "size_bytes": self.size_bytes,
        }


@dataclass
class ScanResult:
    root_path: str
    framework: str | None
    language: str
    files_scanned: int
    file_index: dict[str, list[str]]      # category -> repo-relative file paths
    scan_duration_ms: int
    files: list[ScannedFile] = field(default_factory=list, repr=False)
    framework_evidence: list[Evidence] = field(default_factory=list)
    skipped_files: int = 0
    #: ``{file path: {line: InlineSuppression}}`` -- a fact about the files, so
    #: the scanner collects it and the detectors read it. Not serialised.
    inline_suppressions: dict = field(default_factory=dict, repr=False)

    def files_for(self, category: str) -> list[ScannedFile]:
        """Files the indexer considered relevant to ``category``."""
        wanted = set(self.file_index.get(category, []))
        return [f for f in self.files if f.path in wanted]

    def by_path(self, path: str) -> ScannedFile | None:
        for f in self.files:
            if f.path == path:
                return f
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "root_path": self.root_path,
            "framework": self.framework,
            "language": self.language,
            "files_scanned": self.files_scanned,
            "skipped_files": self.skipped_files,
            "scan_duration_ms": self.scan_duration_ms,
            "file_index": self.file_index,
            "framework_evidence": [e.to_dict() for e in self.framework_evidence],
        }


@dataclass
class Report:
    scan: ScanResult
    findings: list[Finding]
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    schema_version: str = SCHEMA_VERSION
    #: Controls that could not be judged here, with the reason why. Kept in the
    #: report so a thin result is visibly thin rather than silently thin.
    skipped_controls: list[dict[str, str]] = field(default_factory=list)
    #: Categories this run actually covered, and how many exist. When a run
    #: was narrowed (``--category``), the score describes a slice of the
    #: application and the grade is withheld rather than implied.
    categories_scanned: list[str] = field(default_factory=list)
    categories_available: int = 0

    @property
    def scored_findings(self) -> list[Finding]:
        """Findings that count toward the posture score.

        NOT_APPLICABLE controls are excluded: a rate limit on a login route
        cannot be missing from an app that has no login route, and pretending
        otherwise would punish small codebases. Suppressed findings are
        excluded too -- an accepted risk is a decision, not a measurement, and
        leaving it in would mean the score moved when someone wrote a comment.
        """
        return [f for f in self.findings
                if f.status in STATUS_CREDIT and not f.suppressed]

    @property
    def suppressed_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.suppressed]

    @property
    def posture_score(self) -> int:
        """Severity-weighted percentage of applicable controls satisfied.

            score = 100 * sum(weight * credit) / sum(weight)

        weight is 5/3/2/1 for critical/high/medium/low; credit is 1.0 for
        PRESENT, 0.5 for PARTIAL, 0.0 for ABSENT. NOT_APPLICABLE controls are
        left out of both sums.

        A repo with no applicable controls scores 100 -- there is nothing to
        get wrong. The applicable-control count is always reported next to the
        score so the number is never read on its own.
        """
        scored = self.scored_findings
        if not scored:
            return 100
        total = sum(f.severity.weight for f in scored)
        earned = sum(f.severity.weight * STATUS_CREDIT[f.status] for f in scored)
        return round(100 * earned / total)

    @property
    def gaps(self) -> list[Finding]:
        return [f for f in self.findings if f.is_gap]

    @property
    def partial_scope(self) -> bool:
        """True when this run covered only some of the available categories."""
        return bool(self.categories_available
                    and len(self.categories_scanned) < self.categories_available)

    @property
    def grade_cap_reason(self) -> str:
        absent_critical = [f for f in self.gaps
                           if f.severity is Severity.CRITICAL
                           and f.status is Status.ABSENT]
        if not absent_critical:
            return ""
        names = ", ".join(f.control_id for f in absent_critical)
        return f"{len(absent_critical)} critical control(s) absent: {names}"

    @property
    def grade(self) -> str | None:
        """A letter for the score, or None when the run was narrowed.

        Withholding it is the point: a grade reads as a verdict on the whole
        application, and a run restricted to two categories cannot support
        one. The score is still shown, next to the count it describes.
        """
        if self.partial_scope:
            return None
        letter = self._grade_band
        if self.grade_cap_reason:
            # Letters sort worst-last, so max() applies the cap.
            return max(letter, GRADE_CAP_CRITICAL_ABSENT)
        return letter

    @property
    def _grade_band(self) -> str:
        return next(name for floor, name in GRADE_BANDS if self.posture_score >= floor)

    @property
    def grade_capped(self) -> bool:
        """True when the cap actually lowered the letter.

        A score of 44 is already an F, so saying it was "capped at D" there
        would be noise. The cap is only worth reporting where it bites.
        """
        return bool(self.grade_cap_reason and not self.partial_scope
                    and self._grade_band < GRADE_CAP_CRITICAL_ABSENT)

    def display_findings(self, min_severity: str | None = None,
                         show_satisfied: bool = False,
                         min_confidence: str | None = None) -> list[Finding]:
        """Findings a renderer should show.

        Filtering is strictly a display concern: ``findings`` stays complete
        so ``posture_score`` never moves when someone passes
        ``--min-severity high`` or ``--min-confidence high``. A score that
        changed with a display flag would be worse than no score.
        """
        out = list(self.findings)
        if min_severity is not None:
            cutoff = Severity(min_severity).rank
            out = [f for f in out if not f.is_gap or f.severity.rank <= cutoff]
        if min_confidence is not None:
            cutoff = Confidence(min_confidence).rank
            out = [f for f in out if not f.is_gap or f.confidence.rank <= cutoff]
        if not show_satisfied:
            out = [f for f in out if f.is_gap]
        return out

    def counts_by_status(self) -> dict[str, int]:
        out = {s.value: 0 for s in Status}
        for f in self.findings:
            out[f.status.value] += 1
        return out

    def counts_by_severity(self) -> dict[str, int]:
        """Severity histogram over gaps only -- a PRESENT control is not a risk."""
        out = {s.value: 0 for s in Severity}
        for f in self.gaps:
            out[f.severity.value] += 1
        return out

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "generated_at": self.generated_at.isoformat(),
            "tool": {"name": "ai-cyber-defense-copilot", "version": "0.1.0"},
            "scan": self.scan.to_dict(),
            "summary": {
                "posture_score": self.posture_score,
                "grade": self.grade,
                "grade_capped_by": self.grade_cap_reason if self.grade_capped else "",
                "scope": "partial" if self.partial_scope else "full",
                "categories_scanned": sorted(self.categories_scanned),
                "controls_evaluated": len(self.findings),
                "controls_scored": len(self.scored_findings),
                "controls_suppressed": len(self.suppressed_findings),
                "by_status": self.counts_by_status(),
                "gaps_by_severity": self.counts_by_severity(),
            },
            "findings": [f.to_dict() for f in self.findings],
            "skipped_controls": self.skipped_controls,
        }


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Gaps first, then by severity, then by control id -- stable and total."""
    order = {Status.ABSENT: 0, Status.PARTIAL: 1, Status.PRESENT: 2,
             Status.NOT_APPLICABLE: 3}
    return sorted(
        findings,
        key=lambda f: (order[f.status], f.severity.rank, f.control_id),
    )
