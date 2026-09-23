"""Evaluation harness: how often the scanner agrees with the labelled corpus.

The rules were tuned until they matched the samples in corpus/, so a score
computed on those samples is circular -- it measures the tuning, not the
scanner. Every manifest entry therefore carries a ``split``:

* ``dev`` samples were tuned on. They are a regression signal only.
* ``holdout`` samples were never looked at while writing rules. Only they
  produce a number that can be reported as accuracy, and only for as long as
  no rule is changed in response to them.

The unit of evaluation is one (sample, control) pair. A gap (absent or
partial) is the positive class, because a gap is what the tool exists to
report.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import yaml

from ..detectors import RuleEngine, run_all
from ..models import Report, Status
from ..scanner import scan as run_scan

SPLITS = ("dev", "holdout")
SPLIT_CHOICES = ("dev", "holdout", "all")
NOT_REPORTED = "not_reported"

OUTCOMES = ("tp", "fp", "fn", "tn")
GAP_STATUSES = (Status.ABSENT.value, Status.PARTIAL.value)
STATUS_VALUES = frozenset(s.value for s in Status)


class EvaluationError(Exception):
    """The manifest or the requested evaluation cannot be run as asked."""


# --------------------------------------------------------------------------
# manifest
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Sample:
    name: str
    split: str
    path: Path
    expected: dict[str, str]
    skipped: frozenset[str]
    framework: str | None


def load_manifest(path: str | Path) -> list[Sample]:
    """Parse and validate corpus/manifest.yaml. Every problem is fatal: a
    silently dropped entry would quietly change the numbers."""
    path = Path(path)
    if not path.is_file():
        raise EvaluationError(f"manifest not found: {path}")
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (yaml.YAMLError, UnicodeDecodeError) as exc:
        raise EvaluationError(f"manifest is not valid UTF-8 YAML: {path}: {exc}") from exc

    entries = data.get("samples") if isinstance(data, dict) else None
    if not isinstance(entries, list) or not entries:
        raise EvaluationError(f"manifest has no samples list: {path}")

    samples: list[Sample] = []
    seen: set[str] = set()
    for n, entry in enumerate(entries, start=1):
        name = entry.get("name") if isinstance(entry, dict) else None
        if not isinstance(name, str) or not name:
            raise EvaluationError(f"sample #{n} has no name")
        if Path(name).name != name or name in (".", ".."):
            raise EvaluationError(f"{name}: name must be a plain directory name")
        if name in seen:
            raise EvaluationError(f"{name}: duplicate sample name")
        seen.add(name)

        split = entry.get("split")
        if split not in SPLITS:
            raise EvaluationError(
                f"{name}: split must be one of {', '.join(SPLITS)} (got {split!r})")

        expected = entry.get("expected")
        if not isinstance(expected, dict):
            raise EvaluationError(f"{name}: expected must be a mapping of control id -> status")
        for control_id, status in expected.items():
            if not isinstance(status, str) or status not in STATUS_VALUES:
                raise EvaluationError(
                    f"{name}: {control_id} has invalid status {status!r} "
                    f"(valid: {', '.join(sorted(STATUS_VALUES))})")

        skipped = entry.get("skipped", [])
        if not isinstance(skipped, list) or not all(isinstance(s, str) for s in skipped):
            raise EvaluationError(f"{name}: skipped must be a list of control ids")
        both = sorted(set(expected) & set(skipped))
        if both:
            raise EvaluationError(
                f"{name}: control(s) in both expected and skipped: {', '.join(both)}")

        sample_dir = path.parent / "samples" / name
        if not sample_dir.is_dir():
            raise EvaluationError(f"{name}: sample directory not found: {sample_dir}")

        samples.append(Sample(
            name=name,
            split=split,
            path=sample_dir,
            expected={str(k): v for k, v in expected.items()},
            skipped=frozenset(str(s) for s in skipped),
            framework=entry.get("framework"),
        ))
    return samples


def select(samples: list[Sample], split: str) -> list[Sample]:
    if split not in SPLIT_CHOICES:
        raise EvaluationError(
            f"split must be one of {', '.join(SPLIT_CHOICES)} (got {split!r})")
    chosen = list(samples) if split == "all" else [s for s in samples if s.split == split]
    if not chosen:
        raise EvaluationError(f"no samples with split '{split}' in the manifest")
    return chosen


# --------------------------------------------------------------------------
# scoring
# --------------------------------------------------------------------------

def outcome(expected: str, reported: str) -> str:
    want, got = expected in GAP_STATUSES, reported in GAP_STATUSES
    if want and got:
        return "tp"
    if want:
        return "fn"
    if got:
        return "fp"
    return "tn"


def _ratio(num: int, den: int) -> float | None:
    return num / den if den else None


def _rounded(value: float | None) -> float | None:
    return None if value is None else round(value, 4)


@dataclass
class Tally:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0

    def add(self, outcome: str) -> None:
        if outcome not in OUTCOMES:
            raise ValueError(f"unknown outcome: {outcome!r}")
        setattr(self, outcome, getattr(self, outcome) + 1)

    @property
    def precision(self) -> float | None:
        return _ratio(self.tp, self.tp + self.fp)

    @property
    def recall(self) -> float | None:
        return _ratio(self.tp, self.tp + self.fn)

    @property
    def f1(self) -> float | None:
        return _ratio(2 * self.tp, 2 * self.tp + self.fp + self.fn)

    def to_dict(self) -> dict:
        return {
            "tp": self.tp, "fp": self.fp, "fn": self.fn, "tn": self.tn,
            "precision": _rounded(self.precision),
            "recall": _rounded(self.recall),
            "f1": _rounded(self.f1),
        }


@dataclass(frozen=True)
class Disagreement:
    sample: str
    control_id: str
    category: str
    expected: str
    reported: str
    outcome: str

    @property
    def kind(self) -> str:
        if self.outcome == "fn":
            return "missed"
        if self.outcome == "fp":
            return "over_flagged"
        return "wrong_status"

    def to_dict(self) -> dict:
        return {
            "control_id": self.control_id,
            "category": self.category,
            "expected": self.expected,
            "reported": self.reported,
            "outcome": self.outcome,
            "kind": self.kind,
        }


@dataclass
class ControlErrors:
    control_id: str
    category: str
    missed: int = 0
    over_flagged: int = 0
    wrong_status: int = 0
    where: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "control_id": self.control_id,
            "category": self.category,
            "missed": self.missed,
            "over_flagged": self.over_flagged,
            "wrong_status": self.wrong_status,
            "where": list(self.where),
        }


@dataclass
class SampleResult:
    name: str
    split: str
    framework_expected: str | None
    framework_detected: str | None
    disagreements: list[Disagreement] = field(default_factory=list)
    unlabelled: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "split": self.split,
            "framework_expected": self.framework_expected,
            "framework_detected": self.framework_detected,
            "unlabelled": list(self.unlabelled),
            "disagreements": [d.to_dict() for d in self.disagreements],
        }


@dataclass
class EvaluationResult:
    split: str
    manifest_path: str
    rules_dir: str
    samples: list[SampleResult]
    by_category: dict[str, Tally]
    overall: Tally

    @property
    def reportable(self) -> bool:
        return self.split == "holdout"

    @property
    def confusion(self) -> list[ControlErrors]:
        """Controls that disagreed with the manifest, worst first."""
        rows: dict[str, ControlErrors] = {}
        for sample in self.samples:
            for d in sample.disagreements:
                row = rows.setdefault(d.control_id, ControlErrors(d.control_id, d.category))
                setattr(row, d.kind, getattr(row, d.kind) + 1)
                row.where.append(f"{d.sample}: {d.expected}->{d.reported}")
        return sorted(rows.values(), key=lambda r: (
            -(r.missed + r.over_flagged), -r.wrong_status, r.control_id))

    def to_dict(self) -> dict:
        return {
            "schema_version": "1.0",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "split": self.split,
            "reportable": self.reportable,
            "manifest": self.manifest_path,
            "rules_dir": self.rules_dir,
            "samples_evaluated": len(self.samples),
            "overall": self.overall.to_dict(),
            "by_category": {cat: t.to_dict() for cat, t in self.by_category.items()},
            "confusion": [c.to_dict() for c in self.confusion],
            "samples": [s.to_dict() for s in self.samples],
        }


# --------------------------------------------------------------------------
# evaluate
# --------------------------------------------------------------------------

def evaluate(manifest_path: str | Path, split: str,
             engine: RuleEngine | None = None) -> EvaluationResult:
    """Scan every selected sample and score it against the manifest.

    The engine is built fresh when not supplied, so a rule edit is picked up
    by re-running -- there is no cached state to go stale.
    """
    samples = select(load_manifest(manifest_path), split)
    if engine is None:
        engine = RuleEngine()

    controls = sorted(engine.controls(), key=lambda c: (c.category, c.id))
    known = {c.id for c in controls}
    unknown = [f"{s.name}: {', '.join(sorted((set(s.expected) | s.skipped) - known))}"
               for s in samples if (set(s.expected) | s.skipped) - known]
    if unknown:
        raise EvaluationError(
            "manifest labels control(s) the rules do not define -- " + "; ".join(unknown))

    by_category = {cat: Tally() for cat in sorted(engine.categories)}
    overall = Tally()
    results: list[SampleResult] = []

    for sample in samples:
        scan_result = run_scan(str(sample.path))
        findings, skipped = run_all(scan_result, engine)
        report = Report(scan=scan_result, findings=findings,
                        skipped_controls=[s.to_dict() for s in skipped])
        # Read the JSON contract, not the objects: that is what users consume.
        reported = {f["control_id"]: f["status"] for f in report.to_dict()["findings"]}

        result = SampleResult(sample.name, sample.split, sample.framework,
                              scan_result.framework)
        for control in controls:
            if control.id in sample.expected:
                want = sample.expected[control.id]
            elif control.id in sample.skipped:
                want = NOT_REPORTED
            else:
                result.unlabelled.append(control.id)
                continue
            got = reported.get(control.id, NOT_REPORTED)
            verdict = outcome(want, got)
            by_category[control.category].add(verdict)
            overall.add(verdict)
            if want != got:
                result.disagreements.append(Disagreement(
                    sample.name, control.id, control.category, want, got, verdict))
        result.unlabelled.sort()
        results.append(result)

    return EvaluationResult(
        split=split,
        manifest_path=str(manifest_path),
        rules_dir=str(engine.rules_dir),
        samples=results,
        by_category=by_category,
        overall=overall,
    )
