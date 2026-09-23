"""Executable examples for rule files: ``copilot rules test``.

A regex rule fails silently. A pattern that stops matching does not raise;
it reports the control as absent everywhere, and the scan still looks fine.
``rules validate`` catches a rule that is malformed, but not one that is
merely wrong.

So every control carries examples: a few lines of code and the verdict the
control must reach on them. They live in ``<rules dir>/tests/<category>.yaml``
keyed by control id::

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

``expect`` is one of the four statuses, or ``skipped`` for a control that
should not be judged at all on this input (wrong framework, no applicable
files). Examples run through the same pipeline a real scan uses -- framework
detection, the file index, the category's detector -- with the files held in
memory rather than written to disk.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path, PurePosixPath

import yaml

from .models import ScannedFile, Status
from .scanner import scan_files
from .scanner.walker import language_for

#: Also accepted as an expectation: the control was not judged at all.
SKIPPED = "skipped"

_STATUS_VALUES = tuple(s.value for s in Status)
EXPECTATIONS = _STATUS_VALUES + (SKIPPED,)


class RuleTestError(ValueError):
    """An example is malformed. Raised at load time, never mid-run."""


@dataclass(frozen=True)
class RuleTest:
    control_id: str
    name: str
    expect: str
    files: dict[str, str]
    source: str          # "<file>:<control id>" for error messages


@dataclass(frozen=True)
class RuleTestResult:
    test: RuleTest
    got: str
    detail: str

    @property
    def passed(self) -> bool:
        return self.got == self.test.expect


# --------------------------------------------------------------------------
# loading
# --------------------------------------------------------------------------

def load_rule_tests(directory: Path, engine, control_id: str | None = None) -> list[RuleTest]:
    """Every example in ``directory``, in file then declaration order.

    ``engine`` is used to reject examples for controls that do not exist: a
    renamed control whose examples stay behind would otherwise stop testing
    anything and never say so.
    """
    out: list[RuleTest] = []
    for path in sorted(Path(directory).glob("*.yaml")):
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            raise RuleTestError(f"{path}: invalid YAML: {exc}") from exc
        if not isinstance(data, dict):
            raise RuleTestError(f"{path}: must be a mapping of control id -> examples")
        for cid, cases in data.items():
            where = f"{path.name}:{cid}"
            if engine.get(str(cid)) is None:
                raise RuleTestError(f"{where}: no such control in {engine.rules_dir}")
            if not isinstance(cases, list) or not cases:
                raise RuleTestError(f"{where}: must be a non-empty list of examples")
            for n, case in enumerate(cases, start=1):
                out.append(_parse_case(case, str(cid), f"{where}#{n}"))
    if control_id is not None:
        out = [t for t in out if t.control_id.lower() == control_id.lower()]
    return out


def _parse_case(case: object, control_id: str, where: str) -> RuleTest:
    if not isinstance(case, dict):
        raise RuleTestError(f"{where}: each example must be a mapping")
    expect = case.get("expect")
    if expect not in EXPECTATIONS:
        raise RuleTestError(f"{where}: expect must be one of "
                            f"{', '.join(EXPECTATIONS)} (got {expect!r})")
    files = case.get("files")
    if not isinstance(files, dict) or not files:
        raise RuleTestError(f"{where}: files must be a mapping of path -> contents")
    for name in files:
        pure = PurePosixPath(str(name))
        if pure.is_absolute() or ".." in pure.parts or ":" in str(name):
            raise RuleTestError(f"{where}: {name!r} must be a relative path inside "
                                f"the example")
    return RuleTest(
        control_id=control_id,
        name=str(case.get("name") or f"example {where.rsplit('#', 1)[-1]}"),
        expect=expect,
        files={str(k): str(v) for k, v in files.items()},
        source=where,
    )


# --------------------------------------------------------------------------
# running
# --------------------------------------------------------------------------

def run_rule_test(test: RuleTest, engine) -> RuleTestResult:
    """Scan the example in memory and report the verdict the control reached."""
    from .detectors import run_all

    control = engine.get(test.control_id)
    if control is None:                                   # pragma: no cover
        raise RuleTestError(f"{test.source}: no such control")

    files = []
    for path, text in sorted(test.files.items()):
        language = language_for(PurePosixPath(path).name)
        if language is None:
            raise RuleTestError(f"{test.source}: {path!r} is not a file type the "
                                f"scanner reads")
        files.append(ScannedFile(path=path, abs_path=path, language=language,
                                 size_bytes=len(text.encode("utf-8")), text=text))

    scan = scan_files(files, root=f"<example {test.source}>")
    findings, skipped = run_all(scan, engine, [control.category])
    finding = next((f for f in findings if f.control_id == control.id), None)

    if finding is not None:
        got, detail = finding.status.value, finding.message
    elif any(s.control_id == control.id for s in skipped):
        reason = next(s.reason for s in skipped if s.control_id == control.id)
        got, detail = SKIPPED, f"not judged: {reason}"
    else:                                                 # pragma: no cover
        got, detail = "not_reported", "the detector produced no finding"

    if got != test.expect:
        detail = (f"expected {test.expect}, got {got} "
                  f"(framework {scan.framework or 'unknown'}) -- {detail}")
    return RuleTestResult(test=test, got=got, detail=detail)
