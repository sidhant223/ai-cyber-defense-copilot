"""Detectors: work out what a repository is *missing*.

Importing this package registers all five detectors. ``run_all`` is the only
entry point the CLI needs.
"""

from __future__ import annotations

from ..models import Finding, Report, ScanResult, sort_findings
from .base import (Detector, SkippedControl, YamlOnlyDetector, register,
                   registry)
from .rule_engine import RuleEngine, RuleError

from . import access_control          # noqa: F401  (registration side effect)
from . import authentication          # noqa: F401
from . import input_validation        # noqa: F401
from . import rate_limiting           # noqa: F401
from . import secret_management       # noqa: F401


def run_all(
    scan: ScanResult,
    engine: RuleEngine | None = None,
    categories: list[str] | None = None,
) -> tuple[list[Finding], list[SkippedControl]]:
    """Run every detector (or only ``categories``) over a scan.

    A category present in the rule files but with no registered subclass is
    run by ``YamlOnlyDetector``, so a new category really is just a YAML file.
    """
    engine = engine or RuleEngine()
    wanted = set(categories) if categories else None
    detectors = registry()
    findings: list[Finding] = []
    skipped: list[SkippedControl] = []
    for category in sorted(set(detectors) | set(engine.categories)):
        if wanted is not None and category not in wanted:
            continue
        detector_cls = detectors.get(category)
        detector = detector_cls(engine) if detector_cls \
            else YamlOnlyDetector(engine, category)
        got, miss = detector.run(scan)
        findings.extend(got)
        skipped.extend(miss)
    return sort_findings(findings), skipped


__all__ = [
    "Detector", "SkippedControl", "RuleEngine", "RuleError",
    "register", "registry", "run_all", "Report",
]
