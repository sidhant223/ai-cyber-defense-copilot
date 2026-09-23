"""Detector base class and registry.

A detector owns a category. It does not own detection logic -- that lives in
``rules/<category>.yaml`` and is executed by the generic RuleEngine. A
detector subclass exists to (a) declare the category and (b) add the small
amount of judgement the rule language genuinely cannot express, such as
Shannon entropy scoring for secrets.

Detectors are independent by construction: none imports another, none holds
mutable state between runs, and each takes a ScanResult and returns findings.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from ..models import Finding, ScanResult
from .rule_engine import RuleEngine

_REGISTRY: dict[str, type["Detector"]] = {}


def register(cls: type["Detector"]) -> type["Detector"]:
    """Class decorator: add a detector to the registry, keyed by category."""
    if not getattr(cls, "category", ""):
        raise ValueError(f"{cls.__name__} must declare a category")
    if cls.category in _REGISTRY:
        raise ValueError(f"duplicate detector for category {cls.category!r}")
    _REGISTRY[cls.category] = cls
    return cls


def registry() -> dict[str, type["Detector"]]:
    return dict(_REGISTRY)


@dataclass
class SkippedControl:
    control_id: str
    category: str
    reason: str

    def to_dict(self) -> dict[str, str]:
        return {"control_id": self.control_id, "category": self.category,
                "reason": self.reason}


class Detector(ABC):
    """One control category."""

    #: Must match the ``category`` field of the matching YAML rule file.
    category: str = ""

    def __init__(self, engine: RuleEngine) -> None:
        self.engine = engine

    @property
    @abstractmethod
    def description(self) -> str:
        """One line, shown by ``copilot rules list``."""

    def run(self, scan: ScanResult) -> tuple[list[Finding], list[SkippedControl]]:
        findings: list[Finding] = []
        skipped: list[SkippedControl] = []
        for control in self.engine.controls(self.category):
            if control.mode == "custom":
                continue  # implemented by this detector's extra_findings
            reason = self.engine.skip_reason(control, scan)
            if reason is not None:
                skipped.append(SkippedControl(control.id, self.category, reason))
                continue
            finding = self.engine.evaluate(control, scan)
            if finding is not None:
                findings.append(finding)
        findings.extend(self.extra_findings(scan))
        for finding in findings:
            control = self.engine.get(finding.control_id)
            if control is not None:
                finding.cwe, finding.owasp = control.cwe, control.owasp
        return findings, skipped

    def extra_findings(self, scan: ScanResult) -> list[Finding]:
        """Category-specific logic the rule language cannot express.

        Default: nothing. Only ``secret_management`` overrides this today.
        """
        return []


#: Subclasses declare this at class level; ``YamlOnlyDetector`` sets it per
#: instance, which is why the annotation lives on the base class.
class YamlOnlyDetector(Detector):
    """The detector for a category that exists only as a rule file.

    "Adding a control category means adding a YAML file, not editing Python"
    is a load-bearing claim, and it was not quite true: every category needed
    a registered subclass or its controls were never run. A category with no
    subclass now gets this one, which adds no judgement of its own.
    """

    def __init__(self, engine: RuleEngine, category: str) -> None:
        super().__init__(engine)
        self.category = category

    @property
    def description(self) -> str:
        return self.engine.categories.get(self.category) or "declared in YAML only"
