"""Static validation of rule YAML files: ``copilot rules validate``.

``RuleEngine.load()`` fails fast on the first bad control, which is right for
scanning but wrong for authoring -- a rule writer wants every problem in one
pass. This module re-parses the same YAML shape independently (it does not
call ``RuleEngine`` or ``parse_control``) and collects every error, each with
a file:line pointer taken from ``yaml.compose`` node marks.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from .detectors.rule_engine import CWE_FORMAT, OWASP_FORMAT
from .models import Confidence, Severity, Status
from .scanner.framework import SUPPORTED

_SEVERITY_CHOICES = tuple(s.value for s in Severity)
_CONFIDENCE_CHOICES = tuple(c.value for c in Confidence)
_STATUS_CHOICES = tuple(s.value for s in Status)
_MODE_CHOICES = ("subject_guard", "presence", "custom")


@dataclass
class ValidationError:
    file: Path
    line: int
    key: str
    problem: str

    def __str__(self) -> str:
        return f"{self.file}:{self.line}: {self.key}: {self.problem}"


def validate_dir(directory: Path) -> list[ValidationError]:
    """Validate every ``*.yaml`` file in ``directory``. Collects all errors."""
    errors: list[ValidationError] = []
    seen_ids: dict[str, tuple[Path, int]] = {}
    for path in sorted(directory.glob("*.yaml")):
        errors.extend(_validate_file(path, seen_ids))
    return errors


# --------------------------------------------------------------------------
# node helpers -- yaml.compose keeps line marks that yaml.safe_load discards
# --------------------------------------------------------------------------

def _node_get(mapping_node: Any, key: str) -> Any:
    if not isinstance(mapping_node, yaml.MappingNode):
        return None
    for key_node, value_node in mapping_node.value:
        if key_node.value == key:
            return value_node
    return None


def _line(node: Any, fallback: int) -> int:
    return node.start_mark.line + 1 if node is not None else fallback


def _seq_items(node: Any) -> list[Any]:
    return node.value if isinstance(node, yaml.SequenceNode) else []


# --------------------------------------------------------------------------
# per-file / per-control validation
# --------------------------------------------------------------------------

def _validate_file(path: Path, seen_ids: dict[str, tuple[Path, int]]) -> list[ValidationError]:
    text = path.read_text(encoding="utf-8")
    try:
        root = yaml.compose(text, Loader=yaml.SafeLoader)
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        line = mark.line + 1 if mark else 1
        problem = getattr(exc, "problem", None) or str(exc)
        return [ValidationError(path, line, "yaml", f"invalid YAML: {problem}")]

    data = yaml.safe_load(text) or {}
    root_line = _line(root, 1)
    if not data.get("category"):
        return [ValidationError(path, root_line, "category",
                                "missing top-level 'category'")]

    controls_node = _node_get(root, "controls")
    control_nodes = _seq_items(controls_node)
    controls_data = data.get("controls") or []

    errors: list[ValidationError] = []
    for idx, node in enumerate(control_nodes):
        spec = controls_data[idx] if idx < len(controls_data) else {}
        errors.extend(_validate_control(path, node, spec, seen_ids))
    return errors


def _guard_specs(detection: dict, detection_node: Any) -> list[tuple[dict, Any]]:
    """``(guard spec, guard node)`` pairs, from ``guard:`` or ``guards:``."""
    guards_spec = detection.get("guards")
    if guards_spec:
        nodes = _seq_items(_node_get(detection_node, "guards"))
        if len(nodes) != len(guards_spec):
            nodes = [None] * len(guards_spec)
        return list(zip(guards_spec, nodes))
    guard_spec = detection.get("guard")
    if guard_spec:
        return [(guard_spec, _node_get(detection_node, "guard"))]
    return []


def _pattern_nodes(mode: str, detection: dict, detection_node: Any) -> list[tuple[Any, str]]:
    """``(node, pattern string)`` for every regex ``parse_control`` would compile."""
    out: list[tuple[Any, str]] = []
    if mode == "subject_guard":
        subject = detection.get("subject") or {}
        subject_node = _node_get(detection_node, "subject")
        if subject.get("pattern"):
            out.append((_node_get(subject_node, "pattern"), subject["pattern"]))
        for item_node, pattern in zip(_seq_items(_node_get(subject_node, "exclude")),
                                      subject.get("exclude") or []):
            out.append((item_node, pattern))
        for guard, guard_node in _guard_specs(detection, detection_node):
            for key in ("any_of", "none_of"):
                for item_node, pattern in zip(_seq_items(_node_get(guard_node, key)),
                                              guard.get(key) or []):
                    out.append((item_node, pattern))
            if guard.get("stop_at"):
                out.append((_node_get(guard_node, "stop_at"), guard["stop_at"]))
    elif mode == "presence":
        patterns = detection.get("patterns") or {}
        patterns_node = _node_get(detection_node, "patterns")
        for item_node, pattern in zip(_seq_items(_node_get(patterns_node, "any_of")),
                                      patterns.get("any_of") or []):
            out.append((item_node, pattern))
        for item_node, pattern in zip(_seq_items(_node_get(patterns_node, "none_of")),
                                      patterns.get("none_of") or []):
            out.append((item_node, pattern))
    return out


def _validate_control(path: Path, node: Any, spec: dict,
                      seen_ids: dict[str, tuple[Path, int]]) -> list[ValidationError]:
    errors: list[ValidationError] = []
    control_line = _line(node, 1)
    control_id = spec.get("id")
    key = control_id or f"controls[unnamed @ line {control_line}]"

    for required in ("id", "name", "severity"):
        if not spec.get(required):
            errors.append(ValidationError(path, control_line, key,
                                          f"missing required key {required!r}"))

    severity = spec.get("severity")
    if severity is not None and severity not in _SEVERITY_CHOICES:
        line = _line(_node_get(node, "severity"), control_line)
        errors.append(ValidationError(path, line, key,
            f"unknown severity {severity!r} (must be one of {', '.join(_SEVERITY_CHOICES)})"))

    confidence = spec.get("confidence")
    if confidence is not None and confidence not in _CONFIDENCE_CHOICES:
        line = _line(_node_get(node, "confidence"), control_line)
        errors.append(ValidationError(path, line, key,
            f"unknown confidence {confidence!r} "
            f"(must be one of {', '.join(_CONFIDENCE_CHOICES)})"))

    for field_name, fmt, example in (("cwe", CWE_FORMAT, "CWE-306"),
                                     ("owasp", OWASP_FORMAT, "A07:2021")):
        value = spec.get(field_name)
        if value is not None and not fmt.match(str(value).strip()):
            line = _line(_node_get(node, field_name), control_line)
            errors.append(ValidationError(path, line, key,
                f"{field_name} must look like {example!r} (got {value!r})"))

    detection = spec.get("detection") or {}
    detection_node = _node_get(node, "detection")
    mode = detection.get("mode", "subject_guard")
    if mode not in _MODE_CHOICES:
        line = _line(_node_get(detection_node, "mode"), control_line)
        errors.append(ValidationError(path, line, key,
            f"unknown detection mode {mode!r} (must be one of {', '.join(_MODE_CHOICES)})"))

    verdict = spec.get("verdict") or {}
    verdict_node = _node_get(node, "verdict")
    for vkey, vvalue in verdict.items():
        if vvalue not in _STATUS_CHOICES:
            line = _line(_node_get(verdict_node, vkey), control_line)
            errors.append(ValidationError(path, line, key,
                f"unknown verdict status {vvalue!r} for {vkey!r} "
                f"(must be one of {', '.join(_STATUS_CHOICES)})"))

    frameworks = (spec.get("applies_to") or {}).get("frameworks") or []
    frameworks_node = _seq_items(_node_get(_node_get(node, "applies_to"), "frameworks"))
    for i, fw in enumerate(frameworks):
        if fw not in SUPPORTED:
            line = _line(frameworks_node[i], control_line) if i < len(frameworks_node) \
                else control_line
            errors.append(ValidationError(path, line, key,
                f"unknown framework {fw!r} (known: {', '.join(SUPPORTED)})"))

    for guard, guard_node in _guard_specs(detection, detection_node):
        prox = guard.get("proximity_lines")
        if prox is not None and (isinstance(prox, bool) or not isinstance(prox, int)
                                 or prox <= 0):
            line = _line(_node_get(guard_node, "proximity_lines"), control_line)
            errors.append(ValidationError(path, line, key,
                f"proximity_lines must be a positive integer (got {prox!r})"))

    for pattern_node, pattern in _pattern_nodes(mode, detection, detection_node):
        try:
            re.compile(pattern)
        except re.error as exc:
            line = _line(pattern_node, control_line)
            errors.append(ValidationError(path, line, key, f"bad regex {pattern!r}: {exc}"))

    if control_id:
        if control_id in seen_ids:
            first_path, first_line = seen_ids[control_id]
            errors.append(ValidationError(path, control_line, control_id,
                f"duplicate control id (first defined in {first_path}:{first_line})"))
        else:
            seen_ids[control_id] = (path, control_line)

    return errors
