"""Optional per-repository config: ``.copilot.yaml``.

Precedence is CLI flag, then config file, then built-in default -- ``scan``
resolves that in ``cli.py``, this module only loads and validates one file.
``min_severity``/``min_confidence`` are display filters and never touch the
posture score; ``categories``/``ignore_paths``/``rules_dir`` change what gets
scanned, the same as the CLI flags they mirror.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path

import yaml

from .models import Confidence, Severity
from .suppress import ConfigSuppression

CONFIG_FILENAME = ".copilot.yaml"

_SEVERITY_CHOICES = tuple(s.value for s in Severity)
_CONFIDENCE_CHOICES = tuple(c.value for c in Confidence)

_KEYS = ("categories", "min_severity", "min_confidence", "ignore_paths",
         "rules_dir", "fail_on", "fail_under", "guards", "suppress")

DEFAULT_CONFIG_TEMPLATE = """\
# .copilot.yaml -- optional per-repository configuration for copilot scan.
# Precedence is CLI flag, then this file, then the built-in default below.

# Restrict scanning to these categories (same names as --category). Default: all.
categories: null

# Hide findings below this severity in terminal/HTML output (display only).
min_severity: null

# Hide findings below this confidence in terminal/HTML output (display only).
min_confidence: null

# Repo-relative glob patterns for files to skip before scanning.
ignore_paths: []

# Load rule files from this directory instead of the bundled rules.
rules_dir: null

# Exit 1 only when a gap of at least this severity exists.
fail_on: null

# Exit 1 when the posture score is below this number (0-100).
fail_under: null

# Extra guard patterns per control, for protections this codebase writes its
# own way. A subject is satisfied when any guard matches, so these add to the
# built-in ones rather than replacing them.
#   guards:
#     AUTH-001: ['@require_api_key']
guards: {}

# Findings accepted on purpose. A reason is required; expires is optional and
# must be a date. A suppressed finding stays in the report and leaves the gap
# list, the score and the exit code.
#   suppress:
#     - control: RATE-001
#       reason: enforced at the API gateway
#       expires: 2026-12-31
suppress: []
"""


class ConfigError(ValueError):
    """A config file is malformed or invalid. Message is ``<path>:<line>: ...``."""


@dataclass
class Config:
    categories: list[str] | None = None
    min_severity: str | None = None
    min_confidence: str | None = None
    ignore_paths: list[str] = field(default_factory=list)
    rules_dir: str | None = None
    fail_on: str | None = None
    fail_under: int | None = None
    #: control id -> extra guard patterns for this codebase's own protections.
    guards: dict[str, list[str]] = field(default_factory=dict)
    suppress: list[ConfigSuppression] = field(default_factory=list)
    source_path: Path | None = None


def _check_choice(path: Path, line: int, key: str, value, choices: tuple[str, ...]) -> None:
    if value is not None and value not in choices:
        raise ConfigError(f"{path}:{line}: {key}: must be one of {', '.join(choices)} "
                          f"(got {value!r})")


def _check_str_list(path: Path, line: int, key: str, value) -> None:
    if value is not None and (not isinstance(value, list)
                              or not all(isinstance(v, str) for v in value)):
        raise ConfigError(f"{path}:{line}: {key}: must be a list of strings")


def write_default_config(path: Path) -> None:
    """Write the default ``.copilot.yaml`` template to ``path``."""
    path.write_text(DEFAULT_CONFIG_TEMPLATE, encoding="utf-8")


def load_config(path: Path) -> Config:
    """Parse and validate one ``.copilot.yaml``. Raises ``ConfigError`` on any problem."""
    text = path.read_text(encoding="utf-8")
    try:
        root = yaml.compose(text, Loader=yaml.SafeLoader)
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        line = mark.line + 1 if mark else 1
        problem = getattr(exc, "problem", None) or str(exc)
        raise ConfigError(f"{path}:{line}: invalid YAML: {problem}") from exc

    cfg = Config(source_path=path)
    if root is None:
        return cfg
    if not isinstance(root, yaml.MappingNode):
        raise ConfigError(f"{path}:{root.start_mark.line + 1}: "
                          f"config file must be a mapping of keys to values")

    data = yaml.safe_load(text) or {}
    for key_node, _value_node in root.value:
        key = key_node.value
        line = key_node.start_mark.line + 1
        if key not in _KEYS:
            raise ConfigError(f"{path}:{line}: {key}: unknown config key "
                              f"(known: {', '.join(_KEYS)})")
        value = data.get(key)
        if key in ("min_severity", "fail_on"):
            _check_choice(path, line, key, value, _SEVERITY_CHOICES)
            setattr(cfg, key, value)
        elif key == "min_confidence":
            _check_choice(path, line, key, value, _CONFIDENCE_CHOICES)
            cfg.min_confidence = value
        elif key == "categories":
            _check_str_list(path, line, key, value)
            cfg.categories = list(value) if value else None
        elif key == "ignore_paths":
            _check_str_list(path, line, key, value)
            cfg.ignore_paths = list(value) if value else []
        elif key == "rules_dir":
            if value is not None and not isinstance(value, str):
                raise ConfigError(f"{path}:{line}: rules_dir: must be a string path")
            cfg.rules_dir = str((path.parent / value).resolve()) if value else None
        elif key == "fail_under":
            if value is not None and (isinstance(value, bool)
                                      or not isinstance(value, int)
                                      or not 0 <= value <= 100):
                raise ConfigError(f"{path}:{line}: fail_under: must be a whole number "
                                  f"from 0 to 100 (got {value!r})")
            cfg.fail_under = value
        elif key == "guards":
            cfg.guards = _parse_guards(path, line, value)
        elif key == "suppress":
            cfg.suppress = _parse_suppressions(path, line, value)
    return cfg


def _parse_guards(path: Path, line: int, value) -> dict[str, list[str]]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ConfigError(f"{path}:{line}: guards: must be a mapping of control id -> "
                          f"list of regex patterns")
    out: dict[str, list[str]] = {}
    for control_id, patterns in value.items():
        if isinstance(patterns, str):
            patterns = [patterns]
        if not isinstance(patterns, list) or not all(isinstance(p, str) for p in patterns):
            raise ConfigError(f"{path}:{line}: guards: {control_id}: must be a list of "
                              f"regex patterns")
        for pattern in patterns:
            try:
                re.compile(pattern)
            except re.error as exc:
                raise ConfigError(f"{path}:{line}: guards: {control_id}: bad regex "
                                  f"{pattern!r}: {exc}") from exc
        out[str(control_id).upper()] = list(patterns)
    return out


def _parse_suppressions(path: Path, line: int, value) -> list[ConfigSuppression]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ConfigError(f"{path}:{line}: suppress: must be a list of entries with "
                          f"control and reason")
    out: list[ConfigSuppression] = []
    for n, entry in enumerate(value, start=1):
        where = f"{path}:{line}: suppress[{n}]"
        if not isinstance(entry, dict):
            raise ConfigError(f"{where}: must be a mapping with control and reason")
        control = entry.get("control")
        if not isinstance(control, str) or not control.strip():
            raise ConfigError(f"{where}: control: must name a control, e.g. RATE-001")
        reason = entry.get("reason")
        if not isinstance(reason, str) or not reason.strip():
            # An accepted risk with no reason cannot be reviewed later, so it
            # is refused rather than honoured.
            raise ConfigError(f"{where}: reason: required, and must say why "
                              f"{control} is accepted here")
        raw_expiry = entry.get("expires")
        expires: date | None = None
        if raw_expiry is not None:
            if isinstance(raw_expiry, datetime):
                expires = raw_expiry.date()
            elif isinstance(raw_expiry, date):
                expires = raw_expiry
            else:
                try:
                    expires = date.fromisoformat(str(raw_expiry))
                except ValueError as exc:
                    # A malformed date must not mean "never expires".
                    raise ConfigError(f"{where}: expires: must be a date as YYYY-MM-DD "
                                      f"(got {raw_expiry!r})") from exc
        unknown = sorted(set(entry) - {"control", "reason", "expires"})
        if unknown:
            raise ConfigError(f"{where}: unknown key(s) {', '.join(unknown)} "
                              f"(known: control, reason, expires)")
        out.append(ConfigSuppression(control=control.strip(), reason=reason.strip(),
                                     expires=expires))
    return out
