"""Scan orchestration for the web UI, independent of the HTTP layer.

Mirrors ``cli.cmd_scan`` minus output and exit codes: config, engine with
project guards, ignores, scan, detectors, scoped Report, config suppressions.
Detection and scoring stay in ``copilot``; this only wires the calls.
"""

from __future__ import annotations

import io
import re
import stat
import tempfile
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from copilot import suppress
from copilot.config import CONFIG_FILENAME, ConfigError, load_config
from copilot.detectors import RuleEngine, RuleError, run_all
from copilot.detectors.rule_engine import glob_to_regex
from copilot.models import Report
from copilot.scanner import scan as run_scan

MAX_ZIP_MEMBERS = 5_000
MAX_ZIP_BYTES = 200 * 1024 * 1024   # total uncompressed


class ScanError(Exception):
    """A submission that could not produce a report. Message is user-facing."""


@dataclass
class ScanOutcome:
    report: Report
    source: str                        # what the user picked, for display
    scanned_at: datetime
    config_path: str | None = None     # .copilot.yaml that was applied, if any
    suppressions_applied: list[str] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)


def run(root: str | Path, source: str, categories: list[str] | None = None,
        use_config: bool = True, engine: RuleEngine | None = None,
        confine_config_to: Path | None = None) -> ScanOutcome:
    """Scan one directory the way ``copilot scan`` would.

    ``categories`` set explicitly overrides the project config; ``None``
    inherits it, falling back to all categories. ``engine`` is the shared
    default engine; a fresh one is built whenever the config changes rules or
    guards, because guards mutate the engine they are added to.
    ``confine_config_to`` rejects a config ``rules_dir`` outside that folder
    (uploaded archives must not point the scanner at server paths).
    """
    root = Path(root)
    if not root.exists():
        raise ScanError(f"No such path: {root}")
    if not root.is_dir():
        raise ScanError(f"Not a directory: {root}")

    config = None
    config_file = root / CONFIG_FILENAME
    if use_config and config_file.is_file():
        try:
            config = load_config(config_file)
        except (ConfigError, OSError, UnicodeDecodeError) as exc:
            raise ScanError(f"Project config error: {exc}") from exc
        if confine_config_to and config.rules_dir and not Path(
                config.rules_dir).resolve().is_relative_to(confine_config_to.resolve()):
            raise ScanError("Project config rules_dir points outside the uploaded "
                            "archive; refusing to load it.")

    try:
        if config and (config.rules_dir or config.guards) or engine is None:
            engine = RuleEngine(config.rules_dir) if config and config.rules_dir \
                else RuleEngine()
        for control_id, patterns in (config.guards if config else {}).items():
            engine.add_guard_patterns(control_id, patterns)
    except (RuleError, re.error) as exc:
        raise ScanError(f"Rule error: {exc}") from exc

    if categories is None and config and config.categories:
        categories = config.categories
    if categories:
        unknown = [c for c in categories if c not in engine.categories]
        if unknown:
            raise ScanError(f"Unknown categories: {', '.join(unknown)}")

    ignore = ([glob_to_regex(p) for p in config.ignore_paths]
              if config and config.ignore_paths else None)
    try:
        scan_result = run_scan(str(root), ignore_patterns=ignore)
    except OSError as exc:
        raise ScanError(f"Scan failed: {exc}") from exc
    findings, skipped = run_all(scan_result, engine, categories or None)

    report = Report(
        scan=scan_result,
        findings=findings,
        skipped_controls=[s.to_dict() for s in skipped],
        categories_scanned=sorted(categories or engine.categories),
        categories_available=len(engine.categories),
    )
    applied = suppress.apply_config(findings, config.suppress if config else [])
    applied.problems.extend(suppress.problems(
        scan_result.inline_suppressions, {c.id.upper() for c in engine.controls()}))

    return ScanOutcome(
        report=report,
        source=source,
        scanned_at=datetime.now(timezone.utc),
        config_path=str(config_file) if config else None,
        suppressions_applied=applied.applied,
        problems=applied.problems,
    )


def extract_zip(data: bytes, dest: Path) -> Path:
    """Validate and unpack an archive into ``dest``; return the folder to scan.

    Rejects encrypted members, symlinks, absolute or ``..`` paths, and
    archives over the member/size bounds before writing anything.
    """
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise ScanError("Not a valid .zip archive.") from exc

    with archive:
        members = archive.infolist()
        if len(members) > MAX_ZIP_MEMBERS:
            raise ScanError(f"Archive has {len(members)} entries; the limit is "
                            f"{MAX_ZIP_MEMBERS}.")
        if sum(m.file_size for m in members) > MAX_ZIP_BYTES:
            raise ScanError(f"Archive expands past {MAX_ZIP_BYTES // (1024 * 1024)} MB.")
        dest = dest.resolve()
        for m in members:
            if m.flag_bits & 0x1:
                raise ScanError("Encrypted archives are not supported.")
            if stat.S_ISLNK(m.external_attr >> 16):
                raise ScanError(f"Archive contains a symlink: {m.filename}")
            target = (dest / m.filename).resolve()
            if not target.is_relative_to(dest):
                raise ScanError(f"Archive entry escapes the extraction folder: "
                                f"{m.filename}")
        try:
            archive.extractall(dest)
        except (zipfile.BadZipFile, NotImplementedError, OSError) as exc:
            raise ScanError(f"Could not extract archive: {exc}") from exc

    # A zip of a folder usually has one wrapper directory; scanning the wrapper
    # would make every relative path wrong.
    entries = [p for p in dest.iterdir() if not p.name.startswith("__MACOSX")]
    if len(entries) == 1 and entries[0].is_dir():
        return entries[0]
    return dest


def run_zip(data: bytes, name: str, **kwargs) -> ScanOutcome:
    """Extract, scan and always clean up. The report keeps the archive name,
    not the deleted temporary path."""
    with tempfile.TemporaryDirectory(prefix="copilot-upload-") as tmp:
        root = extract_zip(data, Path(tmp))
        outcome = run(root, source=name, confine_config_to=Path(tmp), **kwargs)
    outcome.report.scan.root_path = name
    if outcome.config_path:
        outcome.config_path = f"{name}/{CONFIG_FILENAME}"
    return outcome
