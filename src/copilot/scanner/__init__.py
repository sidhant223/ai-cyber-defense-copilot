"""Scanner: works out what a repository *contains*.

The detectors work out what it is *missing*. Keeping the two apart is the
whole point of the three-module split -- see docs/architecture.md.
"""

from __future__ import annotations

import re
import time

from ..detectors.rule_engine import path_matches
from ..models import ScanResult
from ..suppress import build as build_suppressions
from .framework import detect_framework, dominant_language
from .indexer import build_index
from .walker import walk


def scan(root: str, max_file_bytes: int | None = None,
         ignore_patterns: list[re.Pattern[str]] | None = None) -> ScanResult:
    """Walk, fingerprint and index a repository. Reads files; runs nothing.

    ``ignore_patterns`` (compiled with ``rule_engine.glob_to_regex``) drops
    matching files before framework detection and indexing, so a repo-relative
    glob in ``.copilot.yaml`` affects everything downstream the same way an
    unreadable file does.
    """
    started = time.perf_counter()
    files, skipped = walk(root, max_file_bytes=max_file_bytes)
    if ignore_patterns:
        kept = [f for f in files if not path_matches(f.path, ignore_patterns)]
        skipped += len(files) - len(kept)
        files = kept
    duration_ms = int((time.perf_counter() - started) * 1000)
    return scan_files(files, root=root, skipped=skipped, duration_ms=duration_ms)


def scan_files(files: list, root: str = "<memory>", skipped: int = 0,
               duration_ms: int = 0) -> ScanResult:
    """Fingerprint and index files that are already in memory.

    ``scan`` is this plus the walk. Split out so a rule example (see
    ``copilot rules test``) can go through the same framework detection and
    indexing as a real repository without touching the filesystem.
    """
    framework, fw_evidence = detect_framework(files)
    return ScanResult(
        root_path=root,
        framework=framework,
        language=dominant_language(files),
        files_scanned=len(files),
        file_index=build_index(files, framework),
        scan_duration_ms=duration_ms,
        files=files,
        framework_evidence=fw_evidence,
        skipped_files=skipped,
        inline_suppressions=build_suppressions(files),
    )


__all__ = ["scan", "scan_files", "walk", "detect_framework", "build_index",
           "dominant_language"]
