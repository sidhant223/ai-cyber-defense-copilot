"""Directory traversal with ignore rules.

Deliberately conservative: it is better to skip a vendored file than to spend
a minute of scan time on it and then report findings the developer does not
own. Everything skipped is counted so the report can say so.
"""

from __future__ import annotations

import os
from pathlib import Path

MAX_FILE_BYTES = 1_000_000

IGNORED_DIRS = {
    ".git", ".hg", ".svn",
    "node_modules", "bower_components", "vendor",
    "venv", ".venv", "env", ".env.d", "virtualenv",
    "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".tox",
    "dist", "build", "out", ".next", ".nuxt", ".svelte-kit",
    "site-packages", ".idea", ".vscode", "coverage", "htmlcov",
    ".terraform", "target", ".gradle",
}

#: Extension -> language label used everywhere downstream.
LANGUAGE_BY_EXT = {
    ".py": "python",
    ".pyi": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".json": "config",
    ".yaml": "config",
    ".yml": "config",
    ".toml": "config",
    ".ini": "config",
    ".cfg": "config",
    ".conf": "config",
    ".env": "config",
    ".txt": "text",
    ".md": "text",
    ".html": "markup",
    ".htm": "markup",
}

#: Filenames with no useful extension that we still want to read.
NAMED_FILES = {
    "requirements.txt": "config",
    "requirements-dev.txt": "config",
    "package.json": "config",
    "package-lock.json": "config",
    "pyproject.toml": "config",
    "setup.cfg": "config",
    "go.mod": "config",
    "Pipfile": "config",
    "Dockerfile": "config",
    "docker-compose.yml": "config",
    ".env": "config",
    ".env.local": "config",
    ".env.production": "config",
    ".env.example": "config",
    ".env.sample": "config",
    ".gitignore": "config",
    "Procfile": "config",
}

#: Anything matching these substrings is treated as generated / vendored.
MINIFIED_MARKERS = (".min.js", ".min.css", ".bundle.js", "-lock.json", ".map")


def language_for(name: str) -> str | None:
    """Language label for a filename, or None if we do not read this kind."""
    if name in NAMED_FILES:
        return NAMED_FILES[name]
    if name.startswith(".env"):
        return "config"
    return LANGUAGE_BY_EXT.get(Path(name).suffix.lower())


def is_ignored_dir(name: str) -> bool:
    return name in IGNORED_DIRS or (name.startswith(".") and name not in {".github"})


def looks_generated(name: str) -> bool:
    lowered = name.lower()
    return any(marker in lowered for marker in MINIFIED_MARKERS)


def walk(root: str, max_file_bytes: int | None = None) -> tuple[list, int]:
    """Return (files, skipped_count).

    ``files`` is a list of ScannedFile with text already read. Imported lazily
    to keep this module free of circular imports at module load.
    """
    from ..models import ScannedFile

    limit = MAX_FILE_BYTES if max_file_bytes is None else max_file_bytes
    root_path = Path(root).resolve()
    if not root_path.is_dir():
        raise NotADirectoryError(f"not a directory: {root}")

    files: list[ScannedFile] = []
    skipped = 0

    for dirpath, dirnames, filenames in os.walk(root_path):
        dirnames[:] = sorted(d for d in dirnames if not is_ignored_dir(d))
        for name in sorted(filenames):
            abs_path = Path(dirpath) / name
            language = language_for(name)
            if language is None or looks_generated(name):
                skipped += 1
                continue
            try:
                size = abs_path.stat().st_size
            except OSError:
                skipped += 1
                continue
            if size > limit:
                skipped += 1
                continue
            try:
                text = abs_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                skipped += 1
                continue
            rel = abs_path.relative_to(root_path).as_posix()
            files.append(
                ScannedFile(
                    path=rel,
                    abs_path=str(abs_path),
                    language=language,
                    size_bytes=size,
                    text=text,
                )
            )

    return files, skipped
