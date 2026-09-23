"""Framework fingerprinting.

Two signals, in priority order:

1. Manifest declarations (requirements.txt, package.json, pyproject.toml,
   go.mod). Most reliable -- a dependency is a statement of intent.
2. Import patterns in source. Weaker, but catches vendored or undeclared use.

Returns None when the signals do not agree or are too weak. A wrong framework
makes every downstream detector wrong, so an honest "unknown" is worth more
than a confident guess: rules that require a framework simply do not fire,
and framework-agnostic rules still do.
"""

from __future__ import annotations

import re
from collections import defaultdict

from ..models import Evidence, ScannedFile

SUPPORTED = ["flask", "fastapi", "django", "express", "nextjs", "koa", "nestjs", "starlette"]

#: framework -> regexes matched against manifest file contents.
MANIFEST_SIGNALS: dict[str, list[str]] = {
    "flask": [r"(?m)^\s*[\"']?[Ff]lask[\"']?\s*(?:[=<>~!]|$)", r"[\"']flask[\"']\s*[:=]"],
    "fastapi": [r"(?m)^\s*[\"']?fastapi[\"']?\s*(?:[=<>~!]|$)", r"[\"']fastapi[\"']\s*[:=]"],
    "django": [r"(?mi)^\s*[\"']?django[\"']?\s*(?:[=<>~!]|$)", r"[\"']django[\"']\s*[:=]"],
    "express": [r"[\"']express[\"']\s*:\s*[\"']"],
    "nextjs": [r"[\"']next[\"']\s*:\s*[\"']"],
    "koa": [r"[\"']koa[\"']\s*:\s*[\"']"],
    "nestjs": [r"[\"']@nestjs/core[\"']\s*:\s*[\"']"],
    "starlette": [r"(?m)^\s*[\"']?starlette[\"']?\s*(?:[=<>~!]|$)",
                  r"[\"']starlette[\"']\s*[:=]"],
}

MANIFEST_FILES = {
    "requirements.txt", "requirements-dev.txt", "pyproject.toml", "Pipfile",
    "setup.cfg", "package.json", "go.mod",
}

#: framework -> regexes matched against source files.
IMPORT_SIGNALS: dict[str, list[str]] = {
    "flask": [r"\bfrom\s+flask\s+import\b", r"\bimport\s+flask\b", r"\bFlask\s*\(\s*__name__"],
    "fastapi": [r"\bfrom\s+fastapi\s+import\b", r"\bimport\s+fastapi\b", r"\bFastAPI\s*\("],
    "django": [r"\bfrom\s+django[\w.]*\s+import\b", r"\bDJANGO_SETTINGS_MODULE\b",
               r"\bfrom\s+rest_framework\b"],
    "express": [r"require\s*\(\s*[\"']express[\"']\s*\)", r"from\s+[\"']express[\"']"],
    "nextjs": [r"from\s+[\"']next/", r"require\s*\(\s*[\"']next[\"']\s*\)",
               r"\bexport\s+default\s+async\s+function\s+handler\b"],
    "koa": [r"require\s*\(\s*[\"']koa[\"']\s*\)", r"from\s+[\"']koa[\"']"],
    "nestjs": [r"from\s+[\"']@nestjs/", r"require\s*\(\s*[\"']@nestjs/"],
    "starlette": [r"\bfrom\s+starlette[\w.]*\s+import\b", r"\bimport\s+starlette\b"],
}

MANIFEST_WEIGHT = 10
IMPORT_WEIGHT = 3
MIN_CONFIDENCE = 3

#: When several frameworks are declared, the more specific one wins.
#: Next.js apps very often also depend on express for a custom server; NestJS
#: runs on express by default; FastAPI is built on Starlette and its apps
#: import starlette middleware directly.
PRECEDENCE = {"nextjs": ("express",), "nestjs": ("express",), "django": (),
              "fastapi": ("starlette",), "flask": (), "express": (), "koa": (),
              "starlette": ()}


def _first_match(pattern: str, file: ScannedFile) -> tuple[int, str] | None:
    rx = re.compile(pattern)
    for i, line in enumerate(file.lines, start=1):
        m = rx.search(line)
        if m:
            return i, line.strip()[:200]
    return None


def detect_framework(files: list[ScannedFile]) -> tuple[str | None, list[Evidence]]:
    """Return (framework, evidence). ``framework`` is None when unsure."""
    scores: dict[str, int] = defaultdict(int)
    evidence: dict[str, list[Evidence]] = defaultdict(list)

    for f in files:
        name = f.path.rsplit("/", 1)[-1]
        is_manifest = name in MANIFEST_FILES
        signals = MANIFEST_SIGNALS if is_manifest else IMPORT_SIGNALS
        weight = MANIFEST_WEIGHT if is_manifest else IMPORT_WEIGHT
        if not is_manifest and f.language not in ("python", "javascript", "typescript"):
            continue
        for framework, patterns in signals.items():
            for pattern in patterns:
                hit = _first_match(pattern, f)
                if hit:
                    line_no, snippet = hit
                    scores[framework] += weight
                    evidence[framework].append(
                        Evidence(
                            file_path=f.path,
                            line_number=line_no,
                            snippet=snippet,
                            note=("declared in manifest" if is_manifest
                                  else "import or usage in source"),
                        )
                    )
                    break  # one signal per file per framework is enough

    if not scores:
        return None, [Evidence(
            file_path="", line_number=None, snippet=None,
            note=(f"searched {len(files)} files for manifest and import signals of "
                  f"{', '.join(SUPPORTED)}; none matched"),
        )]

    for winner, losers in PRECEDENCE.items():
        if scores.get(winner, 0) > 0:
            for loser in losers:
                scores.pop(loser, None)

    ranked = sorted(scores.items(), key=lambda kv: (-kv[1], kv[0]))
    top, top_score = ranked[0]
    if top_score < MIN_CONFIDENCE:
        return None, [Evidence(
            file_path="", line_number=None, snippet=None,
            note=f"weak signals only (best: {top} at {top_score}); reporting unknown",
        )]
    if len(ranked) > 1 and ranked[1][1] == top_score:
        tied = ", ".join(name for name, s in ranked if s == top_score)
        return None, [Evidence(
            file_path="", line_number=None, snippet=None,
            note=f"ambiguous: {tied} scored equally; reporting unknown",
        )]

    return top, evidence[top][:5]


def dominant_language(files: list[ScannedFile]) -> str:
    """The language most of the *source* is written in."""
    counts: dict[str, int] = defaultdict(int)
    for f in files:
        if f.language in ("python", "javascript", "typescript"):
            counts[f.language] += 1
    if not counts:
        return "unknown"
    if counts.get("typescript", 0) and counts.get("javascript", 0):
        # A TS project always carries some JS config; report the stricter one.
        if counts["typescript"] >= counts["javascript"]:
            return "typescript"
    return max(counts.items(), key=lambda kv: (kv[1], kv[0]))[0]
