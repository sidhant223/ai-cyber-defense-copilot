"""Guard rails for the unattended Nights Watch runs driven by task.md.

    python scripts/nightwatch.py baseline              capture scan + dev-eval JSON, once
    python scripts/nightwatch.py check [--ignore a,b]  exit 1 if output drifted from baseline
    python scripts/nightwatch.py snapshot PHASE        copy src/ tests/ docs/ before editing
    python scripts/nightwatch.py diff PHASE            write docs/nightwatch/diffs/PHASE.diff

This folder is not tracked by git and the run rules forbid commits, so
snapshot + diff stand in for one commit per feature.
"""

from __future__ import annotations

import argparse
import difflib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NW = ROOT / "docs" / "nightwatch"
TREES = ("src", "tests", "docs")
SKIP_NAMES = ("__pycache__", "*.pyc", "*.egg-info", "nightwatch", "progress.md")
#: Differ on every run without meaning anything changed.
VOLATILE = {"generated_at", "scan_duration_ms"}


# -- output guard ------------------------------------------------------------

def _cli_json(*args: str) -> dict:
    env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONPATH=str(ROOT / "src"))
    proc = subprocess.run([sys.executable, "-m", "copilot.cli", *args], cwd=ROOT, env=env,
                          capture_output=True, text=True, encoding="utf-8")
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        sys.exit(f"FAIL: `copilot {' '.join(args)}` did not print valid JSON "
                 f"(exit {proc.returncode}).\nstdout: {proc.stdout[:800]}\n"
                 f"stderr: {proc.stderr[:800]}")


def _outputs() -> dict[str, dict]:
    samples = sorted(p.name for p in (ROOT / "corpus" / "samples").iterdir() if p.is_dir())
    out = {f"scan-{s}": _cli_json("scan", f"corpus/samples/{s}", "--format", "json")
           for s in samples}
    out["evaluate-dev"] = _cli_json("evaluate", "--split", "dev", "--format", "json")
    return out


def _strip(obj, drop: set[str]):
    if isinstance(obj, dict):
        return {k: _strip(v, drop) for k, v in obj.items() if k not in drop}
    if isinstance(obj, list):
        return [_strip(v, drop) for v in obj]
    return obj


def _headline(name: str, data: dict) -> str:
    if name == "evaluate-dev":
        o = data.get("overall", {})
        keys = ("tp", "fp", "fn", "tn", "precision", "recall")
        return "evaluate-dev overall: " + ", ".join(f"{k}={o.get(k)}" for k in keys)
    s = data.get("summary", {})
    return f"{name}: score={s.get('posture_score')} scored={s.get('controls_scored')}"


def cmd_baseline() -> int:
    base = NW / "baseline"
    if base.exists():
        print(f"REFUSED: {base} already exists. The baseline is captured once, "
              f"before any feature work, and never regenerated.")
        return 1
    base.mkdir(parents=True)
    for name, data in _outputs().items():
        clean = _strip(data, VOLATILE)
        (base / f"{name}.json").write_text(json.dumps(clean, indent=2, ensure_ascii=False),
                                           encoding="utf-8")
        print(_headline(name, clean))
    print(f"baseline written to {base.relative_to(ROOT)}")
    return 0


def cmd_check(ignore: set[str]) -> int:
    base = NW / "baseline"
    if not base.is_dir():
        print("FAIL: no baseline. Run `python scripts/nightwatch.py baseline` first.")
        return 1
    drop = VOLATILE | ignore
    current = _outputs()
    failures = 0
    for path in sorted(base.glob("*.json")):
        name = path.stem
        want = _strip(json.loads(path.read_text(encoding="utf-8")), drop)
        if name not in current:
            print(f"FAIL {name}: in baseline but not produced now")
            failures += 1
            continue
        got = _strip(current[name], drop)
        if got == want:
            print(f"ok   {_headline(name, got)}")
            continue
        failures += 1
        print(f"FAIL {name} differs from baseline:")
        diff = difflib.unified_diff(json.dumps(want, indent=2).splitlines(),
                                    json.dumps(got, indent=2).splitlines(),
                                    "baseline", "now", lineterm="", n=2)
        print("\n".join(list(diff)[:60]))
    print(f"{'FAIL' if failures else 'OK'}: {failures} of {len(list(base.glob('*.json')))} "
          f"outputs drifted (ignored keys: {', '.join(sorted(drop))})")
    return 1 if failures else 0


# -- per-phase snapshot and diff --------------------------------------------

def _files(tree: Path) -> set[str]:
    skip = shutil.ignore_patterns(*SKIP_NAMES)
    out: set[str] = set()
    for dirpath, dirnames, filenames in os.walk(tree):
        ignored = skip(dirpath, dirnames + filenames)
        dirnames[:] = [d for d in dirnames if d not in ignored]
        for f in filenames:
            if f not in ignored:
                out.add(Path(dirpath, f).relative_to(tree).as_posix())
    return out


def cmd_snapshot(phase: str) -> int:
    snap = NW / "snapshots" / phase
    if snap.exists():
        print(f"kept existing snapshot {snap.relative_to(ROOT)} (phase was already started)")
        return 0
    for tree in TREES:
        shutil.copytree(ROOT / tree, snap / tree, ignore=shutil.ignore_patterns(*SKIP_NAMES))
    print(f"snapshot written to {snap.relative_to(ROOT)}")
    return 0


def cmd_diff(phase: str) -> int:
    snap = NW / "snapshots" / phase
    if not snap.is_dir():
        print(f"FAIL: no snapshot for {phase}. Run `snapshot {phase}` before editing.")
        return 1
    chunks: list[str] = []
    summary: list[str] = []
    for tree in TREES:
        before, after = _files(snap / tree), _files(ROOT / tree)
        for rel in sorted(before | after):
            old_p, new_p = snap / tree / rel, ROOT / tree / rel
            old = old_p.read_text(encoding="utf-8", errors="replace").splitlines() \
                if rel in before else []
            new = new_p.read_text(encoding="utf-8", errors="replace").splitlines() \
                if rel in after else []
            if old == new:
                continue
            label = f"{tree}/{rel}"
            kind = "added" if rel not in before else "removed" if rel not in after else "changed"
            plus = sum(1 for _ in difflib.unified_diff(old, new, n=0, lineterm="")
                       if _.startswith("+") and not _.startswith("+++"))
            minus = sum(1 for _ in difflib.unified_diff(old, new, n=0, lineterm="")
                        if _.startswith("-") and not _.startswith("---"))
            summary.append(f"{kind:<8} {label}  (+{plus} -{minus})")
            chunks.extend(difflib.unified_diff(old, new, f"a/{label}", f"b/{label}",
                                               lineterm=""))
    out = NW / "diffs" / f"{phase}.diff"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(chunks) + ("\n" if chunks else ""), encoding="utf-8")
    print("\n".join(summary) if summary else "no changes since snapshot")
    print(f"{len(summary)} file(s) differ; diff written to {out.relative_to(ROOT)}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="nightwatch")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("baseline")
    check = sub.add_parser("check")
    check.add_argument("--ignore", default="", help="comma-separated JSON keys to ignore")
    for name in ("snapshot", "diff"):
        sub.add_parser(name).add_argument("phase")
    args = parser.parse_args(argv)
    if args.cmd == "baseline":
        return cmd_baseline()
    if args.cmd == "check":
        return cmd_check({k.strip() for k in args.ignore.split(",") if k.strip()})
    if args.cmd == "snapshot":
        return cmd_snapshot(args.phase)
    return cmd_diff(args.phase)


if __name__ == "__main__":
    sys.exit(main())
