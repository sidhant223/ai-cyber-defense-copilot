"""Local web UI: static files plus a small JSON API over the scan pipeline.

Standard library only. Binds to 127.0.0.1: this is a single-user local tool
that reads folders on this machine, never a network service.

    python web/server.py            # http://127.0.0.1:8000
    python web/server.py --port 9000 --no-browser
"""

from __future__ import annotations

import argparse
import json
import sys
import threading
import webbrowser
from collections import OrderedDict
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

WEB = Path(__file__).resolve().parent
ROOT = WEB.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(WEB))

from copilot import __version__                                     # noqa: E402
from copilot.detectors import RuleEngine                            # noqa: E402
from copilot.detectors.rule_engine import DEFAULT_RULES_DIR         # noqa: E402
from copilot.evaluation import EvaluationError, evaluate            # noqa: E402
from copilot.evaluation.harness import (NOT_REPORTED, load_manifest,  # noqa: E402
                                        outcome as label_outcome)
from copilot.models import SCHEMA_VERSION                            # noqa: E402
from copilot.reporter import (render_html, render_json,             # noqa: E402
                              render_markdown, render_sarif)
from copilot.reporter.markdown_report import fix_prompt             # noqa: E402
from copilot.routes import COLUMNS, inventory                       # noqa: E402

import scan_service                                                  # noqa: E402
from scan_service import ScanError                                   # noqa: E402

STATIC = WEB / "static"
CORPUS = ROOT / "corpus" / "samples"
MANIFEST = ROOT / "corpus" / "manifest.yaml"
NEGATIVE_CONTROLS = {"fastapi-secure-tasks", "express-secure-notes"}
HISTORY_LIMIT = 10
LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}
MAX_BODY = 60 * 1024 * 1024       # zip uploads; scan_service bounds the expansion
CONTEXT = (3, 5)                  # source lines shown above / below evidence
MIME = {".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8",
        ".js": "text/javascript; charset=utf-8", ".svg": "image/svg+xml"}
EXPORTS = {"html": (render_html, "text/html", "html"),
           "json": (render_json, "application/json", "json"),
           "sarif": (render_sarif, "application/json", "sarif"),
           "md": (render_markdown, "text/markdown", "md")}

ENGINE = RuleEngine()             # shared and never mutated; guards get a fresh engine
_lock = threading.Lock()
_reports: OrderedDict[str, object] = OrderedDict()   # id -> ScanOutcome, newest last
_seq = 0
_cache: dict[str, object] = {}


# --------------------------------------------------------------------------
# data shaping
# --------------------------------------------------------------------------

def _context(outcome, ev) -> list[list]:
    if not ev.file_path or not ev.line_number:
        return []
    scanned = outcome.report.scan.by_path(ev.file_path)
    if scanned is None:
        return []
    lines = scanned.lines
    lo, hi = max(1, ev.line_number - CONTEXT[0]), min(len(lines), ev.line_number + CONTEXT[1])
    return [[n, lines[n - 1]] for n in range(lo, hi + 1)]


def outcome_json(sid: str, outcome) -> dict:
    r = outcome.report
    data = r.to_dict()
    for f, fd in zip(r.findings, data["findings"]):
        fd["is_gap"] = f.is_gap
        fd["weight"] = f.severity.weight
        fd["fix_prompt"] = fix_prompt(f) if f.is_gap else ""
        for ev, evd in zip(f.evidence, fd["evidence"]):
            evd["context"] = _context(outcome, ev)
    scored = r.scored_findings
    credit = {"present": 1.0, "partial": 0.5, "absent": 0.0}
    data["id"] = sid
    data["source"] = outcome.source
    data["scanned_at"] = outcome.scanned_at.isoformat()
    data["config_path"] = outcome.config_path
    data["suppressions_applied"] = outcome.suppressions_applied
    data["problems"] = outcome.problems
    data["categories_available"] = r.categories_available
    data["weights"] = {"total": sum(f.severity.weight for f in scored),
                       "earned": sum(f.severity.weight * credit[f.status.value] for f in scored)}
    data["scan"].pop("file_index", None)      # large and unused by the UI
    return data


def history() -> list[dict]:
    with _lock:
        items = list(_reports.items())[::-1]
    return [{"id": sid, "source": o.source, "scanned_at": o.scanned_at.isoformat(),
             "score": o.report.posture_score, "grade": o.report.grade,
             "gaps": len(o.report.gaps), "framework": o.report.scan.framework}
            for sid, o in items]


def store(outcome) -> str:
    global _seq
    with _lock:
        _seq += 1
        sid = str(_seq)
        _reports[sid] = outcome
        while len(_reports) > HISTORY_LIMIT:
            _reports.popitem(last=False)
    return sid


def samples() -> list[dict]:
    """Full-scope result per bundled sample; fixtures only, so cached for the process."""
    with _lock:
        if "samples" in _cache:
            return _cache["samples"]
    out = []
    for path in sorted(p for p in CORPUS.iterdir() if p.is_dir()) if CORPUS.is_dir() else []:
        try:
            r = scan_service.run(path, path.name, engine=RuleEngine()).report
        except ScanError:
            continue
        out.append({"name": path.name, "framework": r.scan.framework, "language": r.scan.language,
                    "kind": "negative control" if path.name in NEGATIVE_CONTROLS else "realistic",
                    "score": r.posture_score, "grade": r.grade, "gaps": len(r.gaps)})
    with _lock:
        _cache["samples"] = out
    return out


def _rule_yaml(control) -> str:
    path = Path(control.source_file)
    if not path.is_absolute():
        path = Path(DEFAULT_RULES_DIR) / path
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return ""
    m = re.search(rf"^(\s*)- id:\s*{re.escape(control.id)}\s*$", text, re.M)
    if not m:
        return ""
    nxt = re.compile(rf"^{re.escape(m.group(1))}- id:", re.M).search(text, m.end())
    return text[m.start():nxt.start() if nxt else len(text)].rstrip()


def rules() -> list[dict]:
    if "rules" not in _cache:
        _cache["rules"] = [
            {"id": c.id, "name": c.name, "category": c.category, "severity": c.severity.value,
             "mode": c.mode, "cwe": c.cwe, "owasp": c.owasp, "source_file": c.source_file,
             "description": c.description, "rationale": c.rationale,
             "remediation": c.remediation_hint,
             "verdict": {k: v.value for k, v in c.verdict.items()}, "yaml": _rule_yaml(c)}
            for c in sorted(ENGINE.controls(), key=lambda c: (c.category, c.id))]
    return _cache["rules"]


def evaluation(split: str) -> dict:
    key = f"eval-{split}"
    if key not in _cache:
        try:
            res = evaluate(MANIFEST, split)
        except EvaluationError as exc:
            return {"error": str(exc)}
        t = res.overall
        _cache[key] = {"tp": t.tp, "fp": t.fp, "fn": t.fn, "tn": t.tn,
                       "samples": [{"name": s.name, "framework": s.framework_detected,
                                    "disagreements": len(s.disagreements)} for s in res.samples]}
    return _cache[key]


def ground_truth(outcome) -> dict:
    """Compare this report with the manifest labels -- only when the scanned
    folder *is* a labelled corpus sample. Anything else has no ground truth,
    and inventing accuracy for it would be worse than saying so."""
    root = Path(outcome.report.scan.root_path)
    try:
        labelled = {s.path.resolve(): s for s in load_manifest(MANIFEST)}
    except EvaluationError:
        return {"labelled": False}
    sample = labelled.get(root.resolve()) if root.is_absolute() else None
    if sample is None:
        return {"labelled": False}
    r = outcome.report
    scanned = set(r.categories_scanned)
    reported = {f["control_id"]: f["status"] for f in r.to_dict()["findings"]}
    tally = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    rows = []
    for control in sorted(ENGINE.controls(), key=lambda c: c.id):
        if control.category not in scanned:
            continue                      # a narrowed run says nothing about the rest
        if control.id in sample.expected:
            want = sample.expected[control.id]
        elif control.id in sample.skipped:
            want = NOT_REPORTED
        else:
            continue
        got = reported.get(control.id, NOT_REPORTED)
        verdict = label_outcome(want, got)
        tally[verdict] += 1
        if want != got:
            rows.append({"control_id": control.id, "expected": want, "reported": got,
                         "outcome": verdict})
    return {"labelled": True, "sample": sample.name, "split": sample.split, **tally,
            "disagreements": rows}


def routes_json(outcome) -> dict:
    rows = inventory(outcome.report.scan, ENGINE)
    return {"columns": list(COLUMNS), "rows": [r.to_dict() for r in rows]}


def _categories(value) -> list[str] | None:
    if value in (None, "", []):
        return None
    cats = value.split(",") if isinstance(value, str) else value
    if not isinstance(cats, list) or not all(isinstance(c, str) for c in cats):
        raise ScanError("categories must be a list of names")
    return [c.strip() for c in cats if c.strip()] or None


# --------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    server_version = "copilot-web"

    def log_message(self, fmt, *args):      # quiet: one line per error only
        if args and str(args[1]).startswith(("4", "5")):
            sys.stderr.write("%s %s\n" % (self.address_string(), fmt % args))

    # -- responses ---------------------------------------------------------
    def _send(self, status: int, body: bytes, ctype: str, extra: dict | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, data, status: int = 200) -> None:
        self._send(status, json.dumps(data, ensure_ascii=False).encode("utf-8"),
                   "application/json; charset=utf-8")

    def _error(self, status: int, message: str) -> None:
        self._json({"error": message}, status)

    def _body(self) -> bytes:
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_BODY:
            raise ScanError(f"Upload is larger than {MAX_BODY // (1024 * 1024)} MB.")
        return self.rfile.read(length)

    # -- request guard -----------------------------------------------------
    def _trusted(self, state_changing: bool) -> bool:
        """Refuse DNS-rebinding and cross-site requests.

        Binding to 127.0.0.1 is not enough on its own: a hostile page can
        point its own hostname at 127.0.0.1 (Host check) or POST here from
        its origin (Origin check), and a folder scan reads local files.
        """
        host = urlparse("//" + (self.headers.get("Host") or "")).hostname
        if host not in LOCAL_HOSTS:
            self._error(403, "Requests must address this server as localhost.")
            return False
        origin = self.headers.get("Origin")
        if origin and urlparse(origin).hostname not in LOCAL_HOSTS:
            self._error(403, "Cross-origin requests are refused.")
            return False
        if state_changing and not origin and self.headers.get("Sec-Fetch-Site") not in (
                None, "same-origin", "none"):
            self._error(403, "Cross-site requests are refused.")
            return False
        return True

    # -- routing -----------------------------------------------------------
    def do_GET(self) -> None:
        if not self._trusted(state_changing=False):
            return
        url = urlparse(self.path)
        parts = [unquote(p) for p in url.path.strip("/").split("/") if p]
        q = {k: v[0] for k, v in parse_qs(url.query).items()}
        if not parts or parts[0] != "api":
            return self._static(url.path)
        route = parts[1] if len(parts) > 1 else ""
        arg = parts[2] if len(parts) > 2 else None
        if route == "meta":
            return self._json({"version": __version__, "schema": SCHEMA_VERSION,
                               "controls": len(ENGINE.controls()),
                               "categories": sorted(ENGINE.categories),
                               "samples": samples()})
        if route == "history":
            return self._json(history())
        if route == "rules":
            return self._json(rules())
        if route == "eval":
            return self._json(evaluation(q.get("split", "dev")))
        if route in ("report", "routes", "export", "truth"):
            with _lock:
                outcome = _reports.get(arg or "")
            if outcome is None:
                return self._error(404, "That report is no longer held; scan again.")
            if route == "report":
                return self._json(outcome_json(arg, outcome))
            if route == "routes":
                return self._json(routes_json(outcome))
            if route == "truth":
                return self._json(ground_truth(outcome))
            fmt = q.get("format", "html")
            if fmt not in EXPORTS:
                return self._error(400, f"unknown format {fmt!r}")
            render, mime, ext = EXPORTS[fmt]
            name = "".join(c if c.isalnum() or c in "-_." else "-" for c in Path(outcome.source).stem)
            return self._send(200, render(outcome.report).encode("utf-8"), f"{mime}; charset=utf-8",
                              {"Content-Disposition": f'attachment; filename="{name or "report"}-posture.{ext}"'})
        return self._error(404, "unknown endpoint")

    def do_POST(self) -> None:
        if not self._trusted(state_changing=True):
            return
        url = urlparse(self.path)
        q = {k: v[0] for k, v in parse_qs(url.query).items()}
        try:
            if url.path == "/api/scan":
                # A cross-site HTML form cannot send application/json without a
                # CORS preflight, which this server never answers.
                if not (self.headers.get("Content-Type") or "").startswith("application/json"):
                    return self._error(415, "Send the scan request as application/json.")
                req = json.loads(self._body() or b"{}")
                if not isinstance(req, dict):
                    raise ScanError("request must be a JSON object")
                opts = {"categories": _categories(req.get("categories")),
                        "use_config": bool(req.get("use_config", True)), "engine": ENGINE}
                if req.get("kind") == "sample":
                    name = str(req.get("name", ""))
                    if name not in {s["name"] for s in samples()}:
                        raise ScanError(f"No bundled sample named {name!r}.")
                    outcome = scan_service.run(CORPUS / name, name, **opts)
                elif req.get("kind") == "folder":
                    raw = str(req.get("path", "")).strip().strip('"')
                    if not raw:
                        raise ScanError("Enter the path of a folder to scan.")
                    outcome = scan_service.run(Path(raw), Path(raw).name or raw, **opts)
                else:
                    raise ScanError("kind must be 'sample' or 'folder'")
            elif url.path == "/api/scan-zip":
                name = Path(q.get("name", "upload.zip")).name or "upload.zip"
                outcome = scan_service.run_zip(
                    self._body(), name, categories=_categories(q.get("categories")),
                    use_config=q.get("use_config", "1") == "1", engine=ENGINE)
            else:
                return self._error(404, "unknown endpoint")
        except ScanError as exc:
            return self._error(400, str(exc))
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
            return self._error(400, "Request body is not valid JSON.")
        sid = store(outcome)
        self._json(outcome_json(sid, outcome), 201)

    def _static(self, path: str) -> None:
        rel = "index.html" if path in ("", "/") else path.lstrip("/")
        target = (STATIC / rel).resolve()
        if not target.is_relative_to(STATIC.resolve()) or not target.is_file():
            return self._error(404, "not found")
        self._send(200, target.read_bytes(), MIME.get(target.suffix, "application/octet-stream"))


def make_server(port: int = 8000) -> ThreadingHTTPServer:
    return ThreadingHTTPServer(("127.0.0.1", port), Handler)


def main() -> None:
    ap = argparse.ArgumentParser(description="Run the Defense Copilot web UI locally.")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--no-browser", action="store_true")
    args = ap.parse_args()
    server = make_server(args.port)
    url = f"http://127.0.0.1:{args.port}"
    print(f"Defense Copilot {__version__} on {url}  (Ctrl+C to stop)")
    if not args.no_browser:
        threading.Timer(0.6, webbrowser.open, (url,)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
