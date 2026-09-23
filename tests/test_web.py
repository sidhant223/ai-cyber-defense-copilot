"""Web adapter parity with the CLI, archive safety, and UI session state."""

from __future__ import annotations

import io
import json
import shutil
import sys
import tempfile
import zipfile
from pathlib import Path

import pytest

from copilot.cli import main as cli_main
from copilot.detectors.rule_engine import RuleEngine

REPO_ROOT = Path(__file__).resolve().parent.parent
SAMPLES = REPO_ROOT / "corpus" / "samples"
sys.path.insert(0, str(REPO_ROOT / "web"))

import scan_service  # noqa: E402
from scan_service import ScanError  # noqa: E402

CONFIG = """\
categories: [authentication, secret_management]
ignore_paths: ['tests/**']
guards:
  AUTH-001: ['@my_own_guard']
suppress:
  - control: AUTH-001
    reason: accepted for the test
"""


def _cli(capsys, *argv) -> dict:
    assert cli_main(["scan", *map(str, argv), "--format", "json", "--exit-zero"]) == 0
    return json.loads(capsys.readouterr().out)


def _comparable(data: dict) -> dict:
    data = dict(data, generated_at=None)
    data["scan"] = dict(data["scan"], root_path=None, scan_duration_ms=None)
    return data


def _zip(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, text in files.items():
            z.writestr(name, text)
    return buf.getvalue()


def _zip_dir(root: Path) -> bytes:
    return _zip({f"{root.name}/{p.relative_to(root).as_posix()}": p.read_text("utf-8")
                 for p in root.rglob("*") if p.is_file()})


@pytest.mark.parametrize("sample,score,grade,gaps", [
    ("fastapi-secure-tasks", 100, "A", 0),
    ("flask-notes-app", 46, "F", 15),
])
def test_full_scope_matches_verified_cli(sample, score, grade, gaps):
    r = scan_service.run(SAMPLES / sample, sample).report
    assert (r.posture_score, r.grade, len(r.gaps), r.partial_scope) == \
        (score, grade, gaps, False)


def test_narrowed_scope_withholds_grade():
    r = scan_service.run(SAMPLES / "flask-notes-app", "x",
                         categories=["authentication"]).report
    assert r.partial_scope and r.grade is None and len(r.gaps) == 5


def test_configured_scan_matches_cli(tmp_path, capsys):
    project = tmp_path / "proj"
    shutil.copytree(SAMPLES / "flask-notes-app", project)
    (project / ".copilot.yaml").write_text(CONFIG, encoding="utf-8")

    shared = RuleEngine()
    guards_before = len(shared.get("AUTH-001").guards)
    outcome = scan_service.run(project, "proj", engine=shared)

    assert _comparable(outcome.report.to_dict()) == _comparable(_cli(capsys, project))
    assert outcome.report.partial_scope and outcome.config_path
    assert outcome.suppressions_applied
    assert len(shared.get("AUTH-001").guards) == guards_before  # not mutated

    # Explicit selection overrides the config; opting out ignores it.
    assert scan_service.run(project, "p", categories=["rate_limiting"]) \
        .report.categories_scanned == ["rate_limiting"]
    assert scan_service.run(project, "p", use_config=False).report.partial_scope is False


def test_invalid_inputs_raise_scan_error(tmp_path):
    with pytest.raises(ScanError, match="No such path"):
        scan_service.run(tmp_path / "missing", "m")
    (tmp_path / "f.txt").write_text("x")
    with pytest.raises(ScanError, match="Not a directory"):
        scan_service.run(tmp_path / "f.txt", "f")
    (tmp_path / ".copilot.yaml").write_text("categories: [nope]\n")
    with pytest.raises(ScanError):
        scan_service.run(tmp_path, "t")


def test_zip_matches_directory_scan_and_cleans_up():
    before = set(Path(tempfile.gettempdir()).glob("copilot-upload-*"))
    src = SAMPLES / "flask-notes-app"
    outcome = scan_service.run_zip(_zip_dir(src), "notes.zip")
    assert outcome.report.posture_score == scan_service.run(src, "d").report.posture_score
    assert outcome.report.scan.root_path == "notes.zip"
    assert set(Path(tempfile.gettempdir()).glob("copilot-upload-*")) == before


@pytest.mark.parametrize("data,match", [
    (b"not a zip", "valid .zip"),
    (_zip({"../evil.py": "x"}), "escapes"),
    (_zip({"proj/.copilot.yaml": "rules_dir: ../../..\n", "proj/app.py": ""}),
     "outside the uploaded archive"),
])
def test_zip_rejections(data, match):
    before = set(Path(tempfile.gettempdir()).glob("copilot-upload-*"))
    with pytest.raises(ScanError, match=match):
        scan_service.run_zip(data, "bad.zip")
    assert set(Path(tempfile.gettempdir()).glob("copilot-upload-*")) == before


def test_zip_bounds(monkeypatch):
    monkeypatch.setattr(scan_service, "MAX_ZIP_MEMBERS", 1)
    with pytest.raises(ScanError, match="entries"):
        scan_service.run_zip(_zip({"a.py": "", "b.py": ""}), "big.zip")


# --------------------------------------------------------------------------
# Local web server (stdlib, no extra dependencies)
# --------------------------------------------------------------------------

import threading                    # noqa: E402
import urllib.error                 # noqa: E402
import urllib.request               # noqa: E402

import server as web_server          # noqa: E402


@pytest.fixture(scope="module")
def base():
    srv = web_server.make_server(0)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()
    srv.server_close()


def _get(base, path):
    with urllib.request.urlopen(base + path) as res:
        return res.status, res.headers, res.read()


def _post(base, path, body, ctype="application/json"):
    data = json.dumps(body).encode() if ctype == "application/json" else body
    req = urllib.request.Request(base + path, data=data, method="POST",
                                 headers={"Content-Type": ctype})
    try:
        with urllib.request.urlopen(req) as res:
            return res.status, json.loads(res.read())
    except urllib.error.HTTPError as err:
        return err.code, json.loads(err.read())


def test_server_serves_the_app_and_blocks_traversal(base):
    status, headers, body = _get(base, "/")
    assert status == 200 and b"Defense Copilot" in body
    for asset in ("/app.js", "/report.js", "/tools.js", "/app.css"):
        assert _get(base, asset)[0] == 200
    with pytest.raises(urllib.error.HTTPError) as err:
        _get(base, "/../server.py")
    assert err.value.code == 404


def test_server_meta_rules_and_eval(base):
    meta = json.loads(_get(base, "/api/meta")[2])
    assert meta["controls"] == 28 and len(meta["samples"]) == 8
    flask = next(s for s in meta["samples"] if s["name"] == "flask-notes-app")
    assert (flask["score"], flask["grade"], flask["gaps"]) == (46, "F", 15)
    rules = json.loads(_get(base, "/api/rules")[2])
    assert any(r["id"] == "AUTH-001" and "- id: AUTH-001" in r["yaml"] for r in rules)
    dev = json.loads(_get(base, "/api/eval?split=dev")[2])
    assert (dev["fp"], dev["fn"]) == (0, 0)
    assert "error" in json.loads(_get(base, "/api/eval?split=holdout")[2])


def test_server_scan_report_routes_export(base):
    status, rep = _post(base, "/api/scan", {"kind": "sample", "name": "flask-notes-app"})
    assert status == 201
    assert (rep["summary"]["posture_score"], rep["summary"]["grade"]) == (46, "F")
    assert sum(f["is_gap"] for f in rep["findings"]) == 15
    ev = next(f for f in rep["findings"] if f["control_id"] == "INPUT-002")["evidence"][0]
    assert any(n == ev["line_number"] for n, _ in ev["context"])        # real source lines
    assert json.loads(_get(base, "/api/history")[2])[0]["id"] == rep["id"]
    routes = json.loads(_get(base, f"/api/routes/{rep['id']}")[2])
    assert routes["rows"] and "auth" in routes["columns"]
    status, headers, body = _get(base, f"/api/export/{rep['id']}?format=sarif")
    assert "attachment" in headers["Content-Disposition"] and b"2.1.0" in body

    status, narrow = _post(base, "/api/scan", {"kind": "sample", "name": "flask-notes-app",
                                                "categories": ["authentication"]})
    assert narrow["summary"]["grade"] is None and narrow["summary"]["scope"] == "partial"


def test_server_rejects_bad_scans(base):
    assert _post(base, "/api/scan", {"kind": "sample", "name": "../../etc"})[0] == 400
    code, body = _post(base, "/api/scan", {"kind": "folder", "path": str(REPO_ROOT / "nope")})
    assert code == 400 and "No such path" in body["error"]
    assert _post(base, "/api/scan", {"kind": "folder", "path": "x", "categories": "bad-cat"})[0] == 400
    code, body = _post(base, "/api/scan-zip?name=bad.zip", b"not a zip", "application/zip")
    assert code == 400 and "zip" in body["error"]
    code, _ = _post(base, "/api/scan-zip?name=notes.zip", _zip_dir(SAMPLES / "flask-notes-app"),
                    "application/zip")
    assert code == 201
    with pytest.raises(urllib.error.HTTPError) as err:
        _get(base, "/api/report/does-not-exist")
    assert err.value.code == 404


def _raw(base, path, method="GET", body=None, headers=None):
    req = urllib.request.Request(base + path, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req) as res:
            return res.status
    except urllib.error.HTTPError as err:
        return err.code


def test_server_refuses_rebinding_and_cross_site_requests(base):
    scan = json.dumps({"kind": "sample", "name": "flask-notes-app"}).encode()
    assert _raw(base, "/api/meta", headers={"Host": "evil.example:8000"}) == 403
    assert _raw(base, "/api/scan", "POST", scan, {"Content-Type": "application/json",
                                                  "Origin": "https://evil.example"}) == 403
    assert _raw(base, "/api/scan", "POST", scan, {"Content-Type": "text/plain"}) == 415
    assert _raw(base, "/api/scan", "POST", scan, {"Content-Type": "application/json",
                                                  "Sec-Fetch-Site": "cross-site"}) == 403
    assert _raw(base, "/api/scan", "POST", scan, {"Content-Type": "application/json",
                                                  "Origin": base}) == 201


def test_server_ground_truth_only_for_labelled_samples(base):
    _, rep = _post(base, "/api/scan", {"kind": "sample", "name": "flask-notes-app"})
    truth = json.loads(_get(base, f"/api/truth/{rep['id']}")[2])
    assert truth["labelled"] and (truth["tp"], truth["fp"], truth["fn"]) == (15, 0, 0)
    _, other = _post(base, "/api/scan", {"kind": "folder", "path": str(REPO_ROOT / "src")})
    assert json.loads(_get(base, f"/api/truth/{other['id']}")[2]) == {"labelled": False}
    _, zipped = _post(base, "/api/scan-zip?name=flask-notes-app.zip",
                      _zip_dir(SAMPLES / "flask-notes-app"), "application/zip")
    assert json.loads(_get(base, f"/api/truth/{zipped['id']}")[2]) == {"labelled": False}
