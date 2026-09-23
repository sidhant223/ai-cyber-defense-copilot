"""Accepting findings on purpose, and declaring this codebase's own guards.

The rules being asserted here are the ones that keep an accepted risk
honest: a reason is always required, an expired acceptance stops working, a
suppression that did not apply is reported, and an accepted finding leaves
the score and the exit code but stays in the report.
"""

from __future__ import annotations

import json
import shutil
import textwrap
from datetime import date, timedelta

import pytest

from copilot.cli import EXIT_CLEAN, EXIT_ERROR, EXIT_FINDINGS, main
from copilot.config import ConfigError, load_config
from copilot.detectors import run_all
from copilot.detectors.rule_engine import RuleEngine, RuleError
from copilot.models import Status
from copilot.suppress import ConfigSuppression, apply_config, parse_line

from conftest import SAMPLES

VULNERABLE = SAMPLES / "flask-notes-app"


@pytest.fixture
def sample(tmp_path):
    """A writable copy of a corpus sample, never the corpus itself."""
    target = tmp_path / "app"
    shutil.copytree(VULNERABLE, target)
    return target


def write_config(path, body: str):
    path.write_text(textwrap.dedent(body), encoding="utf-8")
    return path


def scan_json(capsys, *args) -> dict:
    main(["scan", *[str(a) for a in args], "--format", "json"])
    return json.loads(capsys.readouterr().out)


class TestInlineParsing:
    def test_reason_after_a_double_dash(self):
        s = parse_line("app.py", 3, "@app.route('/x')  # copilot: ignore AUTH-001 -- behind the VPN")
        assert s.control_ids == ("AUTH-001",) and s.reason == "behind the VPN"
        assert s.valid

    @pytest.mark.parametrize("text", [
        "// copilot: ignore AUTH-002 -- mounted behind the gateway",
        "/* copilot: ignore AUTH-002 -- mounted behind the gateway */",
        "<!-- copilot: ignore AUTH-002 -- mounted behind the gateway -->",
    ])
    def test_other_comment_syntaxes(self, text):
        assert parse_line("a.js", 1, text).reason == "mounted behind the gateway"

    def test_several_controls_in_one_comment(self):
        s = parse_line("app.py", 1, "# copilot: ignore AUTH-001, AC-004 -- internal tool")
        assert s.control_ids == ("AUTH-001", "AC-004")

    def test_reason_is_required(self):
        s = parse_line("app.py", 1, "# copilot: ignore AUTH-001")
        assert not s.valid and "has no reason" in s.problem

    def test_unrelated_comment_is_not_a_suppression(self):
        assert parse_line("app.py", 1, "# TODO: add auth") is None


class TestInlineOnASubject:
    ROUTES = textwrap.dedent("""
        from flask import Flask
        app = Flask(__name__)

        @app.route("/notes")
        def notes():
            return []

        @app.route("/internal/metrics")  # copilot: ignore AUTH-001 -- behind the VPN
        def metrics():
            return {}
    """)

    def test_accepted_subject_leaves_the_count(self, make_repo, engine):
        findings, _ = run_all(make_repo({"app.py": self.ROUTES}), engine,
                              ["authentication"])
        auth = next(f for f in findings if f.control_id == "AUTH-001")
        # One route remains, and it is unguarded.
        assert auth.status is Status.ABSENT
        assert "1 accepted inline" in auth.message
        assert any("behind the VPN" in e.note for e in auth.evidence)

    def test_a_comment_on_the_line_above_also_counts(self, make_repo, engine):
        source = self.ROUTES.replace(
            '@app.route("/notes")',
            '# copilot: ignore AUTH-001 -- public by design\n@app.route("/notes")')
        findings, _ = run_all(make_repo({"app.py": source}), engine, ["authentication"])
        auth = next(f for f in findings if f.control_id == "AUTH-001")
        assert auth.status is Status.NOT_APPLICABLE
        assert "accepted inline" in auth.message

    def test_a_comment_without_a_reason_does_not_suppress(self, make_repo, engine):
        source = self.ROUTES.replace(" -- behind the VPN", "")
        findings, _ = run_all(make_repo({"app.py": source}), engine, ["authentication"])
        auth = next(f for f in findings if f.control_id == "AUTH-001")
        assert auth.status is Status.ABSENT
        assert "accepted" not in auth.message

    def test_it_only_suppresses_the_named_control(self, make_repo, engine):
        source = self.ROUTES.replace("AUTH-001 -- behind the VPN",
                                     "RATE-002 -- behind the VPN")
        findings, _ = run_all(make_repo({"app.py": source}), engine, ["authentication"])
        auth = next(f for f in findings if f.control_id == "AUTH-001")
        assert auth.status is Status.ABSENT and "accepted" not in auth.message

    def test_cli_reports_a_suppression_that_did_not_apply(self, capsys, sample):
        (sample / "app.py").write_text(
            self.ROUTES.replace(" -- behind the VPN", ""), encoding="utf-8")
        main(["scan", str(sample)])
        assert "suppression(s) not applied" in capsys.readouterr().out


class TestConfigSuppression:
    def test_accepted_finding_leaves_gaps_and_the_score(self, capsys, sample, tmp_path):
        before = scan_json(capsys, sample)
        config = write_config(tmp_path / "c.yaml", """
            suppress:
              - control: RATE-001
                reason: rate limiting is enforced at the API gateway
        """)
        after = scan_json(capsys, sample, "--config", config)
        rate = next(f for f in after["findings"] if f["control_id"] == "RATE-001")
        assert rate["suppressed"] is True
        assert rate["suppression_reason"].startswith("rate limiting")
        assert after["summary"]["controls_suppressed"] == 1
        assert after["summary"]["controls_scored"] == before["summary"]["controls_scored"] - 1
        assert after["summary"]["posture_score"] != before["summary"]["posture_score"]

    def test_the_finding_stays_in_the_report(self, capsys, sample, tmp_path):
        config = write_config(tmp_path / "c.yaml", """
            suppress:
              - control: RATE-001
                reason: enforced at the gateway
        """)
        data = scan_json(capsys, sample, "--config", config)
        assert any(f["control_id"] == "RATE-001" for f in data["findings"])

    def test_exit_code_ignores_accepted_findings(self, capsys, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "app.py").write_text(
            "from flask import Flask\napp = Flask(__name__)\n"
            "@app.route('/login', methods=['POST'])\ndef login(): return 'ok'\n",
            encoding="utf-8")
        plain = main(["scan", str(repo)])
        capsys.readouterr()
        assert plain == EXIT_FINDINGS

        gaps = [f["control_id"] for f in scan_json(capsys, repo)["findings"]
                if f["status"] in ("absent", "partial")]
        config = write_config(tmp_path / "c.yaml", "suppress:\n" + "".join(
            f"  - control: {cid}\n    reason: accepted for this test\n" for cid in gaps))
        assert main(["scan", str(repo), "--config", str(config)]) == EXIT_CLEAN
        assert "accepted" in capsys.readouterr().out

    def test_an_expired_entry_does_not_apply_and_is_reported(self, capsys, sample, tmp_path):
        yesterday = (date.today() - timedelta(days=1)).isoformat()
        config = write_config(tmp_path / "c.yaml", f"""
            suppress:
              - control: RATE-001
                reason: was accepted for the last release only
                expires: {yesterday}
        """)
        data = scan_json(capsys, sample, "--config", config)
        rate = next(f for f in data["findings"] if f["control_id"] == "RATE-001")
        assert rate["suppressed"] is False
        main(["scan", str(sample), "--config", str(config)])
        assert "expired on" in capsys.readouterr().out

    def test_a_future_expiry_still_applies(self, capsys, sample, tmp_path):
        tomorrow = (date.today() + timedelta(days=1)).isoformat()
        config = write_config(tmp_path / "c.yaml", f"""
            suppress:
              - control: RATE-001
                reason: accepted until the gateway ships
                expires: {tomorrow}
        """)
        data = scan_json(capsys, sample, "--config", config)
        rate = next(f for f in data["findings"] if f["control_id"] == "RATE-001")
        assert rate["suppressed"] is True

    @pytest.mark.parametrize("body, expected", [
        ("suppress:\n  - control: RATE-001\n", "reason"),
        ("suppress:\n  - reason: no control named\n", "control"),
        ("suppress:\n  - control: RATE-001\n    reason: x\n    expires: soon\n", "YYYY-MM-DD"),
        ("suppress:\n  - control: RATE-001\n    reason: x\n    until: 2026-01-01\n", "unknown key"),
        ("suppress: RATE-001\n", "must be a list"),
    ])
    def test_malformed_entries_are_refused(self, tmp_path, body, expected):
        path = write_config(tmp_path / "c.yaml", body)
        with pytest.raises(ConfigError, match=expected):
            load_config(path)

    def test_a_malformed_date_never_means_never_expires(self, capsys, sample, tmp_path):
        config = write_config(tmp_path / "c.yaml", """
            suppress:
              - control: RATE-001
                reason: x
                expires: 31/12/2026
        """)
        assert main(["scan", str(sample), "--config", str(config)]) == EXIT_ERROR
        assert "expires" in capsys.readouterr().out

    def test_an_entry_for_a_control_that_did_not_run_is_reported(self, capsys, sample, tmp_path):
        config = write_config(tmp_path / "c.yaml", """
            suppress:
              - control: AUTH-002
                reason: this is a Flask app, so AUTH-002 never runs here
        """)
        main(["scan", str(sample), "--config", str(config)])
        assert "had no effect" in capsys.readouterr().out

    def test_apply_config_is_case_insensitive(self, capsys, sample):
        main(["scan", str(sample), "--format", "json"])
        findings_json = json.loads(capsys.readouterr().out)
        assert findings_json["summary"]["controls_suppressed"] == 0

        from copilot.models import Finding, Severity
        finding = Finding("RATE-001", "n", "rate_limiting", Status.ABSENT,
                          Severity.HIGH, "m")
        report = apply_config([finding], [ConfigSuppression("rate-001", "because")])
        assert finding.suppressed and report.applied


class TestCustomGuards:
    ROUTES = textwrap.dedent("""
        from flask import Flask
        app = Flask(__name__)

        @require_api_key
        @app.route("/notes")
        def notes():
            return []
    """)

    def test_without_the_config_an_in_house_guard_is_not_recognised(self, make_repo, engine):
        findings, _ = run_all(make_repo({"app.py": self.ROUTES}), engine,
                              ["authentication"])
        assert next(f for f in findings
                    if f.control_id == "AUTH-001").status is Status.ABSENT

    def test_declared_guards_are_recognised(self, capsys, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "app.py").write_text(self.ROUTES, encoding="utf-8")
        config = write_config(tmp_path / "c.yaml", """
            guards:
              AUTH-001: ['@require_api_key']
        """)
        data = scan_json(capsys, repo, "--config", config)
        auth = next(f for f in data["findings"] if f["control_id"] == "AUTH-001")
        assert auth["status"] == "present"

    def test_the_extra_guard_is_named_in_the_evidence(self, capsys, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "app.py").write_text(self.ROUTES, encoding="utf-8")
        config = write_config(tmp_path / "c.yaml", """
            guards:
              AUTH-001: ['@require_api_key']
        """)
        data = scan_json(capsys, repo, "--config", config)
        auth = next(f for f in data["findings"] if f["control_id"] == "AUTH-001")
        assert any("config" in e["note"] for e in auth["evidence"])

    def test_unknown_control_is_an_error(self, capsys, sample, tmp_path):
        config = write_config(tmp_path / "c.yaml", """
            guards:
              NOPE-001: ['@x']
        """)
        assert main(["scan", str(sample), "--config", str(config)]) == EXIT_ERROR
        assert "no such control" in capsys.readouterr().out

    def test_presence_controls_cannot_take_guards(self, capsys, sample, tmp_path):
        config = write_config(tmp_path / "c.yaml", """
            guards:
              RATE-001: ['\\bmy_limiter\\b']
        """)
        assert main(["scan", str(sample), "--config", str(config)]) == EXIT_ERROR
        # Line wrapping can fall inside the sentence, so match its start.
        assert "has no guards" in capsys.readouterr().out.replace("\n", "")

    def test_bad_regex_is_refused_at_load(self, tmp_path):
        path = write_config(tmp_path / "c.yaml", """
            guards:
              AUTH-001: ['([unclosed']
        """)
        with pytest.raises(ConfigError, match="bad regex"):
            load_config(path)

    def test_engine_rejects_guards_for_a_custom_control(self, engine):
        with pytest.raises(RuleError, match="has no guards to extend"):
            RuleEngine().add_guard_patterns("SECRET-003", ["x"])


class TestFailUnder:
    def test_below_the_threshold_exits_one(self, capsys, sample):
        assert main(["scan", str(sample), "--fail-under", "80"]) == EXIT_FINDINGS
        capsys.readouterr()

    def test_above_the_threshold_with_no_gaps_exits_zero(self, capsys):
        assert main(["scan", str(SAMPLES / "fastapi-secure-tasks"),
                     "--fail-under", "90"]) == EXIT_CLEAN
        capsys.readouterr()

    def test_it_is_independent_of_fail_on(self, capsys, sample):
        """No critical gap here, so --fail-on critical alone would pass."""
        assert main(["scan", str(sample), "--fail-on", "low",
                     "--fail-under", "10"]) == EXIT_FINDINGS
        capsys.readouterr()

    def test_config_key_works_too(self, capsys, sample, tmp_path):
        config = write_config(tmp_path / "c.yaml", "fail_under: 100\n")
        assert main(["scan", str(SAMPLES / "fastapi-secure-tasks"),
                     "--config", str(config)]) == EXIT_CLEAN
        capsys.readouterr()

    def test_a_score_out_of_range_is_refused(self, tmp_path):
        path = write_config(tmp_path / "c.yaml", "fail_under: 120\n")
        with pytest.raises(ConfigError, match="0 to 100"):
            load_config(path)
