"""CLI surface: exit codes, formats, filters, and the rules subcommands.

Exit codes matter more than they look: 0/1/2 is what makes the tool usable as
a CI gate, so they are asserted rather than assumed.
"""

from __future__ import annotations

import json
import sys

import pytest

from copilot.cli import (EXIT_CLEAN, EXIT_ERROR, EXIT_FINDINGS, _show_progress,
                         build_parser, main)

from conftest import SAMPLES

VULNERABLE = str(SAMPLES / "flask-notes-app")
SECURE = str(SAMPLES / "fastapi-secure-tasks")


class TestExitCodes:
    def test_findings_exit_one(self, capsys):
        assert main(["scan", VULNERABLE]) == EXIT_FINDINGS
        capsys.readouterr()

    def test_clean_repo_exits_zero(self, capsys):
        assert main(["scan", SECURE]) == EXIT_CLEAN
        capsys.readouterr()

    def test_missing_path_exits_two(self, capsys):
        assert main(["scan", "./does-not-exist"]) == EXIT_ERROR
        assert "no such path" in capsys.readouterr().out

    def test_file_instead_of_directory_exits_two(self, capsys, tmp_path):
        target = tmp_path / "a.py"
        target.write_text("x = 1", encoding="utf-8")
        assert main(["scan", str(target)]) == EXIT_ERROR
        assert "not a directory" in capsys.readouterr().out

    def test_fail_on_gates_by_severity(self, capsys):
        """--fail-on critical ignores a repo whose worst gap is medium."""
        assert main(["scan", VULNERABLE, "--fail-on", "critical"]) == EXIT_FINDINGS
        capsys.readouterr()

    def test_exit_zero_reports_without_gating(self, capsys):
        assert main(["scan", VULNERABLE, "--exit-zero"]) == EXIT_CLEAN
        # Still a full report: --exit-zero changes the verdict, not the output.
        assert "AUTH-001" in capsys.readouterr().out

    def test_exit_zero_does_not_hide_a_broken_run(self, capsys):
        """A scan that could not run is still an error: the flag says "do not
        gate on findings", not "always succeed"."""
        assert main(["scan", "./does-not-exist", "--exit-zero"]) == EXIT_ERROR
        capsys.readouterr()

    def test_fail_on_below_worst_severity_passes(self, capsys, tmp_path):
        (tmp_path / "app.py").write_text(
            "from flask import Flask\napp = Flask(__name__)\n", encoding="utf-8"
        )
        code = main(["scan", str(tmp_path), "--fail-on", "critical"])
        capsys.readouterr()
        assert code == EXIT_CLEAN


class TestFormats:
    def test_json_to_stdout(self, capsys):
        main(["scan", VULNERABLE, "--format", "json"])
        data = json.loads(capsys.readouterr().out)
        assert data["scan"]["framework"] == "flask"

    def test_json_to_file(self, capsys, tmp_path):
        out = tmp_path / "report.json"
        main(["scan", VULNERABLE, "--format", "json", "-o", str(out)])
        capsys.readouterr()
        assert json.loads(out.read_text(encoding="utf-8"))["findings"]

    def test_html_to_file(self, capsys, tmp_path):
        out = tmp_path / "report.html"
        main(["scan", VULNERABLE, "--format", "html", "-o", str(out)])
        capsys.readouterr()
        assert out.read_text(encoding="utf-8").startswith("<!DOCTYPE html>")

    def test_terminal_is_the_default(self, capsys):
        main(["scan", VULNERABLE])
        assert "posture score" in capsys.readouterr().out


class TestProgressIndicator:
    """The spinner is for a person at a terminal; it must never reach a pipe or a file."""

    @staticmethod
    def _args(*extra):
        return build_parser().parse_args(["scan", VULNERABLE, *extra])

    def test_shown_for_terminal_format_on_a_tty(self, monkeypatch):
        monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
        assert _show_progress(self._args()) is True

    @pytest.mark.parametrize("extra", [["--format", "json"], ["--format", "html"],
                                       ["-o", "report.txt"]])
    def test_hidden_for_machine_formats_and_files(self, monkeypatch, extra):
        monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
        assert _show_progress(self._args(*extra)) is False

    def test_hidden_when_stdout_is_not_a_tty(self, monkeypatch):
        monkeypatch.setattr(sys.stdout, "isatty", lambda: False)
        assert _show_progress(self._args()) is False

    def test_json_stays_clean_on_a_tty(self, capsys, monkeypatch):
        """The point is that the spinner never reaches stdout, so this asserts
        the document parses -- not a particular score, which rule work moves."""
        monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
        main(["scan", VULNERABLE, "--format", "json"])
        score = json.loads(capsys.readouterr().out)["summary"]["posture_score"]
        assert isinstance(score, int) and 0 <= score <= 100

    def test_html_stays_clean_on_a_tty(self, capsys, monkeypatch):
        monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
        main(["scan", VULNERABLE, "--format", "html"])
        assert capsys.readouterr().out.startswith("<!DOCTYPE html>")

    def test_terminal_run_with_spinner_still_reports(self, capsys, monkeypatch):
        monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
        assert main(["scan", VULNERABLE]) == EXIT_FINDINGS
        assert "posture score" in capsys.readouterr().out


class TestFilters:
    def test_category_filter(self, capsys):
        main(["scan", VULNERABLE, "--format", "json", "--category", "rate_limiting"])
        data = json.loads(capsys.readouterr().out)
        assert {f["category"] for f in data["findings"]} == {"rate_limiting"}

    def test_multiple_categories(self, capsys):
        main(["scan", VULNERABLE, "--format", "json",
              "--category", "rate_limiting,secret_management"])
        data = json.loads(capsys.readouterr().out)
        assert {f["category"] for f in data["findings"]} == {
            "rate_limiting", "secret_management"}

    def test_unknown_category_is_an_error(self, capsys):
        assert main(["scan", VULNERABLE, "--category", "nonsense"]) == EXIT_ERROR
        assert "unknown categor" in capsys.readouterr().out

    def test_min_severity_does_not_change_the_score(self, capsys):
        main(["scan", VULNERABLE, "--format", "json"])
        full = json.loads(capsys.readouterr().out)["summary"]["posture_score"]
        main(["scan", VULNERABLE, "--format", "json", "--min-severity", "critical"])
        filtered = json.loads(capsys.readouterr().out)["summary"]["posture_score"]
        assert full == filtered


class TestRulesCommands:
    def test_list_shows_every_control(self, capsys):
        assert main(["rules", "list"]) == EXIT_CLEAN
        out = capsys.readouterr().out
        for control_id in ("AUTH-001", "INPUT-002", "RATE-002",
                           "SECRET-003", "AC-004"):
            assert control_id in out

    def test_list_names_the_detectors(self, capsys):
        main(["rules", "list"])
        out = capsys.readouterr().out
        assert "authentication" in out and "secret_management" in out

    def test_list_filtered_by_category(self, capsys):
        main(["rules", "list", "--category", "rate_limiting"])
        out = capsys.readouterr().out
        assert "RATE-001" in out and "AUTH-001" not in out

    def test_explain_shows_subject_and_guard(self, capsys):
        assert main(["rules", "explain", "AUTH-001"]) == EXIT_CLEAN
        out = capsys.readouterr().out
        assert "Subject" in out and "Guard" in out and "Remediation" in out

    def test_explain_shows_the_verdict_mapping(self, capsys):
        main(["rules", "explain", "AUTH-001"])
        out = capsys.readouterr().out
        assert "no_subjects_guarded" in out and "absent" in out

    def test_explain_is_case_insensitive(self, capsys):
        assert main(["rules", "explain", "auth-001"]) == EXIT_CLEAN
        capsys.readouterr()

    def test_explain_handles_presence_controls(self, capsys):
        assert main(["rules", "explain", "RATE-001"]) == EXIT_CLEAN
        assert "Patterns" in capsys.readouterr().out

    def test_explain_handles_custom_controls(self, capsys):
        assert main(["rules", "explain", "SECRET-003"]) == EXIT_CLEAN
        assert "Implementation" in capsys.readouterr().out

    def test_explain_lists_multiple_guards(self, capsys):
        main(["rules", "explain", "AUTH-002"])
        out = capsys.readouterr().out
        assert "Guards" in out and "1." in out and "2." in out

    def test_explain_unknown_control_errors(self, capsys):
        assert main(["rules", "explain", "NOPE-999"]) == EXIT_ERROR
        assert "no such control" in capsys.readouterr().out


class TestBadRuleDirectory:
    def test_broken_rules_exit_two_rather_than_crash(self, capsys, tmp_path):
        rules = tmp_path / "rules"
        rules.mkdir()
        (rules / "broken.yaml").write_text("category: x\ncontrols: [{id: A}]\n",
                                           encoding="utf-8")
        code = main(["scan", VULNERABLE, "--rules", str(rules)])
        assert code == EXIT_ERROR
        assert "rule error" in capsys.readouterr().out

    def test_missing_rule_directory_exits_two(self, capsys, tmp_path):
        code = main(["rules", "list", "--rules", str(tmp_path / "nope")])
        assert code == EXIT_ERROR
        assert "rule error" in capsys.readouterr().out


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert "0.1.0" in capsys.readouterr().out
