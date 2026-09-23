"""The one-line scan summary: counts must match the report, never the display filters."""

from __future__ import annotations

import sys

import pytest

from copilot.cli import (EXIT_CLEAN, EXIT_ERROR, EXIT_FINDINGS, _show_progress,
                         build_parser, main)
from copilot.models import Finding, Report, ScanResult, Severity, Status
from copilot.reporter.terminal_report import summary_line

from conftest import SAMPLES

VULNERABLE = str(SAMPLES / "flask-notes-app")
SECURE = str(SAMPLES / "fastapi-secure-tasks")
FLASK_NOTES_LINE = "28 checks · 22 applicable · 15 gaps · score 46"
SECURE_TASKS_LINE = "28 checks · 18 applicable · 0 gaps · score 100"


def _finding(cid: str, status: Status, severity: Severity) -> Finding:
    return Finding(cid, cid, "authentication", status, severity, "msg")


def _mixed_report() -> Report:
    scan = ScanResult(root_path=".", framework="flask", language="python",
                      files_scanned=0, file_index={}, scan_duration_ms=0)
    findings = [
        _finding("P-1", Status.PRESENT, Severity.CRITICAL),
        _finding("P-2", Status.PRESENT, Severity.LOW),
        _finding("A-1", Status.ABSENT, Severity.HIGH),
        _finding("A-2", Status.ABSENT, Severity.MEDIUM),
        _finding("X-1", Status.PARTIAL, Severity.CRITICAL),
        _finding("N-1", Status.NOT_APPLICABLE, Severity.HIGH),
        _finding("N-2", Status.NOT_APPLICABLE, Severity.LOW),
    ]
    skipped = [{"control_id": "S-1", "category": "authentication", "reason": "no files"}]
    return Report(scan=scan, findings=findings, skipped_controls=skipped)


def test_summary_line_counts_a_known_mix():
    # checks = 7 findings + 1 skipped = 8; applicable = 5 (two n/a left out);
    # gaps = 2 absent + 1 partial = 3.
    # score: weights 5+1+3+2+5 = 16, earned 5*1 + 1*1 + 3*0 + 2*0 + 5*0.5 = 8.5,
    # 100 * 8.5 / 16 = 53.125 -> 53.
    assert summary_line(_mixed_report()) == "8 checks · 5 applicable · 3 gaps · score 53"


def _last_line(out: str) -> str:
    return [line for line in out.splitlines() if line.strip()][-1]


def test_terminal_output_ends_with_the_summary_line(capsys):
    main(["scan", VULNERABLE])
    assert _last_line(capsys.readouterr().out) == FLASK_NOTES_LINE


def test_min_severity_does_not_change_the_summary_line(capsys):
    main(["scan", VULNERABLE, "--min-severity", "critical"])
    assert _last_line(capsys.readouterr().out) == FLASK_NOTES_LINE


def test_terminal_output_to_file_ends_with_the_summary_line(capsys, tmp_path):
    out = tmp_path / "report.txt"
    main(["scan", VULNERABLE, "-o", str(out)])
    capsys.readouterr()
    assert _last_line(out.read_text(encoding="utf-8")) == FLASK_NOTES_LINE


class TestSummaryOnly:
    @pytest.mark.parametrize("path, line, code", [
        (VULNERABLE, FLASK_NOTES_LINE, EXIT_FINDINGS),
        (SECURE, SECURE_TASKS_LINE, EXIT_CLEAN),
    ])
    def test_prints_exactly_the_summary_line(self, capsys, path, line, code):
        assert main(["scan", path, "--summary-only"]) == code
        assert capsys.readouterr().out.splitlines() == [line]

    @pytest.mark.parametrize("path", [VULNERABLE, SECURE])
    @pytest.mark.parametrize("fail_on", ["critical", "high", "medium", "low"])
    def test_exit_code_matches_a_full_scan(self, capsys, path, fail_on):
        full = main(["scan", path, "--fail-on", fail_on])
        summary = main(["scan", path, "--fail-on", fail_on, "--summary-only"])
        capsys.readouterr()
        assert summary == full

    def test_writes_only_the_line_to_a_file(self, capsys, tmp_path):
        out = tmp_path / "summary.txt"
        assert main(["scan", VULNERABLE, "--summary-only", "-o", str(out)]) == EXIT_FINDINGS
        assert capsys.readouterr().out == ""
        assert out.read_text(encoding="utf-8").splitlines() == [FLASK_NOTES_LINE]

    @pytest.mark.parametrize("fmt", ["json", "html"])
    def test_rejects_machine_formats(self, capsys, fmt):
        assert main(["scan", VULNERABLE, "--summary-only", "--format", fmt]) == EXIT_ERROR
        assert "--summary-only" in capsys.readouterr().out

    def test_hides_the_spinner(self, monkeypatch):
        monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
        args = build_parser().parse_args(["scan", VULNERABLE, "--summary-only"])
        assert _show_progress(args) is False
