"""Finding confidence: set by match strength, overridable in YAML, display-only."""

from __future__ import annotations

import json
import textwrap

import pytest

from copilot.cli import main
from copilot.detectors import run_all
from copilot.detectors.rule_engine import RuleError, load_rule_file
from copilot.models import Confidence, Finding, Report, ScanResult, Severity, Status

from conftest import SAMPLES

VULNERABLE = str(SAMPLES / "flask-notes-app")

RULE = """
category: authentication
controls:
  - id: TEST-001
    name: Rate limiter registered
    severity: high
{confidence}
    detection:
      mode: presence
      patterns:
        any_of: ['Limiter\\(']
    verdict:
      found: present
      not_found: absent
"""


def _load(tmp_path, confidence_line: str):
    path = tmp_path / "rules.yaml"
    path.write_text(textwrap.dedent(RULE).format(confidence=confidence_line),
                    encoding="utf-8")
    return load_rule_file(path)[2][0]


def _finding(scan, engine, control_id):
    findings, _ = run_all(scan, engine)
    return next(f for f in findings if f.control_id == control_id)


class TestRuleOverride:
    def test_default_is_unset(self, tmp_path):
        assert _load(tmp_path, "").confidence is None

    def test_yaml_value_is_parsed(self, tmp_path):
        assert _load(tmp_path, "    confidence: low").confidence is Confidence.LOW

    def test_illegal_value_is_a_rule_error(self, tmp_path):
        with pytest.raises(RuleError, match="confidence"):
            _load(tmp_path, "    confidence: certain")

    def test_known_format_controls_declare_high(self, engine):
        assert engine.get("SECRET-001").confidence is Confidence.HIGH
        assert engine.get("SECRET-002").confidence is Confidence.HIGH


class TestDefaults:
    def test_regex_rules_default_to_medium(self, make_repo, engine):
        scan = make_repo({"app.py": "from flask import Flask\napp = Flask(__name__)\n"})
        assert _finding(scan, engine, "RATE-001").confidence is Confidence.MEDIUM

    def test_yaml_high_reaches_the_finding(self, make_repo, engine):
        scan = make_repo({"app.py": "x = 1\n"})
        assert _finding(scan, engine, "SECRET-001").confidence is Confidence.HIGH

    def test_entropy_alone_is_low(self, make_repo, engine):
        scan = make_repo({"config.py": 'api_key = "k3Jd9vQx7WpLmZ2rT8yB4nH6sC1aE5uG"\n'})
        finding = _finding(scan, engine, "SECRET-003")
        assert finding.status is Status.ABSENT
        assert finding.confidence is Confidence.LOW

    def test_entropy_with_a_known_key_prefix_is_high(self, make_repo, engine):
        scan = make_repo({"config.py": 'api_key = "sk_live_k3Jd9vQx7WpLmZ2rT8yB4nH6sC1aE5"\n'})
        finding = _finding(scan, engine, "SECRET-003")
        assert finding.status is Status.ABSENT
        assert finding.confidence is Confidence.HIGH

    def test_env_gitignore_check_is_high(self, make_repo, engine):
        scan = make_repo({".env": "API_KEY=abc\n", "app.py": "x = 1\n"})
        assert _finding(scan, engine, "SECRET-004").confidence is Confidence.HIGH


class TestDisplayFilter:
    @staticmethod
    def _report() -> Report:
        scan = ScanResult(root_path=".", framework=None, language="python",
                          files_scanned=0, file_index={}, scan_duration_ms=0)
        return Report(scan=scan, findings=[
            Finding("HI", "hi", "c", Status.ABSENT, Severity.HIGH, "m",
                    confidence=Confidence.HIGH),
            Finding("LO", "lo", "c", Status.ABSENT, Severity.HIGH, "m",
                    confidence=Confidence.LOW),
            Finding("OK", "ok", "c", Status.PRESENT, Severity.HIGH, "m",
                    confidence=Confidence.LOW),
        ])

    def test_hides_gaps_below_the_cutoff(self):
        shown = self._report().display_findings(min_confidence="high", show_satisfied=True)
        assert [f.control_id for f in shown] == ["HI", "OK"]

    def test_score_ignores_the_filter(self):
        report = self._report()
        before = report.posture_score
        report.display_findings(min_confidence="high")
        assert report.posture_score == before


class TestCli:
    def test_score_summary_and_exit_code_unchanged(self, capsys):
        plain = main(["scan", VULNERABLE])
        plain_last = capsys.readouterr().out.strip().splitlines()[-1]
        filtered = main(["scan", VULNERABLE, "--min-confidence", "high"])
        filtered_out = capsys.readouterr().out
        assert filtered == plain
        assert filtered_out.strip().splitlines()[-1] == plain_last

    def test_json_score_unchanged_by_the_flag(self, capsys):
        main(["scan", VULNERABLE, "--format", "json"])
        full = json.loads(capsys.readouterr().out)
        main(["scan", VULNERABLE, "--format", "json", "--min-confidence", "high"])
        filtered = json.loads(capsys.readouterr().out)
        assert full["summary"]["posture_score"] == filtered["summary"]["posture_score"] == 46

    def test_json_carries_confidence_and_new_schema(self, capsys):
        main(["scan", VULNERABLE, "--format", "json"])
        data = json.loads(capsys.readouterr().out)
        # 1.1 added confidence, 1.2 the cwe/owasp references, 1.3 suppression.
        assert data["schema_version"] == "1.4"
        assert all(f["confidence"] in ("high", "medium", "low") for f in data["findings"])

    def test_terminal_hides_low_confidence_gaps(self, capsys):
        main(["scan", VULNERABLE, "--min-confidence", "high"])
        out = capsys.readouterr().out
        assert "AC-001" not in out  # a medium-confidence gap in this sample
