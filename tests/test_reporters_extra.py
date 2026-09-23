"""Grade, fingerprints, SARIF and Markdown.

The grade rules are the interesting part: a letter reads as a verdict on the
whole application, so it is capped when a critical control is missing and
withheld entirely when the run only covered part of the categories.
"""

from __future__ import annotations

import json

import pytest

from copilot.cli import EXIT_ERROR, main
from copilot.models import (Evidence, Finding, Report, ScanResult, Severity,
                            Status)
from copilot.reporter import render_markdown, render_sarif
from copilot.reporter.markdown_report import fix_prompt

from conftest import SAMPLES

VULNERABLE = str(SAMPLES / "flask-notes-app")
SECURE = str(SAMPLES / "fastapi-secure-tasks")


def make_report(*findings, categories=("a",), available=1) -> Report:
    scan = ScanResult(root_path="repo", framework="flask", language="python",
                      files_scanned=1, file_index={"entrypoint": ["app.py"]},
                      scan_duration_ms=0)
    return Report(scan=scan, findings=list(findings),
                  categories_scanned=list(categories),
                  categories_available=available)


def finding(status=Status.ABSENT, severity=Severity.HIGH, control_id="X-001",
            evidence=None, **kwargs) -> Finding:
    return Finding(control_id, "A control", "a", status, severity, "a message",
                   evidence=evidence if evidence is not None else
                   [Evidence("app.py", 12, "@app.route('/x')", "no guard nearby")],
                   remediation_hint="add the control", **kwargs)


class TestGrade:
    @pytest.mark.parametrize("score_findings, expected", [
        ([finding(Status.PRESENT, Severity.LOW)], "A"),
        ([finding(Status.PRESENT, Severity.LOW), finding(Status.ABSENT, Severity.LOW)],
         "F"),
    ])
    def test_bands(self, score_findings, expected):
        assert make_report(*score_findings).grade == expected

    def test_a_critical_absence_caps_the_grade(self):
        # Twenty present controls and one absent critical: the weighted
        # average is comfortably a B, and the app has no authentication.
        present = [finding(Status.PRESENT, Severity.LOW, f"OK-{i}") for i in range(20)]
        report = make_report(*present, finding(Status.ABSENT, Severity.CRITICAL,
                                               "AUTH-001"))
        assert report.posture_score >= 80
        assert report.grade == "D"
        assert report.grade_capped is True
        assert "AUTH-001" in report.grade_cap_reason

    def test_the_cap_is_not_announced_when_the_score_is_already_worse(self):
        """A 44 is an F already; saying it was "capped at D" would be noise."""
        report = make_report(finding(Status.ABSENT, Severity.CRITICAL, "AUTH-001"))
        assert report.grade == "F"
        assert report.grade_capped is False
        assert report.grade_cap_reason != ""

    def test_a_critical_partial_does_not_cap(self):
        present = [finding(Status.PRESENT, Severity.LOW, f"OK-{i}") for i in range(20)]
        report = make_report(*present, finding(Status.PARTIAL, Severity.CRITICAL))
        assert report.grade_cap_reason == ""

    def test_an_accepted_critical_absence_does_not_cap(self):
        present = [finding(Status.PRESENT, Severity.LOW, f"OK-{i}") for i in range(20)]
        accepted = finding(Status.ABSENT, Severity.CRITICAL, "AUTH-001",
                           suppressed=True, suppression_reason="gateway")
        assert make_report(*present, accepted).grade_cap_reason == ""

    def test_a_narrowed_run_withholds_the_grade(self):
        report = make_report(finding(Status.PRESENT), categories=("a",), available=5)
        assert report.partial_scope is True
        assert report.grade is None

    def test_cli_reports_the_grade(self, capsys):
        main(["scan", VULNERABLE])
        assert "grade" in capsys.readouterr().out

    def test_json_records_the_cap_only_when_it_bites(self, capsys):
        """fastapi-bookstore has absent critical controls and a score of 44,
        so the band is already F and there is nothing to cap."""
        main(["scan", str(SAMPLES / "fastapi-bookstore"), "--format", "json"])
        summary = json.loads(capsys.readouterr().out)["summary"]
        assert summary["grade"] == "F" and summary["grade_capped_by"] == ""

    def test_cli_withholds_the_grade_for_one_category(self, capsys):
        main(["scan", VULNERABLE, "--category", "rate_limiting"])
        assert "Grade withheld" in capsys.readouterr().out

    def test_json_carries_grade_and_scope(self, capsys):
        main(["scan", SECURE, "--format", "json"])
        summary = json.loads(capsys.readouterr().out)["summary"]
        assert summary["grade"] == "A" and summary["scope"] == "full"
        assert summary["categories_scanned"]


class TestFingerprint:
    def test_it_does_not_move_when_the_line_moves(self):
        a = finding(evidence=[Evidence("app.py", 12, "@app.route('/x')", "n")])
        b = finding(evidence=[Evidence("app.py", 99, "@app.route('/x')", "n")])
        assert a.fingerprint == b.fingerprint

    def test_it_differs_per_control(self):
        assert finding(control_id="A-1").fingerprint != finding(control_id="A-2").fingerprint

    def test_it_differs_per_subject(self):
        a = finding(evidence=[Evidence("app.py", 1, "@app.route('/a')", "n")])
        b = finding(evidence=[Evidence("app.py", 1, "@app.route('/b')", "n")])
        assert a.fingerprint != b.fingerprint

    def test_a_repository_wide_finding_still_has_one(self):
        assert finding(evidence=[Evidence("", None, None, "searched everything")]
                       ).fingerprint


class TestSarif:
    @pytest.fixture
    def document(self, capsys):
        main(["scan", VULNERABLE, "--format", "sarif"])
        return json.loads(capsys.readouterr().out)

    def test_shape_and_version(self, document):
        assert document["version"] == "2.1.0"
        assert document["runs"][0]["tool"]["driver"]["name"] == "ai-cyber-defense-copilot"

    def test_only_gaps_by_default(self, document):
        kinds = {r["kind"] for r in document["runs"][0]["results"]}
        assert kinds <= {"fail", "review"}

    def test_statuses_map_to_sarif_kinds(self, capsys):
        main(["scan", VULNERABLE, "--format", "sarif", "--show-present"])
        results = json.loads(capsys.readouterr().out)["runs"][0]["results"]
        assert {"fail", "review", "pass", "notApplicable"} <= {r["kind"] for r in results}

    def test_every_result_has_a_location_and_a_fingerprint(self, document):
        for result in document["runs"][0]["results"]:
            assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            assert result["partialFingerprints"]["copilotFingerprint/v1"]

    def test_a_repository_wide_finding_anchors_to_a_real_file(self, document):
        rate = next(r for r in document["runs"][0]["results"] if r["ruleId"] == "RATE-001")
        location = rate["locations"][0]["physicalLocation"]
        assert location["artifactLocation"]["uri"] == "app.py"
        assert "region" not in location          # no line to claim

    def test_rules_carry_security_severity_and_cwe_tags(self, document):
        rules = {r["id"]: r for r in document["runs"][0]["tool"]["driver"]["rules"]}
        auth = rules["AUTH-001"]
        assert auth["properties"]["security-severity"] == "9.5"
        assert "external/cwe/cwe-306" in auth["properties"]["tags"]
        assert auth["help"]["markdown"].startswith("**Remediation.**")

    def test_levels_only_on_failing_results(self, capsys):
        main(["scan", VULNERABLE, "--format", "sarif", "--show-present"])
        for result in json.loads(capsys.readouterr().out)["runs"][0]["results"]:
            if result["kind"] in ("pass", "notApplicable"):
                assert "level" not in result

    def test_accepted_findings_are_suppressions_not_omissions(self, tmp_path, capsys):
        config = tmp_path / "c.yaml"
        config.write_text("suppress:\n  - control: RATE-001\n    reason: at the gateway\n",
                          encoding="utf-8")
        main(["scan", VULNERABLE, "--format", "sarif", "--config", str(config),
              "--show-present"])
        results = json.loads(capsys.readouterr().out)["runs"][0]["results"]
        rate = next(r for r in results if r["ruleId"] == "RATE-001")
        assert rate["suppressions"][0]["justification"] == "at the gateway"

    def test_run_properties_carry_the_score(self, document):
        properties = document["runs"][0]["properties"]
        assert isinstance(properties["postureScore"], int)
        assert properties["scope"] == "full"


class TestMarkdown:
    @pytest.fixture
    def text(self, capsys):
        main(["scan", VULNERABLE, "--format", "markdown"])
        return capsys.readouterr().out

    def test_leads_with_the_score_and_grade(self, text):
        assert "## Security posture report" in text
        assert "/100" in text and "grade" in text

    def test_lists_every_gap_in_a_table(self, text):
        assert "| Control | Status | Severity | Where | CWE |" in text
        assert "`AUTH-001`" in text and "CWE-306" in text

    def test_each_gap_carries_a_fix_prompt(self, text):
        assert text.count("**Fix prompt**") >= 5
        assert "re-run" in text

    def test_a_clean_repository_says_so(self, capsys):
        main(["scan", SECURE, "--format", "markdown"])
        assert "No gaps found" in capsys.readouterr().out

    def test_fix_prompt_names_control_location_and_remediation(self):
        prompt = fix_prompt(finding())
        assert "X-001" in prompt and "app.py:12" in prompt
        assert "add the control" in prompt

    def test_accepted_section_appears_when_something_is_accepted(self):
        accepted = finding(suppressed=True, suppression_reason="at the gateway")
        assert "### Accepted" in render_markdown(make_report(accepted))

    def test_capped_grade_is_explained(self):
        present = [finding(Status.PRESENT, Severity.LOW, f"OK-{i}") for i in range(20)]
        report = make_report(*present,
                             finding(Status.ABSENT, Severity.CRITICAL, "AUTH-001"))
        assert "Grade capped at D" in render_markdown(report)

    def test_withheld_grade_is_explained(self):
        report = make_report(finding(), categories=("a",), available=5)
        assert "Grade withheld" in render_markdown(report)


class TestFormatGuards:
    @pytest.mark.parametrize("fmt", ["sarif", "markdown"])
    def test_summary_only_refuses_machine_formats(self, capsys, fmt):
        assert main(["scan", VULNERABLE, "--summary-only", "--format", fmt]) == EXIT_ERROR
        assert "cannot be combined" in capsys.readouterr().out

    @pytest.mark.parametrize("fmt", ["sarif", "markdown"])
    def test_writing_to_a_file(self, capsys, tmp_path, fmt):
        out = tmp_path / f"report.{fmt}"
        main(["scan", VULNERABLE, "--format", fmt, "-o", str(out)])
        capsys.readouterr()
        assert out.read_text(encoding="utf-8").strip()

    def test_sarif_is_valid_json_for_every_sample(self, capsys):
        for sample in sorted(p.name for p in SAMPLES.iterdir() if p.is_dir()):
            main(["scan", str(SAMPLES / sample), "--format", "sarif"])
            json.loads(capsys.readouterr().out)

    def test_markdown_renders_for_every_sample(self, capsys):
        for sample in sorted(p.name for p in SAMPLES.iterdir() if p.is_dir()):
            main(["scan", str(SAMPLES / sample), "--format", "markdown"])
            assert "Security posture report" in capsys.readouterr().out
