"""Full pipeline against the labelled corpus, asserted on manifest.yaml.

This is the test that stops a rule change from quietly altering what the tool
says about a known codebase. When it fails, one of the two sides is wrong and
somebody has to decide which -- see corpus/README.md.

Only `split: dev` samples are scanned and asserted on here. Holdout samples
are measured only by `copilot evaluate`: asserting on them here would turn
every holdout disagreement into pressure to tune a rule, which would spend
the holdout. Well-formedness checks still cover every manifest entry.
"""

from __future__ import annotations

import json

import pytest
import yaml

from copilot.detectors import run_all
from copilot.models import Report, Status
from copilot.reporter import render_html, render_json, render_terminal
from copilot.scanner import scan

from conftest import CORPUS, SAMPLES


def load_manifest() -> list[dict]:
    data = yaml.safe_load((CORPUS / "manifest.yaml").read_text(encoding="utf-8"))
    return data["samples"]


MANIFEST = load_manifest()
SAMPLE_IDS = [s["name"] for s in MANIFEST]
DEV = [e for e in MANIFEST if e.get("split") == "dev"]
DEV_IDS = [s["name"] for s in DEV]


@pytest.fixture(scope="session")
def reports(engine) -> dict[str, Report]:
    """Scan every dev sample once and reuse the reports."""
    out = {}
    for entry in DEV:
        scan_result = scan(str(SAMPLES / entry["name"]))
        findings, skipped = run_all(scan_result, engine)
        out[entry["name"]] = Report(
            scan=scan_result,
            findings=findings,
            skipped_controls=[s.to_dict() for s in skipped],
        )
    return out


def statuses(report: Report) -> dict[str, str]:
    return {f.control_id: f.status.value for f in report.findings}


class TestCorpusIsWellFormed:
    def test_every_sample_directory_has_a_manifest_entry(self):
        on_disk = {p.name for p in SAMPLES.iterdir() if p.is_dir()}
        assert on_disk == set(SAMPLE_IDS)

    @pytest.mark.parametrize("entry", MANIFEST, ids=SAMPLE_IDS)
    def test_every_sample_records_its_generating_prompt(self, entry):
        assert (SAMPLES / entry["name"] / "PROMPT.md").is_file()

    @pytest.mark.parametrize("entry", MANIFEST, ids=SAMPLE_IDS)
    def test_expected_statuses_use_the_real_vocabulary(self, entry):
        allowed = {s.value for s in Status}
        for control_id, status in entry["expected"].items():
            assert status in allowed, f"{entry['name']}/{control_id}"

    @pytest.mark.parametrize("entry", MANIFEST, ids=SAMPLE_IDS)
    def test_expected_control_ids_exist(self, entry, engine):
        known = {c.id for c in engine.controls()}
        unknown = set(entry["expected"]) - known
        assert unknown == set(), f"{entry['name']}: {unknown}"

    @pytest.mark.parametrize("entry", MANIFEST, ids=SAMPLE_IDS)
    def test_every_sample_declares_a_valid_split(self, entry):
        assert entry.get("split") in {"dev", "holdout"}, entry["name"]

    def test_corpus_has_negative_controls(self):
        kinds = [e.get("kind") for e in MANIFEST]
        assert kinds.count("negative-control") >= 2

    def test_corpus_covers_several_frameworks(self):
        assert len({e["framework"] for e in MANIFEST}) >= 4


class TestGroundTruth:
    @pytest.mark.parametrize("entry", DEV, ids=DEV_IDS)
    def test_framework_detected(self, entry, reports):
        assert reports[entry["name"]].scan.framework == entry["framework"]

    @pytest.mark.parametrize("entry", DEV, ids=DEV_IDS)
    def test_language_detected(self, entry, reports):
        assert reports[entry["name"]].scan.language == entry["language"]

    @pytest.mark.parametrize("entry", DEV, ids=DEV_IDS)
    def test_statuses_match_the_audit(self, entry, reports):
        actual = statuses(reports[entry["name"]])
        expected = entry["expected"]
        mismatches = {
            control_id: (want, actual.get(control_id, "<not reported>"))
            for control_id, want in expected.items()
            if actual.get(control_id) != want
        }
        assert mismatches == {}, (
            f"{entry['name']}: manifest says (expected, got) {mismatches}"
        )

    @pytest.mark.parametrize("entry", DEV, ids=DEV_IDS)
    def test_nothing_reported_that_the_audit_did_not_judge(self, entry, reports):
        extra = set(statuses(reports[entry["name"]])) - set(entry["expected"])
        assert extra == set(), f"{entry['name']}: unexpected findings {extra}"

    @pytest.mark.parametrize("entry", DEV, ids=DEV_IDS)
    def test_skipped_controls_match(self, entry, reports):
        actual = {s["control_id"] for s in reports[entry["name"]].skipped_controls}
        assert actual == set(entry.get("skipped", []))

    @pytest.mark.parametrize("entry", DEV, ids=DEV_IDS)
    def test_expected_score_when_declared(self, entry, reports):
        if "expected_score" in entry:
            assert reports[entry["name"]].posture_score == entry["expected_score"]


class TestNegativeControls:
    """A scanner that flags everything measures nothing."""

    def test_secure_sample_has_no_gaps(self, reports):
        report = reports["fastapi-secure-tasks"]
        assert report.gaps == []
        assert report.posture_score == 100

    def test_secure_samples_outscore_realistic_ones(self, reports):
        secure = [reports[e["name"]].posture_score
                  for e in DEV if e.get("kind") == "negative-control"]
        realistic = [reports[e["name"]].posture_score
                     for e in DEV if e.get("kind") == "realistic"]
        assert min(secure) > max(realistic)


class TestEvidence:
    @pytest.mark.parametrize("entry", DEV, ids=DEV_IDS)
    def test_every_finding_cites_evidence(self, entry, reports):
        for finding in reports[entry["name"]].findings:
            assert finding.evidence, f"{entry['name']}/{finding.control_id}"

    @pytest.mark.parametrize("entry", DEV, ids=DEV_IDS)
    def test_evidence_points_at_files_that_exist(self, entry, reports):
        report = reports[entry["name"]]
        scanned = {f.path for f in report.scan.files}
        for finding in report.findings:
            for ev in finding.evidence:
                if ev.file_path:
                    assert ev.file_path in scanned, f"{finding.control_id}: {ev.file_path}"

    @pytest.mark.parametrize("entry", DEV, ids=DEV_IDS)
    def test_absence_findings_say_what_was_searched(self, entry, reports):
        """An absence you cannot point at is not a finding."""
        for finding in reports[entry["name"]].findings:
            if finding.status is Status.ABSENT:
                assert any(ev.note for ev in finding.evidence), finding.control_id

    @pytest.mark.parametrize("entry", DEV, ids=DEV_IDS)
    def test_line_numbers_are_within_the_file(self, entry, reports):
        report = reports[entry["name"]]
        for finding in report.findings:
            for ev in finding.evidence:
                if ev.file_path and ev.line_number:
                    scanned = report.scan.by_path(ev.file_path)
                    assert 1 <= ev.line_number <= len(scanned.lines), (
                        f"{finding.control_id}: {ev.file_path}:{ev.line_number}"
                    )


class TestReporters:
    SAMPLE = "flask-notes-app"

    def test_json_is_valid_and_versioned(self, reports):
        data = json.loads(render_json(reports[self.SAMPLE]))
        assert data["schema_version"] == "1.4"
        assert data["summary"]["posture_score"] == reports[self.SAMPLE].posture_score
        assert len(data["findings"]) == len(reports[self.SAMPLE].findings)

    def test_json_schema_keys_are_stable(self, reports):
        """The evaluation harness consumes this; the shape is a contract."""
        data = json.loads(render_json(reports[self.SAMPLE]))
        assert set(data) == {
            "schema_version", "generated_at", "tool", "scan", "summary",
            "findings", "skipped_controls",
        }
        assert set(data["findings"][0]) == {
            "control_id", "control_name", "category", "status", "severity",
            "message", "evidence", "remediation_hint", "confidence", "cwe", "owasp",
            "suppressed", "suppression_reason", "fingerprint",
        }
        assert set(data["findings"][0]["evidence"][0]) == {
            "file_path", "line_number", "snippet", "note",
        }

    def test_json_round_trips_every_sample(self, reports):
        for report in reports.values():
            json.loads(render_json(report))

    def test_html_is_self_contained(self, reports):
        html = render_html(reports[self.SAMPLE])
        assert "<!DOCTYPE html>" in html
        assert "<script" not in html
        for external in ("http://", "https://cdn", "<link rel=\"stylesheet\""):
            assert external not in html

    def test_html_shows_the_score_and_findings(self, reports):
        report = reports[self.SAMPLE]
        html = render_html(report)
        assert str(report.posture_score) in html
        assert "AUTH-001" in html

    def test_html_escapes_snippets(self, reports):
        """Snippets are source code and must never become markup."""
        html = render_html(reports["express-todo-api"])
        assert "<script>" not in html

    def test_html_renders_every_sample(self, reports):
        for report in reports.values():
            assert render_html(report).startswith("<!DOCTYPE html>")

    def test_terminal_renders_without_error(self, reports, capsys):
        from rich.console import Console

        render_terminal(reports[self.SAMPLE], Console(width=100))
        assert "posture score" in capsys.readouterr().out

    def test_terminal_reports_a_clean_repo_as_clean(self, reports, capsys):
        from rich.console import Console

        render_terminal(reports["fastapi-secure-tasks"], Console(width=100))
        assert "No gaps found" in capsys.readouterr().out


class TestScoring:
    def test_display_filters_do_not_move_the_score(self, reports):
        report = reports["flask-notes-app"]
        before = report.posture_score
        report.display_findings(min_severity="critical", show_satisfied=False)
        assert report.posture_score == before

    def test_min_severity_narrows_what_is_shown(self, reports):
        report = reports["flask-notes-app"]
        shown = report.display_findings(min_severity="critical")
        assert all(f.severity.value == "critical" for f in shown)

    def test_not_applicable_is_excluded_from_scoring(self, reports):
        report = reports["flask-notes-app"]
        assert all(f.status is not Status.NOT_APPLICABLE
                   for f in report.scored_findings)

    def test_score_is_a_percentage(self, reports):
        for report in reports.values():
            assert 0 <= report.posture_score <= 100
