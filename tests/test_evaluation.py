"""The evaluation harness: scoring, manifest validation, splits and the CLI.

Everything here runs on a synthetic manifest, synthetic sample apps and a
synthetic rules directory under tmp_path. The harness logic must not move when
a shipped rule changes, and the real corpus must not be scanned from here:
holdout samples are only ever touched by ``copilot evaluate`` itself.

The fixture is labelled so every count is known in advance, with deliberate
disagreements (one missed, one over-flagged, one wrong status), a control
listed in ``skipped`` and one left unlabelled.
"""

from __future__ import annotations

import json
import textwrap

import pytest

from copilot.cli import EXIT_CLEAN, EXIT_ERROR, main
from copilot.detectors.rule_engine import RuleEngine
from copilot.evaluation import (
    NOT_REPORTED, ControlErrors, Disagreement, EvaluationError, EvaluationResult,
    SampleResult, Tally, evaluate, load_manifest, outcome, select)

AUTH_RULES = r"""
category: authentication
description: fixture
controls:
  - id: AUTH-901
    name: Routes are guarded
    severity: critical
    detection:
      subject:
        type: regex
        description: route
        pattern: '@app\.route\('
      guard:
        type: regex
        proximity_lines: 2
        any_of: ['@login_required']
    verdict: {all_subjects_guarded: present, some_subjects_guarded: partial,
              no_subjects_guarded: absent, no_subjects_found: not_applicable}
    remediation_hint: add a decorator
  - id: AUTH-902
    name: Django views are guarded
    severity: high
    applies_to: {frameworks: [django]}
    detection:
      subject: {type: regex, description: view, pattern: 'def \w+\(request'}
      guard: {type: regex, proximity_lines: 2, any_of: ['@login_required']}
    verdict: {all_subjects_guarded: present, some_subjects_guarded: partial,
              no_subjects_guarded: absent, no_subjects_found: not_applicable}
    remediation_hint: add a decorator
"""

RATE_RULES = r"""
category: rate_limiting
description: fixture
controls:
  - id: RATE-901
    name: Limiter registered
    severity: high
    detection:
      mode: presence
      patterns: {match: content, any_of: ['\bLimiter\s*\(']}
    verdict: {found: present, not_found: absent}
    remediation_hint: install one
"""

FLASK = "from flask import Flask\napp = Flask(__name__)\n"
GUARDED = "\n@login_required\n@app.route('/a')\ndef a(): pass\n"
UNGUARDED = "\n@app.route('/b')\ndef b(): pass\n"

# What the scanner reports under AUTH_RULES / RATE_RULES (AUTH-902 is never
# reported: it applies to django only):
#   good      AUTH-901 present         RATE-901 present
#   bad       AUTH-901 absent          RATE-901 absent
#   mixed     AUTH-901 partial         RATE-901 absent
#   noroutes  AUTH-901 not_applicable  RATE-901 absent   (framework: none)
#   held      same as good
APPS = {
    "good": FLASK + "limiter = Limiter(app)\n" + GUARDED,
    "bad": FLASK + UNGUARDED,
    "mixed": FLASK + GUARDED + UNGUARDED,
    "noroutes": "x = 1\n",
    "held": FLASK + "limiter = Limiter(app)\n" + GUARDED,
}

MANIFEST = """
samples:
  - {name: good, split: dev, framework: flask, skipped: [AUTH-902],
     expected: {AUTH-901: present, RATE-901: present}}
  - {name: bad, split: dev, framework: flask,
     expected: {AUTH-901: absent, RATE-901: present}}     # fp on RATE-901
  - {name: mixed, split: dev, framework: flask, skipped: [AUTH-902],
     expected: {AUTH-901: absent, RATE-901: absent}}      # partial vs absent
  - {name: noroutes, split: dev, framework: flask, skipped: [AUTH-902],
     expected: {AUTH-901: absent, RATE-901: absent}}      # fn on AUTH-901
  - {name: held, split: holdout, framework: flask, skipped: [AUTH-902],
     expected: {AUTH-901: present, RATE-901: present}}
"""
DEV_ONLY = MANIFEST.split("  - {name: held")[0]


def write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(text), encoding="utf-8")
    return path


def build_corpus(root, manifest=MANIFEST, apps=APPS):
    """Lay out rules/, samples/<name>/app.py and manifest.yaml under root."""
    rules = root / "rules"
    write(rules / "authentication.yaml", AUTH_RULES)
    write(rules / "rate_limiting.yaml", RATE_RULES)
    for name, source in apps.items():
        (root / "samples" / name).mkdir(parents=True, exist_ok=True)
        (root / "samples" / name / "app.py").write_text(source, encoding="utf-8")
    return write(root / "manifest.yaml", manifest), rules


@pytest.fixture
def corpus(tmp_path):
    return build_corpus(tmp_path)


def run(manifest, rules, split="dev"):
    return evaluate(manifest, split, RuleEngine(rules))


def counts(tally):
    return (tally.tp, tally.fp, tally.fn, tally.tn)


def squash(text):
    """Undo rich's line wrapping so phrases can be matched."""
    return " ".join(text.split())


class TestOutcome:
    @pytest.mark.parametrize("expected, reported, want", [
        ("absent", "absent", "tp"), ("absent", "partial", "tp"), ("partial", "absent", "tp"),
        ("absent", "present", "fn"), ("partial", "not_applicable", "fn"),
        ("absent", NOT_REPORTED, "fn"),
        ("present", "absent", "fp"), ("not_applicable", "partial", "fp"),
        (NOT_REPORTED, "absent", "fp"),
        ("present", "present", "tn"), ("present", "not_applicable", "tn"),
        (NOT_REPORTED, NOT_REPORTED, "tn"), ("not_applicable", NOT_REPORTED, "tn"),
    ])
    def test_gap_is_absent_or_partial(self, expected, reported, want):
        assert outcome(expected, reported) == want


class TestTally:
    def test_add_increments_the_named_cell(self):
        t = Tally()
        for o in ("tp", "tp", "fp", "fn", "tn", "tn", "tn"):
            t.add(o)
        assert counts(t) == (2, 1, 1, 3)

    def test_ratios_and_rounding(self):
        t = Tally(tp=2, fp=1, fn=3, tn=9)
        assert t.precision == pytest.approx(2 / 3)
        assert t.recall == pytest.approx(2 / 5)
        assert t.f1 == pytest.approx(4 / 8)
        assert t.to_dict() == {"tp": 2, "fp": 1, "fn": 3, "tn": 9,
                               "precision": 0.6667, "recall": 0.4, "f1": 0.5}

    def test_zero_denominators_are_none_not_zero(self):
        t = Tally(tn=5)
        assert (t.precision, t.recall, t.f1) == (None, None, None)
        assert json.loads(json.dumps(t.to_dict()))["precision"] is None
        assert '"f1": null' in json.dumps(t.to_dict())

    def test_precision_undefined_while_recall_is_zero(self):
        t = Tally(fn=2)
        assert (t.precision, t.recall, t.f1) == (None, 0, 0)


class TestLoadManifest:
    def test_valid_manifest_loads(self, corpus, tmp_path):
        samples = load_manifest(corpus[0])
        assert [s.name for s in samples] == ["good", "bad", "mixed", "noroutes", "held"]
        good = samples[0]
        assert (good.split, good.framework, good.path) == \
            ("dev", "flask", tmp_path / "samples" / "good")
        assert good.expected == {"AUTH-901": "present", "RATE-901": "present"}
        assert (good.skipped, samples[1].skipped) == (frozenset({"AUTH-902"}), frozenset())

    def test_missing_file(self, tmp_path):
        with pytest.raises(EvaluationError):
            load_manifest(tmp_path / "nope.yaml")

    @pytest.mark.parametrize("data", [
        b"samples: [unclosed\n", b"version: 1\n", b"samples: []\n", b"samples: {name: good}\n",
        b"samples: \xff\n",
    ], ids=["invalid-yaml", "no-samples", "empty-samples", "samples-not-a-list", "not-utf8"])
    def test_bad_top_level(self, tmp_path, data):
        build_corpus(tmp_path)
        (tmp_path / "manifest.yaml").write_bytes(data)
        with pytest.raises(EvaluationError):
            load_manifest(tmp_path / "manifest.yaml")

    ENTRY = "samples:\n  - name: good\n    split: dev\n    expected: {AUTH-901: present}\n"
    SKIP = "present}\n    skipped: "
    BAD_ENTRIES = {  # id: (old, new); every one but no-name must name the sample
        "no-name": ("name: good\n    ", ""),
        "bad-split": ("split: dev", "split: training"),
        "no-split": ("    split: dev\n", ""),
        "no-expected": ("    expected: {AUTH-901: present}\n", ""),
        "expected-not-mapping": ("expected: {AUTH-901: present}", "expected: [AUTH-901]"),
        "bad-status": ("present}", "maybe}"),
        "skipped-not-list": ("present}\n", SKIP + "AUTH-902\n"),
        "skipped-non-string": ("present}\n", SKIP + "[AUTH-902, 7]\n"),
        "expected-and-skipped": ("present}\n", SKIP + "[AUTH-901]\n"),
        "no-sample-dir": ("name: good", "name: ghost"),
    }

    @pytest.mark.parametrize("case", BAD_ENTRIES)
    def test_bad_entry(self, tmp_path, case):
        build_corpus(tmp_path)
        text = self.ENTRY.replace(*self.BAD_ENTRIES[case])
        assert text != self.ENTRY
        with pytest.raises(EvaluationError) as exc:
            load_manifest(write(tmp_path / "manifest.yaml", text))
        if case != "no-name":
            assert ("ghost" if "ghost" in text else "good") in str(exc.value)

    @pytest.mark.parametrize("name", ["../outside", "a/b", None],
                             ids=["parent", "nested", "absolute"])
    def test_name_must_be_a_plain_directory_name(self, tmp_path, name):
        """A name is joined onto samples/, so a path would scan files outside it.
        The target directory exists, so only the name check can reject it."""
        build_corpus(tmp_path)
        name = name or str(tmp_path / "outside")
        (tmp_path / "samples" / name).mkdir(parents=True, exist_ok=True)
        text = self.ENTRY.replace("name: good", f"name: '{name}'")
        with pytest.raises(EvaluationError):
            load_manifest(write(tmp_path / "manifest.yaml", text))

    def test_duplicate_name(self, tmp_path):
        build_corpus(tmp_path)
        text = self.ENTRY + self.ENTRY.replace("samples:\n", "")
        with pytest.raises(EvaluationError, match="good"):
            load_manifest(write(tmp_path / "manifest.yaml", text))


class TestSelect:
    def test_dev_holdout_all(self, corpus):
        samples = load_manifest(corpus[0])
        assert [s.name for s in select(samples, "dev")] == ["good", "bad", "mixed", "noroutes"]
        assert [s.name for s in select(samples, "holdout")] == ["held"]
        assert len(select(samples, "all")) == 5

    def test_empty_split_is_a_clear_error(self, tmp_path):
        manifest, _ = build_corpus(tmp_path, DEV_ONLY)
        with pytest.raises(EvaluationError, match="no samples with split 'holdout'"):
            select(load_manifest(manifest), "holdout")

    def test_unknown_split(self, corpus):
        with pytest.raises(EvaluationError):
            select(load_manifest(corpus[0]), "train")


class TestEvaluateDev:
    """Counts are derived by hand from the table above APPS."""

    @pytest.fixture
    def result(self, corpus):
        return run(*corpus)

    def test_per_category_counts(self, result):
        assert list(result.by_category) == ["authentication", "rate_limiting"]
        # auth: bad/mixed tp, noroutes fn, good AUTH-901 + three skipped AUTH-902 tn
        assert counts(result.by_category["authentication"]) == (2, 0, 1, 4)
        # rate: mixed/noroutes tp, bad fp, good tn
        assert counts(result.by_category["rate_limiting"]) == (2, 1, 0, 1)

    def test_overall_is_the_sum(self, result):
        assert counts(result.overall) == (4, 1, 1, 5)
        assert result.overall.precision == pytest.approx(0.8)

    def test_only_the_selected_split_is_scored_and_not_reportable(self, result):
        assert [s.name for s in result.samples] == ["good", "bad", "mixed", "noroutes"]
        assert all(s.split == "dev" for s in result.samples)
        assert result.split == "dev"
        assert result.reportable is False

    def test_unlabelled_controls_are_listed_not_counted(self, result):
        by_name = {s.name: s for s in result.samples}
        assert by_name["bad"].unlabelled == ["AUTH-902"]
        assert by_name["good"].unlabelled == []

    def test_disagreements_per_sample(self, result):
        got = {(d.sample, d.control_id, d.expected, d.reported, d.outcome, d.kind)
               for s in result.samples for d in s.disagreements}
        assert got == {
            ("bad", "RATE-901", "present", "absent", "fp", "over_flagged"),
            ("mixed", "AUTH-901", "absent", "partial", "tp", "wrong_status"),
            ("noroutes", "AUTH-901", "absent", "not_applicable", "fn", "missed"),
        }

    def test_framework_detected_is_recorded(self, result):
        frameworks = {s.name: (s.framework_expected, s.framework_detected)
                      for s in result.samples}
        assert frameworks["good"] == ("flask", "flask")
        assert frameworks["noroutes"] == ("flask", None)

    def test_confusion(self, result):
        confusion = result.confusion
        assert [c.control_id for c in confusion] == ["AUTH-901", "RATE-901"]
        auth, rate = confusion
        assert (auth.category, auth.missed, auth.over_flagged, auth.wrong_status) == \
            ("authentication", 1, 0, 1)
        assert sorted(auth.where) == ["mixed: absent->partial", "noroutes: absent->not_applicable"]
        assert (rate.missed, rate.over_flagged, rate.wrong_status) == (0, 1, 0)
        assert rate.where == ["bad: present->absent"]

    def test_to_dict_contract(self, result):
        d = json.loads(json.dumps(result.to_dict()))
        assert set(d) == {"schema_version", "generated_at", "split", "reportable", "manifest",
                          "rules_dir", "samples_evaluated", "overall", "by_category",
                          "confusion", "samples"}
        assert d["schema_version"] == "1.0"
        assert d["samples_evaluated"] == 4
        assert d["reportable"] is False
        assert d["overall"] == {"tp": 4, "fp": 1, "fn": 1, "tn": 5,
                                "precision": 0.8, "recall": 0.8, "f1": 0.8}
        assert d["by_category"]["authentication"]["recall"] == 0.6667
        assert set(d["confusion"][0]) == {"control_id", "category", "missed",
                                          "over_flagged", "wrong_status", "where"}
        assert set(d["samples"][0]) == {"name", "split", "framework_expected",
                                        "framework_detected", "unlabelled", "disagreements"}
        assert set(d["samples"][1]["disagreements"][0]) == {
            "control_id", "category", "expected", "reported", "outcome", "kind"}


class TestEvaluateOtherSplits:
    def test_holdout_is_reportable(self, corpus):
        result = run(*corpus, split="holdout")
        assert result.reportable is True
        assert counts(result.overall) == (0, 0, 0, 3)
        assert result.overall.precision is None
        assert result.confusion == []

    def test_all_is_not_reportable(self, corpus):
        result = run(*corpus, split="all")
        assert result.reportable is False
        assert len(result.samples) == 5
        assert counts(result.overall) == (4, 1, 1, 8)

    def test_category_with_no_labelled_pairs_is_all_zeros(self, corpus):
        manifest, rules = corpus
        write(rules / "access_control.yaml", r"""
            category: access_control
            description: fixture
            controls:
              - {id: AC-901, name: CORS, severity: low, remediation_hint: x,
                 detection: {mode: presence, patterns: {match: content, any_of: ['Flask\(']}},
                 verdict: {found: present, not_found: absent}}
        """)
        result = run(manifest, rules)
        assert list(result.by_category) == ["access_control", "authentication", "rate_limiting"]
        assert result.by_category["access_control"].to_dict() == {
            "tp": 0, "fp": 0, "fn": 0, "tn": 0, "precision": None, "recall": None, "f1": None}
        assert counts(result.overall) == (4, 1, 1, 5)
        assert "AC-901" in result.samples[0].unlabelled

    def test_unknown_control_id_is_an_error(self, tmp_path):
        manifest, rules = build_corpus(
            tmp_path, MANIFEST.replace("skipped: [AUTH-902]", "skipped: [AUTH-999]", 1))
        with pytest.raises(EvaluationError, match="AUTH-999"):
            run(manifest, rules)

    def test_unknown_id_outside_the_split_is_ignored(self, tmp_path):
        held = MANIFEST[len(DEV_ONLY):]
        manifest, rules = build_corpus(tmp_path, DEV_ONLY + held.replace("RATE-901", "NOPE-1"))
        with pytest.raises(EvaluationError, match="NOPE-1"):
            run(manifest, rules, split="holdout")
        assert counts(run(manifest, rules).overall) == (4, 1, 1, 5)


class TestConfusionOrdering:
    def _result(self, split, rows):
        disagreements = [Disagreement(s, c, "authentication", e, r, outcome(e, r))
                         for s, c, e, r in rows]
        sample = SampleResult(name="x", split=split, framework_expected=None,
                              framework_detected=None, disagreements=disagreements, unlabelled=[])
        return EvaluationResult(split=split, manifest_path="m.yaml", rules_dir="rules",
                                samples=[sample], by_category={}, overall=Tally())

    def test_sorted_by_errors_then_wrong_status_then_id(self):
        result = self._result("dev", [
            ("a", "C-E", "absent", "partial"),         # wrong_status only
            ("a", "C-D", "present", "absent"),         # 1 over_flagged
            ("a", "C-C", "absent", "present"),         # 1 missed
            ("a", "C-A", "present", "partial"),        # 1 over_flagged + 1 wrong_status
            ("b", "C-A", "partial", "absent"),
            ("a", "C-B", "absent", NOT_REPORTED),      # 2 missed
            ("b", "C-B", "partial", "not_applicable"),
        ])
        confusion = result.confusion
        assert [c.control_id for c in confusion] == ["C-B", "C-A", "C-C", "C-D", "C-E"]
        assert isinstance(confusion[0], ControlErrors)
        assert confusion[0].missed == 2
        assert "a: absent->not_reported" in confusion[0].where

    def test_kinds(self):
        def kind(e, r):
            return Disagreement("s", "C", "authentication", e, r, outcome(e, r)).kind
        assert kind("absent", "present") == "missed"
        assert kind("present", "absent") == "over_flagged"
        assert kind("absent", "partial") == "wrong_status"
        assert kind("present", "not_applicable") == "wrong_status"

    @pytest.mark.parametrize("split, reportable", [
        ("dev", False), ("holdout", True), ("all", False)])
    def test_reportable_only_for_holdout(self, split, reportable):
        assert self._result(split, []).reportable is reportable


class TestRuleChangeIsPickedUp:
    def test_rerun_after_widening_a_guard(self, corpus):
        manifest, rules = corpus
        before = run(manifest, rules)
        assert counts(before.by_category["authentication"]) == (2, 0, 1, 4)
        # A file-scoped guard makes "mixed" fully guarded: its tp becomes a miss.
        write(rules / "authentication.yaml",
              AUTH_RULES.replace("        proximity_lines: 2\n", "        scope: file\n", 1))
        after = run(manifest, rules)
        assert counts(after.by_category["authentication"]) == (1, 0, 2, 4)
        assert counts(after.by_category["rate_limiting"]) == (2, 1, 0, 1)
        assert "mixed: absent->present" in after.confusion[0].where


class TestCli:
    BANNERS = {
        "dev": "DEV SPLIT: the rules were tuned on these samples. "
               "Regression signal only - not reportable as accuracy.",
        "holdout": "HOLDOUT: reportable accuracy, valid only while no rule has been "
                   "changed in response to these samples.",
        "all": "ALL SPLITS: includes 4 dev sample(s) the rules were tuned on - "
               "not reportable as accuracy.",
    }

    def _args(self, corpus, split="dev", *extra):
        manifest, rules = corpus
        return ["evaluate", "--split", split, "--manifest", str(manifest),
                "--rules", str(rules), *extra]

    def test_json_to_stdout(self, corpus, capsys):
        assert main(self._args(corpus, "dev", "--format", "json")) == EXIT_CLEAN
        data = json.loads(capsys.readouterr().out)
        assert data["split"] == "dev" and data["reportable"] is False
        assert data["overall"]["tp"] == 4
        assert {"schema_version", "by_category", "confusion", "samples"} <= set(data)

    def test_json_to_file(self, corpus, capsys, tmp_path):
        out = tmp_path / "eval.json"
        assert main(self._args(corpus, "dev", "--format", "json", "-o", str(out))) == EXIT_CLEAN
        assert "wrote" in capsys.readouterr().out
        assert json.loads(out.read_text(encoding="utf-8"))["samples_evaluated"] == 4

    @pytest.mark.parametrize("split, extra", [
        ("dev", ["Detection by category", "Most missed / over-flagged controls",
                 "noroutes: framework expected flask",
                 "bad: 1 control(s) not labelled in the manifest, excluded: AUTH-902"]),
        ("holdout", ["Every labelled control matches the manifest."]),
        ("all", []),
    ])
    def test_terminal_banner_and_sections(self, corpus, capsys, split, extra):
        assert main(self._args(corpus, split)) == EXIT_CLEAN
        out = squash(capsys.readouterr().out)
        assert [p for p in [self.BANNERS[split], *extra] if p not in out] == []

    def test_terminal_to_file(self, corpus, capsys, tmp_path):
        out = tmp_path / "eval.txt"
        assert main(self._args(corpus, "holdout", "-o", str(out))) == EXIT_CLEAN
        assert "wrote" in capsys.readouterr().out
        assert self.BANNERS["holdout"] in squash(out.read_text(encoding="utf-8"))

    def test_missing_manifest_exits_two(self, corpus, capsys, tmp_path):
        code = main(["evaluate", "--split", "dev", "--manifest", str(tmp_path / "nope.yaml"),
                     "--rules", str(corpus[1])])
        assert code == EXIT_ERROR
        assert "evaluation error" in capsys.readouterr().out

    def test_empty_split_exits_two(self, tmp_path, capsys):
        manifest, rules = build_corpus(tmp_path, DEV_ONLY)
        assert main(self._args((manifest, rules), "holdout")) == EXIT_ERROR
        assert "no samples with split 'holdout'" in squash(capsys.readouterr().out)

    def test_split_is_required(self, corpus, capsys):
        manifest, rules = corpus
        with pytest.raises(SystemExit) as exc:
            main(["evaluate", "--manifest", str(manifest), "--rules", str(rules)])
        assert exc.value.code == 2
        capsys.readouterr()
