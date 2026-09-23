"""``copilot rules test``: every control ships with executable examples.

A regex rule breaks silently -- a pattern that stops matching reports the
control as absent everywhere and nothing crashes. Each control therefore
carries at least one example that must come back as a gap and one that must
not, in ``rules/tests/<category>.yaml``, and this file runs all of them
through the real pipeline.
"""

from __future__ import annotations

import textwrap

import pytest

from copilot.cli import EXIT_CLEAN, EXIT_ERROR, EXIT_FINDINGS, main
from copilot.detectors.rule_engine import DEFAULT_RULES_DIR, RuleEngine
from copilot.rules_test import RuleTestError, load_rule_tests, run_rule_test

GAPS = {"absent", "partial"}

BUNDLED = load_rule_tests(DEFAULT_RULES_DIR / "tests", RuleEngine())


def _write(tmp_path, text: str):
    d = tmp_path / "tests"
    d.mkdir(exist_ok=True)
    (d / "cases.yaml").write_text(textwrap.dedent(text), encoding="utf-8")
    return d


class TestBundledExamples:
    @pytest.mark.parametrize("case", BUNDLED, ids=[f"{c.control_id}:{c.name}" for c in BUNDLED])
    def test_example_gets_the_expected_verdict(self, case, engine):
        result = run_rule_test(case, engine)
        assert result.passed, f"{case.source}: {result.detail}"

    def test_every_control_has_a_gap_and_a_non_gap_example(self, engine):
        seen: dict[str, set[bool]] = {}
        for case in BUNDLED:
            seen.setdefault(case.control_id, set()).add(case.expect in GAPS)
        incomplete = sorted(c.id for c in engine.controls() if seen.get(c.id) != {True, False})
        assert incomplete == []


class TestLoader:
    def test_unknown_control_is_an_error(self, tmp_path, engine):
        d = _write(tmp_path, """
            NOPE-001:
              - name: x
                expect: absent
                files: {app.py: "x = 1"}
        """)
        with pytest.raises(RuleTestError, match="NOPE-001"):
            load_rule_tests(d, engine)

    def test_bad_expectation_is_an_error(self, tmp_path, engine):
        d = _write(tmp_path, """
            AUTH-001:
              - name: x
                expect: maybe
                files: {app.py: "x = 1"}
        """)
        with pytest.raises(RuleTestError, match="expect"):
            load_rule_tests(d, engine)

    @pytest.mark.parametrize("name", ["../escape.py", "/abs.py", "C:/abs.py"])
    def test_file_names_must_stay_inside_the_example(self, tmp_path, engine, name):
        d = _write(tmp_path, f"""
            AUTH-001:
              - name: x
                expect: absent
                files: {{"{name}": "x = 1"}}
        """)
        with pytest.raises(RuleTestError, match="relative path"):
            load_rule_tests(d, engine)


class TestRunner:
    def test_a_wrong_expectation_fails_with_both_verdicts(self, tmp_path, engine):
        d = _write(tmp_path, """
            RATE-001:
              - name: wrongly expects a limiter
                expect: present
                files:
                  app.py: |
                    from flask import Flask
                    app = Flask(__name__)
        """)
        [case] = load_rule_tests(d, engine)
        result = run_rule_test(case, engine)
        assert not result.passed
        assert "expected present" in result.detail and "got absent" in result.detail

    def test_skipped_control_can_be_expected(self, tmp_path, engine):
        d = _write(tmp_path, """
            AUTH-007:
              - name: django-only control is skipped on flask
                expect: skipped
                files:
                  app.py: |
                    from flask import Flask
                    app = Flask(__name__)
        """)
        [case] = load_rule_tests(d, engine)
        assert run_rule_test(case, engine).passed


class TestCli:
    def test_bundled_examples_pass(self, capsys):
        assert main(["rules", "test"]) == EXIT_CLEAN
        out = capsys.readouterr().out
        assert f"{len(BUNDLED)} passed" in out and "0 failed" in out

    def test_one_control_can_be_selected(self, capsys):
        assert main(["rules", "test", "--control", "AUTH-001"]) == EXIT_CLEAN
        out = capsys.readouterr().out
        wanted = sum(1 for c in BUNDLED if c.control_id == "AUTH-001")
        assert f"{wanted} passed" in out

    def test_failures_exit_one(self, capsys, tmp_path):
        rules = tmp_path / "rules"
        rules.mkdir()
        (rules / "rate_limiting.yaml").write_text(
            (DEFAULT_RULES_DIR / "rate_limiting.yaml").read_text(encoding="utf-8"),
            encoding="utf-8")
        _write(rules, """
            RATE-001:
              - name: wrongly expects a limiter
                expect: present
                files: {app.py: "from flask import Flask"}
        """)
        assert main(["rules", "test", str(rules)]) == EXIT_FINDINGS
        assert "FAIL" in capsys.readouterr().out

    def test_no_tests_directory_exits_two(self, capsys, tmp_path):
        rules = tmp_path / "rules"
        rules.mkdir()
        (rules / "rate_limiting.yaml").write_text(
            (DEFAULT_RULES_DIR / "rate_limiting.yaml").read_text(encoding="utf-8"),
            encoding="utf-8")
        assert main(["rules", "test", str(rules)]) == EXIT_ERROR
        assert "no rule tests" in capsys.readouterr().out
