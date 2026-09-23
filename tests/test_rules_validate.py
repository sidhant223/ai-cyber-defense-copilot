"""``copilot rules validate``: a separate pass that collects every rule error."""

from __future__ import annotations

from pathlib import Path

from copilot.cli import EXIT_CLEAN, EXIT_ERROR, EXIT_FINDINGS, main
from copilot.rules_validate import ValidationError, validate_dir

from conftest import REPO_ROOT

BAD_RULES = REPO_ROOT / "tests" / "fixtures" / "bad_rules"
BUNDLED_RULES = REPO_ROOT / "src" / "copilot" / "rules"


class TestValidateDir:
    def test_bundled_rules_have_no_errors(self):
        assert validate_dir(BUNDLED_RULES) == []

    def test_bad_rules_gives_exactly_three_errors(self):
        errors = validate_dir(BAD_RULES)
        assert len(errors) == 3

    def test_bad_regex_names_file_line_and_compile_error(self):
        errors = validate_dir(BAD_RULES)
        err = next(e for e in errors if e.file.name == "bad_regex.yaml")
        assert err.line == 14
        assert err.key == "BADREGEX-001"
        assert "(unclosed" in err.problem
        assert "unterminated subpattern" in err.problem

    def test_bad_severity_names_file_line_and_legal_values(self):
        errors = validate_dir(BAD_RULES)
        err = next(e for e in errors if e.file.name == "bad_severity.yaml")
        assert err.line == 7
        assert err.key == "BADSEV-001"
        assert "severe" in err.problem
        assert "critical, high, medium, low" in err.problem

    def test_duplicate_id_names_second_file_line_and_first_definition(self):
        errors = validate_dir(BAD_RULES)
        err = next(e for e in errors if e.file.name == "duplicate_id.yaml")
        assert err.line == 20
        assert err.key == "DUPID-001"
        assert "duplicate control id" in err.problem
        assert "duplicate_id.yaml:5" in err.problem

    def test_error_str_matches_the_file_line_key_problem_format(self):
        path = Path("rules") / "x.yaml"
        err = ValidationError(path, 3, "X-001", "something wrong")
        assert str(err) == f"{path}:3: X-001: something wrong"


class TestRulesValidateCli:
    def test_bundled_rules_exit_clean(self, capsys):
        code = main(["rules", "validate"])
        out = capsys.readouterr().out
        assert code == EXIT_CLEAN
        assert "0 error(s)" in out

    def test_bad_rules_dir_exits_one_with_three_errors(self, capsys):
        code = main(["rules", "validate", str(BAD_RULES)])
        out = capsys.readouterr().out
        assert code == EXIT_FINDINGS
        assert "3 error(s)" in out
        assert "BADREGEX-001" in out
        assert "BADSEV-001" in out
        assert "DUPID-001" in out

    def test_missing_dir_exits_two(self, capsys, tmp_path):
        code = main(["rules", "validate", str(tmp_path / "does-not-exist")])
        out = capsys.readouterr().out
        assert code == EXIT_ERROR
        assert "no such directory" in out

    def test_not_a_directory_exits_two(self, capsys, tmp_path):
        f = tmp_path / "a_file.yaml"
        f.write_text("category: x\n", encoding="utf-8")
        code = main(["rules", "validate", str(f)])
        assert code == EXIT_ERROR
