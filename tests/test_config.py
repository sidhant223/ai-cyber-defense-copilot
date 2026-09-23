"""Config file support (.copilot.yaml): precedence is CLI flag, then config, then default."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from copilot.cli import EXIT_CLEAN, EXIT_ERROR, main
from copilot.config import CONFIG_FILENAME, Config, ConfigError, load_config

from conftest import SAMPLES

VULNERABLE = SAMPLES / "flask-notes-app"
FLASK_NOTES_LINE = "28 checks · 22 applicable · 15 gaps · score 46"


def _copy_sample(tmp_path) -> Path:
    dest = tmp_path / "repo"
    shutil.copytree(VULNERABLE, dest)
    return dest


def _write_config(repo: Path, text: str) -> Path:
    path = repo / ".copilot.yaml"
    path.write_text(text, encoding="utf-8")
    return path


class TestScanPrecedence:
    def test_no_config_file_uses_builtin_default(self, capsys, tmp_path):
        repo = _copy_sample(tmp_path)
        main(["scan", str(repo)])
        assert capsys.readouterr().out.splitlines()[-1] == FLASK_NOTES_LINE

    def test_config_beats_default(self, capsys, tmp_path):
        repo = _copy_sample(tmp_path)
        _write_config(repo, "min_severity: critical\n")
        main(["scan", str(repo)])
        out = capsys.readouterr().out
        assert "AUTH-001" in out       # critical gap: still shown
        assert "AC-001" not in out     # high gap: hidden by the config

    def test_cli_beats_config(self, capsys, tmp_path):
        repo = _copy_sample(tmp_path)
        _write_config(repo, "min_severity: critical\n")
        main(["scan", str(repo), "--min-severity", "low"])
        assert "AC-001" in capsys.readouterr().out

    def test_no_config_flag_ignores_the_file(self, capsys, tmp_path):
        repo = _copy_sample(tmp_path)
        _write_config(repo, "min_severity: critical\n")
        main(["scan", str(repo), "--no-config"])
        assert "AC-001" in capsys.readouterr().out

    def test_config_flag_points_elsewhere(self, capsys, tmp_path):
        repo = _copy_sample(tmp_path)
        elsewhere = tmp_path / "elsewhere.yaml"
        elsewhere.write_text("min_severity: critical\n", encoding="utf-8")
        main(["scan", str(repo), "--config", str(elsewhere)])
        assert "AC-001" not in capsys.readouterr().out

    def test_config_and_no_config_together_exits_two(self, capsys, tmp_path):
        repo = _copy_sample(tmp_path)
        cfg = _write_config(repo, "min_severity: critical\n")
        code = main(["scan", str(repo), "--config", str(cfg), "--no-config"])
        assert code == EXIT_ERROR
        assert "--config" in capsys.readouterr().out

    def test_missing_config_flag_target_exits_two(self, capsys, tmp_path):
        repo = _copy_sample(tmp_path)
        code = main(["scan", str(repo), "--config", str(tmp_path / "nope.yaml")])
        assert code == EXIT_ERROR
        assert "no such config file" in capsys.readouterr().out

    def test_score_is_identical_with_a_display_only_config(self, capsys, tmp_path):
        repo = _copy_sample(tmp_path)
        main(["scan", str(repo), "--format", "json"])
        without = json.loads(capsys.readouterr().out)["summary"]["posture_score"]
        _write_config(repo, "min_severity: critical\nmin_confidence: high\n")
        main(["scan", str(repo), "--format", "json"])
        with_config = json.loads(capsys.readouterr().out)["summary"]["posture_score"]
        assert without == with_config == 46


class TestCategoriesKey:
    def test_config_categories_restrict_scope(self, capsys, tmp_path):
        repo = _copy_sample(tmp_path)
        _write_config(repo, "categories: [rate_limiting]\n")
        main(["scan", str(repo), "--format", "json"])
        data = json.loads(capsys.readouterr().out)
        assert {f["category"] for f in data["findings"]} == {"rate_limiting"}

    def test_cli_category_beats_config(self, capsys, tmp_path):
        repo = _copy_sample(tmp_path)
        _write_config(repo, "categories: [rate_limiting]\n")
        main(["scan", str(repo), "--format", "json", "--category", "secret_management"])
        data = json.loads(capsys.readouterr().out)
        assert {f["category"] for f in data["findings"]} == {"secret_management"}


class TestIgnorePaths:
    def test_ignore_paths_drops_matching_files_before_scoring(self, capsys, tmp_path):
        # The config file lives outside the scanned tree so it is not itself
        # walked as a config-language file, which would confound the count.
        repo = tmp_path / "repo"
        (repo / "vendor_extra").mkdir(parents=True)
        (repo / "app.py").write_text(
            "from flask import Flask\napp = Flask(__name__)\n", encoding="utf-8")
        (repo / "vendor_extra" / "skip_me.py").write_text("x = 1\n", encoding="utf-8")

        main(["scan", str(repo), "--format", "json"])
        without = json.loads(capsys.readouterr().out)["scan"]["files_scanned"]

        cfg = tmp_path / "ignore.yaml"
        cfg.write_text('ignore_paths: ["vendor_extra/*.py"]\n', encoding="utf-8")
        main(["scan", str(repo), "--format", "json", "--config", str(cfg)])
        with_ignore = json.loads(capsys.readouterr().out)["scan"]["files_scanned"]

        assert without == 2
        assert with_ignore == 1


class TestBadConfig:
    def test_unknown_key_exits_two_with_key_and_line(self, capsys, tmp_path):
        repo = _copy_sample(tmp_path)
        cfg = _write_config(repo, "not_a_real_key: 1\n")
        code = main(["scan", str(repo)])
        assert code == EXIT_ERROR
        out = capsys.readouterr().out
        assert f"{cfg}:1: not_a_real_key" in out
        assert "unknown config key" in out

    def test_bad_value_exits_two_with_key_line_and_choices(self, capsys, tmp_path):
        repo = _copy_sample(tmp_path)
        cfg = _write_config(repo, "min_severity: extreme\n")
        code = main(["scan", str(repo)])
        assert code == EXIT_ERROR
        out = capsys.readouterr().out
        assert f"{cfg}:1: min_severity" in out
        assert "critical" in out and "extreme" in out

    def test_bad_value_on_a_later_line_reports_that_line(self, capsys, tmp_path):
        repo = _copy_sample(tmp_path)
        cfg = _write_config(repo, "categories: null\nmin_confidence: extreme\n")
        code = main(["scan", str(repo)])
        assert code == EXIT_ERROR
        assert f"{cfg}:2: min_confidence" in capsys.readouterr().out

    def test_malformed_yaml_exits_two_with_a_line(self, capsys, tmp_path):
        repo = _copy_sample(tmp_path)
        cfg = _write_config(repo, "categories: [unterminated\n")
        code = main(["scan", str(repo)])
        assert code == EXIT_ERROR
        out = capsys.readouterr().out
        assert str(cfg) in out and "invalid YAML" in out


class TestInit:
    def test_writes_file_and_prints_path(self, capsys, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        code = main(["init"])
        written = tmp_path / CONFIG_FILENAME
        assert code == EXIT_CLEAN
        assert written.is_file()
        assert str(written) in capsys.readouterr().out

    def test_generated_file_loads_with_no_errors_and_all_defaults(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        main(["init"])
        cfg = load_config(tmp_path / CONFIG_FILENAME)
        assert cfg == Config(source_path=tmp_path / CONFIG_FILENAME)

    def test_generated_config_gives_the_same_scan_summary(self, capsys, tmp_path, monkeypatch):
        repo = _copy_sample(tmp_path)
        monkeypatch.chdir(repo)
        main(["init"])
        capsys.readouterr()
        main(["scan", str(repo)])
        assert capsys.readouterr().out.splitlines()[-1] == FLASK_NOTES_LINE

    def test_refuses_without_force_and_leaves_file_untouched(self, capsys, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        existing = tmp_path / CONFIG_FILENAME
        existing.write_text("categories: [rate_limiting]\n", encoding="utf-8")
        code = main(["init"])
        out = capsys.readouterr().out
        assert code == EXIT_ERROR
        assert "--force" in out
        assert existing.read_text(encoding="utf-8") == "categories: [rate_limiting]\n"

    def test_force_overwrites(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        existing = tmp_path / CONFIG_FILENAME
        existing.write_text("categories: [rate_limiting]\n", encoding="utf-8")
        code = main(["init", "--force"])
        assert code == EXIT_CLEAN
        assert "rate_limiting" not in existing.read_text(encoding="utf-8")


class TestLoadConfig:
    def test_empty_file_is_all_defaults(self, tmp_path):
        cfg_path = tmp_path / ".copilot.yaml"
        cfg_path.write_text("", encoding="utf-8")
        assert load_config(cfg_path) == Config(source_path=cfg_path)

    def test_null_and_empty_list_mean_the_default(self, tmp_path):
        cfg_path = tmp_path / ".copilot.yaml"
        cfg_path.write_text("categories: []\nmin_severity: null\nignore_paths: []\n",
                            encoding="utf-8")
        cfg = load_config(cfg_path)
        assert cfg.categories is None
        assert cfg.min_severity is None
        assert cfg.ignore_paths == []

    def test_rules_dir_resolves_relative_to_the_config_file(self, tmp_path):
        sub = tmp_path / "nested"
        sub.mkdir()
        cfg_path = sub / ".copilot.yaml"
        cfg_path.write_text("rules_dir: ../custom_rules\n", encoding="utf-8")
        cfg = load_config(cfg_path)
        assert cfg.rules_dir == str((tmp_path / "custom_rules").resolve())

    def test_unknown_key_raises_config_error(self, tmp_path):
        cfg_path = tmp_path / ".copilot.yaml"
        cfg_path.write_text("bogus: true\n", encoding="utf-8")
        with pytest.raises(ConfigError, match="bogus"):
            load_config(cfg_path)
