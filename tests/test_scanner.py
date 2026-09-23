"""Walker, framework detection and indexer."""

from __future__ import annotations

import pytest

from copilot.scanner import detect_framework, dominant_language
from copilot.scanner.indexer import build_index
from copilot.scanner.walker import language_for, looks_generated, walk

FLASK_APP = """
from flask import Flask
app = Flask(__name__)

@app.route("/hello")
def hello():
    return "hi"
"""


class TestWalker:
    def test_reads_source_and_config(self, tmp_path):
        (tmp_path / "app.py").write_text(FLASK_APP, encoding="utf-8")
        (tmp_path / "package.json").write_text("{}", encoding="utf-8")
        files, _ = walk(str(tmp_path))
        assert {f.path for f in files} == {"app.py", "package.json"}

    def test_skips_ignored_directories(self, tmp_path):
        (tmp_path / "app.py").write_text(FLASK_APP, encoding="utf-8")
        for junk in ("node_modules", "venv", "__pycache__", ".git", "dist"):
            d = tmp_path / junk
            d.mkdir()
            (d / "mod.py").write_text("x = 1", encoding="utf-8")
        files, skipped = walk(str(tmp_path))
        assert [f.path for f in files] == ["app.py"]
        assert skipped == 0  # ignored dirs are never descended into, not counted

    def test_skips_oversize_files(self, tmp_path):
        (tmp_path / "big.py").write_text("x = 1\n" * 5000, encoding="utf-8")
        (tmp_path / "small.py").write_text("y = 2", encoding="utf-8")
        files, skipped = walk(str(tmp_path), max_file_bytes=100)
        assert [f.path for f in files] == ["small.py"]
        assert skipped == 1

    def test_skips_generated_files(self, tmp_path):
        (tmp_path / "bundle.min.js").write_text("var a=1", encoding="utf-8")
        (tmp_path / "package-lock.json").write_text("{}", encoding="utf-8")
        (tmp_path / "app.js").write_text("var a = 1", encoding="utf-8")
        files, skipped = walk(str(tmp_path))
        assert [f.path for f in files] == ["app.js"]
        assert skipped == 2

    def test_paths_are_relative_and_posix(self, tmp_path):
        nested = tmp_path / "src" / "routes"
        nested.mkdir(parents=True)
        (nested / "api.py").write_text("x = 1", encoding="utf-8")
        files, _ = walk(str(tmp_path))
        assert files[0].path == "src/routes/api.py"

    def test_language_mapping(self):
        assert language_for("app.py") == "python"
        assert language_for("main.ts") == "typescript"
        assert language_for("requirements.txt") == "config"
        assert language_for(".env.production") == "config"
        assert language_for("photo.jpeg") is None

    def test_generated_markers(self):
        assert looks_generated("app.min.js")
        assert looks_generated("yarn-lock.json")
        assert not looks_generated("app.js")


class TestFrameworkDetection:
    def test_manifest_beats_nothing(self, make_repo):
        result = make_repo({"requirements.txt": "Flask==3.0.0\n", "app.py": FLASK_APP})
        assert result.framework == "flask"

    def test_imports_alone_are_enough(self, make_repo):
        result = make_repo({"app.py": FLASK_APP})
        assert result.framework == "flask"

    def test_returns_none_when_nothing_matches(self, make_repo):
        result = make_repo({"util.py": "def add(a, b):\n    return a + b\n"})
        assert result.framework is None

    def test_none_carries_an_explanation(self, make_repo):
        result = make_repo({"util.py": "x = 1"})
        assert result.framework is None
        assert "none matched" in result.framework_evidence[0].note

    def test_ambiguity_reports_unknown(self):
        """Two frameworks declared with equal weight is not a guessable case."""
        from copilot.models import ScannedFile

        files = [
            ScannedFile("requirements.txt", "", "config", 40, "Flask==3.0\nfastapi==0.1\n"),
        ]
        framework, evidence = detect_framework(files)
        assert framework is None
        assert "ambiguous" in evidence[0].note

    def test_nextjs_wins_over_express(self, make_repo):
        result = make_repo({
            "package.json": '{"dependencies": {"next": "14.0.0", "express": "4.18.0"}}',
        })
        assert result.framework == "nextjs"

    @pytest.mark.parametrize("files, expected", [
        ({"package.json": '{"dependencies": {"koa": "2.15.0"}}'}, "koa"),
        ({"package.json": '{"dependencies": {"@nestjs/core": "10.3.0"}}'}, "nestjs"),
        ({"requirements.txt": "starlette==0.37.2\n"}, "starlette"),
    ])
    def test_new_frameworks_from_manifest(self, make_repo, files, expected):
        assert make_repo(files).framework == expected

    @pytest.mark.parametrize("files, expected", [
        ({"server.js": "const Koa = require('koa');\nconst app = new Koa();\n"}, "koa"),
        ({"src/main.ts": "import { NestFactory } from '@nestjs/core';\n"}, "nestjs"),
        ({"app.py": "from starlette.applications import Starlette\n"}, "starlette"),
    ])
    def test_new_frameworks_from_imports(self, make_repo, files, expected):
        assert make_repo(files).framework == expected

    def test_fastapi_manifest_wins_over_starlette_import(self, make_repo):
        result = make_repo({
            "requirements.txt": "fastapi==0.110.0\n",
            "main.py": "from fastapi import FastAPI\n"
                       "from starlette.middleware.cors import CORSMiddleware\n",
        })
        assert result.framework == "fastapi"

    def test_fastapi_wins_when_starlette_is_also_declared(self, make_repo):
        result = make_repo({"requirements.txt": "fastapi==0.110.0\nstarlette==0.37.2\n"})
        assert result.framework == "fastapi"

    def test_nestjs_wins_over_express(self, make_repo):
        result = make_repo({
            "package.json": '{"dependencies": {"@nestjs/core": "10.3.0", "express": "4.18.0"}}',
        })
        assert result.framework == "nestjs"

    def test_koa_and_express_imports_tie_to_unknown(self, make_repo):
        result = make_repo({
            "a.js": "const Koa = require('koa');\n",
            "b.js": "const express = require('express');\n",
        })
        assert result.framework is None
        assert "ambiguous" in result.framework_evidence[0].note

    def test_evidence_points_at_a_real_line(self, make_repo):
        result = make_repo({"requirements.txt": "# deps\nFlask==3.0.0\n"})
        evidence = result.framework_evidence[0]
        assert evidence.file_path == "requirements.txt"
        assert evidence.line_number == 2

    def test_dominant_language(self, make_repo):
        result = make_repo({
            "a.py": "x = 1", "b.py": "y = 2", "c.js": "var z = 3",
        })
        assert result.language == "python"

    def test_language_unknown_without_source(self, make_repo):
        result = make_repo({"README.md": "# hi"})
        assert result.language == "unknown"


class TestIndexer:
    def test_route_file_by_content(self, make_repo):
        result = make_repo({"anywhere.py": FLASK_APP})
        assert "anywhere.py" in result.file_index["routes"]

    def test_route_file_by_conventional_name(self, make_repo):
        """Django views.py holds routes but contains no decorator to match."""
        result = make_repo({"blog/views.py": "def index(request):\n    return None\n"})
        assert "blog/views.py" in result.file_index["routes"]

    def test_config_files_indexed(self, make_repo):
        result = make_repo({"settings.py": "DEBUG = True\n", "app.json": "{}"})
        assert set(result.file_index["config"]) == {"settings.py", "app.json"}

    def test_secrets_category_takes_every_file(self, make_repo):
        result = make_repo({
            "app.py": FLASK_APP, "README.md": "# hi", "package.json": "{}",
        })
        assert len(result.file_index["secret_management"]) == result.files_scanned

    def test_index_is_sorted(self, make_repo):
        result = make_repo({"z.py": FLASK_APP, "a.py": FLASK_APP})
        assert result.file_index["routes"] == sorted(result.file_index["routes"])

    def test_every_category_present_even_when_empty(self, make_repo):
        result = make_repo({"README.md": "# hi"})
        for category in ("authentication", "input_validation", "rate_limiting",
                         "secret_management", "access_control"):
            assert category in result.file_index

    def test_files_for_round_trips(self, make_repo):
        result = make_repo({"app.py": FLASK_APP})
        paths = [f.path for f in result.files_for("authentication")]
        assert paths == result.file_index["authentication"]


def test_scan_reports_duration_and_counts(make_repo):
    result = make_repo({"app.py": FLASK_APP, "README.md": "# hi"})
    assert result.files_scanned == 2
    assert result.scan_duration_ms >= 0
