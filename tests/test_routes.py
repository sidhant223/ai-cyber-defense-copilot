"""``copilot routes``: one row per route handler, one column per control.

The inventory must not invent routes and must not claim a control applies
where it found no subject, so both of those are asserted rather than eyeballed.
"""

from __future__ import annotations

import json
import textwrap

from copilot.cli import EXIT_CLEAN, EXIT_ERROR, main
from copilot.routes import NO, NOT_A_SUBJECT, YES, inventory

from conftest import SAMPLES

FLASK = str(SAMPLES / "flask-notes-app")
EXPRESS = str(SAMPLES / "express-todo-api")


class TestInventory:
    SOURCE = textwrap.dedent("""
        from flask import Flask, request
        app = Flask(__name__)

        @login_required
        @app.route("/notes", methods=["POST"])
        def create():
            title = request.form["title"]
            return {"title": title}

        @app.route("/notes/<int:note_id>", methods=["DELETE"])
        def delete(note_id):
            return "", 204

        @app.route("/login", methods=["POST"])
        def login():
            return "ok"
    """)

    def test_one_row_per_route_handler(self, make_repo, engine):
        rows = inventory(make_repo({"app.py": self.SOURCE}), engine)
        assert [r.line for r in rows] == [6, 11, 15]

    def test_the_auth_column_reflects_the_guard(self, make_repo, engine):
        rows = {r.line: r for r in inventory(make_repo({"app.py": self.SOURCE}), engine)}
        assert rows[6].columns["auth"] == YES
        assert rows[11].columns["auth"] == NO

    def test_a_public_endpoint_is_not_an_auth_subject(self, make_repo, engine):
        """/login is excluded from AUTH-001 by design, so the column is a dash
        rather than a 'no' -- but RATE-002 does claim it."""
        rows = {r.line: r for r in inventory(make_repo({"app.py": self.SOURCE}), engine)}
        assert rows[15].columns["auth"] == NOT_A_SUBJECT
        assert rows[15].columns["rate limit"] == NO

    def test_a_body_read_is_attributed_to_the_route_above_it(self, make_repo, engine):
        rows = {r.line: r for r in inventory(make_repo({"app.py": self.SOURCE}), engine)}
        assert rows[6].columns["validation"] == NO       # request.form on line 8
        assert rows[11].columns["validation"] == NOT_A_SUBJECT

    def test_unprotected_flags_rows_with_a_no(self, make_repo, engine):
        rows = {r.line: r for r in inventory(make_repo({"app.py": self.SOURCE}), engine)}
        assert rows[11].unprotected is True

    def test_a_repository_with_no_routes_is_empty(self, make_repo, engine):
        assert inventory(make_repo({"util.py": "def add(a, b):\n    return a + b\n"}),
                         engine) == []

    def test_it_matches_the_corpus_story(self, engine):
        """flask-notes-app is the AUTH-001 partial case: four of six guarded."""
        from copilot.scanner import scan

        rows = inventory(scan(FLASK), engine)
        auth = [r.columns["auth"] for r in rows]
        assert auth.count(YES) == 4 and auth.count(NO) == 2


class TestCli:
    def test_table_lists_routes_and_a_count(self, capsys):
        assert main(["routes", FLASK]) == EXIT_CLEAN
        out = capsys.readouterr().out
        assert "route(s)" in out and "app.py:95" in out.replace("\n", "")

    def test_json_shape(self, capsys):
        assert main(["routes", EXPRESS, "--format", "json"]) == EXIT_CLEAN
        data = json.loads(capsys.readouterr().out)
        assert data["framework"] == "express"
        assert data["columns"] == ["auth", "rate limit", "role check", "validation"]
        assert data["routes"] and set(data["routes"][0]) == {
            "file_path", "line", "snippet", "columns", "unprotected"}

    def test_unprotected_only_narrows_the_list(self, capsys):
        main(["routes", FLASK, "--format", "json"])
        every = json.loads(capsys.readouterr().out)["routes"]
        main(["routes", FLASK, "--format", "json", "--unprotected-only"])
        narrowed = json.loads(capsys.readouterr().out)["routes"]
        assert 0 < len(narrowed) < len(every)
        assert all(r["unprotected"] for r in narrowed)

    def test_it_is_informational_and_never_gates(self, capsys):
        """Even a repository where nothing is protected exits 0: gating is
        scan's job, and two gates would mean two answers."""
        assert main(["routes", EXPRESS]) == EXIT_CLEAN
        capsys.readouterr()

    def test_a_framework_with_no_routes_says_so(self, capsys, tmp_path):
        (tmp_path / "util.py").write_text("def add(a, b):\n    return a + b\n",
                                          encoding="utf-8")
        assert main(["routes", str(tmp_path)]) == EXIT_CLEAN
        assert "No route handlers found" in capsys.readouterr().out

    def test_a_missing_path_exits_two(self, capsys, tmp_path):
        assert main(["routes", str(tmp_path / "nope")]) == EXIT_ERROR
        assert "not a directory" in capsys.readouterr().out
