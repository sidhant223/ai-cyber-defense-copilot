"""Rule loading and the four verdict paths.

The engine is the part that has to be right: every detector inherits its
behaviour, so a flaw here is five flaws.
"""

from __future__ import annotations

import textwrap

import pytest

from copilot.detectors.rule_engine import (
    RuleEngine,
    RuleError,
    glob_to_regex,
    load_rule_file,
    parse_control,
    strip_comment_lines,
)
from copilot.models import Status

RULE = """
category: authentication
description: fixture
controls:
  - id: TEST-001
    name: Routes are guarded
    severity: critical
    detection:
      subject:
        type: regex
        description: route
        pattern: '@app\\.route\\('
      guard:
        type: regex
        proximity_lines: 2
        any_of: ['@login_required']
    verdict:
      all_subjects_guarded: present
      some_subjects_guarded: partial
      no_subjects_guarded: absent
      no_subjects_found: not_applicable
    remediation_hint: add a decorator
"""


def write_rules(tmp_path, text=RULE, name="authentication.yaml"):
    d = tmp_path / "rules"
    d.mkdir(exist_ok=True)
    (d / name).write_text(textwrap.dedent(text), encoding="utf-8")
    return d


@pytest.fixture
def fixture_engine(tmp_path):
    return RuleEngine(write_rules(tmp_path))


class TestGlobTranslation:
    def test_star_does_not_cross_directories(self):
        rx = glob_to_regex("routes/*.py")
        assert rx.search("routes/api.py")
        assert not rx.search("routes/v1/api.py")

    def test_double_star_crosses_directories(self):
        rx = glob_to_regex("**/routes/*.py")
        assert rx.search("routes/api.py")
        assert rx.search("src/v1/routes/api.py")

    def test_anchored_at_both_ends(self):
        rx = glob_to_regex("*.py")
        assert rx.search("app.py")
        assert not rx.search("app.pyc")

    def test_dots_are_literal(self):
        rx = glob_to_regex("app.py")
        assert not rx.search("appxpy")


class TestCommentStripping:
    def test_whole_line_comments_are_blanked(self):
        lines = ["# @app.route('/admin')", "@app.route('/x')"]
        assert strip_comment_lines(lines) == ["", "@app.route('/x')"]

    def test_js_and_block_comment_markers(self):
        lines = ["// x", " * y", "/* z */", "code()"]
        assert strip_comment_lines(lines) == ["", "", "", "code()"]

    def test_trailing_comments_are_left_alone(self):
        lines = ["x = 1  # note"]
        assert strip_comment_lines(lines) == ["x = 1  # note"]


class TestVerdictPaths:
    """All four outcomes, which is the whole reason the engine exists."""

    def _run(self, fixture_engine, make_repo, source):
        scan = make_repo({"app.py": source})
        control = fixture_engine.get("TEST-001")
        return fixture_engine.evaluate(control, scan)

    def test_no_subjects_is_not_applicable(self, fixture_engine, make_repo):
        finding = self._run(fixture_engine, make_repo, "from flask import Flask\n")
        assert finding.status is Status.NOT_APPLICABLE
        assert "0 matched" in finding.evidence[0].note

    def test_all_guarded_is_present(self, fixture_engine, make_repo):
        finding = self._run(fixture_engine, make_repo, textwrap.dedent("""
            @login_required
            @app.route('/a')
            def a(): pass

            @login_required
            @app.route('/b')
            def b(): pass
        """))
        assert finding.status is Status.PRESENT

    def test_none_guarded_is_absent(self, fixture_engine, make_repo):
        finding = self._run(fixture_engine, make_repo, textwrap.dedent("""
            @app.route('/a')
            def a(): pass

            @app.route('/b')
            def b(): pass
        """))
        assert finding.status is Status.ABSENT
        assert "2" in finding.message

    def test_some_guarded_is_partial(self, fixture_engine, make_repo):
        finding = self._run(fixture_engine, make_repo, textwrap.dedent("""
            @login_required
            @app.route('/a')
            def a(): pass

            @app.route('/b')
            def b(): pass
        """))
        assert finding.status is Status.PARTIAL
        assert "1 of 2" in finding.message

    def test_partial_evidence_points_at_the_unguarded_one(self, fixture_engine, make_repo):
        finding = self._run(fixture_engine, make_repo, textwrap.dedent("""
            @login_required
            @app.route('/a')
            def a(): pass

            @app.route('/b')
            def b(): pass
        """))
        # The leading newline of the dedented block is line 1, so the
        # unguarded route is line 6.
        lines = [e.line_number for e in finding.evidence if e.file_path]
        assert lines == [6]

    def test_commented_out_route_is_not_a_subject(self, fixture_engine, make_repo):
        finding = self._run(fixture_engine, make_repo, "# @app.route('/a')\n")
        assert finding.status is Status.NOT_APPLICABLE


class TestProximity:
    def test_guard_outside_the_window_does_not_count(self, fixture_engine, make_repo):
        scan = make_repo({"app.py": textwrap.dedent("""
            @login_required

            # spacer
            # spacer
            @app.route('/a')
            def a(): pass
        """)})
        finding = fixture_engine.evaluate(fixture_engine.get("TEST-001"), scan)
        assert finding.status is Status.ABSENT

    # FastAPI puts its guard in the handler signature, below the decorator,
    # so looking upward alone reports every FastAPI route as unguarded.
    SOURCE_GUARD_BELOW = "@app.route('/a')\n@login_required\ndef a():\n    pass\n"

    def test_guard_below_is_missed_without_opt_in(self, fixture_engine, make_repo):
        scan = make_repo({"app.py": self.SOURCE_GUARD_BELOW})
        finding = fixture_engine.evaluate(fixture_engine.get("TEST-001"), scan)
        assert finding.status is Status.ABSENT

    def test_guard_below_is_found_with_opt_in(self, tmp_path, make_repo):
        rule = RULE.replace(
            "        proximity_lines: 2",
            "        proximity_lines: 0\n        proximity_lines_below: 3",
        )
        engine = RuleEngine(write_rules(tmp_path, rule))
        scan = make_repo({"app.py": self.SOURCE_GUARD_BELOW})
        finding = engine.evaluate(engine.get("TEST-001"), scan)
        assert finding.status is Status.PRESENT


class TestForbidGuard:
    RULE_FORBID = """
    category: input_validation
    description: fixture
    controls:
      - id: TEST-002
        name: Queries are parameterised
        severity: critical
        detection:
          subject:
            type: regex
            description: query
            pattern: 'SELECT'
          guard:
            type: regex
            mode: forbid
            scope: same_line
            description: parameterised
            any_of: ['f"']
        verdict:
          all_subjects_guarded: present
          no_subjects_guarded: absent
          some_subjects_guarded: partial
          no_subjects_found: not_applicable
        remediation_hint: use placeholders
    """

    def test_absence_of_the_marker_satisfies(self, tmp_path, make_repo):
        engine = RuleEngine(write_rules(tmp_path, self.RULE_FORBID, "input_validation.yaml"))
        scan = make_repo({"q.py": 'db.execute("SELECT 1", (x,))\n'})
        finding = engine.evaluate(engine.get("TEST-002"), scan)
        assert finding.status is Status.PRESENT

    def test_presence_of_the_marker_fails(self, tmp_path, make_repo):
        engine = RuleEngine(write_rules(tmp_path, self.RULE_FORBID, "input_validation.yaml"))
        scan = make_repo({"q.py": 'db.execute(f"SELECT {x}")\n'})
        finding = engine.evaluate(engine.get("TEST-002"), scan)
        assert finding.status is Status.ABSENT


class TestMultipleGuards:
    RULE_MULTI = """
    category: authentication
    description: fixture
    controls:
      - id: TEST-003
        name: Routes are guarded
        severity: critical
        detection:
          subject:
            type: regex
            description: route
            pattern: 'router\\.get\\('
          guards:
            - type: regex
              proximity_lines: 1
              any_of: ['requireAuth']
            - type: regex
              scope: file
              any_of: ['router\\.use\\(auth\\)']
        verdict:
          all_subjects_guarded: present
          no_subjects_guarded: absent
          some_subjects_guarded: partial
          no_subjects_found: not_applicable
        remediation_hint: guard it
    """

    def _engine(self, tmp_path):
        return RuleEngine(write_rules(tmp_path, self.RULE_MULTI))

    def test_second_guard_can_satisfy_alone(self, tmp_path, make_repo):
        engine = self._engine(tmp_path)
        scan = make_repo({"r.js": "router.use(auth)\nrouter.get('/a', h)\n"})
        finding = engine.evaluate(engine.get("TEST-003"), scan)
        assert finding.status is Status.PRESENT

    def test_neither_guard_means_absent(self, tmp_path, make_repo):
        engine = self._engine(tmp_path)
        scan = make_repo({"r.js": "router.get('/a', h)\n"})
        finding = engine.evaluate(engine.get("TEST-003"), scan)
        assert finding.status is Status.ABSENT

    def test_evidence_names_every_scope_searched(self, tmp_path, make_repo):
        engine = self._engine(tmp_path)
        scan = make_repo({"r.js": "router.get('/a', h)\n"})
        finding = engine.evaluate(engine.get("TEST-003"), scan)
        note = finding.evidence[0].note
        assert "within 1 lines above" in note and "same file" in note

    def test_mixed_guard_modes_are_rejected(self, tmp_path):
        bad = self.RULE_MULTI.replace(
            "            - type: regex\n              scope: file",
            "            - type: regex\n              mode: forbid\n              scope: file",
        )
        with pytest.raises(RuleError, match="share a mode"):
            RuleEngine(write_rules(tmp_path, bad))


class TestSwitchedOffGuard:
    """A guard that is named but turned off is not protection.

    ``helmet({ contentSecurityPolicy: false })`` mentions the middleware and
    disables exactly the part the control is about. A guard's ``none_of`` lists
    the lines that do not count, however well they match ``any_of``.
    """

    RULE_OFF = """
    category: access_control
    description: fixture
    controls:
      - id: TEST-005
        name: Content-Security-Policy enabled
        severity: medium
        detection:
          subject:
            type: regex
            description: express app
            pattern: 'express\\(\\)'
          guard:
            type: regex
            scope: file
            description: protected by helmet
            any_of: ['helmet\\(']
            none_of: ['contentSecurityPolicy\\s*:\\s*false']
        verdict:
          all_subjects_guarded: present
          some_subjects_guarded: partial
          no_subjects_guarded: absent
          no_subjects_found: not_applicable
        remediation_hint: turn it on
    """

    def _status(self, tmp_path, make_repo, source):
        engine = RuleEngine(write_rules(tmp_path, self.RULE_OFF, "access_control.yaml"))
        scan = make_repo({"server.js": source})
        return engine.evaluate(engine.get("TEST-005"), scan).status

    def test_enabled_guard_counts(self, tmp_path, make_repo):
        source = "const app = express();\napp.use(helmet());\n"
        assert self._status(tmp_path, make_repo, source) is Status.PRESENT

    def test_switched_off_guard_does_not_count(self, tmp_path, make_repo):
        source = "const app = express();\napp.use(helmet({ contentSecurityPolicy: false }));\n"
        assert self._status(tmp_path, make_repo, source) is Status.ABSENT

    def test_explain_lists_the_exceptions(self, tmp_path, capsys):
        from copilot.cli import main

        rules = write_rules(tmp_path, self.RULE_OFF, "access_control.yaml")
        main(["rules", "explain", "TEST-005", "--rules", str(rules)])
        out = capsys.readouterr().out
        assert "except on lines matching" in out and "contentSecurityPolicy" in out


class TestStandardsMetadata:
    def test_cwe_and_owasp_are_parsed(self, tmp_path):
        rule = RULE.replace("    severity: critical",
                            "    severity: critical\n    cwe: CWE-306\n    owasp: A07:2021")
        control = RuleEngine(write_rules(tmp_path, rule)).get("TEST-001")
        assert (control.cwe, control.owasp) == ("CWE-306", "A07:2021")

    @pytest.mark.parametrize("line, key", [("cwe: 306", "cwe"),
                                           ("owasp: Broken Access Control", "owasp")])
    def test_malformed_references_are_rejected(self, tmp_path, line, key):
        rule = RULE.replace("    severity: critical", f"    severity: critical\n    {line}")
        with pytest.raises(RuleError, match=f"TEST-001: {key}"):
            RuleEngine(write_rules(tmp_path, rule))

    def test_findings_carry_the_references(self, make_repo, engine):
        from copilot.detectors import run_all

        scan = make_repo({"app.py": "from flask import Flask\napp = Flask(__name__)\n"
                                    "@app.route('/notes')\ndef notes(): pass\n"})
        findings, _ = run_all(scan, engine, ["authentication"])
        auth = next(f for f in findings if f.control_id == "AUTH-001")
        assert auth.to_dict()["cwe"] == "CWE-306"
        assert auth.to_dict()["owasp"].startswith("A07")


class TestPresenceMode:
    RULE_PRESENCE = """
    category: rate_limiting
    description: fixture
    controls:
      - id: TEST-004
        name: Limiter registered
        severity: high
        detection:
          mode: presence
          patterns:
            match: content
            any_of: ['Limiter\\(']
            none_of: ['# example']
        verdict:
          found: present
          not_found: absent
        remediation_hint: install one
    """

    def _engine(self, tmp_path):
        return RuleEngine(write_rules(tmp_path, self.RULE_PRESENCE, "rate_limiting.yaml"))

    def test_found(self, tmp_path, make_repo):
        engine = self._engine(tmp_path)
        scan = make_repo({"app.py": "limiter = Limiter(key_func=f)\n"})
        assert engine.evaluate(engine.get("TEST-004"), scan).status is Status.PRESENT

    def test_not_found_carries_negative_evidence(self, tmp_path, make_repo):
        engine = self._engine(tmp_path)
        scan = make_repo({"app.py": "x = 1\n"})
        finding = engine.evaluate(engine.get("TEST-004"), scan)
        assert finding.status is Status.ABSENT
        assert "found nothing" in finding.evidence[0].note

    def test_none_of_suppresses_a_match(self, tmp_path, make_repo):
        engine = self._engine(tmp_path)
        scan = make_repo({"app.py": "limiter = Limiter(f)  # example\n"})
        assert engine.evaluate(engine.get("TEST-004"), scan).status is Status.ABSENT


class TestNewCategoryIsJustAFile:
    """"A new control category is a YAML file, not a Python edit" is a claim
    the project makes, so it is asserted rather than assumed."""

    RULE_NEW = """
    category: transport_security
    description: Controls for how traffic reaches the application.
    controls:
      - id: TRANSPORT-001
        name: TLS certificate verification is not disabled
        severity: high
        cwe: CWE-295
        owasp: A02:2021
        description: An outbound call that skips verification has no TLS.
        detection:
          mode: presence
          patterns:
            match: content
            any_of: ['verify\\s*=\\s*False', 'rejectUnauthorized\\s*:\\s*false']
        verdict:
          found: absent
          not_found: present
        remediation_hint: leave verification on and fix the certificate
    """

    def _report(self, tmp_path, make_repo, source):
        from copilot.detectors import run_all

        engine = RuleEngine(write_rules(tmp_path, self.RULE_NEW, "transport_security.yaml"))
        findings, _ = run_all(make_repo({"client.py": source}), engine)
        return {f.control_id: f.status for f in findings}

    def test_a_yaml_only_category_runs(self, tmp_path, make_repo):
        statuses = self._report(tmp_path, make_repo,
                                "import requests\nrequests.get(url, verify=False)\n")
        assert statuses["TRANSPORT-001"] is Status.ABSENT

    def test_a_yaml_only_category_can_pass(self, tmp_path, make_repo):
        statuses = self._report(tmp_path, make_repo,
                                "import requests\nrequests.get(url, timeout=5)\n")
        assert statuses["TRANSPORT-001"] is Status.PRESENT

    def test_the_category_is_listed_with_its_description(self, tmp_path, capsys):
        from copilot.cli import main

        rules = write_rules(tmp_path, self.RULE_NEW, "transport_security.yaml")
        main(["rules", "list", "--rules", str(rules)])
        # Line wrapping can fall anywhere in the marker, so assert its tail.
        out = capsys.readouterr().out.replace("\n", "")
        assert "transport_security" in out and "TRANSPORT-001" in out
        assert "only)" in out


class TestApplicability:
    def test_framework_mismatch_is_skipped_with_a_reason(self, tmp_path, make_repo):
        rule = RULE.replace(
            "    severity: critical",
            "    severity: critical\n    applies_to:\n      frameworks: [django]",
        )
        engine = RuleEngine(write_rules(tmp_path, rule))
        scan = make_repo({"app.py": "from flask import Flask\n@app.route('/a')\ndef a(): pass\n"})
        control = engine.get("TEST-001")
        assert "applies to django" in engine.skip_reason(control, scan)
        assert engine.evaluate(control, scan) is None

    def test_index_buckets_are_a_union_not_an_intersection(self, tmp_path, make_repo):
        """A rule listing two buckets means either, which is what a rule
        author writing that list means. Intersecting produced an empty set."""
        rule = RULE.replace(
            "    severity: critical",
            "    severity: critical\n    applies_to:\n      index_buckets: [routes, config]",
        )
        engine = RuleEngine(write_rules(tmp_path, rule))
        scan = make_repo({"app.py": "@app.route('/a')\ndef a(): pass\n"})
        files = engine.applicable_files(engine.get("TEST-001"), scan)
        assert [f.path for f in files] == ["app.py"]

    def test_exclude_patterns_win(self, tmp_path, make_repo):
        rule = RULE.replace(
            "    severity: critical",
            '    severity: critical\n    applies_to:\n      exclude_patterns: ["**/test_*.py"]',
        )
        engine = RuleEngine(write_rules(tmp_path, rule))
        scan = make_repo({"test_app.py": "@app.route('/a')\ndef a(): pass\n"})
        assert engine.evaluate(engine.get("TEST-001"), scan) is None


class TestRuleValidation:
    def test_unknown_severity_rejected(self, tmp_path):
        with pytest.raises(RuleError, match="unknown severity"):
            RuleEngine(write_rules(tmp_path, RULE.replace("critical", "catastrophic")))

    def test_unknown_status_rejected(self, tmp_path):
        with pytest.raises(RuleError, match="unknown verdict status"):
            RuleEngine(write_rules(tmp_path, RULE.replace("no_subjects_guarded: absent",
                                                         "no_subjects_guarded: maybe")))

    def test_bad_regex_names_the_control(self, tmp_path):
        with pytest.raises(RuleError, match="TEST-001: bad regex"):
            RuleEngine(write_rules(tmp_path, RULE.replace("'@login_required'", "'([unclosed'")))

    def test_subject_guard_without_a_guard_rejected(self, tmp_path):
        bad = RULE.split("      guard:")[0] + "    verdict:\n      no_subjects_found: not_applicable\n"
        with pytest.raises(RuleError, match="needs detection.guard"):
            RuleEngine(write_rules(tmp_path, bad))

    def test_duplicate_control_ids_rejected(self, tmp_path):
        d = write_rules(tmp_path)
        (d / "other.yaml").write_text(
            textwrap.dedent(RULE).replace("category: authentication", "category: access_control"),
            encoding="utf-8",
        )
        with pytest.raises(RuleError, match="duplicate control id"):
            RuleEngine(d)

    def test_missing_category_rejected(self, tmp_path):
        d = tmp_path / "rules"
        d.mkdir()
        (d / "x.yaml").write_text("controls: []\n", encoding="utf-8")
        with pytest.raises(RuleError, match="missing top-level"):
            RuleEngine(d)


class TestShippedRuleSet:
    """The rule files that actually ship have to load and be well formed."""

    def test_all_five_categories_load(self, engine):
        assert set(engine.categories) == {
            "authentication", "input_validation", "rate_limiting",
            "secret_management", "access_control",
        }

    def test_every_control_has_a_remediation_hint(self, engine):
        missing = [c.id for c in engine.controls() if not c.remediation_hint]
        assert missing == []

    def test_every_control_has_a_description(self, engine):
        missing = [c.id for c in engine.controls() if not c.description]
        assert missing == []

    def test_every_control_maps_to_cwe_and_owasp(self, engine):
        missing = [c.id for c in engine.controls() if not (c.cwe and c.owasp)]
        assert missing == []

    def test_subject_guard_controls_cover_all_four_verdicts(self, engine):
        required = {"all_subjects_guarded", "some_subjects_guarded",
                    "no_subjects_guarded", "no_subjects_found"}
        for control in engine.controls():
            if control.mode == "subject_guard":
                assert required <= set(control.verdict), control.id

    def test_presence_controls_map_both_outcomes(self, engine):
        for control in engine.controls():
            if control.mode == "presence":
                assert {"found", "not_found"} <= set(control.verdict), control.id

    def test_control_ids_are_prefixed_by_category(self, engine):
        prefixes = {
            "authentication": "AUTH-", "input_validation": "INPUT-",
            "rate_limiting": "RATE-", "secret_management": "SECRET-",
            "access_control": "AC-",
        }
        for control in engine.controls():
            assert control.id.startswith(prefixes[control.category]), control.id

    def test_lookup_is_case_insensitive(self, engine):
        assert engine.get("auth-001") is engine.get("AUTH-001")

    def test_unknown_control_returns_none(self, engine):
        assert engine.get("NOPE-999") is None
