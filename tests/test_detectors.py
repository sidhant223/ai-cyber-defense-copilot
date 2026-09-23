"""Per-detector behaviour against small inline fixtures.

One class per category, plus the regression cases the corpus turned up. Every
false positive found during development becomes a permanent test here.
"""

from __future__ import annotations

import textwrap

import pytest

from copilot.detectors import registry, run_all
from copilot.detectors.secret_management import (
    is_interesting,
    redact,
    shannon_entropy,
)
from copilot.models import Status


def status_of(scan, engine, control_id: str) -> Status | None:
    findings, _ = run_all(scan, engine)
    for f in findings:
        if f.control_id == control_id:
            return f.status
    return None


def finding_for(scan, engine, control_id: str):
    findings, _ = run_all(scan, engine)
    for f in findings:
        if f.control_id == control_id:
            return f
    return None


FLASK_HEADER = "from flask import Flask, request, session\napp = Flask(__name__)\n"


class TestRegistry:
    def test_all_five_detectors_registered(self):
        assert set(registry()) == {
            "authentication", "input_validation", "rate_limiting",
            "secret_management", "access_control",
        }

    def test_detectors_do_not_import_each_other(self):
        """Independence is a structural claim, so check it structurally."""
        import pathlib

        directory = pathlib.Path(
            "src/copilot/detectors"
        ).resolve()
        categories = set(registry())
        for module in directory.glob("*.py"):
            if module.stem not in categories:
                continue
            text = module.read_text(encoding="utf-8")
            for other in categories - {module.stem}:
                assert f"import {other}" not in text
                assert f"from .{other}" not in text

    def test_every_detector_has_a_description(self, engine):
        for cls in registry().values():
            assert cls(engine).description


class TestAuthentication:
    def test_unguarded_flask_routes_are_absent(self, make_repo, engine):
        scan = make_repo({"app.py": FLASK_HEADER + textwrap.dedent("""
            @app.route("/orders")
            def orders():
                return "x"
        """)})
        assert status_of(scan, engine, "AUTH-001") is Status.ABSENT

    def test_guarded_flask_routes_are_present(self, make_repo, engine):
        scan = make_repo({"app.py": FLASK_HEADER + textwrap.dedent("""
            @login_required
            @app.route("/orders")
            def orders():
                return "x"
        """)})
        assert status_of(scan, engine, "AUTH-001") is Status.PRESENT

    def test_mixed_routes_are_partial(self, make_repo, engine):
        scan = make_repo({"app.py": FLASK_HEADER + textwrap.dedent("""
            @login_required
            @app.route("/orders")
            def orders():
                return "x"

            @app.route("/invoices")
            def invoices():
                return "y"
        """)})
        finding = finding_for(scan, engine, "AUTH-001")
        assert finding.status is Status.PARTIAL
        assert "1 of 2" in finding.message

    def test_public_endpoints_are_not_subjects(self, make_repo, engine):
        """Login and health checks are unauthenticated by design."""
        scan = make_repo({"app.py": FLASK_HEADER + textwrap.dedent("""
            @app.route("/login", methods=["POST"])
            def login():
                return "x"

            @app.route("/health")
            def health():
                return "ok"
        """)})
        assert status_of(scan, engine, "AUTH-001") is Status.NOT_APPLICABLE

    def test_fastapi_dependency_below_the_decorator_counts(self, make_repo, engine):
        scan = make_repo({
            "requirements.txt": "fastapi==0.109.0\n",
            "main.py": textwrap.dedent("""
                from fastapi import Depends, FastAPI
                app = FastAPI()

                @app.get("/orders")
                def orders(user = Depends(get_current_user)):
                    return []
            """),
        })
        assert status_of(scan, engine, "AUTH-001") is Status.PRESENT

    def test_role_dependency_also_authenticates(self, make_repo, engine):
        """Regression: Depends(require_admin) authenticates before it authorises."""
        scan = make_repo({
            "requirements.txt": "fastapi==0.109.0\n",
            "main.py": textwrap.dedent("""
                from fastapi import Depends, FastAPI
                app = FastAPI()

                @app.get("/reports")
                def reports(admin = Depends(require_admin)):
                    return []
            """),
        })
        assert status_of(scan, engine, "AUTH-001") is Status.PRESENT

    def test_express_router_root_path_is_a_subject(self, make_repo, engine):
        """Regression: router.get('/') is a collection endpoint, not a landing page."""
        scan = make_repo({
            "package.json": '{"dependencies": {"express": "4.18.0"}}',
            "routes/todos.js": "const router = require('express').Router();\n"
                               "router.get('/', handler);\n",
        })
        assert status_of(scan, engine, "AUTH-002") is Status.ABSENT

    def test_express_router_wide_middleware_counts(self, make_repo, engine):
        scan = make_repo({
            "package.json": '{"dependencies": {"express": "4.18.0"}}',
            "routes/todos.js": "const router = require('express').Router();\n"
                               "router.use(requireAuth);\n"
                               "router.get('/', handler);\n",
        })
        assert status_of(scan, engine, "AUTH-002") is Status.PRESENT

    def test_password_hashing_present(self, make_repo, engine):
        scan = make_repo({"auth.py": textwrap.dedent("""
            import bcrypt
            def store(password):
                return bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        """)})
        assert status_of(scan, engine, "AUTH-003") is Status.PRESENT

    def test_password_stored_without_hashing_is_absent(self, make_repo, engine):
        scan = make_repo({"auth.py": textwrap.dedent("""
            def store(user, password):
                user.password = password
                db.save(user)
        """)})
        assert status_of(scan, engine, "AUTH-003") is Status.ABSENT

    def test_md5_password_hashing_is_flagged(self, make_repo, engine):
        scan = make_repo({"auth.py": textwrap.dedent("""
            import hashlib
            def store(password):
                return hashlib.md5(password.encode()).hexdigest()
        """)})
        assert status_of(scan, engine, "AUTH-004") is Status.ABSENT

    def test_session_flags_absent(self, make_repo, engine):
        scan = make_repo({"app.py": FLASK_HEADER + 'app.secret_key = "k"\n'})
        assert status_of(scan, engine, "AUTH-005") is Status.ABSENT

    def test_session_flags_present(self, make_repo, engine):
        scan = make_repo({"app.py": FLASK_HEADER + textwrap.dedent("""
            app.secret_key = "k"
            app.config["SESSION_COOKIE_SECURE"] = True
            app.config["SESSION_COOKIE_HTTPONLY"] = True
        """)})
        assert status_of(scan, engine, "AUTH-005") is Status.PRESENT

    def test_stateless_api_has_no_session_to_judge(self, make_repo, engine):
        """Regression: a token-signing SECRET_KEY is not a session."""
        scan = make_repo({
            "requirements.txt": "fastapi==0.109.0\n",
            "main.py": 'from fastapi import FastAPI\napp = FastAPI()\nSECRET_KEY = "abc"\n',
        })
        assert status_of(scan, engine, "AUTH-005") is Status.NOT_APPLICABLE

    def test_django_views_are_evaluated(self, make_repo, engine):
        """Regression: AUTH-001 matches decorators, and Django has none."""
        scan = make_repo({
            "requirements.txt": "Django==5.0.1\n",
            "blog/views.py": textwrap.dedent("""
                from django.contrib.auth.decorators import login_required

                @login_required
                def dashboard(request):
                    return None

                def secrets(request):
                    return None
            """),
        })
        assert status_of(scan, engine, "AUTH-007") is Status.PARTIAL


class TestInputValidation:
    def test_raw_body_without_a_schema(self, make_repo, engine):
        scan = make_repo({"app.py": FLASK_HEADER + textwrap.dedent("""
            @app.route("/orders", methods=["POST"])
            def create():
                data = request.get_json()
                return data["total"]
        """)})
        assert status_of(scan, engine, "INPUT-001") is Status.ABSENT

    def test_raw_body_with_a_schema_in_the_file(self, make_repo, engine):
        scan = make_repo({"app.py": FLASK_HEADER + textwrap.dedent("""
            from pydantic import BaseModel

            class Order(BaseModel):
                total: int

            @app.route("/orders", methods=["POST"])
            def create():
                data = Order.model_validate(request.get_json())
                return data.total
        """)})
        assert status_of(scan, engine, "INPUT-001") is Status.PRESENT

    def test_parameterised_query_is_present(self, make_repo, engine):
        scan = make_repo({"db.py":
                          'cursor.execute("SELECT * FROM users WHERE id = %s", (uid,))\n'})
        assert status_of(scan, engine, "INPUT-002") is Status.PRESENT

    def test_fstring_query_is_absent(self, make_repo, engine):
        scan = make_repo({"db.py": 'cursor.execute(f"SELECT * FROM users WHERE id = {uid}")\n'})
        assert status_of(scan, engine, "INPUT-002") is Status.ABSENT

    def test_percent_formatting_query_is_absent(self, make_repo, engine):
        scan = make_repo({"db.py": 'cursor.execute("SELECT * FROM u WHERE n = \'%s\'" % name)\n'})
        assert status_of(scan, engine, "INPUT-002") is Status.ABSENT

    def test_template_literal_query_is_absent(self, make_repo, engine):
        scan = make_repo({"db.js": "pool.query(`SELECT * FROM u WHERE n = '${name}'`)\n"})
        assert status_of(scan, engine, "INPUT-002") is Status.ABSENT

    def test_select_star_is_a_subject(self, make_repo, engine):
        """Regression: a trailing \\b after [\\w*] can never match, so every
        SELECT was silently skipped."""
        scan = make_repo({"db.py": 'cursor.execute(f"SELECT * FROM users")\n'})
        assert status_of(scan, engine, "INPUT-002") is Status.ABSENT

    def test_mixed_queries_are_partial(self, make_repo, engine):
        scan = make_repo({"db.py": textwrap.dedent("""
            cursor.execute("SELECT * FROM users WHERE id = %s", (uid,))
            cursor.execute(f"SELECT * FROM notes WHERE q = '{term}'")
        """)})
        assert status_of(scan, engine, "INPUT-002") is Status.PARTIAL

    def test_upload_without_restrictions(self, make_repo, engine):
        scan = make_repo({"app.py": FLASK_HEADER + textwrap.dedent("""
            @app.route("/upload", methods=["POST"])
            def upload():
                f = request.files["file"]
                f.save("/data/" + f.filename)
        """)})
        assert status_of(scan, engine, "INPUT-003") is Status.ABSENT

    def test_upload_with_restrictions(self, make_repo, engine):
        scan = make_repo({"app.py": FLASK_HEADER + textwrap.dedent("""
            app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024
            ALLOWED_EXTENSIONS = {"png", "jpg"}

            @app.route("/upload", methods=["POST"])
            def upload():
                f = request.files["file"]
                f.save("/data/" + f.filename)
        """)})
        assert status_of(scan, engine, "INPUT-003") is Status.PRESENT

    def test_shell_true_is_flagged(self, make_repo, engine):
        scan = make_repo({"run.py":
                          "import subprocess\nsubprocess.run(cmd, shell=True)\n"})
        assert status_of(scan, engine, "INPUT-004") is Status.ABSENT

    def test_nosec_annotation_is_respected(self, make_repo, engine):
        scan = make_repo({"run.py":
                          "import subprocess\nsubprocess.run(cmd, shell=True)  # nosec\n"})
        assert status_of(scan, engine, "INPUT-004") is Status.PRESENT


class TestRateLimiting:
    def test_no_limiter_anywhere(self, make_repo, engine):
        scan = make_repo({"app.py": FLASK_HEADER})
        assert status_of(scan, engine, "RATE-001") is Status.ABSENT

    def test_limiter_registered(self, make_repo, engine):
        scan = make_repo({"app.py": FLASK_HEADER + textwrap.dedent("""
            from flask_limiter import Limiter
            limiter = Limiter(app, key_func=lambda: "x")
        """)})
        assert status_of(scan, engine, "RATE-001") is Status.PRESENT

    def test_login_without_a_limit(self, make_repo, engine):
        scan = make_repo({"app.py": FLASK_HEADER + textwrap.dedent("""
            @app.route("/login", methods=["POST"])
            def login():
                return "x"
        """)})
        assert status_of(scan, engine, "RATE-002") is Status.ABSENT

    def test_login_with_a_limit(self, make_repo, engine):
        scan = make_repo({"app.py": FLASK_HEADER + textwrap.dedent("""
            @limiter.limit("5/minute")
            @app.route("/login", methods=["POST"])
            def login():
                return "x"
        """)})
        assert status_of(scan, engine, "RATE-002") is Status.PRESENT

    def test_no_credential_endpoint_is_not_applicable(self, make_repo, engine):
        scan = make_repo({"app.py": FLASK_HEADER + textwrap.dedent("""
            @app.route("/orders")
            def orders():
                return "x"
        """)})
        assert status_of(scan, engine, "RATE-002") is Status.NOT_APPLICABLE

    def test_global_default_present(self, make_repo, engine):
        scan = make_repo({"app.py": FLASK_HEADER +
                          'limiter = Limiter(default_limits=["200/hour"])\n'})
        assert status_of(scan, engine, "RATE-003") is Status.PRESENT


class TestSecretManagement:
    def test_aws_key_format(self, make_repo, engine):
        scan = make_repo({"config.py": 'AWS_KEY = "AKIAQ4XZ7NLPWJ3MTKVD"\n'})
        assert status_of(scan, engine, "SECRET-001") is Status.ABSENT

    def test_documented_example_key_is_allowlisted(self, make_repo, engine):
        scan = make_repo({"config.py": 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n'})
        assert status_of(scan, engine, "SECRET-001") is Status.PRESENT

    def test_connection_string_with_credentials(self, make_repo, engine):
        scan = make_repo({"config.py":
                          'URL = "postgresql://app:Hunter2Rocks@db:5432/prod"\n'})
        assert status_of(scan, engine, "SECRET-002") is Status.ABSENT

    def test_connection_string_placeholder_is_ignored(self, make_repo, engine):
        scan = make_repo({"config.py":
                          'URL = "postgresql://app:password@db:5432/prod"\n'})
        assert status_of(scan, engine, "SECRET-002") is Status.PRESENT

    def test_secret_read_from_environment(self, make_repo, engine):
        scan = make_repo({"config.py":
                          'import os\nSECRET_KEY = os.environ["SECRET_KEY"]\n'})
        assert status_of(scan, engine, "SECRET-005") in (Status.PRESENT,
                                                         Status.NOT_APPLICABLE)

    def test_secret_assigned_a_literal(self, make_repo, engine):
        scan = make_repo({"config.py": 'JWT_SECRET = "todoapp-jwt-signing-secret"\n'})
        assert status_of(scan, engine, "SECRET-005") is Status.ABSENT

    def test_dict_style_config_secret(self, make_repo, engine):
        """Regression: Django writes DB config as a dict literal."""
        scan = make_repo({"settings.py":
                          'DATABASES = {"default": {"PASSWORD": "bl0g-db-passw0rd"}}\n'})
        assert status_of(scan, engine, "SECRET-005") is Status.ABSENT

    def test_env_without_gitignore(self, make_repo, engine):
        scan = make_repo({".env": "API_KEY=abc\n", "app.py": FLASK_HEADER})
        finding = finding_for(scan, engine, "SECRET-004")
        assert finding.status is Status.ABSENT
        assert "no .gitignore" in finding.evidence[0].note

    def test_env_covered_by_gitignore(self, make_repo, engine):
        scan = make_repo({".env": "API_KEY=abc\n", ".gitignore": ".env\n",
                          "app.py": FLASK_HEADER})
        assert status_of(scan, engine, "SECRET-004") is Status.PRESENT

    def test_env_example_is_not_a_secret_file(self, make_repo, engine):
        scan = make_repo({".env.example": "API_KEY=\n", "app.py": FLASK_HEADER})
        assert status_of(scan, engine, "SECRET-004") is Status.NOT_APPLICABLE

    def test_env_glob_rule_covers(self, make_repo, engine):
        scan = make_repo({".env.production": "K=v\n", ".gitignore": ".env*\n",
                          "app.py": FLASK_HEADER})
        assert status_of(scan, engine, "SECRET-004") is Status.PRESENT


class TestEntropy:
    def test_entropy_of_uniform_string_is_zero(self):
        assert shannon_entropy("aaaaaaaa") == 0.0

    def test_entropy_of_empty_string(self):
        assert shannon_entropy("") == 0.0

    def test_random_base64_scores_high(self):
        assert shannon_entropy("k3Jd9vQx7WpLmZ2rT8yB4nH6sC1aE5uG") > 4.0

    def test_lowercase_hex_stays_under_the_threshold(self):
        """Deliberate: hex tops out at exactly 4.0, so hashes do not fire."""
        assert shannon_entropy("d41d8cd98f00b204e9800998ecf8427e") <= 4.0

    def test_high_entropy_literal_with_context_is_flagged(self):
        line = 'api_key = "k3Jd9vQx7WpLmZ2rT8yB4nH6sC1aE5uG"'
        flagged, _ = is_interesting("config.py", "k3Jd9vQx7WpLmZ2rT8yB4nH6sC1aE5uG", line)
        assert flagged

    def test_test_paths_are_allowlisted(self):
        line = 'api_key = "k3Jd9vQx7WpLmZ2rT8yB4nH6sC1aE5uG"'
        flagged, _ = is_interesting("tests/conftest.py",
                                    "k3Jd9vQx7WpLmZ2rT8yB4nH6sC1aE5uG", line)
        assert not flagged

    def test_fstring_template_is_not_a_secret(self):
        """Regression: f"{user}{datetime.now()}" scores over 4 bits/char."""
        line = 'token = hashlib.sha256(f"{form.username}{datetime.now()}".encode())'
        flagged, _ = is_interesting("main.py", "{form.username}{datetime.now()}", line)
        assert not flagged

    def test_urls_are_not_secrets(self):
        literal = "https://api.example.com/v1/things"
        flagged, _ = is_interesting("app.py", literal, f'url = "{literal}"')
        assert not flagged

    def test_uuid_is_not_a_secret(self):
        literal = "3f2504e0-4f89-11d3-9a0c-0305e82c3301"
        flagged, _ = is_interesting("app.py", literal, f'key = "{literal}"')
        assert not flagged

    def test_placeholders_are_not_secrets(self):
        literal = "your-api-key-goes-right-here"
        flagged, _ = is_interesting("app.py", literal, f'api_key = "{literal}"')
        assert not flagged

    @pytest.mark.parametrize("literal,expected", [
        ("short", "sh***"),
        ("k3Jd9vQx7WpLmZ2rT8yB4nH6sC1aE5uG", "k3Jd...E5uG (32 chars)"),
    ])
    def test_redaction(self, literal, expected):
        assert redact(literal) == expected

    def test_findings_never_carry_the_whole_secret(self, make_repo, engine):
        secret = "k3Jd9vQx7WpLmZ2rT8yB4nH6sC1aE5uG"
        scan = make_repo({"config.py": f'api_key = "{secret}"\n'})
        finding = finding_for(scan, engine, "SECRET-003")
        assert finding.status is Status.ABSENT
        assert all(secret not in (e.snippet or "") for e in finding.evidence)


class TestAccessControl:
    def test_wildcard_cors(self, make_repo, engine):
        scan = make_repo({"app.py": FLASK_HEADER +
                          'CORS(app, origins="*")\n'})
        assert status_of(scan, engine, "AC-001") is Status.ABSENT

    def test_bare_flask_cors_defaults_to_wildcard(self, make_repo, engine):
        scan = make_repo({"app.py": FLASK_HEADER + "CORS(app)\n"})
        assert status_of(scan, engine, "AC-001") is Status.ABSENT

    def test_named_origins_are_fine(self, make_repo, engine):
        scan = make_repo({"app.py": FLASK_HEADER +
                          'CORS(app, origins=["https://app.example.com"])\n'})
        assert status_of(scan, engine, "AC-001") is Status.PRESENT

    def test_debug_true(self, make_repo, engine):
        scan = make_repo({"app.py": FLASK_HEADER + "app.run(debug=True)\n"})
        assert status_of(scan, engine, "AC-002") is Status.ABSENT

    def test_debug_true_alongside_environment_lookup(self, make_repo, engine):
        """Regression: an allowlist on os.environ suppressed real findings."""
        scan = make_repo({"app.py": FLASK_HEADER +
                          'app.run(port=int(os.environ["PORT"]), debug=True)\n'})
        assert status_of(scan, engine, "AC-002") is Status.ABSENT

    def test_security_headers_present(self, make_repo, engine):
        scan = make_repo({"app.py": FLASK_HEADER + textwrap.dedent("""
            @app.after_request
            def headers(response):
                response.headers["Content-Security-Policy"] = "default-src 'self'"
                return response
        """)})
        assert status_of(scan, engine, "AC-003") is Status.PRESENT

    def test_security_headers_absent(self, make_repo, engine):
        scan = make_repo({"app.py": FLASK_HEADER})
        assert status_of(scan, engine, "AC-003") is Status.ABSENT

    def test_admin_route_without_a_role_check(self, make_repo, engine):
        scan = make_repo({"app.py": FLASK_HEADER + textwrap.dedent("""
            @login_required
            @app.route("/admin/users")
            def admin_users():
                return "x"
        """)})
        assert status_of(scan, engine, "AC-004") is Status.ABSENT

    def test_admin_route_with_a_role_check(self, make_repo, engine):
        scan = make_repo({"app.py": FLASK_HEADER + textwrap.dedent("""
            @admin_required
            @app.route("/admin/users")
            def admin_users():
                return "x"
        """)})
        assert status_of(scan, engine, "AC-004") is Status.PRESENT

    def test_wildcard_allowed_hosts(self, make_repo, engine):
        scan = make_repo({
            "requirements.txt": "Django==5.0.1\n",
            "settings.py": 'ALLOWED_HOSTS = ["*"]\n',
        })
        assert status_of(scan, engine, "AC-005") is Status.ABSENT


class TestCategoryFiltering:
    def test_only_the_requested_category_runs(self, make_repo, engine):
        scan = make_repo({"app.py": FLASK_HEADER})
        findings, _ = run_all(scan, engine, categories=["rate_limiting"])
        assert {f.category for f in findings} == {"rate_limiting"}

    def test_unknown_category_yields_nothing(self, make_repo, engine):
        scan = make_repo({"app.py": FLASK_HEADER})
        findings, _ = run_all(scan, engine, categories=["nope"])
        assert findings == []
