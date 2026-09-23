"""Map files to the control categories they could possibly bear on.

The index is a recall device, not a precision device. It exists so that five
detectors do not each re-walk the tree, and so that a rule about route
handlers is never evaluated against a README. Narrowing beyond that is the
rule file's job, via ``applies_to.file_patterns``.

Two structural buckets are also published because they are genuinely useful
in the JSON output: which files hold routes, and which hold configuration.
"""

from __future__ import annotations

import re

from ..models import ScannedFile

CATEGORIES = [
    "authentication",
    "input_validation",
    "rate_limiting",
    "secret_management",
    "access_control",
]

STRUCTURAL = ["routes", "config", "entrypoint", "source"]

SOURCE_LANGUAGES = {"python", "javascript", "typescript"}

ROUTE_DIR_HINTS = (
    "routes/", "route/", "api/", "views/", "view/", "controllers/", "controller/",
    "endpoints/", "handlers/", "resources/", "pages/", "blueprints/",
)

#: Filenames that hold routes by convention even when the content signal is
#: weak. Django is the reason this exists: a views.py is the route layer, but
#: it contains plain function definitions and no decorator to match on.
ROUTE_FILE_NAMES = {
    "views.py", "urls.py", "routes.py", "api.py", "controllers.py",
    "handlers.py", "endpoints.py", "resources.py", "viewsets.py",
    "routes.js", "routes.ts", "router.js", "router.ts",
    "controller.js", "controller.ts",
}

ENTRYPOINT_NAMES = {
    "app.py", "main.py", "server.py", "wsgi.py", "asgi.py", "manage.py",
    "__init__.py", "index.js", "index.ts", "server.js", "server.ts",
    "app.js", "app.ts", "main.js", "main.ts",
}

CONFIG_NAMES = {
    "settings.py", "config.py", "conf.py", "constants.py",
    "config.js", "config.ts", "next.config.js", "next.config.mjs",
    "vite.config.js", "webpack.config.js",
}

ROUTE_CONTENT = re.compile(
    r"@(?:app|router|bp|blueprint|api|[a-z_]+_bp)\.(?:route|get|post|put|delete|patch)\s*\("
    r"|\b(?:app|router|api)\.(?:get|post|put|delete|patch|use|all)\s*\("
    r"|\burlpatterns\s*="
    r"|\bpath\s*\(\s*[\"']"
    r"|\bAPIRouter\s*\("
    r"|\bBlueprint\s*\(",
    re.IGNORECASE,
)

#: category -> content keywords that make a plain source file relevant.
CONTENT_HINTS: dict[str, re.Pattern[str]] = {
    "authentication": re.compile(
        r"\b(auth|login|logout|signin|sign_in|register|signup|password|passwd|"
        r"session|jwt|token|credential|bcrypt|argon2|scrypt|pbkdf2|hashlib|"
        r"current_user|login_required|permission)\b",
        re.IGNORECASE,
    ),
    "input_validation": re.compile(
        r"\b(request\.|req\.body|req\.query|req\.params|body|payload|schema|"
        r"validate|validator|pydantic|BaseModel|marshmallow|serializer|joi|zod|"
        r"yup|execute|cursor|query|SELECT|INSERT|UPDATE|DELETE|upload|multipart|"
        r"multer|FileField|save_file|"
        # Unsafe-execution sinks. INPUT-004 judges these, and a module that
        # only shells out mentions none of the request or query words above.
        r"subprocess|os\.system|popen|eval|exec|pickle|yaml\.load|child_process)\b",
    ),
    "rate_limiting": re.compile(
        r"\b(limiter|Limiter|rate_?limit|rateLimit|throttle|slowapi|"
        r"flask_limiter|express-rate-limit|login|password_reset|forgot_password)\b",
        re.IGNORECASE,
    ),
    "access_control": re.compile(
        r"\b(cors|CORS|helmet|origin|Access-Control|debug|DEBUG|admin|role|"
        r"is_staff|is_superuser|permission|csp|Content-Security-Policy|hsts|"
        r"Strict-Transport-Security|X-Frame-Options|after_request|middleware)\b",
    ),
}


def _basename(path: str) -> str:
    return path.rsplit("/", 1)[-1]


def is_route_file(f: ScannedFile) -> bool:
    if f.language not in SOURCE_LANGUAGES:
        return False
    if ROUTE_CONTENT.search(f.text):
        return True
    if _basename(f.path) in ROUTE_FILE_NAMES:
        return True
    lowered = f.path.lower()
    return any(hint in lowered for hint in ROUTE_DIR_HINTS)


def is_config_file(f: ScannedFile) -> bool:
    name = _basename(f.path)
    if f.language == "config":
        return True
    if name in CONFIG_NAMES:
        return True
    return name.endswith(".config.js") or name.endswith(".config.ts")


def is_entrypoint(f: ScannedFile) -> bool:
    return _basename(f.path) in ENTRYPOINT_NAMES and f.language in SOURCE_LANGUAGES


def build_index(files: list[ScannedFile], framework: str | None = None) -> dict[str, list[str]]:
    """Return ``{bucket: [repo-relative path, ...]}`` for structural buckets
    and each control category. Paths are sorted so output is deterministic.
    """
    index: dict[str, set[str]] = {k: set() for k in STRUCTURAL + CATEGORIES}

    for f in files:
        routey = is_route_file(f)
        configy = is_config_file(f)
        entry = is_entrypoint(f)

        if routey:
            index["routes"].add(f.path)
        if configy:
            index["config"].add(f.path)
        if entry:
            index["entrypoint"].add(f.path)
        if f.language in SOURCE_LANGUAGES:
            index["source"].add(f.path)

        # Secrets can be anywhere, including a committed .env or a README that
        # pastes a key. This category deliberately takes every file we read.
        index["secret_management"].add(f.path)

        for category in ("authentication", "input_validation",
                         "rate_limiting", "access_control"):
            relevant = routey or entry
            if category in ("rate_limiting", "access_control"):
                relevant = relevant or configy
            if not relevant and f.language in SOURCE_LANGUAGES:
                relevant = bool(CONTENT_HINTS[category].search(f.text))
            if relevant:
                index[category].add(f.path)

    return {key: sorted(paths) for key, paths in index.items()}
