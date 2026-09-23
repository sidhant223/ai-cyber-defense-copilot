"""Secret management detector.

Most of this category is YAML: known key formats have known prefixes, and a
connection string with credentials in it is a regex. Two checks are not
expressible as patterns and live here:

``SECRET-003`` Shannon entropy scoring over string literals.
``SECRET-004`` correlating a committed .env against .gitignore.

Both are declared in ``rules/secret_management.yaml`` with
``detection.mode: custom`` so that identifiers, severities and remediation
text still have exactly one home.

On the entropy threshold
------------------------
The threshold is 4.0 bits per character over literals of at least 20
characters. That number is chosen against the alphabets, not tuned against a
sample:

* lowercase hex (``0-9a-f``) tops out at exactly log2(16) = 4.0, so ordinary
  hashes, git SHAs and UUIDs sit just under the line and do not fire.
* base64 and mixed alphanumerics top out near log2(64) = 6.0, and real random
  keys in those alphabets measure 4.5 to 5.5.

That deliberately trades recall for precision: a bare 32-character hex API
key will not be caught by entropy alone. SECRET-001 catches the branded ones
by prefix, which is the higher-confidence signal anyway. False positives
destroy trust in a scanner faster than false negatives do, and an entropy
check that fires on every checksum in a lockfile gets switched off.

To keep the recall loss bounded, literals sitting on a line whose identifier
looks secret-bearing (``api_key = "..."``) are flagged at 4.0, while literals
with no such context need 4.5. Documented in docs/controls.md.
"""

from __future__ import annotations

import math
import re
from collections import Counter

from ..models import Confidence, Evidence, Finding, ScannedFile, ScanResult, Status
from .base import Detector, register

ENTROPY_THRESHOLD = 4.0
ENTROPY_THRESHOLD_NO_CONTEXT = 4.5
MIN_LITERAL_LENGTH = 20
MAX_LITERAL_LENGTH = 512
MAX_ENTROPY_FINDINGS = 12

#: A quoted literal with no escapes, whitespace or interpolation in it.
STRING_LITERAL = re.compile(
    r"'([^'\\\s]{%d,%d})'"
    r'|"([^"\\\s]{%d,%d})"'
    r"|`([^`\\\s]{%d,%d})`"
    % ((MIN_LITERAL_LENGTH, MAX_LITERAL_LENGTH) * 3)
)

#: An identifier on the same line that suggests the literal is a credential.
SECRET_CONTEXT = re.compile(
    r"(?i)\b\w*(?:secret|token|passwd|password|pwd|api[_-]?key|apikey|"
    r"access[_-]?key|private[_-]?key|credential|auth|salt|signature|"
    r"client[_-]?secret|dsn|connection[_-]?string)\w*\b\s*[:=]"
)

#: Paths where a high-entropy literal is expected and harmless.
ALLOWED_PATHS = re.compile(
    r"(?:^|/)(?:tests?|__tests__|spec|fixtures?|examples?|samples?|docs?|"
    r"migrations|locales?|node_modules|vendor)(?:/|$)"
    r"|(?:^|/)(?:test_[^/]+|[^/]+_test|[^/]+\.test|[^/]+\.spec)\.[a-z]+$"
    r"|(?:^|/)(?:package-lock\.json|yarn\.lock|poetry\.lock|Pipfile\.lock)$"
    r"|\.(?:md|lock|svg|png|jpg|ico|map)$"
)

#: Literals that are obviously not live credentials.
PLACEHOLDER = re.compile(
    r"(?i)(?:your[-_]?|my[-_]?|the[-_]?)?(?:x{6,}|placeholder|changeme|change[-_]me|"
    r"example|sample|dummy|fake|redacted|insert[-_]?here|todo|fixme|"
    r"replace[-_]?(?:me|this)|<[^>]+>|\$\{[^}]+\}|\{\{[^}]+\}\}|%\([^)]+\)s)"
)

#: A literal carrying an interpolation slot is a template, not a credential.
#: This is what an f-string body looks like once the quotes are stripped:
#: f"{user}{datetime.now()}" scores over 4 bits/char and is not a secret.
TEMPLATE = re.compile(r"\{[^}]*\}")

#: Things that are long and dense but structurally not secrets.
NOT_A_SECRET = re.compile(
    r"^(?:https?|ftp|file|data|mailto|urn|git\+https?)://"
    r"|^(?:[A-Za-z]:)?[\\/](?:[\w.-]+[\\/])+[\w.-]+$"          # filesystem path
    r"|^[\w.-]+\.(?:com|org|net|io|dev|local|test|py|js|ts|json|yaml|yml|html)$"
    r"|^(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$"  # uuid
    r"|^(?:sha\d*|md5)[-:]"
    r"|^[0-9.]+$"
)

#: .env variants that are meant to be committed.
ENV_TEMPLATE = re.compile(r"\.env\.(?:example|sample|template|dist)$|\.env\.example$")
ENV_REAL = re.compile(r"(?:^|/)\.env(?:\.(?:local|development|production|prod|staging))?$")


def shannon_entropy(text: str) -> float:
    """Bits per character. 0.0 for an empty string."""
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def iter_literals(f: ScannedFile):
    """Yield (line_number, literal) for every candidate string literal."""
    for i, line in enumerate(f.lines, start=1):
        stripped = line.lstrip()
        if stripped.startswith(("#", "//", "*")):
            continue
        for match in STRING_LITERAL.finditer(line):
            literal = next(g for g in match.groups() if g is not None)
            yield i, literal, line


def is_interesting(path: str, literal: str, line: str) -> tuple[bool, float]:
    """Decide whether a literal looks like a live credential.

    Returns ``(flagged, entropy)`` so the caller can report the score even
    when the literal is not flagged.
    """
    entropy = shannon_entropy(literal)
    if ALLOWED_PATHS.search(path):
        return False, entropy
    if PLACEHOLDER.search(literal) or NOT_A_SECRET.search(literal):
        return False, entropy
    if TEMPLATE.search(literal):
        return False, entropy
    if len(set(literal)) < 8:
        # Long but repetitive: separators, ascii art, padding.
        return False, entropy
    has_context = bool(SECRET_CONTEXT.search(line))
    threshold = ENTROPY_THRESHOLD if has_context else ENTROPY_THRESHOLD_NO_CONTEXT
    return entropy >= threshold, entropy


def redact(literal: str) -> str:
    """Never print a full credential into a report that gets shared."""
    if len(literal) <= 12:
        return literal[:2] + "*" * (len(literal) - 2)
    return f"{literal[:4]}...{literal[-4:]} ({len(literal)} chars)"


@register
class SecretManagementDetector(Detector):
    category = "secret_management"

    @property
    def description(self) -> str:
        return "Hardcoded credentials, known key formats, committed .env files"

    def extra_findings(self, scan: ScanResult) -> list[Finding]:
        out = []
        for builder in (self._entropy_finding, self._env_gitignore_finding):
            finding = builder(scan)
            if finding is not None:
                out.append(finding)
        return out

    # -- SECRET-003 ------------------------------------------------------

    def _entropy_finding(self, scan: ScanResult) -> Finding | None:
        control = self.engine.get("SECRET-003")
        if control is None:
            return None

        files = [f for f in scan.files_for(self.category)
                 if f.language in ("python", "javascript", "typescript", "config")]
        hits: list[Evidence] = []
        literals_examined = 0
        # Entropy is a heuristic (low confidence) unless a flagged literal also
        # carries a SECRET-001 known key prefix.
        known = self.engine.get("SECRET-001")
        prefixes = known.patterns if known is not None else []
        confidence = Confidence.LOW

        for f in files:
            for line_no, literal, line in iter_literals(f):
                literals_examined += 1
                flagged, entropy = is_interesting(f.path, literal, line)
                if not flagged:
                    continue
                if any(p.search(literal) for p in prefixes):
                    confidence = Confidence.HIGH
                hits.append(Evidence(
                    file_path=f.path,
                    line_number=line_no,
                    snippet=redact(literal),
                    note=f"Shannon entropy {entropy:.2f} bits/char over "
                         f"{len(literal)} characters",
                ))

        hits.sort(key=lambda e: e.note, reverse=True)

        if hits:
            status = Status.ABSENT
            message = (f"{len(hits)} high-entropy string literal(s) sit in source "
                       f"where a secret store should be used.")
            evidence = hits[:MAX_ENTROPY_FINDINGS]
        else:
            status = Status.PRESENT
            message = "No high-entropy literals found in source."
            evidence = [Evidence(
                file_path="",
                note=(f"examined {literals_examined} string literal(s) of "
                      f"{MIN_LITERAL_LENGTH}+ characters across {len(files)} file(s); "
                      f"none reached {ENTROPY_THRESHOLD} bits/char with a credential-like "
                      f"identifier, or {ENTROPY_THRESHOLD_NO_CONTEXT} without one"),
            )]

        if literals_examined == 0:
            status = Status.NOT_APPLICABLE
            message = "No string literals long enough to score."

        return Finding(
            control_id=control.id,
            control_name=control.name,
            category=self.category,
            status=status,
            severity=control.severity,
            message=message,
            evidence=evidence,
            remediation_hint=control.remediation_hint,
            confidence=control.confidence or confidence,
        )

    # -- SECRET-004 ------------------------------------------------------

    def _env_gitignore_finding(self, scan: ScanResult) -> Finding | None:
        control = self.engine.get("SECRET-004")
        if control is None:
            return None

        env_files = [f for f in scan.files
                     if ENV_REAL.search(f.path) and not ENV_TEMPLATE.search(f.path)]
        gitignores = [f for f in scan.files if f.path.rsplit("/", 1)[-1] == ".gitignore"]

        if not env_files:
            return Finding(
                control_id=control.id,
                control_name=control.name,
                category=self.category,
                status=Status.NOT_APPLICABLE,
                severity=control.severity,
                message="No .env file present in the tree.",
                evidence=[Evidence(
                    file_path="",
                    note=f"searched {len(scan.files)} file(s) for a .env; found none "
                         f"(.env.example and friends are ignored by design)")],
                remediation_hint=control.remediation_hint,
                confidence=control.confidence or Confidence.HIGH,
            )

        ignored = {rule for f in gitignores for rule in _gitignore_env_rules(f)}
        unprotected = [f for f in env_files if not _covered(f.path, ignored)]

        evidence = []
        for f in env_files:
            covered = _covered(f.path, ignored)
            evidence.append(Evidence(
                file_path=f.path,
                note=("listed in .gitignore" if covered
                      else ("not matched by any .gitignore rule" if gitignores
                            else "no .gitignore found anywhere in the tree")),
            ))

        if not unprotected:
            status = Status.PRESENT
            message = f"{len(env_files)} .env file(s) present, all excluded by .gitignore."
        elif len(unprotected) < len(env_files):
            status = Status.PARTIAL
            message = (f"{len(unprotected)} of {len(env_files)} .env file(s) are not "
                       f"excluded by .gitignore.")
        else:
            status = Status.ABSENT
            message = (f"{len(env_files)} .env file(s) present and none are excluded "
                       f"by .gitignore.")

        return Finding(
            control_id=control.id,
            control_name=control.name,
            category=self.category,
            status=status,
            severity=control.severity,
            message=message,
            evidence=evidence[:MAX_ENTROPY_FINDINGS],
            remediation_hint=control.remediation_hint,
            confidence=control.confidence or Confidence.HIGH,
        )


def _gitignore_env_rules(f: ScannedFile) -> list[str]:
    """The .gitignore lines that could plausibly cover a .env file."""
    rules = []
    for line in f.lines:
        rule = line.strip()
        if not rule or rule.startswith("#"):
            continue
        if ".env" in rule or rule in ("*", "**"):
            rules.append(rule.lstrip("/"))
    return rules


def _covered(env_path: str, rules: set[str]) -> bool:
    name = env_path.rsplit("/", 1)[-1]
    for rule in rules:
        clean = rule.rstrip("/")
        if clean in ("*", "**", ".env", ".env*", "*.env", ".env.*"):
            return True
        if clean == name or clean == env_path:
            return True
        if clean.endswith("*") and name.startswith(clean[:-1]):
            return True
    return False
