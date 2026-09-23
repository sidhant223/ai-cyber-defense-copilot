from __future__ import annotations

from pathlib import Path

import pytest

from copilot.detectors.rule_engine import RuleEngine
from copilot.scanner import scan

REPO_ROOT = Path(__file__).resolve().parent.parent
CORPUS = REPO_ROOT / "corpus"
SAMPLES = CORPUS / "samples"


@pytest.fixture(scope="session")
def engine() -> RuleEngine:
    """The shipped rule set, loaded once."""
    return RuleEngine()


@pytest.fixture
def make_repo(tmp_path):
    """Write a dict of {relative path: contents} into a temp dir and scan it."""
    def _make(files: dict[str, str]):
        for rel, text in files.items():
            path = tmp_path / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        return scan(str(tmp_path))
    return _make
