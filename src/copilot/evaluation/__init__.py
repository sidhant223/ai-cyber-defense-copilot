"""Evaluation: measure the scanner against the labelled corpus.

Only the holdout split yields a reportable number; see harness.py for why.
"""

from __future__ import annotations

from .harness import (
    NOT_REPORTED, SPLIT_CHOICES, SPLITS, ControlErrors, Disagreement,
    EvaluationError, EvaluationResult, Sample, SampleResult, Tally,
    evaluate, load_manifest, outcome, select,
)
from .render import render_eval_json, render_eval_terminal

__all__ = [
    "NOT_REPORTED", "SPLIT_CHOICES", "SPLITS", "ControlErrors", "Disagreement",
    "EvaluationError", "EvaluationResult", "Sample", "SampleResult", "Tally",
    "evaluate", "load_manifest", "outcome", "select",
    "render_eval_json", "render_eval_terminal",
]
