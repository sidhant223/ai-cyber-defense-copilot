"""JSON output -- the machine format.

This is the stable contract. The evaluation harness that measures detection
accuracy against corpus/manifest.yaml consumes exactly this, so the shape is
versioned by ``schema_version`` and changes to it are breaking changes.

Schema history
--------------
* **1.1** added ``confidence`` (high | medium | low) to each finding. It is
  display-only and never changes ``posture_score``.
* **1.2** added ``cwe`` and ``owasp`` per finding, copied from the control.
* **1.3** added ``suppressed`` and ``suppression_reason`` per finding, plus
  ``summary.controls_suppressed``. A suppressed finding is an accepted risk:
  it stays in ``findings`` and is excluded from ``controls_scored``, the
  posture score and the exit code.
* **1.4** added ``fingerprint`` per finding -- a stable id built from the
  control, file and subject text rather than the line number, so it survives
  edits above it -- and ``summary.grade``, ``grade_capped_by``, ``scope`` and
  ``categories_scanned``. ``grade`` is null when ``scope`` is ``partial``.

::

    {
      "schema_version": "1.4",
      "generated_at": "<ISO 8601, UTC>",
      "tool": {"name": ..., "version": ...},
      "scan": {
        "root_path", "framework", "language", "files_scanned",
        "skipped_files", "scan_duration_ms", "file_index", "framework_evidence"
      },
      "summary": {
        "posture_score", "grade", "grade_capped_by", "scope",
        "categories_scanned", "controls_evaluated", "controls_scored",
        "controls_suppressed",
        "by_status": {present, absent, partial, not_applicable},
        "gaps_by_severity": {critical, high, medium, low}
      },
      "findings": [
        {"control_id", "control_name", "category", "status", "severity",
         "message", "remediation_hint", "confidence", "cwe", "owasp",
         "suppressed", "suppression_reason", "fingerprint",
         "evidence": [{"file_path", "line_number", "snippet", "note"}]}
      ],
      "skipped_controls": [{"control_id", "category", "reason"}]
    }
"""

from __future__ import annotations

import json

from ..models import Report


def render_json(report: Report, indent: int = 2) -> str:
    """Serialise a report. Keys are ordered by the model, not sorted, so a
    human reading a diff sees the summary before three hundred findings."""
    return json.dumps(report.to_dict(), indent=indent, ensure_ascii=False)
