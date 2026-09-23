"""SARIF 2.1.0 output -- the interchange format.

SARIF is what GitHub code scanning, the VS Code SARIF viewer, DefectDojo and
Sonar all read, so emitting it is what turns this tool from something you run
into something a pipeline consumes.

Two details make the mapping fit unusually well:

**``result.kind``** already has the vocabulary this tool needs. The spec
defines ``pass``, ``fail``, ``review`` and ``notApplicable``, which is
exactly PRESENT / ABSENT / PARTIAL / NOT_APPLICABLE. PARTIAL as ``review``
is the honest reading: some subjects are guarded and some are not, and a
person has to look.

**Anchoring.** Every SARIF result needs a location, and an absence often has
no line to point at -- "no rate limiter anywhere" is a fact about the
repository. Those results are anchored to the application's entry point with
no region, which is how OpenSSF Scorecard handles the same problem, and the
places that were searched travel in ``relatedLocations`` so the negative
evidence is not lost.

Suppressed findings are emitted with ``suppressions[]`` rather than dropped,
so a reviewer sees the accepted risk and its reason.
"""

from __future__ import annotations

import json

from ..models import Report, Severity, Status

SARIF_VERSION = "2.1.0"
SCHEMA_URI = ("https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
              "Schemata/sarif-schema-2.1.0.json")
INFORMATION_URI = "https://github.com/ai-cyber-defense-copilot"

#: Status -> SARIF result.kind.
KIND = {
    Status.PRESENT: "pass",
    Status.ABSENT: "fail",
    Status.PARTIAL: "review",
    Status.NOT_APPLICABLE: "notApplicable",
}

#: Severity -> SARIF level, used only for the kinds that carry one.
LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
}

#: Severity -> GitHub's security-severity property, which drives the
#: critical/high/medium/low banding shown on an alert.
SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "2.0",
}

#: Confidence -> SARIF precision, the same three words the spec uses.
PRECISION = {"high": "high", "medium": "medium", "low": "low"}


def _anchor(report: Report, finding) -> tuple[str, int | None]:
    """``(uri, line)`` for a finding: its own evidence, else the entry point."""
    for ev in finding.evidence:
        if ev.file_path:
            return ev.file_path, ev.line_number
    index = report.scan.file_index
    for bucket in ("entrypoint", "config", "source"):
        paths = index.get(bucket) or []
        if paths:
            return paths[0], None
    return ".", None


def _rule(finding) -> dict:
    tags = ["security", finding.category]
    if finding.cwe:
        tags.append(f"external/cwe/{finding.cwe.lower()}")
    if finding.owasp:
        tags.append(f"external/owasp/{finding.owasp.lower()}")
    help_text = finding.remediation_hint or finding.control_name
    return {
        "id": finding.control_id,
        "name": finding.control_name,
        "shortDescription": {"text": finding.control_name},
        "fullDescription": {"text": finding.remediation_hint or finding.control_name},
        "help": {"text": help_text, "markdown": f"**Remediation.** {help_text}"},
        "defaultConfiguration": {"level": LEVEL[finding.severity]},
        "properties": {
            "security-severity": SECURITY_SEVERITY[finding.severity],
            "precision": PRECISION.get(finding.confidence.value, "medium"),
            "problem.severity": LEVEL[finding.severity],
            "tags": tags,
        },
    }


def _result(report: Report, finding, rule_index: int) -> dict:
    uri, line = _anchor(report, finding)
    location: dict = {"physicalLocation": {"artifactLocation": {
        "uri": uri, "uriBaseId": "%SRCROOT%"}}}
    if line:
        location["physicalLocation"]["region"] = {"startLine": line}

    related = []
    for ev in finding.evidence[1:]:
        entry: dict = {"physicalLocation": {"artifactLocation": {
            "uri": ev.file_path or uri, "uriBaseId": "%SRCROOT%"}}}
        if ev.line_number:
            entry["physicalLocation"]["region"] = {"startLine": ev.line_number}
        if ev.note:
            entry["message"] = {"text": ev.note}
        related.append(entry)

    result: dict = {
        "ruleId": finding.control_id,
        "ruleIndex": rule_index,
        "kind": KIND[finding.status],
        "message": {"text": finding.message},
        "locations": [location],
        "partialFingerprints": {"copilotFingerprint/v1": finding.fingerprint},
        "properties": {"confidence": finding.confidence.value,
                       "status": finding.status.value},
    }
    # The spec only allows level on a failing result.
    if finding.status is Status.ABSENT or finding.status is Status.PARTIAL:
        result["level"] = LEVEL[finding.severity]
    if related:
        result["relatedLocations"] = related
    if finding.suppressed:
        result["suppressions"] = [{
            "kind": "external",
            "status": "accepted",
            "justification": finding.suppression_reason,
        }]
    return result


def render_sarif(report: Report, show_satisfied: bool = False,
                 indent: int = 2) -> str:
    """Serialise a report as SARIF 2.1.0.

    By default only the results a reviewer has to act on are emitted -- gaps
    and accepted gaps. ``show_satisfied`` adds the passing and not-applicable
    ones, which is useful as an evidence pack and noisy in a pull request.
    """
    findings = [f for f in report.findings
                if show_satisfied or f.status in (Status.ABSENT, Status.PARTIAL)]
    rules: list[dict] = []
    rule_index: dict[str, int] = {}
    results = []
    for finding in findings:
        if finding.control_id not in rule_index:
            rule_index[finding.control_id] = len(rules)
            rules.append(_rule(finding))
        results.append(_result(report, finding, rule_index[finding.control_id]))

    document = {
        "$schema": SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {"driver": {
                "name": "ai-cyber-defense-copilot",
                "semanticVersion": report.schema_version,
                "informationUri": INFORMATION_URI,
                "rules": rules,
            }},
            "automationDetails": {"id": "copilot/scan"},
            "invocations": [{
                "executionSuccessful": True,
                "endTimeUtc": report.generated_at.isoformat(),
            }],
            "originalUriBaseIds": {"%SRCROOT%": {"uri": "file:///"}},
            "properties": {
                "postureScore": report.posture_score,
                "grade": report.grade,
                "controlsScored": len(report.scored_findings),
                "scope": "partial" if report.partial_scope else "full",
            },
            "results": results,
        }],
    }
    return json.dumps(document, indent=indent, ensure_ascii=False)
