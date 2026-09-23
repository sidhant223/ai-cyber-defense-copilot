"""Markdown output -- the pull request view.

Written for the two places a person actually reads a scan in CI: a job
summary and a pull request comment. It is deliberately a different shape
from the HTML report, which is an appendix: this one leads with the gaps and
carries a ready-made prompt per finding, because the reader is about to fix
the thing rather than file it.

The prompt is assembled from the control's own remediation text. Nothing is
generated and no model is called -- it is the same sentence `rules explain`
prints, addressed to whoever or whatever is doing the edit.
"""

from __future__ import annotations

from ..models import Report, Status

STATUS_MARK = {
    Status.ABSENT: "absent",
    Status.PARTIAL: "partial",
    Status.PRESENT: "present",
    Status.NOT_APPLICABLE: "n/a",
}


def _where(finding) -> str:
    for ev in finding.evidence:
        if ev.file_path:
            return f"`{ev.file_path}" + (f":{ev.line_number}`" if ev.line_number else "`")
    return "repository-wide"


def fix_prompt(finding) -> str:
    """One paragraph a developer (or a coding agent) can act on directly."""
    location = _where(finding).replace("`", "")
    subject = (f"{finding.control_id} ({finding.control_name}) is "
               f"{finding.status.value} at {location}.")
    return (f"{subject} {finding.message} {finding.remediation_hint} "
            f"Make that change without altering existing behaviour, then re-run "
            f"`copilot scan .` and confirm {finding.control_id} is present.")


def render_markdown(report: Report, show_satisfied: bool = False) -> str:
    scan = report.scan
    counts = report.counts_by_status()
    grade = report.grade or "withheld"
    lines: list[str] = []

    lines.append("## Security posture report")
    lines.append("")
    lines.append(f"**{report.posture_score}/100** (grade {grade}) &middot; "
                 f"`{scan.root_path}` &middot; framework "
                 f"{scan.framework or 'unknown'} &middot; "
                 f"{len(report.scored_findings)} controls scored")
    if report.grade_capped:
        lines.append("")
        lines.append(f"> Grade capped at {report.grade}: {report.grade_cap_reason}.")
    if report.partial_scope:
        lines.append("")
        lines.append(f"> Grade withheld: this run covered "
                     f"{len(report.categories_scanned)} of "
                     f"{report.categories_available} categories, so the score "
                     f"describes part of the application.")
    lines.append("")
    lines.append("| absent | partial | present | n/a | accepted |")
    lines.append("|---|---|---|---|---|")
    lines.append(f"| {counts['absent']} | {counts['partial']} | {counts['present']} "
                 f"| {counts['not_applicable']} | "
                 f"{len(report.suppressed_findings)} |")
    lines.append("")

    gaps = report.gaps
    if not gaps:
        lines.append("No gaps found in the controls that applied.")
    else:
        lines.append(f"### {len(gaps)} gap(s)")
        lines.append("")
        lines.append("| Control | Status | Severity | Where | CWE |")
        lines.append("|---|---|---|---|---|")
        for f in gaps:
            lines.append(f"| `{f.control_id}` {f.control_name} "
                         f"| {STATUS_MARK[f.status]} | {f.severity.value} "
                         f"| {_where(f)} | {f.cwe or '-'} |")
        lines.append("")
        for f in gaps:
            lines.append(f"<details><summary><code>{f.control_id}</code> "
                         f"{f.control_name}</summary>")
            lines.append("")
            lines.append(f"{f.message}")
            lines.append("")
            for ev in f.evidence[:6]:
                location = (f"`{ev.file_path}"
                            + (f":{ev.line_number}`" if ev.line_number else "`")
                            ) if ev.file_path else "_repository-wide_"
                lines.append(f"- {location} &mdash; {ev.note}")
            lines.append("")
            lines.append("**Fix prompt**")
            lines.append("")
            lines.append("```text")
            lines.append(fix_prompt(f))
            lines.append("```")
            lines.append("")
            lines.append("</details>")
            lines.append("")

    if report.suppressed_findings:
        lines.append("### Accepted")
        lines.append("")
        for f in report.suppressed_findings:
            lines.append(f"- `{f.control_id}` ({f.status.value}) &mdash; "
                         f"{f.suppression_reason}")
        lines.append("")

    if show_satisfied:
        satisfied = [f for f in report.findings if not f.is_gap and not f.suppressed]
        lines.append("### Satisfied and not applicable")
        lines.append("")
        for f in satisfied:
            lines.append(f"- `{f.control_id}` {f.control_name} &mdash; "
                         f"{STATUS_MARK[f.status]}")
        lines.append("")

    if report.skipped_controls:
        lines.append(f"### {len(report.skipped_controls)} control(s) not evaluated")
        lines.append("")
        for entry in report.skipped_controls:
            lines.append(f"- `{entry['control_id']}` &mdash; {entry['reason']}")
        lines.append("")

    lines.append("<sub>Static analysis only: no code was executed and no network "
                 "request was made. Score is a severity-weighted percentage of "
                 "applicable controls satisfied.</sub>")
    return "\n".join(lines) + "\n"
