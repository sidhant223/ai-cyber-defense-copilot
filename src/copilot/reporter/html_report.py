"""HTML output -- the artefact.

One self-contained file: no external CSS, no fonts, no scripts beyond the
``<details>`` element the browser already implements. It ends up as a report
appendix, so it has to print.
"""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..models import Report, Severity, Status

TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"

CATEGORY_TITLES = {
    "authentication": "Authentication",
    "input_validation": "Input validation",
    "rate_limiting": "Rate limiting",
    "secret_management": "Secret management",
    "access_control": "Access control configuration",
}


def _environment() -> Environment:
    return Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=select_autoescape(["html", "xml", "j2"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )


def _grouped(findings: list) -> list[dict]:
    """Findings by category, each sorted gaps-first then by severity."""
    groups: dict[str, list] = {}
    for finding in findings:
        groups.setdefault(finding.category, []).append(finding)

    order = {Status.ABSENT: 0, Status.PARTIAL: 1, Status.PRESENT: 2,
             Status.NOT_APPLICABLE: 3}
    out = []
    for category in sorted(groups, key=lambda c: (
        # categories with the worst gaps first
        min((order[f.status], f.severity.rank) for f in groups[c]), c
    )):
        findings = sorted(groups[category],
                          key=lambda f: (order[f.status], f.severity.rank, f.control_id))
        out.append({
            "id": category,
            "title": CATEGORY_TITLES.get(category, category.replace("_", " ").title()),
            "findings": findings,
            "gaps": sum(1 for f in findings if f.is_gap),
        })
    return out


def render_html(report: Report, min_severity: str | None = None,
                show_satisfied: bool = True, min_confidence: str | None = None) -> str:
    """Render the whole report. Satisfied controls are included by default:
    an appendix that only lists failures cannot show that the scanner
    distinguishes between them."""
    template = _environment().get_template("report.html.j2")
    return template.render(
        report=report,
        scan=report.scan,
        groups=_grouped(report.display_findings(min_severity, show_satisfied,
                                                min_confidence)),
        counts=report.counts_by_status(),
        severity_counts=report.counts_by_severity(),
        generated=report.generated_at.strftime("%Y-%m-%d %H:%M UTC"),
        severities=[s.value for s in Severity],
    )
