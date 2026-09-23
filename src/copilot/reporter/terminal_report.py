"""Terminal output -- the feedback loop.

Deliberately dense: score, then the gaps, then what could not be judged. A
developer running this in a loop wants the delta, not a document.
"""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ..models import Report, Severity, Status

STATUS_STYLE = {
    Status.ABSENT: "bold red",
    Status.PARTIAL: "bold yellow",
    Status.PRESENT: "green",
    Status.NOT_APPLICABLE: "dim",
}

SEVERITY_STYLE = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
}


def _score_style(score: int) -> str:
    if score >= 80:
        return "bold green"
    if score >= 50:
        return "bold yellow"
    return "bold red"


def summary_line(report: Report) -> str:
    """One line for the end of a run. Counts the whole report, so display
    filters never move it. Skipped controls count as checks, not applicable."""
    checks = len(report.findings) + len(report.skipped_controls)
    accepted = len(report.suppressed_findings)
    # Only shown when there are any: a run with nothing suppressed keeps the
    # short line it has always had.
    tail = f" · {accepted} accepted" if accepted else ""
    return (f"{checks} checks · {len(report.scored_findings)} applicable · "
            f"{len(report.gaps)} gaps · score {report.posture_score}{tail}")


def render_terminal(report: Report, console: Console | None = None,
                    show_present: bool = False, show_evidence: bool = True,
                    min_severity: str | None = None,
                    min_confidence: str | None = None,
                    suppressions=None) -> None:
    console = console or Console()
    scan = report.scan

    header = Text()
    header.append(f"{report.posture_score}", style=_score_style(report.posture_score))
    header.append("/100 posture score", style="dim")
    if report.grade:
        header.append(f"   grade {report.grade}", style=_score_style(report.posture_score))
    header.append("\n", style="dim")
    header.append(f"{scan.root_path}\n", style="bold")
    header.append(
        f"framework: {scan.framework or 'unknown'}   "
        f"language: {scan.language}   "
        f"files: {scan.files_scanned}   "
        f"{scan.scan_duration_ms} ms",
        style="dim",
    )
    console.print(Panel(header, title="AI Cyber Defense Copilot", border_style="blue"))

    if scan.framework is None:
        console.print(
            "[yellow]No framework identified.[/yellow] "
            "Framework-specific controls were not evaluated -- see 'skipped' below.\n"
        )

    if report.grade_capped:
        console.print(f"[yellow]Grade capped at {report.grade}:[/yellow] "
                      f"{report.grade_cap_reason}.", highlight=False)
    if report.partial_scope:
        console.print(f"[yellow]Grade withheld:[/yellow] this run covered "
                      f"{len(report.categories_scanned)} of "
                      f"{report.categories_available} categories, so the score "
                      f"describes part of the application.", highlight=False)

    counts = report.counts_by_status()
    console.print(
        f"[red]{counts['absent']} absent[/red]  "
        f"[yellow]{counts['partial']} partial[/yellow]  "
        f"[green]{counts['present']} present[/green]  "
        f"[dim]{counts['not_applicable']} n/a[/dim]  "
        f"[dim]({len(report.scored_findings)} controls scored)[/dim]\n"
    )

    shown = report.display_findings(min_severity, show_satisfied=show_present,
                                    min_confidence=min_confidence)

    if not shown:
        console.print("[green]No gaps found in the controls that applied.[/green]")
    else:
        table = Table(show_lines=show_evidence, expand=True,
                      title="Findings", title_style="bold")
        table.add_column("Control", no_wrap=True, width=12)
        table.add_column("Status", no_wrap=True, width=9)
        table.add_column("Sev", no_wrap=True, width=8)
        table.add_column("Finding", overflow="fold")

        for f in shown:
            body = Text(f.message)
            if show_evidence and f.evidence:
                for ev in f.evidence[:4]:
                    body.append("\n  ")
                    if ev.file_path:
                        loc = ev.file_path + (f":{ev.line_number}" if ev.line_number else "")
                        body.append(loc, style="cyan")
                        body.append(" - ")
                    body.append(ev.note or "", style="dim")
                    if ev.snippet:
                        body.append(f"\n      {ev.snippet}", style="dim italic")
                if len(f.evidence) > 4:
                    body.append(f"\n  ... {len(f.evidence) - 4} more", style="dim")
            table.add_row(
                f.control_id,
                Text(f.status.value, style=STATUS_STYLE[f.status]),
                Text(f.severity.value, style=SEVERITY_STYLE[f.severity]),
                body,
            )
        console.print(table)

    if report.skipped_controls:
        console.print(
            f"\n[dim]{len(report.skipped_controls)} control(s) not evaluated:[/dim]"
        )
        for entry in report.skipped_controls:
            console.print(f"  [dim]{entry['control_id']}: {entry['reason']}[/dim]")

    accepted = report.suppressed_findings
    if accepted:
        console.print(f"\n[dim]{len(accepted)} finding(s) accepted "
                      f"(out of the score and the exit code):[/dim]")
        for finding in accepted:
            console.print(f"  [dim]{finding.control_id} ({finding.status.value}): "
                          f"{finding.suppression_reason}[/dim]", highlight=False)

    # A suppression that did not apply is worth more noise than one that did:
    # someone wrote it expecting it to work.
    problems = getattr(suppressions, "problems", None) or []
    if problems:
        console.print(f"\n[yellow]{len(problems)} suppression(s) not applied:[/yellow]")
        for problem in problems:
            console.print(f"  [yellow]{problem}[/yellow]", highlight=False,
                          markup=False, soft_wrap=True)

    console.print("\n" + summary_line(report), markup=False, highlight=False)
