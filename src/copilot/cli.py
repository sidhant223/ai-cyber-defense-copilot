"""Command line entry point.

    copilot scan ./repo
    copilot scan ./repo --format html -o out.html
    copilot scan ./repo --category authentication,secret_management
    copilot scan ./repo --min-severity high
    copilot rules list
    copilot rules explain AUTH-001
    copilot evaluate --split dev
    copilot evaluate --split holdout --format json -o eval.json

Exit codes: 0 clean, 1 findings present, 2 scan error. That makes it usable
as a CI gate without wrapping it in a shell script. ``evaluate`` exits 0
whatever the disagreements, and 2 only when it could not run.
"""

from __future__ import annotations

import argparse
import json
import sys
from contextlib import nullcontext
from pathlib import Path

from rich.console import Console
from rich.markup import escape

from . import __version__
from .config import (CONFIG_FILENAME, Config, ConfigError, load_config,
                     write_default_config)
from .detectors import RuleEngine, RuleError, registry, run_all
from .detectors.rule_engine import DEFAULT_RULES_DIR, glob_to_regex
from .evaluation import (SPLIT_CHOICES, EvaluationError, evaluate,
                         render_eval_json, render_eval_terminal)
from .models import Report
from .reporter import (render_html, render_json, render_markdown, render_sarif,
                       render_terminal)
from .reporter.terminal_report import summary_line
from . import suppress
from .routes import COLUMNS, inventory
from .rules_test import RuleTestError, load_rule_tests, run_rule_test
from .rules_validate import validate_dir
from .scanner import scan as run_scan

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

SEVERITY_ORDER = ["critical", "high", "medium", "low"]


# --------------------------------------------------------------------------
# argument parsing
# --------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="copilot",
        description="Report which security controls are absent from a codebase.",
    )
    parser.add_argument("--version", action="version",
                        version=f"ai-cyber-defense-copilot {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan_cmd = sub.add_parser("scan", help="scan a repository")
    scan_cmd.add_argument("path", help="path to the repository to scan")
    scan_cmd.add_argument("--format",
                          choices=["terminal", "json", "html", "sarif", "markdown"],
                          default="terminal", help="output format (default: terminal)")
    scan_cmd.add_argument("-o", "--output", help="write to this file instead of stdout")
    scan_cmd.add_argument("--category", help="comma-separated categories to run")
    scan_cmd.add_argument("--min-severity", choices=SEVERITY_ORDER,
                          help="hide findings below this severity")
    scan_cmd.add_argument("--min-confidence", choices=["high", "medium", "low"],
                          help="hide findings below this confidence (display only)")
    scan_cmd.add_argument("--show-present", action="store_true",
                          help="include satisfied and not-applicable controls in output")
    scan_cmd.add_argument("--rules", help="load rule files from this directory instead")
    scan_cmd.add_argument("--fail-on", choices=SEVERITY_ORDER, default=None,
                          help="exit 1 only when a gap of at least this severity exists")
    scan_cmd.add_argument("--fail-under", type=int, default=None, metavar="SCORE",
                          help="exit 1 when the posture score is below SCORE (0-100)")
    scan_cmd.add_argument("--exit-zero", action="store_true",
                          help="report findings without failing (exit 0 unless the "
                               "scan itself could not run)")
    scan_cmd.add_argument("--no-evidence", action="store_true",
                          help="terminal output only: omit evidence lines")
    scan_cmd.add_argument("--summary-only", action="store_true",
                          help="print only the one-line summary (terminal format)")
    scan_cmd.add_argument("--config", help="load this config file instead of "
                          f"<path>/{CONFIG_FILENAME}")
    scan_cmd.add_argument("--no-config", action="store_true",
                          help="ignore any .copilot.yaml entirely")

    routes_cmd = sub.add_parser("routes",
                                help="list every route and what protects it")
    routes_cmd.add_argument("path", help="path to the repository to scan")
    routes_cmd.add_argument("--format", choices=["terminal", "json"],
                            default="terminal", help="output format (default: terminal)")
    routes_cmd.add_argument("--rules", help="load rule files from this directory instead")
    routes_cmd.add_argument("--unprotected-only", action="store_true",
                            help="show only routes with an unsatisfied control")

    init_cmd = sub.add_parser("init", help=f"write a default {CONFIG_FILENAME}")
    init_cmd.add_argument("--force", action="store_true",
                          help="overwrite an existing config file")

    rules_cmd = sub.add_parser("rules", help="inspect the loaded rule set")
    rules_sub = rules_cmd.add_subparsers(dest="rules_command", required=True)

    list_cmd = rules_sub.add_parser("list", help="list loaded controls")
    list_cmd.add_argument("--category", help="restrict to one category")
    list_cmd.add_argument("--rules", help="load rule files from this directory instead")

    explain_cmd = rules_sub.add_parser("explain", help="explain one control")
    explain_cmd.add_argument("control_id", help="e.g. AUTH-001")
    explain_cmd.add_argument("--rules", help="load rule files from this directory instead")

    validate_cmd = rules_sub.add_parser("validate",
                                        help="check rule YAML files without scanning")
    validate_cmd.add_argument("dir", nargs="?",
                              help="directory of rule YAML files (default: bundled rules)")

    test_cmd = rules_sub.add_parser("test",
                                    help="run each control's examples through the pipeline")
    test_cmd.add_argument("dir", nargs="?",
                          help="directory of rule YAML files (default: bundled rules); "
                               "examples are read from its tests/ subdirectory")
    test_cmd.add_argument("--control", help="run only this control's examples")

    eval_cmd = sub.add_parser("evaluate",
                              help="measure detection against the labelled corpus")
    eval_cmd.add_argument("--split", choices=SPLIT_CHOICES, required=True,
                          help="dev (tuned on, regression only), holdout (reportable), or all")
    eval_cmd.add_argument("--manifest", default="corpus/manifest.yaml",
                          help="manifest path (default: corpus/manifest.yaml)")
    eval_cmd.add_argument("--rules", help="load rule files from this directory instead")
    eval_cmd.add_argument("--format", choices=["terminal", "json"], default="terminal",
                          help="output format (default: terminal)")
    eval_cmd.add_argument("-o", "--output", help="write to this file instead of stdout")

    return parser


# --------------------------------------------------------------------------
# scan
# --------------------------------------------------------------------------

def cmd_scan(args, console: Console) -> int:
    if args.summary_only and args.format != "terminal":
        console.print(f"[red]error:[/red] --summary-only cannot be combined with "
                      f"--format {args.format}", highlight=False)
        return EXIT_ERROR
    if args.config and args.no_config:
        console.print("[red]error:[/red] --config cannot be combined with --no-config",
                      highlight=False)
        return EXIT_ERROR
    root = Path(args.path)
    if not root.exists():
        console.print(f"[red]error:[/red] no such path: {args.path}", highlight=False)
        return EXIT_ERROR
    if not root.is_dir():
        console.print(f"[red]error:[/red] not a directory: {args.path}", highlight=False)
        return EXIT_ERROR

    config: Config | None = None
    if not args.no_config:
        config_path = Path(args.config) if args.config else root / CONFIG_FILENAME
        if config_path.is_file():
            try:
                config = load_config(config_path)
            except ConfigError as exc:
                console.print(f"[red]config error:[/red] {exc}", highlight=False,
                              soft_wrap=True)
                return EXIT_ERROR
        elif args.config:
            console.print(f"[red]error:[/red] no such config file: {args.config}",
                          highlight=False)
            return EXIT_ERROR

    rules_dir = args.rules or (config.rules_dir if config else None)
    try:
        engine = RuleEngine(rules_dir) if rules_dir else RuleEngine()
        for control_id, patterns in (config.guards if config else {}).items():
            engine.add_guard_patterns(control_id, patterns)
    except RuleError as exc:
        console.print(f"[red]rule error:[/red] {exc}", highlight=False)
        return EXIT_ERROR

    if args.category is not None:
        categories = [c.strip() for c in args.category.split(",") if c.strip()]
    elif config and config.categories:
        categories = config.categories
    else:
        categories = None
    if categories:
        unknown = [c for c in categories if c not in engine.categories]
        if unknown:
            console.print(
                f"[red]error:[/red] unknown categor{'y' if len(unknown) == 1 else 'ies'}: "
                f"{', '.join(unknown)}\n"
                f"        known: {', '.join(sorted(engine.categories))}",
                highlight=False,
            )
            return EXIT_ERROR

    min_severity = (args.min_severity if args.min_severity is not None
                    else (config.min_severity if config else None))
    min_confidence = (args.min_confidence if args.min_confidence is not None
                      else (config.min_confidence if config else None))
    fail_on = args.fail_on if args.fail_on is not None else (config.fail_on if config else None)
    fail_under = (args.fail_under if args.fail_under is not None
                  else (config.fail_under if config else None))
    ignore_patterns = ([glob_to_regex(p) for p in config.ignore_paths]
                       if config and config.ignore_paths else None)

    spinner = (Console(stderr=True).status("Scanning ...") if _show_progress(args)
               else nullcontext())
    with spinner:
        try:
            scan_result = run_scan(str(root), ignore_patterns=ignore_patterns)
        except OSError as exc:
            console.print(f"[red]scan error:[/red] {exc}", highlight=False)
            return EXIT_ERROR
        findings, skipped = run_all(scan_result, engine, categories)

    # The report always holds every finding, so the posture score is the same
    # number whatever display filters are in play. --min-severity narrows what
    # is shown, never what is scored.
    report = Report(
        scan=scan_result,
        findings=findings,
        skipped_controls=[s.to_dict() for s in skipped],
        categories_scanned=sorted(categories or engine.categories),
        categories_available=len(engine.categories),
    )

    suppression_report = suppress.apply_config(
        findings, config.suppress if config else [])
    suppression_report.problems.extend(
        suppress.problems(scan_result.inline_suppressions,
                          {c.id.upper() for c in engine.controls()}))

    if args.summary_only:
        text = summary_line(report)
        if args.output:
            Path(args.output).write_text(text + "\n", encoding="utf-8")
        else:
            console.print(text, markup=False, highlight=False, soft_wrap=True)
        return _exit_code(report, fail_on, fail_under, args.exit_zero)

    if args.format == "json":
        text = render_json(report)
    elif args.format == "html":
        text = render_html(report, min_severity=min_severity,
                           show_satisfied=True, min_confidence=min_confidence)
    elif args.format == "sarif":
        text = render_sarif(report, show_satisfied=args.show_present)
    elif args.format == "markdown":
        text = render_markdown(report, show_satisfied=args.show_present)
    else:
        text = None

    if text is not None:
        if args.output:
            Path(args.output).write_text(text, encoding="utf-8")
            console.print(f"wrote {args.output}", highlight=False)
        else:
            sys.stdout.write(text + "\n")
    else:
        out_console = Console(file=open(args.output, "w", encoding="utf-8")) \
            if args.output else console
        render_terminal(report, out_console, show_present=args.show_present,
                        show_evidence=not args.no_evidence,
                        min_severity=min_severity,
                        min_confidence=min_confidence,
                        suppressions=suppression_report)
        if args.output:
            out_console.file.close()
            console.print(f"wrote {args.output}", highlight=False)

    return _exit_code(report, fail_on, fail_under, args.exit_zero)


def _show_progress(args) -> bool:
    """Spinner only for a person at a terminal: never into JSON, HTML, a file or a pipe."""
    return (args.format == "terminal" and not args.output and not args.summary_only
            and sys.stdout.isatty())


def _exit_code(report: Report, fail_on: str | None,
               fail_under: int | None = None, exit_zero: bool = False) -> int:
    """0 clean, 1 policy failure, 2 handled by the caller.

    ``--fail-under`` is a second, independent gate: a repository can be under
    the score threshold without holding a gap of the severity ``--fail-on``
    names, and either one failing should fail the run. ``--exit-zero`` turns
    both off, for the runs that exist to produce a report rather than to
    decide anything.
    """
    if exit_zero:
        return EXIT_CLEAN
    if fail_under is not None and report.posture_score < fail_under:
        return EXIT_FINDINGS
    gaps = report.gaps
    if not gaps:
        return EXIT_CLEAN
    if fail_on is None:
        return EXIT_FINDINGS
    cutoff = SEVERITY_ORDER.index(fail_on)
    triggering = [f for f in gaps if SEVERITY_ORDER.index(f.severity.value) <= cutoff]
    return EXIT_FINDINGS if triggering else EXIT_CLEAN


# --------------------------------------------------------------------------
# routes
# --------------------------------------------------------------------------

def cmd_routes(args, console: Console) -> int:
    """Informational: always exits 0 unless it could not run. Gating on the
    posture of a route is ``scan``'s job, and having two gates would mean two
    answers to the same question."""
    from rich.table import Table

    root = Path(args.path)
    if not root.is_dir():
        console.print(f"[red]error:[/red] not a directory: {args.path}", highlight=False)
        return EXIT_ERROR
    try:
        engine = RuleEngine(args.rules) if args.rules else RuleEngine()
    except RuleError as exc:
        console.print(f"[red]rule error:[/red] {exc}", highlight=False)
        return EXIT_ERROR
    try:
        scan_result = run_scan(str(root))
    except OSError as exc:
        console.print(f"[red]scan error:[/red] {exc}", highlight=False)
        return EXIT_ERROR

    rows = inventory(scan_result, engine)
    if args.unprotected_only:
        rows = [r for r in rows if r.unprotected]

    if args.format == "json":
        sys.stdout.write(json.dumps({
            "root_path": str(root),
            "framework": scan_result.framework,
            "columns": list(COLUMNS),
            "routes": [r.to_dict() for r in rows],
        }, indent=2) + "\n")
        return EXIT_CLEAN

    if not rows:
        console.print(f"No route handlers found in {root}.", highlight=False)
        console.print("[dim]Routes come from the same controls that judge them, so "
                      "a framework this tool does not know has no routes here.[/dim]")
        return EXIT_CLEAN

    table = Table(title=f"{len(rows)} route(s) in {root}", expand=True)
    table.add_column("Route", overflow="fold")
    for column in COLUMNS:
        table.add_column(column, no_wrap=True, justify="center")
    for row in rows:
        cells = []
        for column in COLUMNS:
            value = row.columns[column]
            style = {"yes": "green", "no": "bold red"}.get(value, "dim")
            cells.append(f"[{style}]{value}[/{style}]")
        table.add_row(f"{row.file_path}:{row.line}\n[dim]{escape(row.snippet)}[/dim]",
                      *cells)
    console.print(table)
    unprotected = sum(1 for r in rows if r.unprotected)
    console.print(f"{len(rows)} route(s), {unprotected} with an unsatisfied control. "
                  f"A dash means the control does not apply to that route.",
                  highlight=False)
    return EXIT_CLEAN


# --------------------------------------------------------------------------
# init
# --------------------------------------------------------------------------

def cmd_init(args, console: Console) -> int:
    path = Path.cwd() / CONFIG_FILENAME
    if path.exists() and not args.force:
        console.print(f"[red]error:[/red] {path} already exists; pass --force to overwrite",
                      highlight=False, soft_wrap=True)
        return EXIT_ERROR
    write_default_config(path)
    console.print(f"wrote {path}", highlight=False, soft_wrap=True)
    return EXIT_CLEAN


# --------------------------------------------------------------------------
# rules
# --------------------------------------------------------------------------

def cmd_rules_list(args, console: Console) -> int:
    from rich.table import Table

    try:
        engine = RuleEngine(args.rules) if args.rules else RuleEngine()
    except RuleError as exc:
        console.print(f"[red]rule error:[/red] {exc}", highlight=False)
        return EXIT_ERROR

    detectors = registry()
    controls = engine.controls(args.category) if args.category else engine.controls()
    if args.category and args.category not in engine.categories:
        console.print(f"[red]error:[/red] unknown category: {args.category}",
                      highlight=False)
        return EXIT_ERROR

    table = Table(title=f"{len(controls)} controls in {len(engine.categories)} categories",
                  show_lines=False, expand=True)
    # No fixed widths: a custom rule set may use longer ids and category names
    # than the bundled one, and a truncated id is not an id.
    for column in ("ID", "Category", "Sev", "Mode", "CWE"):
        table.add_column(column, no_wrap=True)
    table.add_column("Name", overflow="fold")

    for control in sorted(controls, key=lambda c: (c.category, c.id)):
        table.add_row(control.id, control.category, control.severity.value,
                      control.mode, control.cwe, control.name)
    console.print(table)

    console.print("\n[bold]Detectors[/bold]")
    for category in sorted(set(detectors) | set(engine.categories)):
        cls = detectors.get(category)
        if cls is None:
            description = engine.categories.get(category) or ""
            marker = "  [cyan](rule file only)[/cyan]"
        else:
            description, marker = cls(engine).description, ""
            if category not in engine.categories:
                marker = "  [yellow](no rule file)[/yellow]"
        console.print(f"  {category:<20} {description}{marker}", highlight=False)
    return EXIT_CLEAN


def cmd_rules_explain(args, console: Console) -> int:
    try:
        engine = RuleEngine(args.rules) if args.rules else RuleEngine()
    except RuleError as exc:
        console.print(f"[red]rule error:[/red] {exc}", highlight=False)
        return EXIT_ERROR

    control = engine.get(args.control_id)
    if control is None:
        known = ", ".join(sorted(c.id for c in engine.controls()))
        console.print(f"[red]error:[/red] no such control: {args.control_id}\n"
                      f"        known: {known}", highlight=False)
        return EXIT_ERROR

    console.print(f"\n[bold]{control.id}[/bold]  {control.name}")
    console.print(f"[dim]category {control.category} | severity {control.severity.value} "
                  f"| mode {control.mode} | defined in {control.source_file}[/dim]")
    if control.cwe or control.owasp:
        console.print(f"[dim]standards: {' | '.join(x for x in (control.cwe, control.owasp) if x)}"
                      f"[/dim]")
    console.print()

    if control.description:
        console.print(f"[bold]What it checks[/bold]\n  {control.description}\n")
    if control.rationale:
        console.print(f"[bold]Why it matters[/bold]\n  {control.rationale}\n")

    applies = control.applies_to
    console.print("[bold]Applies to[/bold]")
    console.print(f"  frameworks:    {', '.join(applies.frameworks) or 'any'}")
    console.print(f"  languages:     {', '.join(applies.languages) or 'any'}")
    console.print(f"  index buckets: {', '.join(applies.index_buckets) or 'category index'}")
    if applies.file_patterns:
        console.print(f"  file patterns: {', '.join(applies.file_patterns)}")
    if applies.exclude_patterns:
        console.print(f"  excluding:     {', '.join(applies.exclude_patterns)}")

    if control.mode == "subject_guard":
        subject = control.subject
        console.print("\n[bold]Subject[/bold] -- what should be protected")
        console.print(f"  {subject.description}")
        console.print(f"  [cyan]{subject.pattern.pattern}[/cyan]", highlight=False)
        for ex in subject.exclude:
            console.print(f"  [dim]except: {ex.pattern}[/dim]", highlight=False)
        plural = "s" if len(control.guards) > 1 else ""
        console.print(f"\n[bold]Guard{plural}[/bold] -- a subject is satisfied when "
                      f"{'any one' if plural else 'this guard'} matches")
        for n, guard in enumerate(control.guards, start=1):
            verb = "must be present" if guard.mode == "require" else "must NOT be present"
            label = f"{n}. " if plural else ""
            console.print(f"  {label}{verb}, {_scope_text(guard)}"
                          + (f" ({guard.description})" if guard.description else ""))
            for pattern in guard.patterns:
                console.print(f"     [cyan]{pattern.pattern}[/cyan]", highlight=False)
            for pattern in guard.anti_patterns:
                console.print(f"     [dim]except on lines matching: {pattern.pattern}[/dim]",
                              highlight=False)
    elif control.mode == "presence":
        target = "file paths" if control.match_target == "path" else "file contents"
        console.print(f"\n[bold]Patterns[/bold] -- matched against {target}")
        for pattern in control.patterns:
            console.print(f"  [cyan]{pattern.pattern}[/cyan]", highlight=False)
        for pattern in control.anti_patterns:
            console.print(f"  [dim]except on lines matching: {pattern.pattern}[/dim]",
                          highlight=False)
    else:
        console.print("\n[bold]Implementation[/bold]")
        console.print("  Implemented in Python by the category's detector; the rule "
                      "file carries the metadata only.")

    if control.verdict:
        console.print("\n[bold]Verdict mapping[/bold]")
        for key, status in control.verdict.items():
            console.print(f"  {key:<24} -> {status.value}")

    if control.remediation_hint:
        console.print(f"\n[bold]Remediation[/bold]\n  {control.remediation_hint}\n")
    return EXIT_CLEAN


def cmd_rules_validate(args, console: Console) -> int:
    directory = Path(args.dir) if args.dir else DEFAULT_RULES_DIR
    if not directory.is_dir():
        console.print(f"[red]error:[/red] no such directory: {directory}", highlight=False)
        return EXIT_ERROR

    errors = validate_dir(directory)
    for err in errors:
        console.print(str(err), highlight=False, markup=False, soft_wrap=True)
    console.print(f"{len(errors)} error(s) in {directory}", highlight=False, markup=False)
    return EXIT_CLEAN if not errors else EXIT_FINDINGS


def cmd_rules_test(args, console: Console) -> int:
    directory = Path(args.dir) if args.dir else DEFAULT_RULES_DIR
    if not directory.is_dir():
        console.print(f"[red]error:[/red] no such directory: {directory}", highlight=False)
        return EXIT_ERROR
    try:
        engine = RuleEngine(directory)
    except RuleError as exc:
        console.print(f"[red]rule error:[/red] {exc}", highlight=False)
        return EXIT_ERROR

    tests_dir = directory / "tests"
    if not tests_dir.is_dir():
        console.print(f"[red]error:[/red] no rule tests: {tests_dir} does not exist",
                      highlight=False, soft_wrap=True)
        return EXIT_ERROR
    try:
        cases = load_rule_tests(tests_dir, engine, args.control)
    except RuleTestError as exc:
        console.print(f"[red]rule test error:[/red] {exc}", highlight=False, soft_wrap=True)
        return EXIT_ERROR
    if not cases:
        console.print(f"[red]error:[/red] no rule tests found in {tests_dir}"
                      + (f" for {args.control}" if args.control else ""),
                      highlight=False, soft_wrap=True)
        return EXIT_ERROR

    failures = []
    for case in cases:
        result = run_rule_test(case, engine)
        if result.passed:
            continue
        failures.append(result)
        console.print(f"[red]FAIL[/red] {case.control_id}  {case.name}\n"
                      f"     [dim]{case.source}: {result.detail}[/dim]",
                      highlight=False, soft_wrap=True)

    console.print(f"{len(cases) - len(failures)} passed, {len(failures)} failed "
                  f"({len(cases)} example(s) in {tests_dir})",
                  highlight=False, markup=False, soft_wrap=True)
    return EXIT_CLEAN if not failures else EXIT_FINDINGS


def _scope_text(guard) -> str:
    if guard.scope == "same_line":
        return "on the same line as the subject"
    if guard.scope == "file":
        return "anywhere in the same file"
    if guard.scope == "project":
        return "anywhere in the project"
    below = f" or {guard.lines_below} below" if guard.lines_below else ""
    stop = f", stopping at /{guard.stop_at.pattern}/" if guard.stop_at else ""
    return f"within {guard.lines_above} lines above the subject{below}{stop}"


# --------------------------------------------------------------------------
# evaluate
# --------------------------------------------------------------------------

def cmd_evaluate(args, console: Console) -> int:
    # Disagreements never change the exit code: this measures the scanner,
    # it is not a gate. Only "could not run" is an error.
    try:
        engine = RuleEngine(args.rules) if args.rules else RuleEngine()
        result = evaluate(args.manifest, args.split, engine)
        if args.format == "json":
            text = render_eval_json(result)
            if args.output:
                Path(args.output).write_text(text, encoding="utf-8")
            else:
                sys.stdout.write(text + "\n")
        elif args.output:
            with open(args.output, "w", encoding="utf-8") as fh:
                render_eval_terminal(result, Console(file=fh, width=120))
        else:
            render_eval_terminal(result, console)
    except RuleError as exc:
        console.print(f"[red]rule error:[/red] {escape(str(exc))}",
                      highlight=False, soft_wrap=True)
        return EXIT_ERROR
    except (EvaluationError, OSError) as exc:
        console.print(f"[red]evaluation error:[/red] {escape(str(exc))}",
                      highlight=False, soft_wrap=True)
        return EXIT_ERROR

    if args.output:
        console.print(f"wrote {args.output}", highlight=False, markup=False, soft_wrap=True)
    return EXIT_CLEAN


# --------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    console = Console()
    try:
        if args.command == "scan":
            return cmd_scan(args, console)
        if args.command == "routes":
            return cmd_routes(args, console)
        if args.command == "init":
            return cmd_init(args, console)
        if args.command == "rules":
            if args.rules_command == "list":
                return cmd_rules_list(args, console)
            if args.rules_command == "validate":
                return cmd_rules_validate(args, console)
            if args.rules_command == "test":
                return cmd_rules_test(args, console)
            return cmd_rules_explain(args, console)
        if args.command == "evaluate":
            return cmd_evaluate(args, console)
    except KeyboardInterrupt:
        console.print("\n[yellow]interrupted[/yellow]")
        return EXIT_ERROR
    return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
