"""Evaluation output.

The banner is not decoration. A dev-split number looks exactly like an
accuracy figure and is not one, so every terminal run says which kind of
number it is before it shows any.
"""

from __future__ import annotations

import json

from rich.console import Console
from rich.table import Table

from .harness import EvaluationResult

BANNERS = {
    "holdout": ("bold green",
                "HOLDOUT: reportable accuracy, valid only while no rule has been "
                "changed in response to these samples."),
    "dev": ("bold yellow",
            "DEV SPLIT: the rules were tuned on these samples. Regression signal "
            "only - not reportable as accuracy."),
}


def render_eval_json(result: EvaluationResult) -> str:
    return json.dumps(result.to_dict(), indent=2)


def _num(value: float | None) -> str:
    return "-" if value is None else f"{value:.3f}"


def _plain(console: Console, text: str, style: str | None = None) -> None:
    # Paths and manifest data may contain "[" -- never treat them as markup,
    # and never wrap, so a banner phrase stays greppable.
    console.print(text, style=style, markup=False, highlight=False, soft_wrap=True)


def render_eval_terminal(result: EvaluationResult, console: Console) -> None:
    _plain(console, f"split: {result.split}   samples: {len(result.samples)}   "
                    f"rules: {result.rules_dir}   manifest: {result.manifest_path}",
           style="dim")

    if result.split in BANNERS:
        style, banner = BANNERS[result.split]
    else:
        dev = sum(1 for s in result.samples if s.split == "dev")
        style, banner = ("bold yellow",
                         f"ALL SPLITS: includes {dev} dev sample(s) the rules were "
                         "tuned on - not reportable as accuracy.")
    _plain(console, banner, style=style)
    console.print()

    table = Table(title="Detection by category", title_style="bold", expand=True)
    table.add_column("Category", no_wrap=True)
    for name in ("TP", "FP", "FN", "TN", "Precision", "Recall", "F1"):
        table.add_column(name, justify="right", no_wrap=True)
    rows = list(result.by_category.items())
    for n, (category, tally) in enumerate(rows, start=1):
        table.add_row(category, str(tally.tp), str(tally.fp), str(tally.fn), str(tally.tn),
                      _num(tally.precision), _num(tally.recall), _num(tally.f1),
                      end_section=n == len(rows))
    o = result.overall
    table.add_row("all", str(o.tp), str(o.fp), str(o.fn), str(o.tn),
                  _num(o.precision), _num(o.recall), _num(o.f1), style="bold")
    console.print(table)

    confusion = result.confusion
    if not confusion:
        console.print("\n[green]Every labelled control matches the manifest.[/green]")
    else:
        table = Table(title="Most missed / over-flagged controls", title_style="bold",
                      expand=True, show_lines=True)
        table.add_column("Control", no_wrap=True)
        table.add_column("Category", overflow="fold")
        for name in ("Missed", "Over-flagged", "Wrong status"):
            table.add_column(name, justify="right", overflow="fold")
        table.add_column("Where", overflow="fold", ratio=1)
        for row in confusion:
            table.add_row(row.control_id, row.category, str(row.missed),
                          str(row.over_flagged), str(row.wrong_status), "\n".join(row.where))
        console.print()
        console.print(table)

    warnings = []
    for s in result.samples:
        if s.framework_expected != s.framework_detected:
            warnings.append(f"{s.name}: framework expected {s.framework_expected}, "
                            f"detected {s.framework_detected}")
        if s.unlabelled:
            warnings.append(f"{s.name}: {len(s.unlabelled)} control(s) not labelled in "
                            f"the manifest, excluded: {', '.join(s.unlabelled)}")
    if warnings:
        console.print("\n[bold yellow]Warnings[/bold yellow]")
        for line in warnings:
            _plain(console, f"  {line}", style="yellow")
