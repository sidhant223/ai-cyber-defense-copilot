"""Reporter: how the posture report reads.

Five formats, one report object. JSON is the contract, HTML is the artefact,
the terminal is the feedback loop, SARIF is what other tools consume, and
Markdown is what a pull request shows.
"""

from __future__ import annotations

from .html_report import render_html
from .json_report import render_json
from .markdown_report import render_markdown
from .sarif_report import render_sarif
from .terminal_report import render_terminal

__all__ = ["render_json", "render_html", "render_terminal", "render_sarif",
           "render_markdown"]
