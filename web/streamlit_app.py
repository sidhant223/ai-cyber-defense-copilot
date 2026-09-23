"""Web UI for the AI Cyber Defense Copilot.

A thin presentation layer over the same three calls the CLI makes:

    scan(path) -> run_all(scan, engine) -> Report

Nothing about detection lives here. If this file and cli.py ever disagree
about a finding, one of them is calling the pipeline wrong, because there is
only one pipeline.

Run with:  streamlit run web/streamlit_app.py
"""

from __future__ import annotations

import sys
import tempfile
import zipfile
from html import escape
from pathlib import Path

import streamlit as st

# Make `copilot` importable when run straight from a checkout, without
# requiring `pip install -e .` first.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from copilot import __version__                                    # noqa: E402
from copilot.detectors import RuleEngine, RuleError, run_all       # noqa: E402
from copilot.models import Report, Severity, Status                # noqa: E402
from copilot.reporter import (render_html, render_json,            # noqa: E402
                              render_markdown, render_sarif)
from copilot.scanner import scan as run_scan                       # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
CORPUS = REPO_ROOT / "corpus" / "samples"

CATEGORY_TITLES = {
    "authentication": "Authentication",
    "input_validation": "Input validation",
    "rate_limiting": "Rate limiting",
    "secret_management": "Secret management",
    "access_control": "Access control",
}

STATUS_META = {
    Status.ABSENT: ("ABSENT", "#b3261e"),
    Status.PARTIAL: ("PARTIAL", "#a86400"),
    Status.PRESENT: ("PRESENT", "#1b6e3c"),
    Status.NOT_APPLICABLE: ("N/A", "#6b7280"),
}

SEVERITY_ORDER = ["critical", "high", "medium", "low"]

STATUS_ORDER = {Status.ABSENT: 0, Status.PARTIAL: 1,
                Status.PRESENT: 2, Status.NOT_APPLICABLE: 3}


# --------------------------------------------------------------------------
# styling
# --------------------------------------------------------------------------

CSS = """
<style>
  .block-container { padding-top: 2.2rem; max-width: 1150px; }
  #MainMenu, footer { visibility: hidden; }

  .hero {
    display: flex; align-items: center; gap: 2rem; flex-wrap: wrap;
    border: 1px solid rgba(128,128,128,.25); border-radius: 12px;
    padding: 1.25rem 1.6rem; margin-bottom: 1rem;
  }
  .hero .score { font-size: 3.4rem; font-weight: 800; line-height: 1; }
  .hero .score small {
    display: block; font-size: .72rem; font-weight: 500; letter-spacing: .08em;
    text-transform: uppercase; opacity: .6; margin-top: .3rem;
  }
  .hero .facts {
    display: grid; grid-template-columns: repeat(auto-fit, minmax(7.5rem, 1fr));
    gap: .6rem 1.6rem; flex: 1; font-size: .9rem;
  }
  .hero .facts b { display: block; font-weight: 600; }
  .hero .facts span {
    font-size: .68rem; letter-spacing: .07em; text-transform: uppercase; opacity: .55;
  }

  .chips { display: flex; gap: .45rem; flex-wrap: wrap; margin: .2rem 0 1.4rem; }
  .chip {
    border: 1px solid currentColor; border-radius: 999px;
    padding: .12rem .7rem; font-size: .78rem; font-weight: 600;
  }
  .chip.muted { color: #6b7280; }

  .badge {
    border: 1px solid currentColor; border-radius: 4px; padding: .02rem .4rem;
    font-size: .66rem; font-weight: 800; letter-spacing: .05em;
  }
  .sev {
    font-size: .68rem; letter-spacing: .06em; text-transform: uppercase; opacity: .6;
  }

  .ev {
    border-left: 3px solid rgba(128,128,128,.35); padding: .1rem 0 .1rem .8rem;
    margin: .5rem 0; font-size: .86rem;
  }
  .ev .loc { font-family: ui-monospace, Menlo, Consolas, monospace; font-size: .8rem; }
  .ev .note { opacity: .72; }

  .hint {
    border-radius: 8px; padding: .7rem .9rem; margin-top: .6rem;
    background: rgba(128,128,128,.09); font-size: .88rem;
  }
  .hint b {
    display: block; font-size: .66rem; letter-spacing: .07em;
    text-transform: uppercase; opacity: .6; margin-bottom: .25rem;
  }
  .catline {
    font-size: 1.05rem; font-weight: 700; margin: 1.4rem 0 .3rem;
    padding-bottom: .3rem; border-bottom: 2px solid rgba(128,128,128,.25);
  }
  .catline small { font-weight: 400; opacity: .55; font-size: .8rem; }
</style>
"""


def score_colour(score: int) -> str:
    if score >= 80:
        return "#1b6e3c"
    if score >= 50:
        return "#a86400"
    return "#b3261e"


# --------------------------------------------------------------------------
# pipeline
# --------------------------------------------------------------------------

@st.cache_resource(show_spinner=False)
def get_engine(rules_dir: str | None = None) -> RuleEngine:
    """Rule files are parsed once per session, not once per scan."""
    return RuleEngine(rules_dir) if rules_dir else RuleEngine()


def build_report(path: str, engine: RuleEngine,
                 categories: list[str] | None) -> Report:
    scan_result = run_scan(path)
    findings, skipped = run_all(scan_result, engine, categories)
    return Report(
        scan=scan_result,
        findings=findings,
        skipped_controls=[s.to_dict() for s in skipped],
    )


def extract_upload(uploaded) -> str:
    """Unpack an uploaded zip into a temp dir and return the folder to scan."""
    target = Path(tempfile.mkdtemp(prefix="copilot-upload-"))
    with zipfile.ZipFile(uploaded) as archive:
        archive.extractall(target)
    # A zip made from a folder usually has one top-level directory; scanning
    # the wrapper rather than the project makes every relative path wrong.
    entries = [p for p in target.iterdir() if not p.name.startswith("__MACOSX")]
    if len(entries) == 1 and entries[0].is_dir():
        return str(entries[0])
    return str(target)


# --------------------------------------------------------------------------
# rendering
# --------------------------------------------------------------------------

def render_hero(report: Report) -> None:
    scan = report.scan
    colour = score_colour(report.posture_score)
    st.markdown(
        f"""
        <div class="hero">
          <div class="score" style="color:{colour}">
            {report.posture_score}<small>posture score{
                f" &middot; grade {report.grade}" if report.grade else ""}</small>
          </div>
          <div class="facts">
            <div><span>Framework</span><b>{scan.framework or "unknown"}</b></div>
            <div><span>Language</span><b>{scan.language}</b></div>
            <div><span>Files scanned</span><b>{scan.files_scanned}</b></div>
            <div><span>Files skipped</span><b>{scan.skipped_files}</b></div>
            <div><span>Controls scored</span>
                 <b>{len(report.scored_findings)} of {len(report.findings)}</b></div>
            <div><span>Scan time</span><b>{scan.scan_duration_ms} ms</b></div>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    counts = report.counts_by_status()
    sev = report.counts_by_severity()
    chips = [
        f'<span class="chip" style="color:#b3261e">{counts["absent"]} absent</span>',
        f'<span class="chip" style="color:#a86400">{counts["partial"]} partial</span>',
        f'<span class="chip" style="color:#1b6e3c">{counts["present"]} present</span>',
        f'<span class="chip muted">{counts["not_applicable"]} n/a</span>',
    ]
    chips += [
        f'<span class="chip muted">{sev[name]} {name} gap'
        f'{"s" if sev[name] != 1 else ""}</span>'
        for name in SEVERITY_ORDER if sev[name]
    ]
    st.markdown(f'<div class="chips">{"".join(chips)}</div>', unsafe_allow_html=True)

    if report.grade_capped:
        st.warning(f"Grade capped at {report.grade}: {report.grade_cap_reason}. "
                   f"A weighted average can sit high while a critical control "
                   f"is missing entirely.")

    if scan.framework is None:
        st.warning(
            "No framework identified with confidence, so framework-specific "
            "controls were not evaluated. They are listed under *Not evaluated* "
            "below. Reporting an honest unknown beats guessing: a wrong "
            "framework would make every downstream control wrong."
        )


def render_finding(finding) -> None:
    label, colour = STATUS_META[finding.status]
    header = (f"{finding.control_id}  ·  {finding.control_name}  "
              f"·  {label}  ·  {finding.severity.value}")

    with st.expander(header, expanded=finding.is_gap):
        standards = " ".join(f'<span class="sev">{escape(x)}</span>'
                             for x in (finding.cwe, finding.owasp) if x)
        st.markdown(
            f'<span class="badge" style="color:{colour}">{label}</span> '
            f'<span class="sev">{escape(finding.severity.value)}</span> {standards}',
            unsafe_allow_html=True,
        )
        st.write(finding.message)
        if finding.suppressed:
            st.info(f"Accepted: {finding.suppression_reason}")

        for ev in finding.evidence:
            loc = ev.file_path or "\u2014"
            if ev.file_path and ev.line_number:
                loc = f"{ev.file_path}:{ev.line_number}"
            # Both of these came out of the scanned repository, and this page
            # renders raw HTML. Escaping is not optional here: an evidence
            # note quotes a matched line, and a scanned file can contain
            # anything at all -- including a <script> tag.
            st.markdown(
                f'<div class="ev"><span class="loc">{escape(loc)}</span> '
                f'<span class="note">{escape(ev.note or "")}</span></div>',
                unsafe_allow_html=True,
            )
            if ev.snippet:
                st.code(ev.snippet, language=None)

        if finding.remediation_hint:
            st.markdown(
                f'<div class="hint"><b>Remediation</b>'
                f'{escape(finding.remediation_hint)}</div>',
                unsafe_allow_html=True,
            )


def render_findings(report: Report, shown: list) -> None:
    if not shown:
        st.success("No gaps found in the controls that applied.")
        return

    groups: dict[str, list] = {}
    for finding in shown:
        groups.setdefault(finding.category, []).append(finding)

    for category in sorted(groups, key=lambda c: (
        min((STATUS_ORDER[f.status], f.severity.rank) for f in groups[c]), c
    )):
        items = sorted(groups[category],
                       key=lambda f: (STATUS_ORDER[f.status], f.severity.rank, f.control_id))
        gaps = sum(1 for f in items if f.is_gap)
        st.markdown(
            f'<div class="catline">{CATEGORY_TITLES.get(category, category)}'
            f'<small> &mdash; {gaps} gap{"s" if gaps != 1 else ""} '
            f'of {len(items)} control{"s" if len(items) != 1 else ""}</small></div>',
            unsafe_allow_html=True,
        )
        for finding in items:
            render_finding(finding)


def render_downloads(report: Report, name: str) -> None:
    formats = [
        ("Download HTML report", render_html(report), f"{name}-posture.html",
         "text/html"),
        ("Download JSON", render_json(report), f"{name}-posture.json",
         "application/json"),
        ("Download SARIF", render_sarif(report), f"{name}-posture.sarif",
         "application/json"),
        ("Download Markdown", render_markdown(report), f"{name}-posture.md",
         "text/markdown"),
    ]
    for column, (label, data, file_name, mime) in zip(st.columns(len(formats)),
                                                      formats):
        with column:
            st.download_button(label, data=data, file_name=file_name, mime=mime,
                               use_container_width=True)


# --------------------------------------------------------------------------
# tabs
# --------------------------------------------------------------------------

def scan_tab(engine: RuleEngine) -> None:
    st.subheader("Choose what to scan")

    samples = sorted(p.name for p in CORPUS.iterdir() if p.is_dir()) \
        if CORPUS.is_dir() else []
    options = ["Corpus sample", "Local folder", "Upload a .zip"]
    source = st.radio("Source", options, horizontal=True, label_visibility="collapsed")

    target: str | None = None
    label = "repo"

    if source == "Corpus sample":
        if not samples:
            st.error(f"No corpus samples found under {CORPUS}")
        else:
            chosen = st.selectbox("Sample", samples, label_visibility="collapsed")
            target, label = str(CORPUS / chosen), chosen
            st.caption(
                "Eight labelled samples with known ground truth. "
                "`fastapi-secure-tasks` and `express-secure-notes` are the "
                "negative controls -- they should come back close to clean."
            )
    elif source == "Local folder":
        raw = st.text_input(
            "Absolute path to a repository",
            placeholder=r"C:\Users\you\projects\my-api",
            label_visibility="collapsed",
        )
        if raw:
            candidate = Path(raw.strip().strip('"'))
            if not candidate.exists():
                st.error(f"No such path: {candidate}")
            elif not candidate.is_dir():
                st.error(f"Not a directory: {candidate}")
            else:
                target, label = str(candidate), candidate.name
    else:
        uploaded = st.file_uploader("Zipped project", type=["zip"],
                                    label_visibility="collapsed")
        if uploaded is not None:
            target = extract_upload(uploaded)
            label = Path(uploaded.name).stem
            st.caption(f"Extracted to a temporary folder: `{target}`")

    with st.expander("Filters", expanded=False):
        col1, col2 = st.columns([3, 2])
        with col1:
            categories = st.multiselect(
                "Categories",
                sorted(engine.categories),
                default=[],
                format_func=lambda c: CATEGORY_TITLES.get(c, c),
                help="Empty means all five.",
            )
        with col2:
            min_sev = st.selectbox(
                "Minimum severity shown", ["(all)"] + SEVERITY_ORDER,
                help="Display only. The posture score always uses every control.",
            )
            show_satisfied = st.checkbox("Show satisfied controls", value=False)

    if not st.button("Scan", type="primary", disabled=target is None,
                     use_container_width=True):
        return

    with st.spinner("Scanning..."):
        try:
            report = build_report(target, engine, categories or None)
        except OSError as exc:
            st.error(f"Scan failed: {exc}")
            return

    st.divider()
    render_hero(report)

    shown = report.display_findings(
        min_severity=None if min_sev == "(all)" else min_sev,
        show_satisfied=show_satisfied,
    )
    if len(shown) != len(report.findings):
        st.caption(
            f"Showing {len(shown)} of {len(report.findings)} controls. "
            f"Filters change the view only -- the score above is computed from all "
            f"{len(report.scored_findings)} scored controls."
        )

    render_findings(report, shown)

    if report.skipped_controls:
        with st.expander(f"{len(report.skipped_controls)} control(s) not evaluated"):
            for entry in report.skipped_controls:
                st.markdown(f"**`{entry['control_id']}`** &mdash; {entry['reason']}")

    st.divider()
    render_downloads(report, label)


def rules_tab(engine: RuleEngine) -> None:
    controls = sorted(engine.controls(), key=lambda c: (c.category, c.id))
    st.subheader(f"{len(controls)} controls in {len(engine.categories)} categories")
    st.caption(
        "Every one of these is defined in a YAML file under `src/copilot/rules/`. "
        "Adding a control means adding YAML, not editing Python."
    )

    st.dataframe(
        [
            {
                "ID": c.id,
                "Category": CATEGORY_TITLES.get(c.category, c.category),
                "Severity": c.severity.value,
                "Mode": c.mode,
                "Name": c.name,
            }
            for c in controls
        ],
        hide_index=True,
        use_container_width=True,
    )

    st.divider()
    st.subheader("Explain a control")
    chosen_id = st.selectbox(
        "Control", [c.id for c in controls],
        format_func=lambda cid: f"{cid} — {engine.get(cid).name}",
        label_visibility="collapsed",
    )
    control = engine.get(chosen_id)

    st.markdown(f"### {control.id} &nbsp; {control.name}")
    st.caption(
        f"category {control.category} · severity {control.severity.value} · "
        f"mode {control.mode} · defined in `{control.source_file}`"
    )

    if control.description:
        st.markdown("**What it checks**")
        st.write(control.description)
    if control.rationale:
        st.markdown("**Why it matters**")
        st.write(control.rationale)

    applies = control.applies_to
    st.markdown("**Applies to**")
    st.markdown(
        f"- frameworks: `{', '.join(applies.frameworks) or 'any'}`\n"
        f"- languages: `{', '.join(applies.languages) or 'any'}`\n"
        f"- index buckets: `{', '.join(applies.index_buckets) or 'category index'}`"
        + (f"\n- excluding: `{', '.join(applies.exclude_patterns)}`"
           if applies.exclude_patterns else "")
    )

    if control.mode == "subject_guard":
        st.markdown(f"**Subject** — what should be protected "
                    f"({control.subject.description})")
        st.code(control.subject.pattern.pattern, language="regex")
        for ex in control.subject.exclude:
            st.caption(f"except: `{ex.pattern}`")

        plural = len(control.guards) > 1
        st.markdown(f"**Guard{'s' if plural else ''}** — a subject is satisfied "
                    f"when {'any one' if plural else 'this guard'} matches")
        for n, guard in enumerate(control.guards, start=1):
            verb = "must be present" if guard.mode == "require" else "must NOT be present"
            st.markdown(f"{n}. {verb}, {scope_text(guard)}"
                        + (f" — *{guard.description}*" if guard.description else ""))
            st.code("\n".join(p.pattern for p in guard.patterns), language="regex")
    elif control.mode == "presence":
        target = "file paths" if control.match_target == "path" else "file contents"
        st.markdown(f"**Patterns** — matched against {target}")
        st.code("\n".join(p.pattern for p in control.patterns), language="regex")
        if control.anti_patterns:
            st.markdown("**Allowlisted** — a line matching any of these never counts")
            st.code("\n".join(p.pattern for p in control.anti_patterns), language="regex")
    else:
        st.markdown("**Implementation**")
        st.info(
            "Implemented in Python by this category's detector, because the check "
            "is a computation rather than a match. The rule file carries the "
            "identifier, severity and remediation text so there is still exactly "
            "one definition of the control."
        )

    if control.verdict:
        st.markdown("**Verdict mapping**")
        st.markdown("\n".join(f"- `{k}` → **{v.value}**"
                              for k, v in control.verdict.items()))

    if control.remediation_hint:
        st.markdown("**Remediation**")
        st.info(control.remediation_hint)


def scope_text(guard) -> str:
    if guard.scope == "same_line":
        return "on the same line as the subject"
    if guard.scope == "file":
        return "anywhere in the same file"
    if guard.scope == "project":
        return "anywhere in the project"
    below = f" or {guard.lines_below} below" if guard.lines_below else ""
    stop = ", not crossing a blank line" if guard.stop_at else ""
    return f"within {guard.lines_above} lines above the subject{below}{stop}"


def about_tab() -> None:
    st.subheader("What this reports")
    st.write(
        "A linter finds bad code that exists. This finds good code that *should* "
        "exist and does not: no auth on a route, no rate limit on a login "
        "endpoint, a secret sitting in plaintext."
    )
    st.markdown(
        """
| Status | Meaning |
|---|---|
| **PRESENT** | Every subject is guarded |
| **PARTIAL** | Some guarded, some not |
| **ABSENT** | Subjects exist, none guarded |
| **N/A** | No subjects — nothing to judge |
"""
    )
    st.caption(
        "PARTIAL is the interesting one. Authentication applied to most routes "
        "and forgotten on two is far more common than authentication missing "
        "entirely, and a binary scanner calls that present."
    )

    st.subheader("Posture score")
    st.latex(r"\text{score} = 100 \times "
             r"\frac{\sum (\text{weight} \times \text{credit})}{\sum \text{weight}}")
    st.caption(
        "Weights 5/3/2/1 for critical/high/medium/low; credit 1.0 present, "
        "0.5 partial, 0.0 absent. Not-applicable controls are excluded from both "
        "sums, so a small codebase is not punished for being small. Display "
        "filters never move the number."
    )

    st.subheader("Same engine as the CLI")
    st.code(
        "copilot scan ./repo\n"
        "copilot scan ./repo --format html -o report.html\n"
        "copilot scan ./repo --format json -o report.json\n"
        "copilot rules explain AUTH-001",
        language="bash",
    )
    st.caption(
        "This page calls scan() and run_all() directly — the same two functions "
        "the CLI calls. There is no second implementation to drift."
    )

    st.subheader("Limits worth knowing")
    st.markdown(
        "- **Static analysis only.** Nothing is executed, no network calls are made.\n"
        "- **Regex, not a parser.** Whole-line comments are stripped, but "
        "multi-line constructs can defeat proximity windows.\n"
        "- **No cross-module dataflow.** Express middleware mounted in another "
        "file cannot be tied to a specific router, so AUTH-002 accepts a "
        "project-wide mount. Documented in `docs/controls.md`.\n"
        "- **Five frameworks.** Flask, FastAPI, Django, Express, Next.js. "
        "Anything else runs only the framework-agnostic controls, and the report "
        "says which were skipped and why."
    )


# --------------------------------------------------------------------------

def main() -> None:
    st.set_page_config(
        page_title="AI Cyber Defense Copilot",
        page_icon="\U0001F6E1",
        layout="wide",
    )
    st.markdown(CSS, unsafe_allow_html=True)

    st.title("AI Cyber Defense Copilot")
    st.caption(
        f"Reports which security controls are **absent** from a codebase "
        f"· v{__version__}"
    )

    try:
        engine = get_engine()
    except RuleError as exc:
        st.error(f"Rule files failed to load: {exc}")
        st.stop()
        return

    scan_view, rules_view, about_view = st.tabs(["Scan", "Rules", "How it works"])
    with scan_view:
        scan_tab(engine)
    with rules_view:
        rules_tab(engine)
    with about_view:
        about_tab()


main()
