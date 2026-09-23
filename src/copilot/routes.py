"""``copilot routes`` -- the attack surface as a table.

A posture report answers "is authentication present?". The question a
reviewer actually asks next is "on which routes?", and that answer already
exists inside the scan: the route-shaped controls find route handlers as
their subjects and record whether each one was guarded. This presents those
subjects directly instead of summarising them.

Nothing is detected twice. Each column is one control's subject pass:

===========  =========================================
Column       Control(s)
===========  =========================================
auth         AUTH-001 (Flask/FastAPI), AUTH-002
             (Express/Next.js), AUTH-007 (Django views)
rate limit   RATE-002, on credential endpoints only
validation   INPUT-001, where a raw body is read
role check   AC-004, on administrative routes
===========  =========================================

A dash means that control did not consider the line a subject at all -- a
listing endpoint has no credential rate limit to miss, and saying "no" there
would be a finding the tool does not believe.
"""

from __future__ import annotations

from dataclasses import dataclass, field

#: Columns whose subject *is* a route handler. These define the rows.
ROUTE_COLUMNS: dict[str, tuple[str, ...]] = {
    "auth": ("AUTH-001", "AUTH-002", "AUTH-007"),
    "rate limit": ("RATE-002",),
    "role check": ("AC-004",),
}

#: Columns whose subject sits *inside* a handler -- a raw body read is not a
#: route -- and is attributed to the nearest route above it in the same file.
#: That is a heuristic, not dataflow: a read in a helper function further down
#: the file lands on the last route declared, which is why this is a column in
#: an inventory and not a finding.
ATTRIBUTED_COLUMNS: dict[str, tuple[str, ...]] = {
    "validation": ("INPUT-001",),
}

COLUMNS: dict[str, tuple[str, ...]] = {**ROUTE_COLUMNS, **ATTRIBUTED_COLUMNS}

YES, NO, NOT_A_SUBJECT = "yes", "no", "-"


@dataclass
class RouteRow:
    file_path: str
    line: int
    snippet: str
    columns: dict[str, str] = field(default_factory=dict)

    @property
    def unprotected(self) -> bool:
        """True when some control that applies here is not satisfied."""
        return NO in self.columns.values()

    def to_dict(self) -> dict:
        return {
            "file_path": self.file_path,
            "line": self.line,
            "snippet": self.snippet,
            "columns": dict(self.columns),
            "unprotected": self.unprotected,
        }


def inventory(scan, engine) -> list[RouteRow]:
    """Every route handler in the scan, with what protects it."""
    rows: dict[tuple[str, int], RouteRow] = {}

    for column, control_ids in ROUTE_COLUMNS.items():
        for control_id in control_ids:
            control = engine.get(control_id)
            if control is None:
                continue
            for hit in engine.subject_hits(control, scan):
                key = (hit.file_path, hit.line_number)
                row = rows.get(key)
                if row is None:
                    row = RouteRow(hit.file_path, hit.line_number, hit.snippet,
                                   {name: NOT_A_SUBJECT for name in COLUMNS})
                    rows[key] = row
                # A line already claimed by one control in this column keeps
                # its verdict; two dialects matching the same line would be a
                # rule overlap, not a second route.
                if row.columns[column] == NOT_A_SUBJECT:
                    row.columns[column] = YES if hit.satisfied else NO

    ordered = [rows[key] for key in sorted(rows)]
    for column, control_ids in ATTRIBUTED_COLUMNS.items():
        for control_id in control_ids:
            control = engine.get(control_id)
            if control is None:
                continue
            for hit in engine.subject_hits(control, scan):
                row = _nearest_route_above(ordered, hit.file_path, hit.line_number)
                if row is None:
                    continue
                # One unsatisfied read is enough to answer the column: the
                # question is whether this handler validates what it reads.
                if row.columns[column] == NOT_A_SUBJECT or not hit.satisfied:
                    row.columns[column] = YES if hit.satisfied else NO
    return ordered


def _nearest_route_above(rows: list[RouteRow], file_path: str,
                         line: int) -> RouteRow | None:
    best: RouteRow | None = None
    for row in rows:
        if row.file_path == file_path and row.line <= line:
            if best is None or row.line > best.line:
                best = row
    return best
