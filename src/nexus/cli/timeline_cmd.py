"""Timeline on Elasticsearch (WO-A10): ``nexus timeline build|query|export``.

The CLI is the same reader the portal uses, so a count from the terminal and a
count from the grid cannot disagree. Two rules it keeps:

* **Never a fake zero.** Elasticsearch unreachable exits non-zero with the
  reason. ``nexus timeline query`` on a down backend must never print "0
  events", because that reads as an absence of activity.
* **Counts say whether they are exact.** A total ES reported as a floor is
  marked, not printed as a fact.
"""

from __future__ import annotations

import contextlib
import csv
import json
import sys

import typer

app = typer.Typer(help="Queryable timeline (events index)")

# one column list, shared by the file and stdout paths
_COLUMNS = [
    "event_id", "ts", "ts_desc", "ts_src", "family", "host", "user",
    "artifact", "source_file", "source_line", "audit_id",
]


def _resolve_case_dir(case_id: str):
    """The named case, or the active one. Refuses an id that would traverse."""
    from nexus.case_manager import CaseManager
    from nexus.config import settings
    from nexus.discipline import validate_case_id

    cid = (case_id or "").strip()
    if not cid:
        try:
            cid = CaseManager().require_active_case().name
        except Exception as exc:  # noqa: BLE001
            typer.echo(f"No active case: {exc}", err=True)
            raise typer.Exit(1) from None
    if validate_case_id(cid):
        typer.echo(f"Invalid case id: {cid}", err=True)
        raise typer.Exit(1)
    case_dir = settings.cases_root / cid
    if not case_dir.is_dir():
        typer.echo(f"Case not found: {case_dir}", err=True)
        raise typer.Exit(1)
    return case_dir


@app.command("build")
def build(
    case: str = typer.Option("", "--case", "-c", help="Case ID (default: active case)"),
    force: bool = typer.Option(False, "--force", help="Rebuild even if the schema is current"),
) -> None:
    """Build the events index from the document index (never re-parses evidence)."""
    from nexus.langgraph.case_index import es_url
    from nexus.langgraph.timeline_events import build_events

    case_dir = _resolve_case_dir(case)
    if not es_url():
        typer.echo("NEXUS_ES_URL is not set — the timeline needs Elasticsearch.", err=True)
        raise typer.Exit(1)

    result = build_events(case_dir, force=force)
    if not result.get("built"):
        typer.echo(f"Not built: {result.get('reason') or 'unknown reason'}", err=True)
        raise typer.Exit(1)
    skipped = result.get("events_skipped") or {}
    typer.echo(
        f"Timeline built: {result.get('events')} event(s) in {result.get('index')} "
        f"errors={result.get('errors', 0)}"
    )
    if skipped:
        # silence would read as "no activity in those families"
        typer.echo(f"Skipped families (not in this slice): {json.dumps(skipped)}")


@app.command("query")
def query(
    case: str = typer.Option("", "--case", "-c", help="Case ID (default: active case)"),
    size: int = typer.Option(50, "--size", help="Rows per page (max 1000)"),
    cursor: str = typer.Option("", "--cursor", help="Continue from a previous page"),
    family: str = typer.Option("", "--family", help="Filter: family"),
    user: str = typer.Option("", "--user", help="Filter: user"),
    host: str = typer.Option("", "--host", help="Filter: host"),
    since: str = typer.Option("", "--since", help="Filter: ts gte (ISO)"),
    until: str = typer.Option("", "--until", help="Filter: ts lte (ISO)"),
    order: str = typer.Option("asc", "--order", help="asc or desc"),
    as_json: bool = typer.Option(False, "--json", help="Emit JSON instead of a table"),
) -> None:
    """Print timeline events in order, one page at a time."""
    from nexus.dashboard.timeline_api import TimelineStore, TimelineUnavailable

    case_dir = _resolve_case_dir(case)
    filters = _filters(family=family, user=user, host=host, since=since, until=until)

    try:
        page = TimelineStore(case_dir.name).paged(
            cursor=cursor or None,
            size=size,
            filters=filters,
            sort_dir="desc" if order == "desc" else "asc",
        )
    except TimelineUnavailable as exc:
        typer.echo(f"Timeline unavailable — {exc}", err=True)
        raise typer.Exit(1) from None
    except ValueError as exc:
        typer.echo(f"Bad cursor: {exc}", err=True)
        raise typer.Exit(1) from None

    if as_json:
        typer.echo(json.dumps(page, indent=2, default=str))
        return

    for row in page["rows"]:
        typer.echo(
            f"{row.get('ts', '?'):32} {row.get('family', '?'):10} "
            f"{str(row.get('user') or '-'):16} {row.get('ts_desc', ''):20} "
            f"{row.get('artifact', '')}:{row.get('source_line', '')}"
        )
    total = page.get("total")
    shown = len(page["rows"])
    if page.get("capped") or not page.get("exact"):
        typer.echo(f"showing {shown}; total is at least {total} (not exact)", err=True)
    else:
        typer.echo(f"showing {shown} of {total}")
    if page.get("next_cursor"):
        typer.echo(f"next page: --cursor {page['next_cursor']}")


@app.command("export")
def export(
    case: str = typer.Option("", "--case", "-c", help="Case ID (default: active case)"),
    out: str = typer.Option("", "--out", "-o", help="Write CSV here (default: stdout)"),
    family: str = typer.Option("", "--family", help="Filter: family"),
    since: str = typer.Option("", "--since", help="Filter: ts gte (ISO)"),
    until: str = typer.Option("", "--until", help="Filter: ts lte (ISO)"),
) -> None:
    """Export every event as CSV — the same rows the grid shows."""
    from nexus.dashboard.timeline_api import TimelineStore, TimelineUnavailable

    case_dir = _resolve_case_dir(case)
    filters = _filters(family=family, since=since, until=until)
    store = TimelineStore(case_dir.name)

    with (
        open(out, "w", encoding="utf-8", newline="") if out
        else contextlib.nullcontext(sys.stdout)
    ) as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(_COLUMNS)
        rows = 0
        try:
            for chunk in _chunks(store, filters):
                for row in chunk:
                    writer.writerow([row.get(c, "") for c in _COLUMNS])
                    rows += 1
        except TimelineUnavailable as exc:
            typer.echo(f"Timeline unavailable — {exc}", err=True)
            raise typer.Exit(1) from None

    typer.echo(
        f"exported {rows} event(s) to {out}" if out else f"exported {rows} event(s)",
        err=True,
    )


def _chunks(store, filters: dict):
    """Every matching row, paged with the same cursor the grid uses.

    Rows are yielded before the next page is requested, so a long export is
    written progressively rather than held in memory.
    """
    from nexus.dashboard.timeline_api import MAX_PAGE

    cursor = None
    while True:
        page = store.paged(cursor=cursor, size=MAX_PAGE, filters=filters)
        if not page["rows"]:
            return
        yield page["rows"]
        cursor = page.get("next_cursor")
        if not cursor:
            return


def _filters(**parts) -> dict:
    out: dict = {}
    if parts.get("family"):
        out["family"] = parts["family"]
    if parts.get("user"):
        out["user"] = parts["user"]
    if parts.get("host"):
        out["host"] = parts["host"]
    window = {}
    if parts.get("since"):
        window["gte"] = parts["since"]
    if parts.get("until"):
        window["lte"] = parts["until"]
    if window:
        out["ts"] = window
    return out
