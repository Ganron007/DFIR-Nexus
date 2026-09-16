"""Index maintenance — rebuild the per-case N3 Elasticsearch index (4j.30).

The index schema is versioned; a rebuild drops and repopulates with the
current schema (v2: structured host/user/event_id + parsed ``fields.*`` so
DSL filters and aggregations push down to ES).
"""

from __future__ import annotations

import typer

app = typer.Typer(help="Case index maintenance")


@app.command("rebuild")
def rebuild(
    case: str = typer.Option("", "--case", "-c", help="Case ID (default: active case)"),
) -> None:
    """Rebuild the case's Elasticsearch index with the current schema."""
    from nexus.config import settings
    from nexus.langgraph.case_index import es_url, index_case

    if not es_url():
        typer.echo("NEXUS_ES_URL is not set — the CSV pack backend needs no index.")
        raise typer.Exit(1)

    case_id = case.strip()
    if not case_id:
        from nexus.case_manager import CaseManager

        try:
            case_id = CaseManager().require_active_case().name
        except Exception as exc:  # noqa: BLE001
            typer.echo(f"No active case: {exc}", err=True)
            raise typer.Exit(1) from None

    case_dir = settings.cases_root / case_id
    if not case_dir.is_dir():
        typer.echo(f"Case not found: {case_dir}", err=True)
        raise typer.Exit(1)

    meta = index_case(case_dir)
    typer.echo(
        f"Index rebuilt: {meta.get('index')} "
        f"docs={meta.get('docs')} errors={meta.get('errors')}"
    )
