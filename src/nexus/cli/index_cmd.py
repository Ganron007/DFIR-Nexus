"""Index maintenance - rebuild the per-case N3 Elasticsearch index (4j.30).

The index schema is versioned; a rebuild drops and repopulates with the
current schema (v5: explicit typed ``fields.*`` from the shipped field
registry + structured host/user/event_id/envelope so DSL filters, typed
ranges and aggregations push down to ES).
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

    try:
        meta = index_case(case_dir)
    except Exception as exc:  # noqa: BLE001 — actionable message, no traceback
        typer.echo(
            f"Index rebuild failed — Elasticsearch unreachable or rejected the "
            f"request at {es_url()}: {exc}",
            err=True,
        )
        raise typer.Exit(1) from None
    typer.echo(
        f"Index rebuilt: {meta.get('index')} "
        f"docs={meta.get('docs')} errors={meta.get('errors')}"
    )


@app.command("verify")
def verify(
    case: str = typer.Option("", "--case", "-c", help="Case ID (default: active case)"),
) -> None:
    """Prove indexed source files are unmodified since the index build (WO-A5).

    Re-hashes every file recorded in ``analysis/index_state.json`` against the
    digests stored at index time. A changed or missing file means the index no
    longer matches the evidence — exit 1.
    """
    import json
    from pathlib import Path

    from nexus.config import settings

    case_id = case.strip()
    if not case_id:
        from nexus.case_manager import CaseManager

        try:
            case_id = CaseManager().require_active_case().name
        except Exception as exc:  # noqa: BLE001
            typer.echo(f"No active case: {exc}", err=True)
            raise typer.Exit(1) from None

    state_path = settings.cases_root / case_id / "analysis" / "index_state.json"
    if not state_path.is_file():
        typer.echo(f"No index state for {case_id} — run the indexer first.")
        raise typer.Exit(1)
    state = json.loads(state_path.read_text(encoding="utf-8"))
    recorded: dict[str, str] = state.get("file_sha256s") or {}
    if not recorded:
        typer.echo(
            "index_state.json predates source digests — rebuild the index to record them."
        )
        raise typer.Exit(1)

    import hashlib

    changed: list[str] = []
    missing: list[str] = []
    for rel, digest in sorted(recorded.items()):
        rel_path = Path(rel)
        candidates = [settings.cases_root / case_id / rel_path]
        if not rel.startswith("ingest/"):
            candidates.append(settings.cases_root / case_id / "extractions" / rel_path)
        found = next((c for c in candidates if c.is_file()), None)
        if found is None:
            missing.append(rel)
            continue
        h = hashlib.sha256()
        with open(found, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        if h.hexdigest() != digest:
            changed.append(rel)

    typer.echo(f"Verified {len(recorded)} indexed source file(s) for {case_id}")
    for rel in missing:
        typer.echo(f"  MISSING: {rel}")
    for rel in changed:
        typer.echo(f"  MODIFIED: {rel}")
    if missing or changed:
        typer.echo(
            f"Index does not match the evidence: {len(missing)} missing, "
            f"{len(changed)} modified. Rebuild the index.",
            err=True,
        )
        raise typer.Exit(1)
    typer.echo("All indexed source files match their recorded digests.")
