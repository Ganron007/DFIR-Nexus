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
    case: str = typer.Option("", "--case", "-c", help="Case ID (required)"),
) -> None:
    """Rebuild the case's Elasticsearch index with the current schema."""
    from nexus.config import settings
    from nexus.langgraph.case_index import es_url, index_case

    if not es_url():
        typer.echo("NEXUS_ES_URL is not set — the CSV pack backend needs no index.")
        raise typer.Exit(1)

    case_id = case.strip()
    if not case_id:
        typer.echo("--case is required: name the case this command acts on.", err=True)
        raise typer.Exit(1)

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
    case: str = typer.Option("", "--case", "-c", help="Case ID (required)"),
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
        typer.echo("--case is required: name the case this command acts on.", err=True)
        raise typer.Exit(1)

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
    # R13: the rows were read from the run the index recorded; a current run layout
    # (runs/<run>/extractions) is checked too, so an unchanged source is not reported missing.
    case_dir = settings.cases_root / case_id
    source_root = str(state.get("source_extractions") or "")
    for rel, digest in sorted(recorded.items()):
        rel_path = Path(rel)
        candidates = []
        if source_root and not rel.startswith("ingest/"):
            candidates.append(Path(source_root) / rel_path)
        candidates.append(case_dir / rel_path)
        if not rel.startswith("ingest/"):
            candidates.append(case_dir / "extractions" / rel_path)
            try:
                from nexus.langgraph.pipeline_runs import resolve_tools_extractions

                candidates.append(resolve_tools_extractions(case_dir) / rel_path)
            except Exception:  # noqa: BLE001 - no resolvable run: legacy paths only
                pass
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


@app.command("recompute-ecs")
def recompute_ecs(
    case: str = typer.Option("", "--case", "-c", help="Case ID (required)"),
    event: str = typer.Option("4634,4776", "--event", help="Security event ids to recompute (comma-separated)"),
    apply: bool = typer.Option(False, "--apply", help="Write the recomputed ecs. Without it, report only."),
) -> None:
    """Recompute the ecs of stored EVTX documents from their source rows (D113).

    Run after an ecs_map change: a stored document keeps the mapping it was indexed with until it is recomputed.
    Reads the source rows of the named events and writes only the ecs of documents it can verify. Report only
    unless --apply is given. Exits 1 when any document was refused.
    """
    from nexus.config import settings
    from nexus.langgraph.case_index import es_url
    from nexus.langgraph.ecs_recompute import recompute_case

    if not es_url():
        typer.echo("NEXUS_ES_URL is not set; there is no index to recompute.", err=True)
        raise typer.Exit(1)
    case_id = case.strip()
    if not case_id:
        typer.echo("--case is required: name the case this command acts on.", err=True)
        raise typer.Exit(1)
    case_dir = settings.cases_root / case_id
    if not case_dir.is_dir():
        typer.echo(f"Case not found: {case_dir}", err=True)
        raise typer.Exit(1)
    ids = tuple(x.strip() for x in event.split(",") if x.strip())
    report = recompute_case(case_id, case_dir, event_ids=ids, apply=apply)
    mode = "Applied" if apply else "Dry run"
    typer.echo(
        f"{mode}: {report['documents']} document(s) in {report['files']} file(s); "
        f"{report['verified']} verified; {report['changed']} changed; {report['written']} written"
    )
    if report["leaves_added"]:
        typer.echo("  leaves added: " + ", ".join(f"{k} x{v}" for k, v in report["leaves_added"].items()))
    for problem in report["problems"][:50]:
        typer.echo(f"  PROBLEM: {problem}")
    if len(report["problems"]) > 50:
        typer.echo(f"  ... {len(report['problems']) - 50} more problem(s)")
    if report["problems"]:
        raise typer.Exit(1)


@app.command("reindex")
def reindex(
    case: str = typer.Option("", "--case", "-c", help="Case ID (required)"),
    file: list[str] = typer.Option([], "--file", help="An indexed file, by its `file` value (repeatable)."),
    apply: bool = typer.Option(False, "--apply", help="Replace the documents. Without it, report only."),
) -> None:
    """Replace the documents of named indexed files with what the current readers produce (D116, D118, D119).

    Report only unless --apply is given. With --apply the named files' documents are deleted and written again, and the
    index state records the new count. Exits 1 when the request is incomplete.
    """
    from nexus.config import settings
    from nexus.langgraph.case_index import es_url
    from nexus.langgraph.targeted_reindex import (
        apply_targeted_reindex,
        indexed_documents,
        new_documents,
    )

    if not es_url():
        typer.echo("NEXUS_ES_URL is not set; there is no index to re-index.", err=True)
        raise typer.Exit(1)
    case_id = case.strip()
    if not case_id:
        typer.echo("--case is required: name the case this command acts on.", err=True)
        raise typer.Exit(1)
    rels = {name.strip() for name in file if name.strip()}
    if not rels:
        typer.echo("--file is required (repeatable): name the indexed file(s) to replace.", err=True)
        raise typer.Exit(1)
    case_dir = settings.cases_root / case_id
    if not case_dir.is_dir():
        typer.echo(f"Case not found: {case_dir}", err=True)
        raise typer.Exit(1)
    old = indexed_documents(case_id, rels)
    new = new_documents(case_dir, rels)
    for rel in sorted(rels):
        typer.echo(f"  {rel}: indexed {old.get(rel, 0)} -> readers produce {new.get(rel, 0)}")
    if not apply:
        typer.echo("Dry run: nothing written. Re-run with --apply to replace these documents.")
        return
    result = apply_targeted_reindex(case_dir, rels)
    typer.echo(
        f"Applied: {result['written']} document(s) written; the case index now holds {result['total_docs']}."
    )
