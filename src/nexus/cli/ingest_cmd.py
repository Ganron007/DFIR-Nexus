"""CLI ingest — same detect + registry path as MCP ingest_auto."""

from __future__ import annotations

from pathlib import Path

import typer


def ingest(
    path: Path = typer.Argument(..., exists=True, readable=True, help="File or directory"),
    recursive: bool = typer.Option(False, "--recursive", "-r", help="Walk a directory"),
    limit: int = typer.Option(50, "--limit", help="Max files when walking a directory"),
    case_id: str = typer.Option("", "--case", help="Merge onto this case (I3) when set"),
    source: str = typer.Option(
        "",
        "--source",
        help="Force ArtifactSource (e.g. zeek, evtx, generic_csv). Default: auto-detect.",
    ),
) -> None:
    """Auto-detect format and ingest. Prints source, artifact count, audit_id, errors."""
    from nexus.audit import AuditWriter
    from nexus.ingest.detect import ingest_auto

    targets: list[Path]
    if path.is_dir():
        if not recursive:
            typer.echo("Directory given — pass --recursive to walk it", err=True)
            raise typer.Exit(1)
        targets = [p for p in path.rglob("*") if p.is_file()][:limit]
    else:
        targets = [path]

    any_fail = False
    total = 0
    case_dir = None
    if case_id:
        from nexus.config import settings
        case_dir = settings.cases_root / case_id
        if not case_dir.is_dir():
            typer.echo(f"Case directory missing: {case_dir}", err=True)
            raise typer.Exit(1)

    writer = AuditWriter(
        "nexus",
        audit_dir=(case_dir / "audit") if case_dir is not None else None,
    )
    src_override = source.strip() or None

    for t in targets:
        if case_dir is not None:
            from nexus.langgraph.timeline_merge import ingest_into_case

            result = ingest_into_case(t, case_dir, limit=400, source=src_override)
        else:
            result = ingest_auto(t, source=src_override)
        ok = bool(result.get("success"))
        n = int(result.get("artifacts") or 0)
        total += n
        mark = "ok" if ok else "fail"
        src = result.get("source") or result.get("error") or "?"
        aid = writer.log(
            tool="ingest_auto",
            params={"path": str(t), "source": src_override or ""},
            result_summary={
                "success": ok,
                "artifacts": n,
                "source": result.get("source"),
            },
            source="cli",
            input_files=[str(t)],
        )
        result["audit_id"] = aid
        typer.echo(f"[{mark}] {n:6d}  {src:<20}  audit_id={aid or '-'}  {t}")
        errs = result.get("errors") or []
        if result.get("error"):
            typer.echo(f"       {result['error']}")
            any_fail = True
        for e in errs[:3]:
            typer.echo(f"       {e}")
            any_fail = True
    if case_dir is not None:
        from nexus.langgraph.timeline_merge import rebuild_case_timeline

        events = rebuild_case_timeline(case_dir)
        typer.echo(f"I3 merged timeline events={len(events)}")
    typer.echo(f"total_artifacts={total} files={len(targets)}")
    if any_fail:
        raise typer.Exit(1)
