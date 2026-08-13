"""CLI ingest — same detect + registry path as MCP ingest_auto."""

from __future__ import annotations

from pathlib import Path

import typer


def ingest(
    path: Path = typer.Argument(..., exists=True, readable=True, help="File or directory"),
    recursive: bool = typer.Option(False, "--recursive", "-r", help="Walk a directory"),
    limit: int = typer.Option(50, "--limit", help="Max files when walking a directory"),
) -> None:
    """Auto-detect format and ingest. Prints source, artifact count, errors."""
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
    for t in targets:
        result = ingest_auto(t)
        ok = bool(result.get("success"))
        n = int(result.get("artifacts") or 0)
        total += n
        mark = "ok" if ok else "fail"
        src = result.get("source") or result.get("error") or "?"
        typer.echo(f"[{mark}] {n:6d}  {src:<20}  {t}")
        errs = result.get("errors") or []
        if result.get("error"):
            typer.echo(f"       {result['error']}")
            any_fail = True
        for e in errs[:3]:
            typer.echo(f"       {e}")
            any_fail = True
    typer.echo(f"total_artifacts={total} files={len(targets)}")
    if any_fail:
        raise typer.Exit(1)
