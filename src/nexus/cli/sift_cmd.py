"""``nexus sift`` — the SIFT lane: selection, reachability, and Option B ingest.

SIFT is an explicitly selected, always-optional lane. Selecting it marks SIFT
analysis as required (``sift_required``) — the only switch that can refuse
analysis when the host is unreachable. Recovery is exactly three paths: bring
the host up and re-run, clear the selection (``nexus sift disable``), or the
examiner's audited skip. Nothing else is ever skipped.
"""
from __future__ import annotations

from pathlib import Path

import typer

app = typer.Typer(help="SIFT lane: status, selection, and SIFT-output ingest.")


def _resolve_case_dir(case: str) -> Path:
    from pathlib import Path as _P

    if case:
        candidate = _P(case)
        if candidate.is_dir():
            return candidate
        for base in (_P.home() / ".nexus" / "cases", _P("cases")):
            hit = base / case
            if hit.is_dir():
                return hit
        typer.echo(f"case not found: {case}")
        raise typer.Exit(1)
    from nexus.case.outputs import resolve_active_case_dir

    try:
        case_dir = resolve_active_case_dir()
    except Exception:  # noqa: BLE001
        case_dir = None
    if case_dir is None:
        typer.echo("No active case. Pass --case <id|dir>.")
        raise typer.Exit(1)
    return case_dir


def _context(case_dir: Path) -> dict[str, str]:
    import yaml

    meta_path = case_dir / "CASE.yaml"
    if not meta_path.is_file():
        return {}
    loaded = yaml.safe_load(meta_path.read_text(encoding="utf-8")) or {}
    intake = loaded.get("intake") if isinstance(loaded, dict) else None
    return {str(k): str(v) for k, v in (intake or {}).items() if v is not None}


def _required(ctx: dict[str, str]) -> bool:
    return (ctx.get("sift_required") or "").strip().lower() in ("1", "true", "yes")


@app.command("status")
def status(case: str = typer.Option("", "--case", help="Case id or directory. Default: the active case.")):
    """Show the SIFT lane selection, evidence paths, and reachability."""
    from nexus.case.sift_sync import sift_reachable

    case_dir = _resolve_case_dir(case)
    ctx = _context(case_dir)
    required = _required(ctx)
    typer.echo(f"case: {case_dir.name}")
    typer.echo(f"SIFT lane selected (sift_required): {'yes' if required else 'no'}")
    for key in ("sift_evidence_root", "sift_memory_file", "sift_disk_image", "sift_os"):
        if ctx.get(key):
            typer.echo(f"  {key}: {ctx[key]}")
    try:
        ok, msg = sift_reachable()
    except Exception as exc:  # noqa: BLE001
        ok, msg = False, str(exc)
    typer.echo(f"SIFT reachable: {'yes' if ok else 'NO'} ({msg[:120]})")
    import os

    mcp = os.environ.get("NEXUS_SIFT_MCP_URL", "").strip()
    typer.echo(f"SIFT MCP URL: {mcp or '(not set - NEXUS_SIFT_MCP_URL)'}")
    if required and not ok:
        typer.echo("")
        typer.echo("SIFT is REQUIRED for this case and unreachable - analysis will refuse. "
                   "Recoveries: bring the host up and re-run; `nexus sift disable`; "
                   "or the examiner's audited skip (`nexus lane skip`).")
        raise typer.Exit(1)


@app.command("enable")
def enable(case: str = typer.Option("", "--case", help="Case id or directory. Default: the active case.")):
    """Mark SIFT analysis as required for this case and run the online check."""
    from nexus.case.sift_sync import sift_reachable
    from nexus.langgraph.case_intake import persist_case_intake

    case_dir = _resolve_case_dir(case)
    persist_case_intake(case_dir, {"sift_required": "true"})
    typer.echo(f"SIFT required: on ({case_dir.name})")
    try:
        ok, msg = sift_reachable()
    except Exception as exc:  # noqa: BLE001
        ok, msg = False, str(exc)
    typer.echo(f"online check: {'reachable' if ok else 'UNREACHABLE'} ({msg[:120]})")
    if not ok:
        typer.echo("Analysis will refuse until the host is up, the selection is "
                   "cleared (`nexus sift disable`), or an audited skip is recorded.")


@app.command("disable")
def disable(case: str = typer.Option("", "--case", help="Case id or directory. Default: the active case.")):
    """Clear the SIFT selection (a first-class recovery path)."""
    from nexus.langgraph.case_intake import clear_case_intake

    case_dir = _resolve_case_dir(case)
    remaining = clear_case_intake(case_dir, ("sift_required",))
    typer.echo(f"SIFT required: cleared ({case_dir.name})")
    if remaining.get("sift_evidence_root"):
        typer.echo("Note: sift_evidence_root is kept; without the selection its jobs "
                   "SKIP with reasons (never a refusal).")


@app.command("ingest")
def ingest(
    path: str = typer.Argument(..., help="SIFT outputs: a file, a directory, or a .zip"),
    case: str = typer.Option("", "--case", help="Case id or directory. Default: the active case."),
    family: str = typer.Option(
        "", "--as", help="Destination family name (plaso / vol / fls / bulk_extractor) for mapping"
    ),
):
    """Option B - stage SIFT-produced outputs for indexing (no SIFT host needed)."""
    from nexus.case.sift_ingest import stage_sift_outputs

    case_dir = _resolve_case_dir(case)
    src = Path(path)
    staged = stage_sift_outputs(case_dir, [src], family=family)
    for dest in staged:
        n = sum(1 for _ in dest.rglob("*") if _.is_file())
        typer.echo(f"staged: {dest.relative_to(case_dir)}  ({n} file(s))")
    typer.echo("Next: run the indexer (`nexus index rebuild` or the pipeline) so the rows "
               "land in the case index with the mapped fields.")
