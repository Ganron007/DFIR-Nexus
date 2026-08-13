"""nexus data — download RAG / triage / fixtures without MCP."""

from __future__ import annotations

from pathlib import Path

import typer

app = typer.Typer(help="Download RAG index, triage baselines, or fixtures")


@app.command("download-rag")
def download_rag(tag: str = typer.Option("latest", "--tag")) -> None:
    """Download the AppliedIR RAG index into ~/.nexus/data/rag (no-op if present)."""
    dest = Path.home() / ".nexus" / "data" / "rag" / "chroma"
    if dest.is_dir() and any(dest.iterdir()):
        typer.echo(f"already present: {dest}")
        return
    from nexus.tools.rag import register_tools
    from nexus.audit import AuditWriter
    from mcp.server.fastmcp import FastMCP

    server = FastMCP("tmp")
    register_tools(server, AuditWriter("nexus"))
    fn = server._tool_manager._tools["forensic_rag_download"].fn
    result = fn(tag=tag)
    typer.echo(result)


@app.command("download-triage")
def download_triage() -> None:
    """Download triage baselines into ~/.nexus/data/triage (no-op if present)."""
    dest = Path.home() / ".nexus" / "data" / "triage"
    if dest.is_dir() and any(dest.iterdir()):
        typer.echo(f"already present: {dest}")
        return
    from nexus.triage.download import download_databases

    ok = download_databases(dest)
    typer.echo({"ok": ok, "dest": str(dest)})


@app.command("download-fixtures")
def download_fixtures() -> None:
    """Point at the in-repo Evidence-files / fixtures tree (no network)."""
    repo = Path(__file__).resolve().parents[3]
    ev = repo / "Evidence-files"
    fx = repo / "fixtures"
    typer.echo(f"Evidence-files: {'present' if ev.is_dir() else 'missing'}  {ev}")
    typer.echo(f"fixtures/: {'present' if fx.is_dir() else 'missing (Phase D still open)'}  {fx}")
