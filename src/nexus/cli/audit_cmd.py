"""Audit trail CLI — view and summarize audit entries."""

import json
import typer
from pathlib import Path

app = typer.Typer(help="View and analyze audit trail")


@app.command()
def log(
    limit: int = typer.Option(50, "--limit", help="Max entries to show"),
    mcp: str = typer.Option("", "--mcp", help="Filter by MCP server name"),
    tool: str = typer.Option("", "--tool", help="Filter by tool name"),
    case_id: str = typer.Option("", "--case", help="Case ID"),
):
    """Show audit log entries with optional filters."""
    from nexus.cli.main import _resolve_case
    case_dir = _resolve_case(case_id)
    if not case_dir:
        return
    audit_dir = case_dir / "audit"
    if not audit_dir.exists():
        typer.echo("No audit directory found")
        return
    entries = []
    for f in sorted(audit_dir.glob("*.jsonl")):
        for line in f.read_text().strip().split("\n"):
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
                if mcp and mcp not in entry.get("mcp", ""):
                    continue
                if tool and tool not in entry.get("tool", ""):
                    continue
                entries.append(entry)
            except json.JSONDecodeError:
                continue
    entries.sort(key=lambda e: e.get("ts", ""), reverse=True)
    entries = entries[:limit]
    if not entries:
        typer.echo("No matching audit entries")
        return
    for e in entries:
        ts = e.get("ts", "")[:19]
        m = e.get("mcp", "")
        t = e.get("tool", "")
        aid = e.get("audit_id", "")
        ex = e.get("examiner", "")
        typer.echo(f"{ts} [{m}] {t}  audit_id={aid}  examiner={ex}")


@app.command()
def summary(
    case_id: str = typer.Option("", "--case", help="Case ID"),
):
    """Summary of audit entries per MCP server and tool."""
    from nexus.cli.main import _resolve_case
    case_dir = _resolve_case(case_id)
    if not case_dir:
        return
    audit_dir = case_dir / "audit"
    if not audit_dir.exists():
        typer.echo("No audit directory found")
        return
    counts = {}
    for f in sorted(audit_dir.glob("*.jsonl")):
        for line in f.read_text().strip().split("\n"):
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
                key = (entry.get("mcp", "?"), entry.get("tool", "?"))
                counts[key] = counts.get(key, 0) + 1
            except json.JSONDecodeError:
                continue
    typer.echo("Audit Summary:")
    for (mcp, tool), count in sorted(counts.items()):
        typer.echo(f"  {mcp}/{tool}: {count} calls")
    typer.echo(f"Total: {sum(counts.values())} entries")
