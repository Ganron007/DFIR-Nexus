"""TODO management CLI."""

import json
import typer
from pathlib import Path
from datetime import datetime, timezone

app = typer.Typer(help="Manage TODO items")


@app.command()
def list(
    status: str = typer.Option("open", "--status", help="Filter: open/completed/all"),
    assignee: str = typer.Option("", "--assignee", help="Filter by assignee"),
    case_id: str = typer.Option("", "--case", help="Case ID"),
):
    """List TODO items."""
    from nexus.cli.main import _resolve_case
    case_dir = _resolve_case(case_id)
    if not case_dir:
        return
    path = case_dir / "todos.json"
    if not path.exists():
        typer.echo("No TODOs found")
        return
    todos = json.loads(path.read_text())
    for t in todos:
        t_status = t.get("status", "open")
        if status != "all" and t_status != status:
            continue
        if assignee and assignee.lower() not in t.get("assignee", "").lower():
            continue
        tid = t.get("todo_id", t.get("id", "?"))
        desc = t.get("description", "")[:80]
        prio = t.get("priority", "medium")
        assign = t.get("assignee", "")
        typer.echo(f"  [{t_status[:4].upper()}] {tid} [{prio}] {desc}  {assign}")


@app.command()
def add(
    description: str = typer.Argument(..., help="TODO description"),
    assignee: str = typer.Option("", "--assignee", help="Assignee"),
    priority: str = typer.Option("medium", "--priority", help="Priority: high/medium/low"),
    case_id: str = typer.Option("", "--case", help="Case ID"),
):
    """Add a new TODO item."""
    from nexus.cli.main import _resolve_case
    case_dir = _resolve_case(case_id)
    if not case_dir:
        return
    path = case_dir / "todos.json"
    todos = json.loads(path.read_text()) if path.exists() else []
    tid = f"TODO-{len(todos)+1:03d}"
    todos.append({
        "todo_id": tid, "description": description, "assignee": assignee,
        "priority": priority, "status": "open",
        "created_at": datetime.now(timezone.utc).isoformat(),
    })
    path.write_text(json.dumps(todos, indent=2, default=str))
    typer.echo(f"Added: {tid}")


@app.command()
def complete(
    todo_id: str = typer.Argument(..., help="TODO ID to complete"),
    case_id: str = typer.Option("", "--case", help="Case ID"),
):
    """Mark a TODO as completed."""
    from nexus.cli.main import _resolve_case
    case_dir = _resolve_case(case_id)
    if not case_dir:
        return
    path = case_dir / "todos.json"
    if not path.exists():
        typer.echo("No TODOs found")
        return
    todos = json.loads(path.read_text())
    for t in todos:
        if t.get("todo_id") == todo_id or t.get("id") == todo_id:
            t["status"] = "completed"
            t["completed_at"] = datetime.now(timezone.utc).isoformat()
            path.write_text(json.dumps(todos, indent=2, default=str))
            typer.echo(f"Completed: {todo_id}")
            return
    typer.echo(f"TODO not found: {todo_id}")
