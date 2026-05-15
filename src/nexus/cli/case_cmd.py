"""Case lifecycle commands."""

import typer

app = typer.Typer(help="Manage investigation cases")


@app.command()
def init(
    name: str = typer.Argument(..., help="Case name"),
    case_id: str = typer.Option("", "--case-id", help="Custom case ID"),
):
    """Create a new investigation case."""
    typer.echo(f"Case '{name}' created (ID: {case_id or 'auto'})")


@app.command()
def activate(case_id: str = typer.Argument(..., help="Case ID to activate")):
    """Activate an existing case."""
    typer.echo(f"Case {case_id} activated")


@app.command()
def close(case_id: str = typer.Argument(..., help="Case ID to close")):
    """Close a case."""
    typer.echo(f"Case {case_id} closed")


@app.command()
def reopen(case_id: str = typer.Argument(..., help="Case ID to reopen")):
    """Reopen a closed case."""
    typer.echo(f"Case {case_id} reopened")


@app.command()
def list_cases():
    """List all cases."""
    typer.echo("No cases found.")
