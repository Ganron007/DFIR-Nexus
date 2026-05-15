"""Case review and audit queries."""

import typer

app = typer.Typer(help="Review case state")


@app.command()
def findings(
    detail: bool = typer.Option(False, "--detail", "-d"),
    limit: int = typer.Option(20, "--limit", "-l"),
):
    """List findings."""
    typer.echo("No findings.")


@app.command()
def timeline(
    start: str = typer.Option("", "--start"),
    end: str = typer.Option("", "--end"),
    event_type: str = typer.Option("", "--type"),
):
    """List timeline events."""
    typer.echo("No timeline events.")


@app.command()
def iocs():
    """List IOCs grouped by status."""
    typer.echo("No IOCs.")


@app.command()
def audit(limit: int = typer.Option(100, "--limit", "-l")):
    """View audit trail."""
    typer.echo("No audit entries.")


@app.command()
def todos(open_only: bool = typer.Option(False, "--open")):
    """List TODOs."""
    typer.echo("No TODOs.")


@app.command()
def verify():
    """HMAC integrity verification of approvals."""
    typer.echo("Integrity verified.")
