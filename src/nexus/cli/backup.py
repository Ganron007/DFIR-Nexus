"""Case backup and restore."""

import typer

app = typer.Typer(help="Backup and restore cases")


@app.command()
def create(
    path: str = typer.Argument(..., help="Backup destination path"),
    all_data: bool = typer.Option(False, "--all", help="Include evidence and OpenSearch"),
    verify: bool = typer.Option(False, "--verify", help="Verify backup integrity"),
):
    """Backup the active case."""
    typer.echo(f"Backing up to {path}...")


@app.command()
def restore(
    path: str = typer.Argument(..., help="Backup file to restore"),
    skip_opensearch: bool = typer.Option(False, "--skip-opensearch"),
    skip_ledger: bool = typer.Option(False, "--skip-ledger"),
):
    """Restore a case from backup."""
    typer.echo(f"Restoring from {path}...")


@app.command()
def verify(
    path: str = typer.Argument(..., help="Backup path to verify"),
):
    """Verify backup integrity."""
    typer.echo(f"Verifying {path}...")
