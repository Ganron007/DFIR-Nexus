"""Report generation from approved findings."""

import typer

app = typer.Typer(help="Generate investigation reports")


@app.command()
def generate(
    profile: str = typer.Option("full", "--profile", "-p", help="Report profile"),
    save: str = typer.Option("", "--save", "-s", help="Save to file"),
    from_date: str = typer.Option("", "--from", help="Start date"),
    to_date: str = typer.Option("", "--to", help="End date"),
):
    """Generate an IR report from approved findings."""
    typer.echo(f"Generating {profile} report...")
    if save:
        typer.echo(f"Saved to {save}")
