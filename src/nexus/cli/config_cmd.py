"""Examiner configuration management with approval password support."""

import getpass
from pathlib import Path

import typer

app = typer.Typer(help="Manage examiner configuration")


@app.command()
def set(
    examiner: str = typer.Option("", "--examiner", "-e", help="Examiner name"),
    setup_password: bool = typer.Option(False, "--setup-password", help="Set approval password"),
):
    """Set examiner identity or configure approval password."""
    config_path = Path.home() / ".nexus" / "config.yaml"
    config_path.parent.mkdir(parents=True, exist_ok=True)

    if examiner:
        config = {"examiner": examiner}
        import yaml
        if config_path.exists():
            try:
                existing = yaml.safe_load(config_path.read_text()) or {}
                config = {**existing, **config}
            except Exception:
                pass
        config_path.write_text(yaml.dump(config, default_flow_style=False))
        typer.echo(f"Examiner set to: {examiner}")

    if setup_password:
        import os

        from nexus.auth import has_password as _has_password
        from nexus.auth import reset_password as _do_reset_password
        from nexus.auth import setup_password as _do_setup_password
        from nexus.config import settings

        analyst = examiner or settings.examiner or os.environ.get("USER") or os.environ.get("USERNAME") or ""
        if not analyst:
            typer.echo("No examiner identity. Use --examiner or set NEXUS_EXAMINER.", err=True)
            raise typer.Exit(1)
        if _has_password(analyst):
            typer.echo(f"Password already configured for {analyst}")
            reset = typer.confirm("Reset password?", default=False)
            if reset:
                old_pw = getpass.getpass("Current password: ")
                new_pw = getpass.getpass("New password (min 8 chars): ")
                confirm = getpass.getpass("Confirm new password: ")
                if new_pw != confirm:
                    typer.echo("Passwords do not match", err=True)
                    raise typer.Exit(1)
                result = _do_reset_password(analyst, old_pw, new_pw)
                if result["status"] == "ok":
                    typer.echo(f"Password rotated. {result.get('re_signed', 0)} ledger entries re-signed.")
                else:
                    typer.echo(f"Error: {result['message']}", err=True)
                    raise typer.Exit(1)
            return

        typer.echo(f"Setting approval password for: {analyst}")
        pw = getpass.getpass("New password (min 8 chars): ")
        confirm = getpass.getpass("Confirm password: ")

        if pw != confirm:
            typer.echo("Passwords do not match", err=True)
            raise typer.Exit(1)

        try:
            result = _do_setup_password(analyst, pw)
            typer.echo(f"Password configured ({result['status']})")
            typer.echo("This password is now required for approve/reject operations")
        except ValueError as e:
            typer.echo(f"Error: {e}", err=True)
            raise typer.Exit(1)


@app.command()
def show():
    """Show current configuration."""
    config_path = Path.home() / ".nexus" / "config.yaml"
    if config_path.exists():
        import yaml
        try:
            config = yaml.safe_load(config_path.read_text()) or {}
            for k, v in config.items():
                typer.echo(f"{k}: {v}")
        except Exception as e:
            typer.echo(f"Error reading config: {e}")
    else:
        typer.echo("No config file found")
    typer.echo(f"Config path: {config_path}")
    typer.echo(f"Data root: {Path.home() / '.nexus' / 'data'}")
