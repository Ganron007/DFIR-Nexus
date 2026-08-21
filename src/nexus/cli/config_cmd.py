"""Examiner configuration management with approval password support.

Supports both invocation styles:

    nexus config --examiner "Jane Doe"      # documented quickstart form
    nexus config --setup-password
    nexus config --examiner e2e_host --setup-password --replace
    nexus config --show
    nexus config set --examiner "Jane Doe"  # subcommand form
    nexus config show
"""

import getpass
import os
from pathlib import Path

import typer

app = typer.Typer(help="Manage examiner configuration")

_MIN_PASSWORD_LENGTH = 8


def _new_password(analyst: str) -> str:
    """Prefer NEXUS_APPROVAL_PASSWORD so PowerShell/Cursor can set HMAC without getpass."""
    env_pw = (os.environ.get("NEXUS_APPROVAL_PASSWORD") or "").strip()
    if env_pw:
        if len(env_pw) < _MIN_PASSWORD_LENGTH:
            typer.echo(
                f"NEXUS_APPROVAL_PASSWORD must be at least {_MIN_PASSWORD_LENGTH} characters.",
                err=True,
            )
            raise typer.Exit(1)
        typer.echo(f"Using NEXUS_APPROVAL_PASSWORD for {analyst} (not echoed).")
        return env_pw
    pw = getpass.getpass("New password (min 8 chars): ")
    confirm = getpass.getpass("Confirm password: ")
    if pw != confirm:
        typer.echo("Passwords do not match", err=True)
        raise typer.Exit(1)
    return pw


def _run_set(examiner: str, setup_password: bool, replace: bool = False) -> None:
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
        from nexus.auth import has_password as _has_password
        from nexus.auth import reset_password as _do_reset_password
        from nexus.auth import setup_password as _do_setup_password
        from nexus.config import settings

        analyst = examiner or settings.examiner or os.environ.get("USER") or os.environ.get("USERNAME") or ""
        if not analyst:
            typer.echo("No examiner identity. Use --examiner or set NEXUS_EXAMINER.", err=True)
            raise typer.Exit(1)

        if _has_password(analyst) and not replace:
            typer.echo(f"Password already configured for {analyst}")
            typer.echo(
                "Forgot it / never set it? Re-run with --replace "
                "(old HMAC ledger entries for this examiner will not verify)."
            )
            reset = typer.confirm("Reset using the current password?", default=False)
            if not reset:
                return
            old_pw = (os.environ.get("NEXUS_APPROVAL_PASSWORD_OLD") or "").strip()
            if not old_pw:
                old_pw = getpass.getpass("Current password: ")
            new_pw = _new_password(analyst)
            result = _do_reset_password(analyst, old_pw, new_pw)
            if result["status"] == "ok":
                typer.echo(f"Password rotated. {result.get('re_signed', 0)} ledger entries re-signed.")
            else:
                typer.echo(f"Error: {result['message']}", err=True)
                raise typer.Exit(1)
            return

        if replace and _has_password(analyst):
            typer.echo(
                f"WARNING: replacing HMAC password for {analyst} without the old key. "
                "Prior verification ledger entries signed with the old password will not verify."
            )

        typer.echo(f"Setting approval password for: {analyst}")
        pw = _new_password(analyst)
        try:
            result = _do_setup_password(analyst, pw)
            typer.echo(f"Password configured ({result['status']})")
            typer.echo("This password is now required for approve/reject operations")
        except ValueError as e:
            typer.echo(f"Error: {e}", err=True)
            raise typer.Exit(1) from None


def _run_show() -> None:
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


@app.callback(invoke_without_command=True)
def _config_callback(
    ctx: typer.Context,
    examiner: str = typer.Option("", "--examiner", "-e", help="Examiner name"),
    setup_password: bool = typer.Option(False, "--setup-password", help="Set approval password"),
    replace: bool = typer.Option(
        False,
        "--replace",
        help="Overwrite an existing HMAC password without the old one (forgot / never set)",
    ),
    show: bool = typer.Option(False, "--show", help="Show current configuration"),
):
    """Manage examiner configuration (also: nexus config set / show)."""
    if ctx.invoked_subcommand is not None:
        return
    if examiner or setup_password:
        _run_set(examiner, setup_password, replace=replace)
    elif show:
        _run_show()
    else:
        typer.echo(ctx.get_help())


@app.command()
def set(
    examiner: str = typer.Option("", "--examiner", "-e", help="Examiner name"),
    setup_password: bool = typer.Option(False, "--setup-password", help="Set approval password"),
    replace: bool = typer.Option(
        False,
        "--replace",
        help="Overwrite an existing HMAC password without the old one",
    ),
):
    """Set examiner identity or configure approval password."""
    _run_set(examiner, setup_password, replace=replace)


@app.command()
def show():
    """Show current configuration."""
    _run_show()
