"""Audit-logged command execution CLI."""

import hashlib
import subprocess
from datetime import UTC

import typer

app = typer.Typer(help="Execute forensic commands with audit trail")


@app.command()
def run(
    command: list[str] = typer.Argument(..., help="Command and arguments to execute"),
    purpose: str = typer.Option("", "--purpose", "-p", help="Why this command is being run"),
    case_id: str = typer.Option("", "--case", help="Case ID for audit trail"),
):
    """Execute a forensic command with audit trailing SHA-256 hashed output."""
    from nexus.cli.main import _resolve_case
    case_dir = _resolve_case(case_id)
    if not command:
        typer.echo("No command specified", err=True)
        raise typer.Exit(1)

    typer.echo(f"Executing: {' '.join(command)}")
    if purpose:
        typer.echo(f"Purpose:   {purpose}")

    try:
        proc = subprocess.run(command, capture_output=True, text=True, timeout=600)
        typer.echo(f"Exit code: {proc.returncode}")
        if proc.stdout:
            typer.echo(f"Stdout ({len(proc.stdout)} bytes):")
            typer.echo(proc.stdout[:5000])
        if proc.stderr:
            typer.echo(f"Stderr: {proc.stderr[:1000]}", err=True)

        if case_dir:
            audit_dir = case_dir / "audit"
            audit_dir.mkdir(parents=True, exist_ok=True)
            import json
            from datetime import datetime
            stdout_hash = hashlib.sha256(proc.stdout.encode()).hexdigest()
            stderr_hash = hashlib.sha256(proc.stderr.encode()).hexdigest()
            entry = {
                "timestamp": datetime.now(UTC).isoformat(),
                "command": " ".join(command),
                "purpose": purpose,
                "exit_code": proc.returncode,
                "stdout_sha256": stdout_hash,
                "stderr_sha256": stderr_hash,
                "stdout_bytes": len(proc.stdout.encode()),
                "stderr_bytes": len(proc.stderr.encode()),
            }
            audit_file = audit_dir / "exec_commands.jsonl"
            with open(audit_file, "a") as f:
                f.write(json.dumps(entry) + "\n")
            typer.echo(f"  Audit: stdout SHA-256={stdout_hash[:16]}...")
    except FileNotFoundError:
        typer.echo(f"Command not found: {command[0]}", err=True)
    except subprocess.TimeoutExpired:
        typer.echo("Command timed out", err=True)
