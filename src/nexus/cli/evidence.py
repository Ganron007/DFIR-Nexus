"""Evidence management — register, list, verify, lock, unlock."""

import hashlib
import json
import os
import stat
import typer
from datetime import datetime, timezone
from pathlib import Path

app = typer.Typer(help="Manage evidence files")


def _get_case_dir(case_id: str = "") -> Path | None:
    active = Path.home() / ".nexus" / "active_case"
    if case_id:
        d = Path.home() / ".nexus" / "cases" / case_id
        return d if d.exists() else None
    if active.exists():
        content = active.read_text().strip()
        if content:
            d = Path(content) if Path(content).is_absolute() else Path.home() / ".nexus" / "cases" / content
            return d if d.exists() else None
    typer.echo("No active case. Use 'nexus case activate'", err=True)
    return None


@app.command()
def register(
    path: str = typer.Argument(..., help="Path to evidence file"),
    description: str = typer.Option("", "--description", "-d", help="Evidence description"),
    case_id: str = typer.Option("", "--case", help="Case ID"),
):
    """Register an evidence file with SHA-256 hash."""
    case_dir = _get_case_dir(case_id)
    if not case_dir:
        raise typer.Exit(1)

    fpath = Path(path)
    if not fpath.exists():
        typer.echo(f"File not found: {path}", err=True)
        raise typer.Exit(1)

    sha256 = hashlib.sha256()
    with open(fpath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha256.update(chunk)
    digest = sha256.hexdigest()

    registry_path = case_dir / "evidence_registry.json"
    registry = json.loads(registry_path.read_text()) if registry_path.exists() else []

    entry = {
        "path": str(fpath.resolve()),
        "sha256": digest,
        "description": description,
        "size": fpath.stat().st_size,
        "registered_at": datetime.now(timezone.utc).isoformat(),
    }
    registry.append(entry)
    registry_path.write_text(json.dumps(registry, indent=2, default=str))

    typer.echo(f"Registered: {fpath.name}")
    typer.echo(f"  SHA-256: {digest}")
    typer.echo(f"  Size: {fpath.stat().st_size:,} bytes")


@app.command()
def list(
    case_id: str = typer.Option("", "--case", help="Case ID"),
):
    """List registered evidence files."""
    case_dir = _get_case_dir(case_id)
    if not case_dir:
        raise typer.Exit(1)

    registry_path = case_dir / "evidence_registry.json"
    if not registry_path.exists():
        typer.echo("No evidence registered")
        return

    registry = json.loads(registry_path.read_text())
    if not registry:
        typer.echo("No evidence registered")
        return

    for e in registry:
        p = Path(e.get("path", "?"))
        sha = e.get("sha256", "")[:16]
        desc = e.get("description", "")[:40]
        ts = e.get("registered_at", "")[:10]
        typer.echo(f"  {p.name:30s} {sha}...  {desc}  {ts}")


@app.command()
def verify(
    case_id: str = typer.Option("", "--case", help="Case ID"),
):
    """Re-hash registered evidence to verify integrity."""
    case_dir = _get_case_dir(case_id)
    if not case_dir:
        raise typer.Exit(1)

    registry_path = case_dir / "evidence_registry.json"
    if not registry_path.exists():
        typer.echo("No evidence registered")
        return

    registry = json.loads(registry_path.read_text())
    all_ok = True
    for e in registry:
        fpath = Path(e["path"])
        if not fpath.exists():
            typer.echo(f"  MISSING: {fpath.name}")
            all_ok = False
            continue

        sha256 = hashlib.sha256()
        with open(fpath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)
        digest = sha256.hexdigest()

        if digest == e["sha256"]:
            typer.echo(f"  ✓ {fpath.name}")
        else:
            typer.echo(f"  ✗ HASH MISMATCH: {fpath.name}")
            all_ok = False

    if all_ok:
        typer.echo("All evidence verified OK")


@app.command()
def lock(
    case_id: str = typer.Option("", "--case", help="Case ID"),
):
    """Lock evidence directory to read-only to prevent tampering."""
    case_dir = _get_case_dir(case_id)
    if not case_dir:
        raise typer.Exit(1)

    registry_path = case_dir / "evidence_registry.json"
    if not registry_path.exists():
        typer.echo("No evidence registered")
        return

    registry = json.loads(registry_path.read_text())
    count = 0
    for e in registry:
        fpath = Path(e["path"])
        if fpath.exists():
            try:
                current = stat.S_IMODE(fpath.stat().st_mode)
                fpath.chmod(current & ~stat.S_IWUSR & ~stat.S_IWGRP & ~stat.S_IWOTH)
                count += 1
            except OSError as err:
                typer.echo(f"  Could not lock {fpath.name}: {err}")

    typer.echo(f"Locked {count} evidence files (read-only)")


@app.command()
def unlock(
    case_id: str = typer.Option("", "--case", help="Case ID"),
):
    """Unlock evidence directory for new files."""
    case_dir = _get_case_dir(case_id)
    if not case_dir:
        raise typer.Exit(1)

    registry_path = case_dir / "evidence_registry.json"
    if not registry_path.exists():
        typer.echo("No evidence registered")
        return

    registry = json.loads(registry_path.read_text())
    count = 0
    for e in registry:
        fpath = Path(e["path"])
        if fpath.exists():
            try:
                current = stat.S_IMODE(fpath.stat().st_mode)
                fpath.chmod(current | stat.S_IWUSR)
                count += 1
            except OSError as err:
                typer.echo(f"  Could not unlock {fpath.name}: {err}")

    typer.echo(f"Unlocked {count} evidence files")
