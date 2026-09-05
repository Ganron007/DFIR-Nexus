"""Evidence management — register, list, verify, lock, unlock.

Backed by the SQLite case stack.
"""

import hashlib
import stat
from pathlib import Path

import typer

app = typer.Typer(help="Manage evidence files")

_ACTIVE_CASE_FILE = Path.home() / ".nexus" / "active_case"


def _get_active_case_id() -> str | None:
    if _ACTIVE_CASE_FILE.exists():
        content = _ACTIVE_CASE_FILE.read_text().strip()
        if content:
            # Tolerate a legacy absolute-path pointer: use the directory name.
            p = Path(content)
            if p.is_absolute():
                return p.name
            return content
    return None


def _get_sqlite_mgr():
    from nexus.case import CaseManager
    from nexus.config import settings
    db_path = settings.cases_root / "cases.db"
    return CaseManager(db_path)


@app.command()
def register(
    path: str = typer.Argument(..., help="Path to evidence file"),
    description: str = typer.Option("", "--description", "-d", help="Evidence description"),
    case_id: str = typer.Option("", "--case", help="Case ID (defaults to active)"),
):
    """Register an evidence file with SHA-256 hash."""
    if not case_id:
        case_id = _get_active_case_id() or ""
    if not case_id:
        typer.echo("No active case. Use 'nexus case activate' first.", err=True)
        raise typer.Exit(1)

    fpath = Path(path)
    if not fpath.exists():
        typer.echo(f"Path not found: {path}", err=True)
        raise typer.Exit(1)

    sha256 = hashlib.sha256()
    if fpath.is_dir():
        sha256.update(str(fpath.resolve()).encode())
        n = 0
        for child in sorted(fpath.rglob("*")):
            if not child.is_file():
                continue
            rel = str(child.relative_to(fpath)).encode()
            sha256.update(rel)
            sha256.update(str(child.stat().st_size).encode())
            n += 1
            if n >= 400:
                break
        digest = sha256.hexdigest()
        size = n
        size_label = f"{n} files (dir fingerprint)"
    else:
        with open(fpath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)
        digest = sha256.hexdigest()
        size = fpath.stat().st_size
        size_label = f"{size:,} bytes"

    mgr = _get_sqlite_mgr()
    from nexus.audit import resolve_examiner
    mgr.add_evidence(
        case_id=case_id,
        name=fpath.name,
        description=description,
        file_path=str(fpath.resolve()),
        file_hash_sha256=digest,
        collected_by=resolve_examiner(),
    )

    typer.echo(f"Registered: {fpath.name}")
    typer.echo(f"  SHA-256: {digest}")
    typer.echo(f"  Size: {size_label}")


@app.command()
def list(
    case_id: str = typer.Option("", "--case", help="Case ID (defaults to active)"),
):
    """List registered evidence files."""
    if not case_id:
        case_id = _get_active_case_id() or ""
    if not case_id:
        typer.echo("No active case. Use 'nexus case activate' first.", err=True)
        raise typer.Exit(1)

    mgr = _get_sqlite_mgr()
    if mgr.get_case(case_id) is None:
        typer.echo(f"Case not found: {case_id}", err=True)
        raise typer.Exit(1)

    evidence_list = mgr.list_evidence(case_id)
    if not evidence_list:
        typer.echo("No evidence registered")
        return

    for ev in evidence_list:
        fname = Path(ev.file_path).name if ev.file_path else ev.name
        sha = (ev.file_hash_sha256 or "")[:16]
        desc = ev.description[:40] if ev.description else ""
        typer.echo(f"  {fname:30s} {sha}...  {desc}")


@app.command()
def verify(
    case_id: str = typer.Option("", "--case", help="Case ID (defaults to active)"),
):
    """Re-hash registered evidence to verify integrity."""
    if not case_id:
        case_id = _get_active_case_id() or ""
    if not case_id:
        typer.echo("No active case. Use 'nexus case activate' first.", err=True)
        raise typer.Exit(1)

    mgr = _get_sqlite_mgr()
    evidence_list = mgr.list_evidence(case_id)
    if not evidence_list:
        typer.echo("No evidence registered")
        return

    all_ok = True
    for ev in evidence_list:
        fpath = Path(ev.file_path) if ev.file_path else None
        if fpath is None or not fpath.exists():
            typer.echo(f"  MISSING: {ev.name}")
            all_ok = False
            continue

        sha256 = hashlib.sha256()
        with open(fpath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)
        digest = sha256.hexdigest()

        if digest == ev.file_hash_sha256:
            typer.echo(f"  OK {ev.name}")
        else:
            typer.echo(f"  HASH MISMATCH: {ev.name}")
            all_ok = False

    if all_ok:
        typer.echo("All evidence verified OK")


@app.command()
def lock(
    case_id: str = typer.Option("", "--case", help="Case ID (defaults to active)"),
):
    """Lock evidence directory to read-only to prevent tampering."""
    if not case_id:
        case_id = _get_active_case_id() or ""
    mgr = _get_sqlite_mgr()
    evidence_list = mgr.list_evidence(case_id)
    count = 0
    for ev in evidence_list:
        fpath = Path(ev.file_path) if ev.file_path else None
        if fpath and fpath.exists():
            try:
                current = stat.S_IMODE(fpath.stat().st_mode)
                fpath.chmod(current & ~stat.S_IWUSR & ~stat.S_IWGRP & ~stat.S_IWOTH)
                count += 1
            except OSError as err:
                typer.echo(f"  Could not lock {fpath.name}: {err}")
    typer.echo(f"Locked {count} evidence files (read-only)")


@app.command()
def unlock(
    case_id: str = typer.Option("", "--case", help="Case ID (defaults to active)"),
):
    """Unlock evidence directory for new files."""
    if not case_id:
        case_id = _get_active_case_id() or ""
    mgr = _get_sqlite_mgr()
    evidence_list = mgr.list_evidence(case_id)
    count = 0
    for ev in evidence_list:
        fpath = Path(ev.file_path) if ev.file_path else None
        if fpath and fpath.exists():
            try:
                current = stat.S_IMODE(fpath.stat().st_mode)
                fpath.chmod(current | stat.S_IWUSR)
                count += 1
            except OSError as err:
                typer.echo(f"  Could not unlock {fpath.name}: {err}")
    typer.echo(f"Unlocked {count} evidence files")
