"""Case backup and restore."""

import hashlib
import json
import zipfile
from datetime import UTC, datetime
from pathlib import Path

import typer

app = typer.Typer(help="Backup and restore cases")


def _resolve_case_dir() -> Path | None:
    active = Path.home() / ".nexus" / "active_case"
    if active.exists():
        content = active.read_text().strip()
        if content:
            case_dir = Path(content) if Path(content).is_absolute() else Path.home() / ".nexus" / "cases" / content
            if case_dir.exists():
                return case_dir
    return None


@app.command()
def create(
    path: str = typer.Argument(..., help="Backup destination path"),
    all_data: bool = typer.Option(False, "--all", help="Include evidence and triage data"),
    verify: bool = typer.Option(True, "--verify", help="Verify backup integrity after creation"),
):
    """Backup the active case to a ZIP archive with SHA-256 manifest."""
    case_dir = _resolve_case_dir()
    if not case_dir:
        typer.echo("No active case. Use 'nexus case activate' first.", err=True)
        raise typer.Exit(1)

    dest = Path(path)
    if dest.suffix.lower() != ".zip":
        dest = dest.with_suffix(".zip")
    dest.parent.mkdir(parents=True, exist_ok=True)

    typer.echo(f"Backing up {case_dir.name} to {dest}...")
    manifest: dict[str, str] = {}
    file_count = 0

    with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("_backup_manifest.json", json.dumps({
            "case_id": case_dir.name,
            "created_at": datetime.now(UTC).isoformat(),
            "source": str(case_dir),
        }, indent=2))

        for fpath in sorted(case_dir.rglob("*")):
            if fpath.is_file():
                arcname = fpath.relative_to(case_dir).as_posix()
                zf.write(fpath, arcname)
                sha = hashlib.sha256(fpath.read_bytes()).hexdigest()
                manifest[arcname] = sha
                file_count += 1

        zf.writestr("_file_manifest.json", json.dumps(manifest, indent=2))

    backup_sha = hashlib.sha256(dest.read_bytes()).hexdigest()
    typer.echo(f"  Files: {file_count}")
    typer.echo(f"  Archive SHA-256: {backup_sha}")

    if verify:
        typer.echo("  Verifying...")
        ok, detail = _verify_backup(dest)
        if ok:
            typer.echo(f"  Verified: {detail}")
        else:
            typer.echo(f"  Verification FAILED: {detail}", err=True)
            raise typer.Exit(1)

    typer.echo(f"Backup complete: {dest}")


@app.command()
def restore(
    path: str = typer.Argument(..., help="Backup file to restore"),
    skip_ledger: bool = typer.Option(False, "--skip-ledger"),
):
    """Restore a case from backup."""
    src = Path(path)
    if not src.exists():
        typer.echo(f"Backup file not found: {path}", err=True)
        raise typer.Exit(1)

    typer.echo(f"Restoring from {src}...")

    with zipfile.ZipFile(src, "r") as zf:
        manifest_raw = zf.read("_backup_manifest.json")
        manifest = json.loads(manifest_raw)
        case_id = manifest.get("case_id", "restored")

        cases_dir = Path.home() / ".nexus" / "cases"
        target = cases_dir / case_id
        if target.exists():
            overwrite = typer.confirm(f"Case directory {target} already exists. Overwrite?", default=False)
            if not overwrite:
                typer.echo("Restore cancelled.")
                return

        target.mkdir(parents=True, exist_ok=True)
        restored = 0
        for info in zf.infolist():
            if info.filename.startswith("_backup_manifest") or info.filename.startswith("_file_manifest"):
                continue
            data = zf.read(info.filename)
            dest_file = target / info.filename
            dest_file.parent.mkdir(parents=True, exist_ok=True)
            dest_file.write_bytes(data)
            restored += 1

    typer.echo(f"  Restored {restored} files to {target}")
    active_file = Path.home() / ".nexus" / "active_case"
    active_file.write_text(str(target))
    typer.echo(f"  Active case set to: {target}")


@app.command()
def verify(
    path: str = typer.Argument(..., help="Backup path to verify"),
):
    """Verify backup integrity against embedded manifest."""
    src = Path(path)
    if not src.exists():
        typer.echo(f"Backup file not found: {path}", err=True)
        raise typer.Exit(1)

    ok, detail = _verify_backup(src)
    if ok:
        typer.echo(f"OK: {detail}")
    else:
        typer.echo(f"FAILED: {detail}", err=True)
        raise typer.Exit(1)


def _verify_backup(backup_path: Path) -> tuple[bool, str]:
    """Verify a backup archive against its embedded file manifest."""
    try:
        with zipfile.ZipFile(backup_path, "r") as zf:
            manifest = json.loads(zf.read("_file_manifest.json"))
            mismatches = []
            for arcname, expected_sha in manifest.items():
                try:
                    data = zf.read(arcname)
                    actual_sha = hashlib.sha256(data).hexdigest()
                    if actual_sha != expected_sha:
                        mismatches.append(arcname)
                except KeyError:
                    mismatches.append(f"{arcname} (missing)")
            if mismatches:
                return False, f"{len(mismatches)} file(s) mismatched: {mismatches[:5]}"
            return True, f"{len(manifest)} file(s) verified"
    except (zipfile.BadZipFile, json.JSONDecodeError, KeyError) as exc:
        return False, f"Invalid backup: {exc}"
