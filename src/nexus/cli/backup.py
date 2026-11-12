"""Case backup and restore."""

import hashlib
import json
import zipfile
from datetime import UTC, datetime
from pathlib import Path

import typer

app = typer.Typer(help="Backup and restore cases")


def _resolve_case_dir(case: str) -> Path | None:
    """The folder of the case a backup names. Never the active case (WO-R2F item 1, D41)."""
    from nexus.config import settings

    name = (case or "").strip()
    if not name:
        return None
    case_dir = Path(name) if Path(name).is_absolute() else settings.cases_root / name
    return case_dir if case_dir.exists() else None


@app.command()
def create(
    path: str = typer.Argument(..., help="Backup destination path"),
    case: str = typer.Option("", "--case", help="Case id (required)"),
    all_data: bool = typer.Option(False, "--all", help="Include evidence and triage data"),
    verify: bool = typer.Option(True, "--verify", help="Verify backup integrity after creation"),
    skip_ledger: bool = typer.Option(False, "--skip-ledger", help="Skip archiving verification ledger"),
):
    """Backup the named case to a ZIP archive with SHA-256 manifest."""
    case_dir = _resolve_case_dir(case)
    if not case_dir:
        typer.echo("Pass --case <id>: a backup names the case it archives.", err=True)
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

        # Archive verification ledger if available
        if not skip_ledger:
            try:
                from nexus.auth import VERIFICATION_DIR
                ledger_src = VERIFICATION_DIR / f"{case_dir.name}.jsonl"
                if ledger_src.is_file():
                    data = ledger_src.read_bytes()
                    zf.writestr("_verification_ledger.jsonl", data)
                    manifest["_verification_ledger.jsonl"] = hashlib.sha256(data).hexdigest()
            except Exception:
                pass

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
    target_dir: str = typer.Option("", "--target-dir", "-t", help="Custom destination directory"),
    cases_root: str = typer.Option("", "--cases-root", help="Custom cases root directory"),
    skip_ledger: bool = typer.Option(False, "--skip-ledger", help="Skip restoring verification ledger"),
    no_activate: bool = typer.Option(False, "--no-activate", help="Do not set restored case as active"),
    force: bool = typer.Option(False, "--force", "-f", help="Overwrite without confirmation and bypass checksum errors"),
):
    """Restore a case from backup with manifest verification and path validation."""
    from nexus.config import settings

    src = Path(path)
    if not src.exists():
        typer.echo(f"Backup file not found: {path}", err=True)
        raise typer.Exit(1)

    typer.echo(f"Restoring from {src}...")

    # Manifest and file integrity verification prior to extraction (D533)
    if not force:
        ok, detail = _verify_backup(src)
        if not ok:
            typer.echo(f"Refusing restore: backup integrity verification failed ({detail}). Pass --force to override.", err=True)
            raise typer.Exit(1)

    with zipfile.ZipFile(src, "r") as zf:
        try:
            manifest_raw = zf.read("_backup_manifest.json")
            manifest = json.loads(manifest_raw)
            case_id = manifest.get("case_id", "restored")
        except (KeyError, json.JSONDecodeError):
            case_id = "restored"

        if target_dir:
            target = Path(target_dir).resolve()
        else:
            root = Path(cases_root).resolve() if cases_root else settings.cases_root
            target = (root / case_id).resolve()

        if target.exists() and not force:
            overwrite = typer.confirm(f"Case directory {target} already exists. Overwrite?", default=False)
            if not overwrite:
                typer.echo("Restore cancelled.")
                return

        target.mkdir(parents=True, exist_ok=True)
        restored = 0
        for info in zf.infolist():
            if info.filename.startswith("_backup_manifest") or info.filename.startswith("_file_manifest"):
                continue
            if info.filename == "_verification_ledger.jsonl":
                continue

            # Safe extraction path validation: reject path traversal and escape (D533)
            rel_path = Path(info.filename)
            if rel_path.is_absolute() or ".." in rel_path.parts:
                typer.echo(f"Path traversal detected in archive entry: {info.filename}. Aborting restore.", err=True)
                raise typer.Exit(1)

            dest_file = (target / rel_path).resolve()
            if not str(dest_file).startswith(str(target)):
                typer.echo(f"Path escape detected: {dest_file} is outside target root {target}. Aborting restore.", err=True)
                raise typer.Exit(1)

            data = zf.read(info.filename)
            dest_file.parent.mkdir(parents=True, exist_ok=True)
            dest_file.write_bytes(data)
            restored += 1

        # Restore verification ledger if present
        if not skip_ledger and "_verification_ledger.jsonl" in zf.namelist():
            try:
                from nexus.auth import VERIFICATION_DIR
                VERIFICATION_DIR.mkdir(parents=True, exist_ok=True)
                ledger_target = VERIFICATION_DIR / f"{case_id}.jsonl"
                ledger_data = zf.read("_verification_ledger.jsonl")
                ledger_target.write_bytes(ledger_data)
                typer.echo(f"  Restored verification ledger: {ledger_target}")
            except Exception as exc:
                typer.echo(f"  Warning: could not restore verification ledger: {exc}")

    typer.echo(f"  Restored {restored} files to {target}")

    # Register in canonical DB
    try:
        from nexus.case_manager import get_case_manager
        mgr = get_case_manager()
        mgr.register_case(case_id, target, name=f"Restored: {case_id}")
    except Exception as exc:
        typer.echo(f"  Note: canonical case DB registration: {exc}")

    if not no_activate:
        try:
            from nexus.config import set_active_case
            set_active_case(case_id)
        except Exception:
            active_file = settings.active_case_file
            active_file.parent.mkdir(parents=True, exist_ok=True)
            active_file.write_text(str(target), encoding="utf-8")
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
