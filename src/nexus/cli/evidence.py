"""Evidence management — register, list, verify, lock, unlock.

Backed by the SQLite case stack.
"""

import hashlib
import os
import stat
from pathlib import Path

import typer

app = typer.Typer(help="Manage evidence files")

_ACTIVE_CASE_FILE = Path(
    os.environ.get("NEXUS_ACTIVE_CASE_FILE", str(Path.home() / ".nexus" / "active_case"))
)


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
    sift_hosted: bool = typer.Option(
        False, "--sift-hosted",
        help="Evidence lives on the SIFT host: PATH is the remote path; no local read",
    ),
    sha256_hash: str = typer.Option(
        "", "--sha256", help="Known SHA-256 for --sift-hosted evidence (computed on the SIFT host)"
    ),
):
    """Register an evidence file with SHA-256 hash."""
    if not case_id:
        case_id = _get_active_case_id() or ""
    if not case_id:
        typer.echo("No active case. Use 'nexus case activate' first.", err=True)
        raise typer.Exit(1)

    if sift_hosted:
        # Evidence on the SIFT host: path is remote, the local-existence check
        # must not apply. The hash is supplied (computed on the host) or left
        # empty - never invented.
        digest = sha256_hash.strip().lower()
        mgr = _get_sqlite_mgr()
        from nexus.audit import resolve_examiner

        mgr.add_evidence(
            case_id=case_id,
            name=Path(path).name,
            description=(f"[SIFT-hosted] {description}".strip()),
            file_path=path,
            file_hash_sha256=digest or None,
            collected_by=resolve_examiner(),
            metadata={"storage": "sift", "host": "sift", "remote_path": path},
        )
        typer.echo(f"Registered (SIFT-hosted): {Path(path).name}")
        typer.echo(f"  Remote path: {path}")
        typer.echo(f"  SHA-256: {digest or 'not provided'}")
        return

    fpath = Path(path)
    if not fpath.exists():
        typer.echo(f"Path not found: {path}", err=True)
        raise typer.Exit(1)

    from nexus.audit import resolve_examiner
    from nexus.case.evidence_service import register_evidence
    from nexus.config import settings

    # One registration path for every write path (evidence_service): the same hash rule,
    # the already-registered check, and every unreadable entry recorded with its reason.
    try:
        result = register_evidence(
            settings.cases_root / case_id, str(fpath.resolve()),
            description=description, examiner=resolve_examiner(),
        )
    except ValueError as err:
        typer.echo(str(err), err=True)
        raise typer.Exit(1) from err

    verb = "Registered" if result["status"] == "registered" else "Already registered"
    typer.echo(f"{verb}: {fpath.name or fpath}")
    typer.echo(f"  SHA-256: {result['sha256']}")
    if fpath.is_dir():
        typer.echo(f"  Size: {result['files']} files, {result['total_bytes']:,} bytes")
    else:
        typer.echo(f"  Size: {result['total_bytes']:,} bytes")
    if result.get("unreadable"):
        typer.echo(
            f"  Unreadable: {len(result['unreadable'])} entries recorded with their reasons"
        )


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


@app.command("status")
def status(
    case_id: str = typer.Option("", "--case", help="Case ID (defaults to active)"),
):
    """Show the captured evidence freshness state (WO-A5).

    Reads ``analysis/evidence_freshness.json`` — written automatically at
    lane start/end — rather than re-hashing anything; use
    ``nexus evidence verify`` for an on-demand re-hash.
    """
    import json as _json

    from nexus.config import settings

    if not case_id:
        case_id = _get_active_case_id() or ""
    if not case_id:
        typer.echo("No active case. Use 'nexus case activate' first.", err=True)
        raise typer.Exit(1)

    fp = Path(settings.cases_root) / case_id / "analysis" / "evidence_freshness.json"
    if not fp.is_file():
        typer.echo(
            f"No freshness state for {case_id} yet — it is captured at lane start/end."
        )
        return
    data = _json.loads(fp.read_text(encoding="utf-8"))
    typer.echo(
        f"Result: {data.get('result', 'unknown').upper()} "
        f"(captured {data.get('verified_at', '?')}, phase: {data.get('phase', '?')})"
    )
    for item in data.get("items") or []:
        mark = "OK" if item.get("valid") else "NOT OK"
        detail = item.get("error") or (
            "hash matches" if item.get("valid") else "hash mismatch"
        )
        typer.echo(f"  {mark} {item.get('name')} — {detail}")


@app.command("pair")
def pair(
    raw_name: str = typer.Argument(..., help="Raw artifact name"),
    output_name: str = typer.Argument(..., help="Pre-processed output file name"),
    output_sha256: str = typer.Option(..., "--sha256", help="SHA-256 of the pre-processed output"),
    confirm: bool = typer.Option(False, "--confirm", help="Record the audited pairing"),
    case_id: str = typer.Option("", "--case", help="Case ID (defaults to active)"),
):
    """Pair a raw artifact with a pre-processed output the examiner accepts."""
    from nexus.config import settings
    from nexus.langgraph.lane_gate import confirm_preprocessed_pair

    if not case_id:
        case_id = _get_active_case_id() or ""
    if not case_id:
        typer.echo("No active case. Use 'nexus case activate' first.", err=True)
        raise typer.Exit(1)
    if not confirm:
        typer.echo(
            f"Proposed: {raw_name} covered by {output_name} ({output_sha256}). "
            "Re-run with --confirm to record it."
        )
        return
    from nexus.audit import resolve_examiner

    gate = confirm_preprocessed_pair(
        Path(settings.cases_root) / case_id,
        raw_name=raw_name,
        output_name=output_name,
        output_sha256=output_sha256.strip().lower(),
        examiner=resolve_examiner(),
    )
    typer.echo(
        f"Paired {raw_name} -> {output_name}. Gate status: {gate.get('status', 'recorded')}."
    )


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
