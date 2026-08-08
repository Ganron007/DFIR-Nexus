"""Case lifecycle commands — backed by the SQLite case stack."""

from pathlib import Path

import typer

app = typer.Typer(help="Manage investigation cases")

_ACTIVE_CASE_FILE = Path.home() / ".nexus" / "active_case"


def _get_sqlite_mgr():
    from nexus.case import CaseManager
    from nexus.config import settings
    db_path = settings.cases_root / "cases.db"
    return CaseManager(db_path)


def _get_active_case_id() -> str | None:
    if _ACTIVE_CASE_FILE.exists():
        content = _ACTIVE_CASE_FILE.read_text().strip()
        if content:
            return content
    return None


def _set_active_case(case_id: str) -> None:
    _ACTIVE_CASE_FILE.parent.mkdir(parents=True, exist_ok=True)
    _ACTIVE_CASE_FILE.write_text(case_id)


@app.command()
def init(
    name: str = typer.Argument(..., help="Case name"),
    case_id: str = typer.Option("", "--case-id", help="Custom case ID"),
):
    """Create a new investigation case."""
    mgr = _get_sqlite_mgr()
    try:
        case = mgr.create_case(name=name, description=f"Case: {name}", case_id=case_id)
    except ValueError as e:
        typer.echo(str(e), err=True)
        raise typer.Exit(1) from None
    _set_active_case(case.id)
    typer.echo(f"Case '{name}' created (ID: {case.id})")
    typer.echo(f"Active case set to: {case.id}")


@app.command()
def activate(case_id: str = typer.Argument(..., help="Case ID to activate")):
    """Activate an existing case."""
    mgr = _get_sqlite_mgr()
    case = mgr.get_case(case_id)
    if case is None:
        typer.echo(f"Case not found: {case_id}", err=True)
        raise typer.Exit(1)
    _set_active_case(case_id)
    typer.echo(f"Case {case_id} activated ({case.name})")


@app.command()
def close(case_id: str = typer.Argument("", help="Case ID to close (defaults to active)")):
    """Close a case."""
    if not case_id:
        case_id = _get_active_case_id() or ""
    if not case_id:
        typer.echo("No case specified and no active case", err=True)
        raise typer.Exit(1)
    mgr = _get_sqlite_mgr()
    from nexus.audit import resolve_examiner
    analyst = resolve_examiner()
    closed = mgr.close_case(case_id, closed_by=analyst)
    if closed is None:
        typer.echo(f"Case not found: {case_id}", err=True)
        raise typer.Exit(1)
    typer.echo(f"Case {case_id} closed")


@app.command()
def reopen(case_id: str = typer.Argument("", help="Case ID to reopen (defaults to active)")):
    """Reopen a closed case."""
    if not case_id:
        case_id = _get_active_case_id() or ""
    if not case_id:
        typer.echo("No case specified and no active case", err=True)
        raise typer.Exit(1)
    mgr = _get_sqlite_mgr()
    from nexus.case import CaseStatus
    updated = mgr.update_status(case_id, CaseStatus.OPEN)
    if updated is None:
        typer.echo(f"Case not found: {case_id}", err=True)
        raise typer.Exit(1)
    typer.echo(f"Case {case_id} reopened")


@app.command(name="list")
def list_cases():
    """List all cases."""
    mgr = _get_sqlite_mgr()
    cases = mgr.list_cases()
    if not cases:
        typer.echo("No cases found.")
        return
    for c in cases:
        ts = c.created_at.strftime("%Y-%m-%d") if c.created_at else ""
        findings = len(mgr.list_findings(c.id))
        typer.echo(f"  {c.id:20s} {c.status.value:12s} {findings:3d} findings  {ts}  {c.name}")


@app.command()
def migrate(
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview without importing"),
):
    """Migrate legacy flat-JSON cases into the SQLite case stack."""
    from nexus.case import LegacyJsonImporter
    from nexus.config import settings

    cases_root = settings.cases_root
    importer = LegacyJsonImporter()
    mgr = _get_sqlite_mgr()

    existing_ids = {c.id for c in mgr.list_cases()}
    typer.echo(f"Scanning {cases_root} for legacy cases...")

    found = 0
    for case_dir in sorted(cases_root.iterdir()):
        if not case_dir.is_dir():
            continue
        cid = case_dir.name
        # only consider directories that have findings.json or CASE.yaml and are not already imported
        has_data = (case_dir / "findings.json").exists() or (case_dir / "CASE.yaml").exists()
        if not has_data:
            continue
        found += 1
        if cid in existing_ids:
            typer.echo(f"  {cid}: already in SQLite — skipping")
            continue
        if dry_run:
            typer.echo(f"  {cid}: would import")
            continue

        imported = importer.import_case(case_dir)
        if imported:
            fc = len(mgr.list_findings(cid))
            typer.echo(f"  {cid}: imported ({fc} findings)")
        else:
            typer.echo(f"  {cid}: import failed", err=True)

    if found == 0:
        typer.echo("No legacy cases found.")
    elif dry_run:
        pending = sum(1 for c in sorted(cases_root.iterdir()) if c.is_dir() and c.name not in existing_ids)
        typer.echo(f"\n{pending} cases would be imported (remove --dry-run to execute)")
    else:
        typer.echo("\nMigration complete.")
