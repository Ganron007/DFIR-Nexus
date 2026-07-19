"""Case review and audit queries — backed by SQLite case stack."""

from pathlib import Path

import typer

app = typer.Typer(help="Review case state")

_ACTIVE_CASE_FILE = Path.home() / ".nexus" / "active_case"


def _get_active_case_id() -> str | None:
    if _ACTIVE_CASE_FILE.exists():
        content = _ACTIVE_CASE_FILE.read_text().strip()
        if content:
            return content
    return None


def _get_case_mgr(case_id: str = ""):
    from nexus.case import CaseManager
    from nexus.config import settings
    db_path = settings.cases_root / "cases.db"
    return CaseManager(db_path)


@app.command()
def findings(
    case_id: str = typer.Option("", "--case", help="Case ID (defaults to active)"),
    detail: bool = typer.Option(False, "--detail", "-d"),
    limit: int = typer.Option(20, "--limit", "-l"),
    status: str = typer.Option("", "--status", help="Filter by status: draft, approved, rejected"),
):
    """List findings."""
    if not case_id:
        case_id = _get_active_case_id() or ""
    if not case_id:
        typer.echo("No active case.", err=True)
        raise typer.Exit(1)

    mgr = _get_case_mgr()
    findings_list = mgr.list_findings(case_id)
    if status:
        findings_list = [f for f in findings_list if f.approval_state.value == status.lower()]
    findings_list = findings_list[:limit]

    if not findings_list:
        typer.echo("No findings.")
        return

    for f in findings_list:
        state = f.approval_state.value
        typer.echo(f"  [{state:10s}] {f.id}  {f.title[:60]}")
        if detail:
            if f.description:
                typer.echo(f"           {f.description[:120]}")
            if f.technique_ids:
                typer.echo(f"           MITRE: {', '.join(f.technique_ids[:5])}")


@app.command()
def timeline(
    case_id: str = typer.Option("", "--case", help="Case ID (defaults to active)"),
    start: str = typer.Option("", "--start"),
    end: str = typer.Option("", "--end"),
    event_type: str = typer.Option("", "--type"),
):
    """List timeline events (flat-JSON only for now)."""
    if not case_id:
        case_id = _get_active_case_id() or ""
    if not case_id:
        typer.echo("No active case.", err=True)
        raise typer.Exit(1)

    from nexus.case_manager import CaseManager as FlatCaseManager
    mgr = FlatCaseManager()
    try:
        events = mgr.get_timeline(status=None, event_type=event_type or None,
                                  start_date=start or None, end_date=end or None)
    except Exception:
        events = []

    if not events:
        typer.echo("No timeline events.")
        return

    for ev in events[:50]:
        ts = ev.get("timestamp", "")[:19]
        desc = ev.get("description", "")[:80]
        typer.echo(f"  {ts}  {desc}")


@app.command()
def iocs(
    case_id: str = typer.Option("", "--case", help="Case ID (defaults to active)"),
):
    """List IOCs (flat-JSON only for now)."""
    if not case_id:
        case_id = _get_active_case_id() or ""
    if not case_id:
        typer.echo("No active case.", err=True)
        raise typer.Exit(1)

    from nexus.case_manager import CaseManager as FlatCaseManager
    mgr = FlatCaseManager()
    try:
        ioc_list = mgr.get_iocs()
    except Exception:
        ioc_list = []

    if not ioc_list:
        typer.echo("No IOCs.")
        return

    for ioc in ioc_list[:50]:
        val = ioc.get("value", "")[:60]
        ioc_type = ioc.get("type", "")
        typer.echo(f"  [{ioc_type:20s}] {val}")


@app.command()
def audit(
    case_id: str = typer.Option("", "--case", help="Case ID (defaults to active)"),
    limit: int = typer.Option(100, "--limit", "-l"),
):
    """View audit trail."""
    if not case_id:
        case_id = _get_active_case_id() or ""
    if not case_id:
        typer.echo("No active case.", err=True)
        raise typer.Exit(1)

    mgr = _get_case_mgr()
    entries = mgr.get_audit_log(case_id)[:limit]
    if not entries:
        typer.echo("No audit entries.")
        return

    for e in entries:
        ts = e.timestamp.isoformat()[:19] if e.timestamp else ""
        act = e.action.value
        actor = e.actor
        typer.echo(f"  {ts}  [{act:25s}] {actor}")


@app.command()
def todos(
    case_id: str = typer.Option("", "--case", help="Case ID (defaults to active)"),
    open_only: bool = typer.Option(False, "--open"),
):
    """List TODOs (flat-JSON only for now)."""
    if not case_id:
        case_id = _get_active_case_id() or ""
    if not case_id:
        typer.echo("No active case.", err=True)
        raise typer.Exit(1)

    from nexus.case_manager import CaseManager as FlatCaseManager
    mgr = FlatCaseManager()
    try:
        todo_list = mgr.list_todos(status="open" if open_only else "all")
    except Exception:
        todo_list = []

    if not todo_list:
        typer.echo("No TODOs.")
        return

    for t in todo_list:
        tid = t.get("id", "")
        desc = t.get("description", "")[:80]
        status = t.get("status", "")
        typer.echo(f"  [{status:10s}] {tid}  {desc}")


@app.command()
def verify(
    case_id: str = typer.Option("", "--case", help="Case ID (defaults to active)"),
):
    """HMAC audit-chain integrity verification."""
    if not case_id:
        case_id = _get_active_case_id() or ""
    if not case_id:
        typer.echo("No active case.", err=True)
        raise typer.Exit(1)

    mgr = _get_case_mgr()
    ok, errors = mgr.verify_audit_chain(case_id)
    if ok:
        typer.echo("Audit chain verified — integrity intact.")
    else:
        typer.echo("Audit chain verification FAILED:", err=True)
        for err in errors[:10]:
            typer.echo(f"  {err}", err=True)
