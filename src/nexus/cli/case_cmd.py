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


def _case_dir(case_id: str = "") -> Path:
    from nexus.config import settings

    cid = case_id or _get_active_case_id() or ""
    if not cid:
        typer.echo("No case specified and no active case", err=True)
        raise typer.Exit(1)
    path = settings.cases_root / cid
    if not path.is_dir():
        typer.echo(f"Case directory missing: {path}", err=True)
        raise typer.Exit(1)
    return path


@app.command("index")
def index_case(
    case_id: str = typer.Argument("", help="Case ID (defaults to active)"),
):
    """N3: index this case's processed outputs into Elasticsearch (NEXUS_ES_URL)."""
    from nexus.langgraph.case_index import es_available, es_url
    from nexus.langgraph.case_index import index_case as _index
    from nexus.langgraph.query_pack import collect_query_terms, load_case_intake

    if not es_url():
        typer.echo("NEXUS_ES_URL is empty — CSV pack remains the N4 backend.", err=True)
        raise typer.Exit(2)
    if not es_available():
        typer.echo(f"Elasticsearch not reachable at {es_url()}", err=True)
        raise typer.Exit(2)
    case_dir = _case_dir(case_id)
    terms = collect_query_terms(load_case_intake(case_dir))
    meta = _index(case_dir, extra_needles=terms)
    typer.echo(f"Indexed {meta.get('docs')} docs into {meta.get('index')}")


@app.command("query")
def query_case(
    case_id: str = typer.Argument("", help="Case ID (defaults to active)"),
    needles: str = typer.Option(
        "",
        "--needles",
        help="Extra search terms (comma-separated). Searches processed output, not raw evidence.",
    ),
    persist: bool = typer.Option(
        True,
        "--persist/--no-persist",
        help="Save needles on CASE.yaml intake.query_extra and rebuild query_pack.md",
    ),
    limit: int = typer.Option(50, "--limit", help="Max hits to print"),
    backend: str = typer.Option("auto", "--backend", help="auto | csv | es"),
):
    """N4: search this case's processed outputs (CSV pack or Elasticsearch)."""
    from nexus.langgraph.query_pack import _parse_needles, run_ad_hoc_query

    case_dir = _case_dir(case_id)
    extras = _parse_needles(needles)
    result = run_ad_hoc_query(
        case_dir,
        extra_needles=extras,
        persist=persist,
        backend=backend,
        limit=limit,
    )
    typer.echo(
        f"backend={result.get('backend')} hits={result.get('count')} "
        f"terms={len(result.get('terms') or [])} persist={result.get('persisted')}"
    )
    if result.get("empty"):
        typer.echo("No rows matched. INSUFFICIENT — do not invent findings.")
        return
    for hit in result.get("hits") or []:
        loc = f"{hit.get('file')}:{hit.get('line')}"
        typer.echo(f"{hit.get('family')}\t{loc}\t{hit.get('terms')}\t{hit.get('text')}")


@app.command("detections")
def detections_case(
    case_id: str = typer.Argument("", help="Case ID (defaults to active)"),
    finding_ids: str = typer.Option(
        "",
        "--finding-ids",
        help="Comma-separated this-run finding IDs (skip leftover APPROVED rows)",
    ),
):
    """D1: draft Sigma/KQL/Suricata from APPROVED findings (file for SIEM, not N5)."""
    from nexus.detection.draft_from_findings import draft_from_approved

    case_dir = _case_dir(case_id)
    ids = [x.strip() for x in finding_ids.split(",") if x.strip()] or None
    meta = draft_from_approved(case_dir, finding_ids=ids)
    typer.echo(f"Drafted {meta.get('dir')} from {meta.get('approved')} APPROVED findings")
    if meta.get("needles"):
        typer.echo("Needles: " + ", ".join(meta["needles"]))


@app.command("intake")
def intake_case(
    case_id: str = typer.Option("", "--case", help="Case ID (defaults to active)"),
    question: str = typer.Option("", "--question"),
    window: str = typer.Option("", "--window"),
    extras: str = typer.Option("", "--extras", help="chrome_profiles,drivefs,email,usb_serial"),
    playbooks: str = typer.Option("", "--playbooks"),
    query_extra: str = typer.Option("", "--query-extra", help="Persistent N4 needles"),
):
    """Update N1 intake on CASE.yaml (does not re-parse)."""
    from nexus.langgraph.case_intake import persist_case_intake

    case_dir = _case_dir(case_id)
    ctx = {}
    if question:
        ctx["question"] = question
    if window:
        ctx["window"] = window
    if extras:
        ctx["extras"] = extras
    if playbooks:
        ctx["playbooks"] = playbooks
    if query_extra:
        ctx["query_extra"] = query_extra
    written = persist_case_intake(case_dir, ctx)
    typer.echo(f"Intake fields: {', '.join(written) or '(none)'}")
