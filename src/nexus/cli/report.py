"""Report generation from approved findings — backed by SQLite case stack."""

import json
from datetime import datetime
from pathlib import Path

import typer

app = typer.Typer(help="Generate investigation reports")

_ACTIVE_CASE_FILE = Path.home() / ".nexus" / "active_case"


def _get_active_case_id() -> str | None:
    if _ACTIVE_CASE_FILE.exists():
        content = _ACTIVE_CASE_FILE.read_text().strip()
        if content:
            return content
    return None


@app.command()
def generate(
    case_id: str = typer.Option("", "--case", help="Case ID (defaults to active)"),
    profile: str = typer.Option("full", "--profile", "-p", help="Report profile"),
    save: str = typer.Option("", "--save", "-s", help="Save to file"),
    from_date: str = typer.Option("", "--from", help="Start date"),
    to_date: str = typer.Option("", "--to", help="End date"),
):
    """Generate an IR report from approved findings."""
    if not case_id:
        case_id = _get_active_case_id() or ""
    if not case_id:
        typer.echo("No active case.", err=True)
        raise typer.Exit(1)

    from nexus.case import CaseManager
    from nexus.config import settings
    db_path = settings.cases_root / "cases.db"
    mgr = CaseManager(db_path)

    case = mgr.get_case(case_id)
    if case is None:
        typer.echo(f"Case not found in SQLite stack: {case_id}", err=True)
        typer.echo("Checking flat-JSON stack...", err=True)
        try:
            cases_root = Path.home() / ".nexus" / "cases"
            candidate = Path(case_id) if Path(case_id).is_absolute() else cases_root / case_id
            if candidate.exists() and (candidate / "findings.json").exists():
                findings = json.loads((candidate / "findings.json").read_text())
                approved = [f for f in findings if f.get("status") == "APPROVED"]
                lines = ["# DFIR-Nexus IR Report (flat-JSON stack)", ""]
                lines.append(f"## Case: {case_id}")
                lines.append(f"- Total findings: {len(findings)} ({len(approved)} approved)")
                lines.append("")
                if approved:
                    lines.append("## Approved Findings")
                    for f in approved:
                        lines.append(f"### {f.get('title', 'Untitled')}")
                        lines.append(f"- ID: {f.get('id', f.get('finding_id', '?'))}")
                        lines.append(f"- Severity: {f.get('severity', f.get('confidence', '?'))}")
                        lines.append(f"- Approved by: {f.get('approved_by', 'n/a')}")
                        if f.get("description"):
                            lines.append("")
                            lines.append(str(f["description"]))
                        lines.append("")
                report_text = "\n".join(lines)
                if save:
                    Path(save).write_text(report_text)
                    typer.echo(f"Saved to {save}")
                else:
                    typer.echo(report_text)
                return
        except Exception:
            pass
        typer.echo("Case not found in either stack.", err=True)
        raise typer.Exit(1)

    findings_list = mgr.list_findings(case_id)
    approved = [f for f in findings_list if f.approval_state.value == "approved"]
    evidence_list = mgr.list_evidence(case_id)

    date_filter_from = None
    date_filter_to = None
    if from_date:
        try:
            date_filter_from = datetime.fromisoformat(from_date)
        except ValueError:
            typer.echo(f"Invalid --from date: {from_date}", err=True)
            raise typer.Exit(1) from None
    if to_date:
        try:
            date_filter_to = datetime.fromisoformat(to_date)
        except ValueError:
            typer.echo(f"Invalid --to date: {to_date}", err=True)
            raise typer.Exit(1) from None

    if date_filter_from or date_filter_to:
        approved = [
            f for f in approved
            if f.approved_at and (
                (not date_filter_from or f.approved_at >= date_filter_from)
                and (not date_filter_to or f.approved_at <= date_filter_to)
            )
        ]

    lines: list[str] = []
    lines.append("# DFIR-Nexus IR Report")
    lines.append("")
    lines.append(f"## Case: {case.name} ({case.id})")
    lines.append(f"- Status: {case.status.value}")
    lines.append(f"- Severity: {case.severity.value}")
    lines.append(f"- Created: {case.created_at.isoformat()[:19] if case.created_at else ''}")
    lines.append(f"- Total findings: {len(findings_list)} ({len(approved)} approved)")
    lines.append(f"- Evidence files: {len(evidence_list)}")
    lines.append("")

    if approved:
        lines.append("## Approved Findings")
        lines.append("")
        for f in approved:
            lines.append(f"### {f.title}")
            lines.append(f"- ID: {f.id}")
            lines.append(f"- Severity: {f.severity.value}")
            lines.append(f"- Approved by: {f.approved_by or 'n/a'}")
            if f.technique_ids:
                lines.append(f"- MITRE: {', '.join(f.technique_ids)}")
            if f.description:
                lines.append("")
                lines.append(f.description)
            lines.append("")

    if evidence_list:
        lines.append("## Registered Evidence")
        lines.append("")
        for ev in evidence_list:
            lines.append(f"- {ev.name} (SHA-256: {ev.file_hash_sha256 or 'n/a'})")
        lines.append("")

    report_text = "\n".join(lines)

    if save:
        Path(save).write_text(report_text)
        typer.echo(f"Saved to {save}")
    else:
        typer.echo(report_text)
