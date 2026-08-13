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


def _finding_dicts(findings) -> list[dict]:
    out = []
    for f in findings:
        if hasattr(f, "to_dict"):
            d = f.to_dict()
        else:
            d = dict(f)
        # Normalize approval for DFIR renderer
        state = getattr(getattr(f, "approval_state", None), "value", None) or d.get("status") or d.get("approval_state")
        if state:
            d["status"] = str(state).upper()
            d["approval_state"] = str(state).upper()
        if hasattr(f, "severity") and hasattr(f.severity, "value"):
            d["severity"] = f.severity.value
        if hasattr(f, "technique_ids"):
            d["technique_ids"] = list(f.technique_ids or [])
            d["mitre_ids"] = list(f.technique_ids or [])
        if hasattr(f, "description"):
            d["description"] = f.description
            d["observation"] = f.description
        out.append(d)
    return out


def _evidence_dicts(evidence_list) -> list[dict]:
    out = []
    for ev in evidence_list:
        if hasattr(ev, "to_dict"):
            d = ev.to_dict()
        else:
            d = dict(ev)
        meta = dict(getattr(ev, "metadata", None) or d.get("metadata") or {})
        d["name"] = getattr(ev, "name", None) or d.get("name")
        d["path"] = getattr(ev, "file_path", None) or d.get("file_path") or d.get("path")
        d["sha256"] = getattr(ev, "file_hash_sha256", None) or d.get("sha256")
        d["description"] = getattr(ev, "description", None) or d.get("description")
        for k in ("host", "dest_ip", "source_ip", "process_name"):
            if meta.get(k):
                d[k] = meta[k]
        d["metadata"] = meta
        out.append(d)
    return out


def _load_flat_evidence(case_dir: Path) -> list[dict]:
    """Prefer evidence.json (product flat stack); fall back to evidence_registry.json."""
    for name in ("evidence.json", "evidence_registry.json"):
        path = case_dir / name
        if not path.exists():
            continue
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(raw, list):
            return raw
        if isinstance(raw, dict):
            items = raw.get("files") or raw.get("items") or raw.get("evidence") or []
            if isinstance(items, list):
                return items
    return []


def _extraction_notes(extractions_dir: Path, limit: int = 40) -> list[str]:
    """Surface on-disk tool outputs so the report is not hollow when notes were omitted."""
    if not extractions_dir.is_dir():
        return []
    notes: list[str] = []
    for path in sorted(extractions_dir.rglob("*")):
        if not path.is_file():
            continue
        if path.name.endswith(("_meta.json",)):
            continue
        rel = path.relative_to(extractions_dir).as_posix()
        try:
            size = path.stat().st_size
        except OSError:
            size = 0
        notes.append(f"`extractions/{rel}` ({size} bytes)")
        if len(notes) >= limit:
            break
    return notes


@app.command()
def generate(
    case_id: str = typer.Option("", "--case", help="Case ID (defaults to active)"),
    profile: str = typer.Option(
        "dfir",
        "--profile",
        "-p",
        help="Report profile: dfir (The DFIR Report style), full, executive",
    ),
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
                evidence = _load_flat_evidence(candidate)
                timeline = []
                if (candidate / "timeline.json").exists():
                    timeline = json.loads((candidate / "timeline.json").read_text())
                meta = {}
                for name in ("CASE.yaml", "case.json"):
                    p = candidate / name
                    if p.exists():
                        if name.endswith(".yaml"):
                            import yaml
                            meta = yaml.safe_load(p.read_text()) or {}
                        else:
                            meta = json.loads(p.read_text())
                        break
                case_summary = (
                    meta.get("case_summary")
                    or meta.get("summary")
                    or meta.get("description")
                    or ""
                )
                sift_notes = _extraction_notes(candidate / "extractions")
                if profile.lower() in ("dfir", "full", "narrative"):
                    from nexus.integration.dfir_report import build_dfir_markdown
                    report_text = build_dfir_markdown(
                        case_id=case_id if not Path(case_id).is_absolute() else candidate.name,
                        case_name=meta.get("name") or candidate.name,
                        findings=findings,
                        evidence=evidence,
                        timeline=timeline if isinstance(timeline, list) else [],
                        sift_notes=sift_notes,
                        examiner=meta.get("examiner") or meta.get("created_by") or "",
                        status=str(meta.get("status") or "open"),
                        severity=str(meta.get("severity") or "high"),
                        case_summary=str(case_summary),
                    )
                else:
                    approved = [f for f in findings if str(f.get("status", "")).upper() == "APPROVED"]
                    lines = ["# DFIR-Nexus IR Report (flat-JSON stack)", ""]
                    lines.append(f"## Case: {case_id}")
                    lines.append(f"- Total findings: {len(findings)} ({len(approved)} approved)")
                    lines.append("")
                    for f in approved:
                        lines.append(f"### {f.get('title', 'Untitled')}")
                        lines.append(str(f.get("description") or f.get("observation") or ""))
                        lines.append("")
                    report_text = "\n".join(lines)
                if save:
                    out = Path(save)
                    out.parent.mkdir(parents=True, exist_ok=True)
                    out.write_text(report_text, encoding="utf-8")
                    typer.echo(f"Saved to {out}")
                else:
                    typer.echo(report_text)
                return
        except Exception as exc:
            typer.echo(f"Flat-JSON fallback failed: {exc}", err=True)
        typer.echo("Case not found in either stack.", err=True)
        raise typer.Exit(1)

    findings_list = mgr.list_findings(case_id)
    approved = [f for f in findings_list if f.approval_state.value == "approved"]
    evidence_list = mgr.list_evidence(case_id)
    try:
        timeline_list = mgr.list_timeline(case_id) if hasattr(mgr, "list_timeline") else []
    except Exception:
        timeline_list = []

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

    if profile.lower() in ("dfir", "full", "narrative"):
        from nexus.integration.dfir_report import build_dfir_markdown
        tl = []
        for e in timeline_list or []:
            if hasattr(e, "to_dict"):
                tl.append(e.to_dict())
            else:
                tl.append(dict(e) if isinstance(e, dict) else {"description": str(e)})
        flat_dir = settings.cases_root / case.id
        case_summary = getattr(case, "description", "") or ""
        sift_notes = _extraction_notes(flat_dir / "extractions") if flat_dir.is_dir() else []
        # Merge flat evidence.json extractions into registry view when present
        flat_ev = _load_flat_evidence(flat_dir) if flat_dir.is_dir() else []
        evidence_dicts = _evidence_dicts(evidence_list)
        seen_paths = {e.get("path") for e in evidence_dicts if e.get("path")}
        for entry in flat_ev:
            if isinstance(entry, dict) and entry.get("path") not in seen_paths:
                evidence_dicts.append(entry)
        report_text = build_dfir_markdown(
            case_id=case.id,
            case_name=case.name,
            findings=_finding_dicts(approved),
            evidence=evidence_dicts,
            timeline=tl,
            sift_notes=sift_notes,
            examiner=case.created_by or "",
            status=case.status.value,
            severity=case.severity.value,
            case_summary=str(case_summary),
        )
    else:
        # Legacy compact markdown
        lines: list[str] = []
        lines.append("# DFIR-Nexus IR Report")
        lines.append("")
        lines.append(f"## Case: {case.name} ({case.id})")
        lines.append(f"- Status: {case.status.value}")
        lines.append(f"- Severity: {case.severity.value}")
        lines.append(f"- Total findings: {len(findings_list)} ({len(approved)} approved)")
        lines.append("")
        for f in approved:
            lines.append(f"### {f.title}")
            lines.append(f"- ID: {f.id}")
            lines.append(f"- Severity: {f.severity.value}")
            if f.description:
                lines.append("")
                lines.append(f.description)
            lines.append("")
        report_text = "\n".join(lines)

    if save:
        out = Path(save)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(report_text, encoding="utf-8")
        typer.echo(f"Saved to {out}")
    else:
        typer.echo(report_text)
