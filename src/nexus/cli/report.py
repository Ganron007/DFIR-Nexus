"""Report generation from approved findings — backed by SQLite case stack."""

import json
from datetime import datetime
from pathlib import Path

import typer

app = typer.Typer(help="Generate investigation reports")

_ACTIVE_CASE_FILE = Path.home() / ".nexus" / "active_case"


def _normalize_case_ref(raw: str) -> tuple[str, Path]:
    """Turn an ID or absolute case dir into ``(case_id, case_dir)``."""
    from nexus.config import settings

    raw = (raw or "").strip().strip('"')
    p = Path(raw)
    if p.is_absolute():
        case_dir = p if p.is_dir() else settings.cases_root / p.name
        return case_dir.name, case_dir
    cid = Path(raw).name
    return cid, settings.cases_root / cid


def _get_active_case_id() -> str | None:
    if _ACTIVE_CASE_FILE.exists():
        content = _ACTIVE_CASE_FILE.read_text().strip()
        if content:
            return content
    return None


def _finding_dicts(findings) -> list[dict]:
    out = []
    for f in findings:
        d = f.to_dict() if hasattr(f, "to_dict") else dict(f)
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
        d = ev.to_dict() if hasattr(ev, "to_dict") else dict(ev)
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
    from nexus.config import settings

    candidate: Path | None = None
    if not case_id:
        from nexus.case.outputs import resolve_active_case_dir

        resolved = resolve_active_case_dir()
        if resolved is not None:
            case_id, candidate = resolved.name, resolved
        else:
            case_id = _get_active_case_id() or ""
    if not case_id:
        typer.echo("No active case.", err=True)
        raise typer.Exit(1)
    if candidate is None:
        case_id, candidate = _normalize_case_ref(case_id)

    from nexus.case import CaseManager
    db_path = settings.cases_root / "cases.db"
    mgr = CaseManager(db_path)

    # HMAC CLI/portal write findings.json — prefer that store when present.
    if candidate.is_dir() and (candidate / "findings.json").is_file():
        try:
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
            intake = meta.get("intake") if isinstance(meta.get("intake"), dict) else {}
            case_summary = (
                str(intake.get("question") or "")
                or meta.get("case_summary")
                or meta.get("summary")
                or meta.get("description")
                or ""
            )
            from nexus.integration.dfir_report import (
                _split_questions,
                build_dfir_markdown,
                load_case_ledger,
                sift_notes_from_ledger,
            )
            questions = _split_questions(
                str(intake.get("question") or meta.get("question") or "")
            )
            approved_flat = [
                f for f in findings
                if str(f.get("status") or f.get("approval_state") or "").upper() == "APPROVED"
            ]
            typer.echo(
                f"Case {candidate.name}: {len(approved_flat)} APPROVED / {len(findings)} findings. "
                "Rebuilding N7 timeline (CSV scan; can take a minute)..."
            )
            try:
                from nexus.langgraph.timeline_merge import rebuild_case_timeline
                timeline = rebuild_case_timeline(candidate)
            except Exception:
                if not isinstance(timeline, list):
                    timeline = []
            ledger = load_case_ledger(candidate)
            if profile.lower() in ("dfir", "full", "narrative"):
                report_text = build_dfir_markdown(
                    case_id=candidate.name,
                    case_name=meta.get("name") or candidate.name,
                    findings=findings,
                    evidence=evidence,
                    timeline=timeline if isinstance(timeline, list) else [],
                    sift_notes=sift_notes_from_ledger(ledger),
                    examiner=meta.get("examiner") or meta.get("created_by") or "",
                    status=str(meta.get("status") or "open"),
                    severity=str(meta.get("severity") or "unrated"),
                    case_summary=str(case_summary),
                    tool_ledger=ledger,
                    questions=questions,
                )
            else:
                approved = [f for f in findings if str(f.get("status", "")).upper() == "APPROVED"]
                lines = ["# DFIR-Nexus IR Report (flat-JSON stack)", ""]
                lines.append(f"## Case: {candidate.name}")
                lines.append(f"- Total findings: {len(findings)} ({len(approved)} approved)")
                lines.append("")
                for f in approved:
                    lines.append(f"### {f.get('title', 'Untitled')}")
                    lines.append(str(f.get("description") or f.get("observation") or ""))
                    lines.append("")
                report_text = "\n".join(lines)
            if not approved_flat:
                from nexus.integration.dfir_report import write_findings_preview
                preview = write_findings_preview(candidate)
                typer.echo(
                    "No APPROVED findings — official REPORT.md would be empty. "
                    f"Wrote examiner preview: {preview}",
                    err=True,
                )
                return
            if not save:
                save = str(candidate / "reports" / "REPORT.md")
            if save:
                out = Path(save)
                out.parent.mkdir(parents=True, exist_ok=True)
                out.write_text(report_text, encoding="utf-8")
                typer.echo(f"Saved to {out}")
            else:
                typer.echo(report_text)
            return
        except Exception as exc:
            typer.echo(f"Flat-JSON report failed: {exc}", err=True)

    case = mgr.get_case(case_id)
    if case is None:
        typer.echo(f"Case not found in SQLite stack: {case_id}", err=True)
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
        from nexus.integration.dfir_report import (
            _split_questions,
            build_dfir_markdown,
            load_case_ledger,
            sift_notes_from_ledger,
        )
        tl = []
        for e in timeline_list or []:
            if hasattr(e, "to_dict"):
                tl.append(e.to_dict())
            else:
                tl.append(dict(e) if isinstance(e, dict) else {"description": str(e)})
        flat_dir = settings.cases_root / case.id
        try:
            from nexus.langgraph.timeline_merge import rebuild_case_timeline
            rebuilt = rebuild_case_timeline(flat_dir)
            if rebuilt:
                tl = rebuilt
        except Exception:
            pass
        case_summary = getattr(case, "description", "") or ""
        ledger = load_case_ledger(flat_dir) if flat_dir.is_dir() else []
        questions = _split_questions(case_summary)
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
            sift_notes=sift_notes_from_ledger(ledger),
            examiner=case.created_by or "",
            status=case.status.value,
            severity=getattr(getattr(case, "severity", None), "value", None) or "unrated",
            case_summary=str(case_summary),
            tool_ledger=ledger,
            questions=questions,
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

    if not approved:
        from nexus.integration.dfir_report import write_findings_preview

        preview = write_findings_preview(settings.cases_root / case.id)
        typer.echo(
            "No APPROVED findings — official REPORT.md would be empty. "
            f"Wrote examiner preview: {preview}",
            err=True,
        )
        return

    if not save:
        save = str(settings.cases_root / case.id / "reports" / "REPORT.md")
    out = Path(save)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(report_text, encoding="utf-8")
    typer.echo(f"Saved to {out}")
