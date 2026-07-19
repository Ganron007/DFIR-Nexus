"""Case export — multiple output formats.

Exports a Case (with findings, evidence, audit log) to:
- JSON (full structured)
- Markdown (human-readable)
- HTML (formatted report with styling)
- STIX 2.0 (for sharing with other security tools)
"""

from __future__ import annotations

import html
import json
import logging
from datetime import UTC, datetime
from io import StringIO
from pathlib import Path
from typing import Any

from nexus.case import AuditEntry, Case, CaseManager, EvidenceRecord, Finding

log = logging.getLogger(__name__)


class CaseExporter:
    """Export a Case to various formats."""

    def __init__(self, manager: CaseManager) -> None:
        self.manager = manager

    def export(
        self,
        case_id: str,
        export_format: str,
        output_path: Path | str | None = None,
    ) -> str:
        """Export a case in the specified format."""
        case = self.manager.get_case(case_id)
        if case is None:
            raise ValueError(f"Case not found: {case_id}")
        findings = self.manager.list_findings(case_id)
        evidence = self.manager.list_evidence(case_id)
        audit = self.manager.get_audit_log(case_id)
        ok, errors = self.manager.verify_audit_chain(case_id)

        bundle = {
            "case": case,
            "findings": findings,
            "evidence": evidence,
            "audit_log": audit,
            "audit_verified": ok,
            "audit_errors": errors,
        }

        if export_format == "json":
            content = export_to_json(bundle)
        elif export_format == "markdown" or export_format == "md":
            content = export_to_markdown(bundle)
        elif export_format == "html":
            content = export_to_html(bundle)
        elif export_format == "stix" or export_format == "stix2":
            content = export_to_stix(bundle)
        else:
            raise ValueError(f"Unknown format: {export_format}")

        if output_path is not None:
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(content, encoding="utf-8")
            log.info("Exported case %s to %s", case_id, output_path)
        return content


def export_to_json(bundle: dict[str, Any]) -> str:
    """Export case bundle to JSON."""
    serializable = {
        "case": bundle["case"].to_dict(),
        "findings": [f.to_dict() for f in bundle["findings"]],
        "evidence": [e.to_dict() for e in bundle["evidence"]],
        "audit_log": [_audit_entry_to_dict(a) for a in bundle["audit_log"]],
        "audit_verified": bundle["audit_verified"],
        "audit_errors": bundle["audit_errors"],
        "exported_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
    }
    return json.dumps(serializable, indent=2, default=str)


def _audit_entry_to_dict(entry: Any) -> dict[str, Any]:
    """Safely convert an AuditEntry to dict, handling string-vs-enum action."""
    from nexus.case.schemas import AuditAction
    raw_action: Any = entry.action
    action_str: str
    if isinstance(raw_action, str):
        try:
            enum_action = AuditAction(raw_action)
            action_str = enum_action.value
        except ValueError:
            action_str = raw_action
    elif hasattr(raw_action, "value"):
        action_str = raw_action.value
    else:
        action_str = str(raw_action)
    return {
        "id": entry.id,
        "case_id": entry.case_id,
        "action": action_str,
        "timestamp": entry.timestamp.isoformat(),
        "actor": entry.actor,
        "payload": entry.payload,
        "prev_hash": entry.prev_hash,
        "hash": entry.hash,
        "signature": entry.signature,
    }


def export_to_markdown(bundle: dict[str, Any]) -> str:
    """Export case bundle to a human-readable Markdown report."""
    case: Case = bundle["case"]
    findings: list[Finding] = bundle["findings"]
    evidence: list[EvidenceRecord] = bundle["evidence"]
    audit: list[AuditEntry] = bundle["audit_log"]

    out = StringIO()
    out.write(f"# Case Report: {case.name}\n\n")
    out.write(f"**Case ID:** `{case.id}`  \n")
    out.write(f"**Status:** {case.status.value}  \n")
    out.write(f"**Severity:** {case.severity.value}  \n")
    out.write(f"**Created:** {case.created_at.isoformat()} by {case.created_by}  \n")
    if case.closed_at:
        out.write(f"**Closed:** {case.closed_at.isoformat()} by {case.closed_by or 'unknown'}  \n")
    if case.tags:
        out.write(f"**Tags:** {', '.join(case.tags)}  \n")
    out.write(f"\n## Description\n\n{case.description or '_(no description)_'}\n\n")

    out.write(f"## Findings ({len(findings)})\n\n")
    if not findings:
        out.write("_No findings recorded._\n\n")
    else:
        for f in findings:
            out.write(f"### [{f.severity.value.upper()}] {f.title}\n\n")
            out.write(f"- **Finding ID:** `{f.id}`\n")
            out.write(f"- **Created:** {f.created_at.isoformat()} by {f.created_by}\n")
            if f.artifact_id:
                out.write(f"- **Artifact ID:** `{f.artifact_id}`\n")
            if f.technique_ids:
                out.write(f"- **MITRE ATT&CK:** {', '.join(f.technique_ids)}\n")
            if f.description:
                out.write(f"\n{f.description}\n")
            out.write("\n")

    out.write(f"## Evidence ({len(evidence)})\n\n")
    if not evidence:
        out.write("_No evidence registered._\n\n")
    else:
        out.write("| ID | Name | Path | SHA-256 | Collected |\n")
        out.write("|----|------|------|---------|----------|\n")
        for e in evidence:
            sha = (e.file_hash_sha256 or "")[:16] + "..." if e.file_hash_sha256 else "-"
            path = e.file_path or "-"
            out.write(f"| `{e.id}` | {e.name[:40]} | {path[:50]} | `{sha}` | {e.collected_at.isoformat()} |\n")
        out.write("\n")

    out.write(f"## Audit Log ({len(audit)} entries)\n\n")
    verified = bundle.get("audit_verified", False)
    out.write(f"**Chain integrity:** {'VALID' if verified else 'INVALID'}  \n")
    if not verified and bundle.get("audit_errors"):
        out.write(f"**Errors:** {', '.join(bundle['audit_errors'])}\n\n")
    if not audit:
        out.write("_No audit entries._\n\n")
    else:
        out.write("| Timestamp | Actor | Action | Hash (first 8) |\n")
        out.write("|-----------|-------|--------|--------------|\n")
        for a in audit:
            action_str = a.action.value if hasattr(a.action, "value") else str(a.action)
            out.write(f"| {a.timestamp.isoformat()} | {a.actor} | {action_str} | `{a.hash[:8]}` |\n")
        out.write("\n")

    out.write(f"\n---\n*Exported by DFIR-Nexus at {datetime.now(UTC).isoformat().replace('+00:00', 'Z')}*\n")
    return out.getvalue()


def export_to_html(bundle: dict[str, Any]) -> str:
    """Export case bundle to a styled HTML report."""
    case: Case = bundle["case"]
    findings: list[Finding] = bundle["findings"]
    evidence: list[EvidenceRecord] = bundle["evidence"]
    audit: list[AuditEntry] = bundle["audit_log"]
    verified = bundle.get("audit_verified", False)

    css = """
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 1100px; margin: 30px auto; padding: 0 20px; color: #222; }
        h1 { border-bottom: 3px solid #2563eb; padding-bottom: 8px; }
        h2 { color: #2563eb; margin-top: 30px; }
        h3 { color: #1e40af; }
        .meta { background: #f1f5f9; padding: 12px 16px; border-radius: 6px; margin: 16px 0; }
        .meta-item { display: inline-block; margin-right: 24px; }
        .meta-label { font-weight: 600; color: #475569; }
        .severity-critical { color: #dc2626; font-weight: 700; }
        .severity-high { color: #ea580c; font-weight: 700; }
        .severity-medium { color: #d97706; }
        .severity-low { color: #65a30d; }
        .severity-informational { color: #64748b; }
        table { width: 100%; border-collapse: collapse; margin: 16px 0; }
        th, td { padding: 8px 12px; text-align: left; border-bottom: 1px solid #e2e8f0; }
        th { background: #f8fafc; font-weight: 600; }
        tr:hover { background: #f8fafc; }
        code { background: #f1f5f9; padding: 1px 6px; border-radius: 3px; font-family: 'Consolas', monospace; font-size: 90%; }
        .audit-ok { color: #16a34a; font-weight: 700; }
        .audit-fail { color: #dc2626; font-weight: 700; }
        .footer { margin-top: 40px; padding-top: 16px; border-top: 1px solid #e2e8f0; color: #64748b; font-size: 12px; }
    </style>
    """

    sev_class = f"severity-{case.severity.value}"

    out = StringIO()
    out.write("<!DOCTYPE html>\n<html><head><meta charset='utf-8'>")
    out.write(f"<title>Case {html.escape(case.name)} - DFIR-Nexus</title>")
    out.write(css)
    out.write("</head><body>")

    out.write(f"<h1>Case Report: {html.escape(case.name)}</h1>")

    out.write('<div class="meta">')
    out.write(f'<div class="meta-item"><span class="meta-label">Case ID:</span> <code>{html.escape(case.id)}</code></div>')
    out.write(f'<div class="meta-item"><span class="meta-label">Status:</span> {html.escape(case.status.value)}</div>')
    out.write(f'<div class="meta-item"><span class="meta-label">Severity:</span> <span class="{sev_class}">{html.escape(case.severity.value.upper())}</span></div>')
    out.write(f'<div class="meta-item"><span class="meta-label">Created:</span> {html.escape(case.created_at.isoformat())}</div>')
    if case.closed_at:
        out.write(f'<div class="meta-item"><span class="meta-label">Closed:</span> {html.escape(case.closed_at.isoformat())}</div>')
    if case.tags:
        out.write(f'<div class="meta-item"><span class="meta-label">Tags:</span> {html.escape(", ".join(case.tags))}</div>')
    out.write('</div>')

    if case.description:
        out.write(f"<h2>Description</h2><p>{html.escape(case.description)}</p>")

    out.write(f"<h2>Findings ({len(findings)})</h2>")
    if not findings:
        out.write("<p><em>No findings recorded.</em></p>")
    else:
        for f in findings:
            out.write('<div class="finding">')
            out.write(f'<h3><span class="severity-{f.severity.value}">[{f.severity.value.upper()}]</span> {html.escape(f.title)}</h3>')
            out.write(f'<p><strong>ID:</strong> <code>{html.escape(f.id)}</code><br>')
            out.write(f'<strong>Created:</strong> {html.escape(f.created_at.isoformat())} by {html.escape(f.created_by)}<br>')
            if f.artifact_id:
                out.write(f'<strong>Artifact:</strong> <code>{html.escape(f.artifact_id)}</code><br>')
            if f.technique_ids:
                out.write(f'<strong>MITRE ATT&CK:</strong> {html.escape(", ".join(f.technique_ids))}')
            out.write('</p>')
            if f.description:
                out.write(f"<p>{html.escape(f.description)}</p>")
            out.write('</div>')

    out.write(f"<h2>Evidence ({len(evidence)})</h2>")
    if not evidence:
        out.write("<p><em>No evidence registered.</em></p>")
    else:
        out.write("<table>")
        out.write("<tr><th>ID</th><th>Name</th><th>Path</th><th>SHA-256</th><th>Collected</th></tr>")
        for e in evidence:
            sha = (e.file_hash_sha256 or "")[:16] + "..." if e.file_hash_sha256 else "-"
            out.write("<tr>")
            out.write(f"<td><code>{html.escape(e.id)}</code></td>")
            out.write(f"<td>{html.escape(e.name[:50])}</td>")
            out.write(f"<td>{html.escape((e.file_path or '-')[:60])}</td>")
            out.write(f"<td><code>{html.escape(sha)}</code></td>")
            out.write(f"<td>{html.escape(e.collected_at.isoformat())}</td>")
            out.write("</tr>")
        out.write("</table>")

    out.write(f"<h2>Audit Log ({len(audit)} entries)</h2>")
    audit_class = "audit-ok" if verified else "audit-fail"
    out.write(f'<p><strong>Chain integrity:</strong> <span class="{audit_class}">{"VALID" if verified else "INVALID"}</span></p>')
    if audit:
        out.write("<table>")
        out.write("<tr><th>Timestamp</th><th>Actor</th><th>Action</th><th>Hash</th></tr>")
        for a in audit:
            action_str = a.action.value if hasattr(a.action, "value") else str(a.action)
            out.write("<tr>")
            out.write(f"<td>{html.escape(a.timestamp.isoformat())}</td>")
            out.write(f"<td>{html.escape(a.actor)}</td>")
            out.write(f"<td>{html.escape(action_str)}</td>")
            out.write(f"<td><code>{html.escape(a.hash[:16])}</code></td>")
            out.write("</tr>")
        out.write("</table>")

    out.write(f'<div class="footer">Exported by DFIR-Nexus at {datetime.now(UTC).isoformat().replace("+00:00", "Z")}</div>')
    out.write("</body></html>")
    return out.getvalue()


def export_to_stix(bundle: dict[str, Any]) -> str:
    """Export case bundle as STIX 2.0 JSON."""
    case: Case = bundle["case"]
    evidence: list[EvidenceRecord] = bundle["evidence"]

    case_id = f"case--{case.id.lower()}"
    objects: list[dict[str, Any]] = [
        {
            "type": "custom-object",
            "spec_version": "2.0",
            "id": case_id,
            "x_nexus_case_id": case.id,
            "x_nexus_name": case.name,
            "x_nexus_description": case.description,
            "x_nexus_severity": case.severity.value,
            "x_nexus_status": case.status.value,
            "x_nexus_created_at": case.created_at.isoformat(),
            "x_nexus_audit_chain_verified": bundle.get("audit_verified", False),
        }
    ]

    seen_hashes: set[str] = set()
    for e in evidence:
        for hash_type, hash_val in [
            ("SHA-256", e.file_hash_sha256),
            ("SHA-1", e.file_hash_sha1),
            ("MD5", e.file_hash_md5),
        ]:
            if hash_val and hash_val not in seen_hashes:
                seen_hashes.add(hash_val)
                objects.append({
                    "type": "indicator",
                    "spec_version": "2.0",
                    "id": f"indicator--{hash_type.lower().replace('-', '')}-{hash_val}",
                    "created": e.collected_at.isoformat() + "Z",
                    "modified": e.collected_at.isoformat() + "Z",
                    "pattern_type": "stixfile",
                    "pattern": f"[file:hashes.'{hash_type.upper()}' = '{hash_val}']",
                    "labels": ["malicious-activity"],
                    "name": f"Evidence hash {e.name}",
                    "valid_from": e.collected_at.isoformat() + "Z",
                })
        if e.metadata.get("source_ip"):
            ip = e.metadata["source_ip"]
            objects.append({
                "type": "indicator",
                "spec_version": "2.0",
                "id": f"indicator--ipv4--{ip.replace('.', '-')}",
                "created": e.collected_at.isoformat() + "Z",
                "modified": e.collected_at.isoformat() + "Z",
                "pattern_type": "stix",
                "pattern": f"[ipv4-addr:value = '{ip}']",
                "labels": ["malicious-activity"],
                "name": f"Source IP from {e.name}",
                "valid_from": e.collected_at.isoformat() + "Z",
            })

    stix_bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid_str()}",
        "objects": objects,
    }
    return json.dumps(stix_bundle, indent=2)


def uuid_str() -> str:
    """Generate a UUID string for STIX bundle IDs."""
    import uuid
    return str(uuid.uuid4())
