"""E.0.4 — Extended case export formats."""

from __future__ import annotations

import csv
import json
import math
import zipfile
from datetime import UTC, datetime
from io import BytesIO, StringIO
from typing import Any
from xml.sax.saxutils import escape

from nexus.case import AuditEntry, Case, Finding


def export_findings_csv(findings: list[Finding]) -> str:
    buf = StringIO()
    writer = csv.writer(buf)
    writer.writerow(
        ["id", "title", "severity", "approval_state", "technique_ids", "created_by", "created_at"]
    )
    for f in findings:
        writer.writerow(
            [
                f.id,
                f.title,
                f.severity.value,
                f.approval_state.value,
                ";".join(f.technique_ids),
                f.created_by,
                f.created_at.isoformat(),
            ]
        )
    return buf.getvalue()


def export_timeline_csv(audit_log: list[AuditEntry]) -> str:
    buf = StringIO()
    writer = csv.writer(buf)
    writer.writerow(["sequence", "action", "actor", "timestamp", "payload_json"])
    for idx, entry in enumerate(audit_log, start=1):
        action = entry.action.value if hasattr(entry.action, "value") else str(entry.action)
        writer.writerow(
            [
                idx,
                action,
                entry.actor,
                entry.timestamp.isoformat(),
                json.dumps(entry.payload, default=str),
            ]
        )
    return buf.getvalue()


def export_ioc_blocklist(bundle: dict[str, Any], *, fmt: str = "txt") -> str:
    """Extract IoC-like strings from findings/evidence metadata."""
    iocs: set[str] = set()
    for finding in bundle.get("findings") or []:
        for tid in finding.technique_ids:
            iocs.add(tid)
        text = f"{finding.title} {finding.description}"
        for token in text.split():
            if len(token) >= 32 and all(c in "0123456789abcdefABCDEF" for c in token):
                iocs.add(token.lower())
    for evidence in bundle.get("evidence") or []:
        if evidence.file_hash_sha256:
            iocs.add(evidence.file_hash_sha256.lower())
        meta = json.dumps(evidence.metadata or {})
        for part in meta.replace('"', " ").split():
            if part.count(".") == 3 and all(p.isdigit() for p in part.split(".")):
                iocs.add(part)
    sorted_iocs = sorted(iocs)
    if fmt == "csv":
        buf = StringIO()
        writer = csv.writer(buf)
        writer.writerow(["ioc"])
        for ioc in sorted_iocs:
            writer.writerow([ioc])
        return buf.getvalue()
    return "\n".join(sorted_iocs) + ("\n" if sorted_iocs else "")


def export_investigation_snapshot(bundle: dict[str, Any]) -> str:
    """Compact JSON snapshot for sharing / diffing."""
    case: Case = bundle["case"]
    snapshot = {
        "snapshot_version": "1.0",
        "exported_at": datetime.now(UTC).isoformat(),
        "case": {
            "id": case.id,
            "name": case.name,
            "status": case.status.value,
            "severity": case.severity.value,
            "tags": case.tags,
        },
        "counts": {
            "findings": len(bundle.get("findings") or []),
            "evidence": len(bundle.get("evidence") or []),
            "audit_entries": len(bundle.get("audit_log") or []),
        },
        "techniques": sorted(
            {t for f in bundle.get("findings") or [] for t in f.technique_ids}
        ),
        "audit_verified": bundle.get("audit_verified"),
    }
    return json.dumps(snapshot, indent=2)


def export_swimlane_svg(bundle: dict[str, Any]) -> str:
    """Minimal swimlane SVG from audit timeline."""
    audit: list[AuditEntry] = bundle.get("audit_log") or []
    lanes = ["analyst", "system", "agent"]
    lane_y = {name: 40 + i * 80 for i, name in enumerate(lanes)}
    width = max(400, 60 + len(audit) * 120)
    height = 40 + len(lanes) * 80
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}">',
        '<style>text{font-family:sans-serif;font-size:11px}</style>',
    ]
    for lane in lanes:
        y = lane_y[lane]
        parts.append(f'<line x1="0" y1="{y}" x2="{width}" y2="{y}" stroke="#ccc"/>')
        parts.append(f'<text x="4" y="{y - 8}">{escape(lane)}</text>')
    for idx, entry in enumerate(audit):
        lane = "system" if entry.actor in {"system", "push-server"} else "analyst"
        if "agent" in entry.actor.lower():
            lane = "agent"
        x = 60 + idx * 110
        y = lane_y.get(lane, lane_y["analyst"])
        action = entry.action.value if hasattr(entry.action, "value") else str(entry.action)
        parts.append(f'<rect x="{x}" y="{y - 18}" width="100" height="36" fill="#e8f0fe" stroke="#336"/>')
        parts.append(f'<text x="{x + 4}" y="{y}">{escape(action[:14])}</text>')
    parts.append("</svg>")
    return "\n".join(parts)


def export_asset_graph_svg(bundle: dict[str, Any]) -> str:
    """Simple host/evidence graph SVG."""
    hosts: set[str] = set()
    for evidence in bundle.get("evidence") or []:
        host = (evidence.metadata or {}).get("host") or (evidence.metadata or {}).get("hostname")
        if host:
            hosts.add(str(host))
    case: Case = bundle["case"]
    parts = [
        '<svg xmlns="http://www.w3.org/2000/svg" width="480" height="240">',
        f'<text x="200" y="24" text-anchor="middle">{escape(case.name)}</text>',
    ]
    cx, cy = 240, 120
    parts.append(f'<circle cx="{cx}" cy="{cy}" r="28" fill="#fdd" stroke="#900"/>')
    parts.append(f'<text x="{cx}" y="{cy + 4}" text-anchor="middle">case</text>')
    host_list = sorted(hosts) or ["unknown"]
    for i, host in enumerate(host_list[:6]):
        angle = (i / max(len(host_list), 1)) * 6.28
        hx = int(cx + 100 * math.cos(angle))
        hy = int(cy + 80 * math.sin(angle))
        parts.append(f'<line x1="{cx}" y1="{cy}" x2="{hx}" y2="{hy}" stroke="#666"/>')
        parts.append(f'<circle cx="{hx}" cy="{hy}" r="20" fill="#efe" stroke="#363"/>')
        parts.append(f'<text x="{hx}" y="{hy + 4}" text-anchor="middle">{escape(host[:10])}</text>')
    parts.append("</svg>")
    return "\n".join(parts)


def export_case_zip(bundle: dict[str, Any], *, include_redacted: bool = False) -> bytes:
    """ZIP package with JSON + CSV + SVG artifacts."""
    from nexus.integration.case_export import (
        export_to_html,
        export_to_json,
        export_to_markdown,
    )

    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("case.json", export_to_json(bundle))
        zf.writestr("report.md", export_to_markdown(bundle))
        zf.writestr("report.html", export_to_html(bundle))
        zf.writestr("findings.csv", export_findings_csv(bundle.get("findings") or []))
        zf.writestr("timeline.csv", export_timeline_csv(bundle.get("audit_log") or []))
        zf.writestr("iocs.txt", export_ioc_blocklist(bundle, fmt="txt"))
        zf.writestr("snapshot.json", export_investigation_snapshot(bundle))
        zf.writestr("swimlane.svg", export_swimlane_svg(bundle))
        zf.writestr("asset_graph.svg", export_asset_graph_svg(bundle))
        if include_redacted:
            redacted = export_to_json(bundle).replace("password", "[REDACTED]")
            zf.writestr("case.redacted.json", redacted)
    return buf.getvalue()


def export_to_docx(bundle: dict[str, Any]) -> bytes:
    """Minimal DOCX (OOXML) without external dependencies."""
    case: Case = bundle["case"]
    findings: list[Finding] = bundle.get("findings") or []
    paragraphs = [
        f"<w:p><w:r><w:t>{escape(case.name)}</w:t></w:r></w:p>",
        f"<w:p><w:r><w:t>Severity: {escape(case.severity.value)}</w:t></w:r></w:p>",
        f"<w:p><w:r><w:t>Findings: {len(findings)}</w:t></w:r></w:p>",
    ]
    for f in findings[:50]:
        paragraphs.append(
            f"<w:p><w:r><w:t>{escape(f.severity.value)} — {escape(f.title)}</w:t></w:r></w:p>"
        )
    document_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        f"<w:body>{''.join(paragraphs)}</w:body></w:document>"
    )
    content_types = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/word/document.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
        "</Types>"
    )
    rels = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
        'Target="word/document.xml"/>'
        "</Relationships>"
    )
    out = BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", content_types)
        zf.writestr("_rels/.rels", rels)
        zf.writestr("word/document.xml", document_xml)
    return out.getvalue()
