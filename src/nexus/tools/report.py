"""Report generation — 6 profiles with data aggregation, IOC extraction, MITRE mapping.

Generates structured report data from approved findings using
profile-based filtering and Zeltser IR Writing guidance.
"""

import json
import logging
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml
from mcp.server.fastmcp import FastMCP

from nexus.audit import AuditWriter
from nexus.case_manager import CaseManager
from nexus.config import settings

logger = logging.getLogger(__name__)
manager = CaseManager()

_ACTIVE_CASE_FILE = Path.home() / ".nexus" / "active_case"
_MAX_FILENAME = 200
_MAX_REPORT_BYTES = 10 * 1024 * 1024

_PROFILES = {
    "full": {
        "name": "Full Incident Report",
        "description": "Comprehensive IR report with all approved data, IOC aggregation, and MITRE mapping.",
        "data_keys": ["metadata", "findings", "timeline", "iocs", "mitre_mapping", "evidence", "todos", "summary"],
        "findings_mode": "all",
        "timeline_mode": "all",
        "sections": 10,
        "zeltser_tools": ["ir_get_template", "ir_get_guidelines", "ir_load_context", "ir_review_report"],
    },
    "executive": {
        "name": "Executive Summary",
        "description": "Management briefing — 1-2 pages, non-technical. Top 5 findings only.",
        "data_keys": ["metadata", "findings", "todos", "summary"],
        "findings_mode": "top_5",
        "timeline_mode": "count",
        "sections": 4,
        "zeltser_tools": ["ir_get_guidelines", "ir_load_context", "ir_review_report"],
    },
    "timeline": {
        "name": "Timeline Report",
        "description": "Chronological event narrative with optional date filtering.",
        "data_keys": ["metadata", "timeline", "summary"],
        "findings_mode": "referenced",
        "timeline_mode": "all",
        "sections": 1,
        "zeltser_tools": ["ir_get_guidelines", "ir_load_context"],
    },
    "ioc": {
        "name": "IOC Report",
        "description": "Structured IOC export with MITRE ATT&CK technique mapping.",
        "data_keys": ["metadata", "iocs", "mitre_mapping", "summary"],
        "findings_mode": "referenced",
        "timeline_mode": "none",
        "sections": 2,
        "zeltser_tools": [],
    },
    "findings": {
        "name": "Findings Report",
        "description": "All approved findings in detail, with optional finding ID filter.",
        "data_keys": ["metadata", "findings", "summary"],
        "findings_mode": "all",
        "timeline_mode": "referenced",
        "sections": 1,
        "zeltser_tools": ["ir_get_guidelines", "ir_load_context"],
    },
    "status": {
        "name": "Status Brief",
        "description": "Quick standup brief — counts and open TODOs only.",
        "data_keys": ["metadata", "todos", "summary"],
        "findings_mode": "count",
        "timeline_mode": "count",
        "sections": 2,
        "zeltser_tools": [],
    },
}

_STRIPPED_FINDING_FIELDS = {
    "provenance", "content_hash", "audit_ids", "staged", "modified_at",
    "approved_by", "approved_at", "rejected_by", "rejected_at",
    "rejection_reason", "verification", "created_by", "examiner_notes",
    "examiner_modifications", "provenance_warnings", "provenance_gaps",
}

_WRITING_GUIDANCE = """
Report Writing Rules:
1. Only include APPROVED findings — never DRAFT or REJECTED
2. Reference evidence paths and tool output provenance
3. Confidence levels: HIGH (multiple corroborating sources), MEDIUM (single reliable source), LOW (indirect indication), SPECULATIVE (hypothesis)
4. MITRE ATT&CK techniques should be described in context, not just listed
5. IOCs must be presented with type classification and source finding references
6. Flag any evidence integrity verification failures prominently
7. State clearly when findings are based on incomplete evidence
8. Separate objective observation from analytical interpretation
9. Use precise forensic terminology; avoid speculative language
"""


def _resolve_case_dir(case_id: str = "") -> Path:
    if case_id:
        case_dir = settings.cases_root / case_id
        if case_dir.is_dir():
            return case_dir
        case_dir_legacy = Path.home() / "cases" / case_id
        if case_dir_legacy.is_dir():
            return case_dir_legacy
        raise ValueError(f"Case not found: {case_id}")
    if _ACTIVE_CASE_FILE.exists():
        try:
            content = _ACTIVE_CASE_FILE.read_text().strip()
        except OSError:
            content = ""
        if content:
            p = Path(content) if os.path.isabs(content) else settings.cases_root / content
            if p.is_dir():
                return p
            p2 = Path(content) if os.path.isabs(content) else Path.home() / "cases" / content
            if p2.is_dir():
                return p2
    raise ValueError("No active case")


def _atomic_write(path: Path, content: str) -> None:
    fd, tmp = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _strip_finding(f: dict) -> dict:
    return {k: v for k, v in f.items() if k not in _STRIPPED_FINDING_FIELDS}


def _extract_iocs(findings: list[dict]) -> dict[str, list]:
    """Extract IOCs from findings with cross-references to source finding IDs."""
    iocs: dict[str, list] = {}
    for finding in findings:
        fid = finding.get("id", "")
        for ioc in finding.get("iocs", []):
            if isinstance(ioc, dict):
                val = ioc.get("value", ioc.get("indicator", ""))
                iotype = ioc.get("type", "unknown")
            else:
                val = str(ioc)
                iotype = "unknown"
            if not val:
                continue
            if iotype not in iocs:
                iocs[iotype] = []
            existing = None
            for entry in iocs[iotype]:
                if entry["value"] == val:
                    existing = entry
                    break
            if existing:
                if fid and fid not in existing.get("source_findings", []):
                    existing.setdefault("source_findings", []).append(fid)
            else:
                iocs[iotype].append({"value": val, "source_findings": [fid] if fid else []})

    for text_field in ("observation", "interpretation"):
        for finding in findings:
            fid = finding.get("id", "")
            text = finding.get(text_field, "") or ""
            for match in re.finditer(r"\b(?:[a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b", text):
                val = match.group(0)
                if len(val) == 64:
                    t = "sha256"
                elif len(val) == 40:
                    t = "sha1"
                else:
                    t = "md5"
                if t not in iocs:
                    iocs[t] = []
                existing = None
                for entry in iocs[t]:
                    if entry["value"] == val:
                        existing = entry
                        break
                if existing:
                    if fid and fid not in existing.get("source_findings", []):
                        existing.setdefault("source_findings", []).append(fid)
                else:
                    iocs[t].append({"value": val, "source_findings": [fid] if fid else []})
    return iocs


def _build_mitre_mapping(findings: list[dict]) -> dict:
    mapping: dict[str, dict] = {}
    name_map = {
        "T1055": "Process Injection", "T1059": "Command and Scripting Interpreter",
        "T1078": "Valid Accounts", "T1087": "Account Discovery",
        "T1098": "Account Manipulation", "T1110": "Brute Force",
        "T1136": "Create Account", "T1134": "Access Token Manipulation",
        "T1204": "User Execution", "T1218": "Signed Binary Proxy Execution",
        "T1485": "Data Destruction", "T1486": "Data Encrypted for Impact",
        "T1490": "Inhibit System Recovery", "T1505": "Server Software Component",
        "T1547": "Boot or Logon Autostart Execution",
        "T1548": "Abuse Elevation Control Mechanism",
        "T1550": "Use Alternate Authentication Material",
        "T1552": "Unsecured Credentials", "T1555": "Credentials from Password Stores",
        "T1562": "Impair Defenses", "T1566": "Phishing",
        "T1569": "System Services", "T1574": "Hijack Execution Flow",
        "T1583": "Acquire Infrastructure", "T1659": "Content Injection",
    }
    for finding in findings:
        fid = finding.get("id", "")
        for tid in finding.get("mitre_ids", []):
            tid = tid.strip().upper()
            if not tid.startswith("T"):
                continue
            if tid not in mapping:
                mapping[tid] = {"name": name_map.get(tid, f"Technique {tid}"), "findings": []}
            if fid not in mapping[tid]["findings"]:
                mapping[tid]["findings"].append(fid)
        for tech in finding.get("mitre_techniques", []):
            if isinstance(tech, dict):
                tid = tech.get("id", "").strip().upper()
            elif isinstance(tech, str):
                tid = tech.strip().upper()
            else:
                continue
            if not tid.startswith("T"):
                continue
            if tid not in mapping:
                mapping[tid] = {"name": name_map.get(tid, f"Technique {tid}"), "findings": []}
            if fid not in mapping[tid]["findings"]:
                mapping[tid]["findings"].append(fid)
    return mapping


def _reconcile_verification(case_id: str, approved_findings: list[dict]) -> list[dict]:
    """Check approved findings against the HMAC verification ledger."""
    try:
        from nexus.auth import read_verification_ledger
        ledger = read_verification_ledger(case_id)
    except Exception as e:
        return [{"status": "LEDGER_UNAVAILABLE", "detail": str(e)}]

    approved_ids = {f.get("id") for f in approved_findings if f.get("id")}
    ledger_ids = {
        entry.get("finding_id")
        for entry in ledger
        if entry.get("type", "finding") == "finding" and entry.get("finding_id")
    }
    alerts = []
    for fid in sorted(approved_ids - ledger_ids):
        alerts.append({
            "status": "APPROVED_WITHOUT_LEDGER",
            "finding_id": fid,
            "detail": "Finding is APPROVED but has no HMAC verification ledger entry.",
        })
    for fid in sorted(ledger_ids - approved_ids):
        alerts.append({
            "status": "LEDGER_WITHOUT_APPROVAL",
            "finding_id": fid,
            "detail": "Ledger contains an approval for a finding that is not currently APPROVED.",
        })
    return alerts


def _generate(profile_name: str, case_dir: Path, finding_ids: list[str] | None = None,
              start_date: str = "", end_date: str = "") -> dict:
    profile = _PROFILES.get(profile_name)
    if not profile:
        return {"error": f"Unknown profile: {profile_name}. Use list_profiles() to see available profiles."}

    meta_path = case_dir / "CASE.yaml"
    metadata = {}
    if meta_path.exists():
        try:
            metadata = yaml.safe_load(meta_path.read_text()) or {}
        except Exception:
            pass

    findings = manager.get_findings()
    timeline = manager.get_timeline()
    todos = manager.list_todos(status="all")

    approved_findings = [f for f in findings if f.get("status") == "APPROVED"]
    approved_timeline = [e for e in timeline if e.get("status") == "APPROVED"]

    evidence = manager.list_evidence()
    iocs = manager.get_iocs()

    # Apply findings_mode
    mode = profile.get("findings_mode", "all")
    if mode == "top_5":
        report_findings = approved_findings[:5]
    elif mode == "count":
        report_findings = []
    elif mode == "referenced":
        report_findings = approved_findings
    else:
        report_findings = approved_findings

    # Apply finding_ids filter
    if finding_ids and "findings" in profile.get("data_keys", []):
        report_findings = [f for f in report_findings if f.get("id") in finding_ids]

    # Apply timeline_mode
    tl_mode = profile.get("timeline_mode", "all")
    if tl_mode == "count":
        report_timeline = []
    elif tl_mode == "none":
        report_timeline = []
    elif tl_mode == "referenced":
        report_timeline = approved_timeline
    else:
        report_timeline = approved_timeline

    if start_date:
        report_timeline = [e for e in report_timeline if e.get("timestamp", "") >= start_date]
    if end_date:
        report_timeline = [e for e in report_timeline if e.get("timestamp", "") <= end_date]

    # Build IOC aggregation from ALL approved findings
    all_iocs = _extract_iocs(approved_findings)
    all_mitre = _build_mitre_mapping(approved_findings)

    open_todos = [t for t in todos if t.get("status") == "open"]

    summary = {
        "findings_total": len(findings),
        "findings_approved": len(approved_findings),
        "timeline_events": len(approved_timeline),
        "evidence_files": len(evidence),
        "ioc_count": sum(len(v) for v in all_iocs.values()),
        "todos_open": len(open_todos),
    }

    report_data: dict[str, Any] = {
        "profile": profile["name"],
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "case_id": case_dir.name,
    }
    for key in profile.get("data_keys", []):
        if key == "metadata":
            report_data["metadata"] = metadata
        elif key == "findings":
            report_data["findings"] = [_strip_finding(f) for f in report_findings]
        elif key == "timeline":
            report_data["timeline"] = report_timeline
        elif key == "iocs":
            report_data["iocs"] = all_iocs
        elif key == "mitre_mapping":
            report_data["mitre_mapping"] = all_mitre
        elif key == "evidence":
            report_data["evidence"] = evidence
        elif key == "todos":
            report_data["todos"] = open_todos
        elif key == "summary":
            report_data["summary"] = summary

    report_data["writing_guidance"] = _WRITING_GUIDANCE
    report_data["human_review_required"] = [
        {"section": "Business Impact", "reason": "The AI cannot assess business context"},
        {"section": "Third-Party Involvement", "reason": "Requires human knowledge of relationships"},
        {"section": "Action Items", "reason": "Requires organizational awareness"},
    ]
    report_data["generation_constraints"] = (
        "Only APPROVED findings are included. DRAFT and REJECTED findings are excluded."
    )

    verification_alerts = _reconcile_verification(case_dir.name, approved_findings)
    if verification_alerts:
        report_data["verification_alerts"] = verification_alerts
        if any(a.get("status") == "APPROVED_WITHOUT_LEDGER" for a in verification_alerts):
            report_data["integrity_warning"] = (
                "One or more approved findings do not have a matching HMAC verification ledger entry."
            )

    return report_data


def register_tools(server: FastMCP, audit: AuditWriter):
    @server.tool()
    def generate_report(
        profile: str = "full",
        case_id: str = "",
        finding_ids: list[str] | None = None,
        start_date: str = "",
        end_date: str = "",
    ) -> dict:
        """Generate a structured IR report from approved findings.

        Profiles: full, executive, timeline, ioc, findings, status
        """
        if profile not in _PROFILES:
            return {"error": f"Unknown profile: {profile}. Use list_profiles() to see available profiles."}
        try:
            case_dir = _resolve_case_dir(case_id)
        except ValueError as e:
            return {"error": str(e)}

        report_data = _generate(profile, case_dir, finding_ids, start_date, end_date)
        if "error" in report_data:
            return report_data

        audit.log(tool="generate_report",
                  params={"profile": profile, "case_id": case_id},
                  result_summary={"profile": profile,
                                  "findings_count": len(report_data.get("findings", []))})
        return report_data

    @server.tool()
    def set_case_metadata(field: str, value: str | list[str] = "") -> dict:
        """Set a metadata field in CASE.yaml.

        Allowed fields: incident_type, severity, tlp, lead_examiner,
        client, point_of_contact, impact_summary, affected_systems,
        affected_accounts, distribution_list, tags, related_cases.
        """
        try:
            case_dir = _resolve_case_dir()
        except ValueError as e:
            return {"error": str(e)}

        protected = {"case_id", "status", "created_at", "examiner",
                     "closed_at", "name", "description", "modified_at"}
        if field in protected:
            return {"error": f"Cannot modify protected field: {field}"}

        meta_path = case_dir / "CASE.yaml"
        try:
            meta = yaml.safe_load(meta_path.read_text()) or {}
        except Exception:
            meta = {}
        meta[field] = value
        meta["modified_at"] = datetime.now(timezone.utc).isoformat()
        _atomic_write(meta_path, yaml.dump(meta, default_flow_style=False))

        audit.log(tool="set_case_metadata", params={"field": field},
                  result_summary={"status": "set"})
        return {"status": "set", "field": field, "value": value}

    @server.tool()
    def get_case_metadata(field: str = "") -> dict:
        """Retrieve case metadata from CASE.yaml."""
        try:
            case_dir = _resolve_case_dir()
        except ValueError as e:
            return {"error": str(e)}
        meta_path = case_dir / "CASE.yaml"
        if not meta_path.exists():
            return {"error": "CASE.yaml not found"}
        try:
            meta = yaml.safe_load(meta_path.read_text()) or {}
        except Exception as e:
            return {"error": f"Cannot read metadata: {e}"}
        if field:
            return {"field": field, "value": meta.get(field)}
        return meta

    @server.tool()
    def list_profiles() -> dict:
        """List available report profiles with descriptions."""
        profiles = [
            {"name": k, "description": v["description"],
             "zeltser_tools": v.get("zeltser_tools", [])}
            for k, v in _PROFILES.items()
        ]
        return {"profiles": profiles, "count": len(profiles)}

    @server.tool()
    def save_report(filename: str, content: str, profile: str = "") -> dict:
        """Persist a rendered report to case reports/ directory."""
        if len(filename) > _MAX_FILENAME:
            return {"error": f"Filename exceeds {_MAX_FILENAME} characters"}
        content_bytes = content.encode("utf-8")
        if len(content_bytes) > _MAX_REPORT_BYTES:
            return {"error": f"Content exceeds {_MAX_REPORT_BYTES // 1024 // 1024} MB"}
        if ".." in filename or "/" in filename or "\\" in filename:
            return {"error": "Filename contains path traversal characters"}
        sanitized = re.sub(r"[^a-zA-Z0-9._-]", "_", filename)
        if not sanitized:
            return {"error": "Filename is empty after sanitization"}

        try:
            case_dir = _resolve_case_dir()
        except ValueError as e:
            return {"error": str(e)}

        reports_dir = case_dir / "reports"
        reports_dir.mkdir(exist_ok=True)
        report_path = reports_dir / sanitized

        version = 2
        while report_path.exists():
            stem = report_path.stem
            ext = report_path.suffix
            versioned = f"{stem.rsplit('_v', 1)[0]}_v{version}{ext}"
            report_path = reports_dir / versioned
            version += 1
            if version > 999:
                return {"error": "Too many versions of this filename"}

        _atomic_write(report_path, content)
        return {
            "status": "saved",
            "filename": report_path.name,
            "path": str(report_path),
            "characters": len(content),
        }

    @server.tool()
    def list_reports() -> list:
        """List saved reports in case reports/ directory."""
        try:
            case_dir = _resolve_case_dir()
        except ValueError:
            return []
        reports_dir = case_dir / "reports"
        if not reports_dir.is_dir():
            return []
        result = []
        for f in sorted(reports_dir.iterdir()):
            if f.is_file():
                try:
                    ctime = datetime.fromtimestamp(f.stat().st_ctime, tz=timezone.utc).isoformat()
                except OSError:
                    ctime = ""
                result.append({
                    "filename": f.name,
                    "size_bytes": f.stat().st_size,
                    "created_at": ctime,
                })
        return result
