"""Case lifecycle — init, activate, close, list, evidence registry, export/import.

All case data is stored as flat JSON/YAML files in ~/.nexus/cases/<case-id>/.
"""

import json
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml
from mcp.server.fastmcp import FastMCP

from nexus.audit import AuditWriter, resolve_examiner
from nexus.case_manager import CaseManager
from nexus.config import settings
from nexus.discipline import validate_case_id

logger = logging.getLogger(__name__)
manager = CaseManager()
_MAX_NAME = 200
_MAX_TEXT = 10_000

_ACTIVE_CASE_FILE = Path.home() / ".nexus" / "active_case"


def _detect_capabilities() -> dict:
    """Detect which optional / platform-gated tool surfaces are available.

    Two classes of capability:

    1. In-process — registered inside this nexus instance. Detected via
       package import (extras) and OS check (platform-gated modules).
    2. External MCP servers — REMnux is the canonical example. Upstream
       case-mcp ships no REMnux module either; it detects whether the
       analyst has wired up an external `remnux-mcp` (or
       `dfir-nexus-remnux`) entry in their LLM client config.

    The flags below match upstream's `_build_platform_capabilities`
    semantics with one adjustment: upstream looks under a gateway
    config file because they ship a fan-out gateway; we read the same
    `.mcp.json` / `~/.claude.json` that `nexus setup client` writes,
    since DFIR-Nexus uses direct multi-server connections.
    """
    import importlib.util
    import sys

    def _has(mod: str) -> bool:
        return importlib.util.find_spec(mod) is not None

    return {
        "sift_tools": sys.platform.startswith("linux"),
        "windows_tools": sys.platform.startswith("win"),
        "forensic_rag": _has("chromadb"),
        "opensearch": _has("opensearchpy"),
        "opencti": _has("pycti"),
        "triage_baseline": _has("zstandard"),
        "remnux": _detect_external_mcp("remnux"),
    }


def _detect_external_mcp(prefix: str) -> bool:
    """Look for an MCP server entry whose name starts with `prefix`.

    Checks (in order): `./.mcp.json`, `~/.claude.json`, `~/.mcp.json`.
    Matches keys like `remnux-mcp`, `dfir-nexus-remnux`, `remnux-malware`
    so the user can name the server however they like.
    """
    candidates = [
        Path.cwd() / ".mcp.json",
        Path.home() / ".claude.json",
        Path.home() / ".mcp.json",
    ]
    for path in candidates:
        if not path.exists():
            continue
        try:
            data = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        servers = data.get("mcpServers") or data.get("mcp_servers") or {}
        if any(prefix in name.lower() for name in servers):
            return True
    return False


def _build_guidance(caps: dict) -> str:
    lines = ["Available investigation capabilities:", ""]
    if caps.get("sift_tools"):
        lines.append("- SIFT forensic tools via run_command (65+ catalog entries, Linux)")
    if caps.get("windows_tools"):
        lines.append("- Windows forensic tools via run_windows_command (31 catalog entries)")
    if caps.get("forensic_rag"):
        lines.append("- Knowledge search: forensic_rag_search (Sigma, MITRE, KAPE; install: pip install dfir-nexus[rag])")
    if caps.get("opensearch"):
        lines.append("- Evidence indexing: idx_ingest for structured querying at scale (install: pip install dfir-nexus[opensearch])")
    if caps.get("opencti"):
        lines.append("- Threat intel: lookup_indicator on OpenCTI (install: pip install dfir-nexus[opencti])")
    if caps.get("triage_baseline"):
        lines.append("- Windows baseline validation: check_file / check_process_tree / ... (install: pip install dfir-nexus[triage])")
    if caps.get("remnux"):
        lines.append("- Malware analysis: upload_from_host + analyze_file on REMnux (external MCP server; configure via `nexus setup client --remnux HOST:PORT`)")
    lines.append("")
    lines.append("Do not rely on a single source. Call suggest_tools(artifact_type='...') for corroboration recommendations.")
    return "\n".join(lines)


def register_tools(server: FastMCP, audit: AuditWriter):
    @server.tool()
    def case_init(
        name: str,
        description: str = "",
        case_id: str = "",
        cases_dir: str = "",
    ) -> dict:
        """Create a new investigation case.

        Case ID is auto-generated (INC-YYYYMMDDHHMMSS) unless provided.
        Confirm with the examiner before creating.
        """
        if not name or not name.strip():
            return {"error": "Case name is required"}
        if len(name) > _MAX_NAME:
            return {"error": f"Case name exceeds {_MAX_NAME} characters"}

        exam = resolve_examiner()
        cases_root = Path(cases_dir) if cases_dir else settings.cases_root

        if case_id:
            err = validate_case_id(case_id)
            if err:
                return {"error": err}
            if not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{1,63}$", case_id):
                return {"error": "case_id must be alphanumeric with hyphens/underscores, 2-64 chars"}
            cid = case_id
        else:
            cid = f"INC-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"

        case_dir = cases_root / cid
        if case_dir.exists():
            return {"error": f"Case directory already exists: {cid}"}

        try:
            case_dir.mkdir(parents=True, exist_ok=True)
            for sub in ("evidence", "extractions", "reports", "audit"):
                (case_dir / sub).mkdir(exist_ok=True)
            for fname in ("findings.json", "timeline.json", "evidence.json", "iocs.json", "todos.json"):
                (case_dir / fname).write_text("[]", encoding="utf-8")
        except OSError as e:
            return {"error": f"Failed to create case directory: {e}"}

        meta = {
            "case_id": cid,
            "name": name.strip(),
            "description": description.strip(),
            "examiner": exam,
            "status": "open",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "modified_at": datetime.now(timezone.utc).isoformat(),
        }
        try:
            (case_dir / "CASE.yaml").write_text(yaml.dump(meta, default_flow_style=False))
        except OSError as e:
            return {"error": f"Failed to write case metadata: {e}"}

        # Bridge: register the case in the SQLite stack too, so CLI
        # commands (case list / approve / review) see MCP-created cases.
        try:
            from nexus.case import CaseManager as _SQLiteCaseManager
            from nexus.case.schemas import (
                Case as _SQLiteCase,
                CaseStatus as _SQLiteCaseStatus,
                FindingSeverity as _SQLiteSeverity,
            )
            _mgr = _SQLiteCaseManager(settings.cases_root / "cases.db")
            try:
                if _mgr.get_case(cid) is None:
                    _mgr.store.save_case(_SQLiteCase(
                        id=cid,
                        name=name.strip(),
                        description=description.strip(),
                        status=_SQLiteCaseStatus.OPEN,
                        severity=_SQLiteSeverity.MEDIUM,
                        created_at=datetime.now(timezone.utc),
                        created_by=exam,
                    ))
            finally:
                _mgr.close()
        except Exception:  # noqa: BLE001
            logger.debug("SQLite case registration skipped", exc_info=True)

        try:
            _ACTIVE_CASE_FILE.parent.mkdir(parents=True, exist_ok=True)
            _ACTIVE_CASE_FILE.write_text(str(case_dir))
        except OSError:
            pass

        created_ts = datetime.now(timezone.utc).isoformat()
        result = {
            "status": "created",
            "case_id": cid,
            "case_dir": str(case_dir),
            "examiner": exam,
            "created": created_ts,
        }
        audit_id = audit.log(tool="case_init", params={"name": name, "description": description},
                  result_summary=result)
        if audit_id is None:
            result["warning"] = "Audit write failed -- action not recorded"

        caps = _detect_capabilities()
        result["platform_capabilities"] = caps
        result["investigation_guidance"] = _build_guidance(caps)
        result["next_steps"] = [
            "Ask the examiner what triggered this investigation",
            "Register evidence: evidence_register(path=...)",
            "List available tools: list_available_tools() or list_windows_tools()",
            "Record timeline context: record_timeline_event(...)",
            "Begin analysis: run_command() on registered evidence",
            "Stage findings: record_finding() with audit_ids from tool execution",
        ]
        return result

    @server.tool()
    def case_activate(case_id: str) -> dict:
        """Switch the active case. All subsequent operations apply to this case."""
        err = validate_case_id(case_id)
        if err:
            return {"error": err}

        case_dir = settings.cases_root / case_id
        if not case_dir.exists() or not (case_dir / "CASE.yaml").exists():
            return {"error": f"Case not found: {case_id}"}

        try:
            _ACTIVE_CASE_FILE.parent.mkdir(parents=True, exist_ok=True)
            _ACTIVE_CASE_FILE.write_text(case_id)
        except OSError as e:
            return {"error": f"Failed to write active case: {e}"}

        result = {"status": "activated", "case_id": case_id, "case_dir": str(case_dir)}
        audit.log(tool="case_activate", params={"case_id": case_id}, result_summary=result)
        return result

    @server.tool()
    def case_list() -> list:
        """List all cases with their status and examiner."""
        cases_root = settings.cases_root
        if not cases_root.is_dir():
            return []
        results = []
        for case_dir in sorted(cases_root.iterdir()):
            meta_file = case_dir / "CASE.yaml"
            if not meta_file.exists():
                continue
            try:
                meta = yaml.safe_load(meta_file.read_text()) or {}
            except Exception:
                meta = {}
            results.append({
                "case_id": case_dir.name,
                "name": meta.get("name", case_dir.name),
                "status": meta.get("status", "unknown"),
                "examiner": meta.get("examiner", ""),
                "created_at": meta.get("created_at", ""),
            })
        return results

    @server.tool()
    def case_status(case_id: str = "") -> dict:
        """Get detailed case status — finding counts, timeline, TODOs, evidence."""
        try:
            case_dir = manager.resolve_case_dir(case_id) if case_id else manager.require_active_case()
            status = manager.get_case_status(case_dir)
            caps = _detect_capabilities()
            status["platform_capabilities"] = caps
            status["investigation_guidance"] = _build_guidance(caps)
            return status
        except ValueError as e:
            return {"error": str(e)}

    @server.tool()
    def case_close(case_id: str = "") -> dict:
        """Close a case. No further findings can be staged."""
        try:
            case_dir = manager.resolve_case_dir(case_id) if case_id else manager.require_active_case()
        except ValueError as e:
            return {"error": str(e)}

        meta_file = case_dir / "CASE.yaml"
        try:
            meta = yaml.safe_load(meta_file.read_text()) or {}
            meta["status"] = "closed"
            meta["closed_at"] = datetime.now(timezone.utc).isoformat()
            meta_file.write_text(yaml.dump(meta, default_flow_style=False))
        except OSError as e:
            return {"error": f"Failed to close case: {e}"}
        return {"status": "closed", "case_id": case_dir.name}

    @server.tool()
    def evidence_register(path: str, description: str = "") -> dict:
        """Register an evidence file — SHA-256 hash, chain of custody.

        Confirm with the examiner before registering.
        """
        try:
            result = manager.register_evidence(path, description)
        except (ValueError, FileNotFoundError) as e:
            return {"error": str(e)}

        audit.log(tool="evidence_register", params={"path": path, "description": description},
                  result_summary=result)
        return result

    @server.tool()
    def evidence_list() -> list:
        """List all registered evidence with hashes and descriptions."""
        try:
            return manager.list_evidence()
        except Exception as e:
            return [{"error": str(e)}]

    @server.tool()
    def evidence_verify() -> dict:
        """Re-hash all evidence and compare against registry."""
        try:
            return manager.verify_evidence()
        except Exception as e:
            return {"error": str(e)}

    @server.tool()
    def get_case_actions(limit: int = 50) -> list:
        """Retrieve recent action records for the active case."""
        try:
            case_dir = manager.require_active_case()
        except ValueError:
            return []
        path = case_dir / "actions.jsonl"
        if not path.exists():
            return []
        actions = []
        try:
            with open(path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        actions.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        except OSError:
            pass
        return actions[-limit:]

    @server.tool()
    def record_action(description: str, tool: str = "", command: str = "",
                      analyst_override: str = "") -> dict:
        """Log a supplemental action note. Auto-committed, no approval needed."""
        try:
            case_dir = manager.require_active_case()
        except ValueError as e:
            return {"error": str(e)}

        exam = analyst_override.strip().lower() if analyst_override.strip() else resolve_examiner()
        now = datetime.now(timezone.utc).isoformat()
        entry = {
            "ts": now,
            "description": description[:5000],
            "examiner": exam,
            "source": "mcp",
        }
        if tool:
            entry["tool"] = tool[:200]
        if command:
            entry["command"] = command[:2000]

        try:
            path = case_dir / "actions.jsonl"
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
                f.flush()
                os.fsync(f.fileno())
        except OSError as e:
            return {"status": "write_failed", "error": str(e)}

        audit.log(tool="record_action", params={"description": description[:200]},
                  result_summary={"status": "recorded"})
        return {"status": "recorded", "timestamp": now}

    @server.tool()
    def export_case(since: str = "") -> dict:
        """Export case data as a JSON bundle for collaboration."""
        try:
            case_dir = manager.require_active_case()
        except ValueError as e:
            return {"error": str(e)}

        from nexus.case_manager import CaseManager
        cm = CaseManager()
        bundle = {
            "case_id": case_dir.name,
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "findings": cm.get_findings(None),
            "timeline": cm.get_timeline(),
            "iocs": cm.get_iocs(),
        }
        audit.log(tool="export_case", params={"since": since},
                  result_summary={"findings": len(bundle["findings"])})
        return bundle

    @server.tool()
    def import_case(bundle_json: str) -> dict:
        """Import a case bundle (JSON string) — merges findings and timeline."""
        try:
            case_dir = manager.require_active_case()
        except ValueError as e:
            return {"error": str(e)}

        try:
            bundle = json.loads(bundle_json)
        except json.JSONDecodeError as e:
            return {"error": f"Invalid JSON bundle: {e}"}

        from nexus.case_manager import CaseManager
        cm = CaseManager()

        imported_findings = bundle.get("findings", [])
        imported_timeline = bundle.get("timeline", [])

        existing_findings = cm._load_findings(case_dir)
        existing_ids = {f.get("id") for f in existing_findings}
        new_findings = [f for f in imported_findings if f.get("id") not in existing_ids]
        if new_findings:
            existing_findings.extend(new_findings)
            cm._save_findings(case_dir, existing_findings)

        existing_timeline = cm._load_timeline(case_dir)
        existing_tids = {t.get("id") for t in existing_timeline}
        new_events = [t for t in imported_timeline if t.get("id") not in existing_tids]
        if new_events:
            existing_timeline.extend(new_events)
            cm._save_timeline(case_dir, existing_timeline)

        result = {
            "status": "imported",
            "findings_imported": len(new_findings),
            "timeline_imported": len(new_events),
        }
        audit.log(tool="import_case", params={}, result_summary=result)
        return result

    @server.tool()
    def backup_case(destination: str, purpose: str = "") -> dict:
        """Back up case data to a destination directory.

        Creates a timestamped backup of metadata, findings, timeline,
        approvals, and reports. Does NOT include evidence files.
        """
        try:
            case_dir = manager.require_active_case()
        except ValueError as e:
            return {"error": str(e)}

        dest = Path(destination)
        if not dest.is_dir():
            try:
                dest.mkdir(parents=True)
            except OSError as e:
                return {"error": f"Cannot create backup destination: {e}"}

        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
        backup_name = f"{case_dir.name}-{ts}"
        backup_dir = dest / backup_name
        try:
            backup_dir.mkdir()
        except OSError as e:
            return {"error": f"Cannot create backup directory: {e}"}

        import shutil
        for fname in ("CASE.yaml", "findings.json", "timeline.json",
                      "evidence.json", "iocs.json", "todos.json",
                      "approvals.jsonl", "actions.jsonl"):
            src = case_dir / fname
            if src.exists():
                shutil.copy2(src, backup_dir / fname)
        reports_src = case_dir / "reports"
        if reports_src.is_dir():
            shutil.copytree(reports_src, backup_dir / "reports")
        audit_src = case_dir / "audit"
        if audit_src.is_dir():
            shutil.copytree(audit_src, backup_dir / "audit")

        result = {
            "status": "backed_up",
            "backup_path": str(backup_dir),
            "case_id": case_dir.name,
        }
        audit.log(tool="backup_case", params={"destination": destination, "purpose": purpose},
                  result_summary=result)
        return result
