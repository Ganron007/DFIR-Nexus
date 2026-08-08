"""Case directory state management — findings, timeline, evidence, IOCs, TODOs.

All investigation data lives in flat JSON files within the case directory.
This module provides atomic read/write access with SHA-256 content hashing.
"""

import contextlib
import hashlib
import json
import logging
import os
import re
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from nexus.audit import resolve_examiner
from nexus.config import settings
from nexus.discipline import validate_finding

logger = logging.getLogger(__name__)

_AUDIT_ID_PATTERN = re.compile(r"^[a-z]+-[a-z0-9](?:[a-z0-9-]*[a-z0-9])?-[0-9]{8}-[0-9]{3,}\Z")
_HASH_EXCLUDE_KEYS = {
    "status", "approved_at", "approved_by", "rejected_at", "rejected_by",
    "rejection_reason", "examiner_notes", "examiner_modifications",
    "content_hash", "verification", "modified_at", "provenance",
    "provenance_detail", "provenance_chain", "provenance_grade",
    "provenance_warnings", "provenance_gaps", "timeline_event_id",
}


def _atomic_write(path: Path, content: str) -> None:
    fd, tmp_path = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp_path)
        raise


def _compute_content_hash(item: dict) -> str:
    hashable = {k: v for k, v in item.items() if k not in _HASH_EXCLUDE_KEYS}
    canonical = json.dumps(hashable, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


def _next_seq(items: list[dict], id_field: str, prefix: str, examiner: str) -> int:
    pattern = f"{prefix}-{examiner}-"
    max_num = 0
    for item in items:
        item_id = item.get(id_field, "")
        if item_id.startswith(pattern):
            try:
                num = int(item_id[len(pattern):])
                max_num = max(max_num, num)
            except ValueError:
                pass
    return max_num + 1


def _load_json_file(path: Path, default: Any) -> Any:
    """Load JSON without silently overwriting corrupt case state."""
    if not path.exists():
        return default
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as e:
        logger.error("Failed to read JSON file %s: %s", path, e)
        raise ValueError(f"Cannot read {path.name}: {e}") from e
    if not text.strip():
        return default
    try:
        return json.loads(text)
    except json.JSONDecodeError as e:
        logger.error("Corrupt JSON file: %s", path)
        raise ValueError(
            f"{path.name} is corrupt (invalid JSON). Refusing to overwrite; fix or restore it."
        ) from e


def _detect_ioc_type(value: str) -> tuple[str, str]:
    v = value.strip()
    if re.match(r"^https?://", v, re.IGNORECASE):
        return "url", "network"
    if re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", v):
        return "email-addr", "network"
    if re.match(r"^[a-fA-F0-9]{64}$", v):
        return "file:hash:sha256", "host"
    if re.match(r"^[a-fA-F0-9]{40}$", v):
        return "file:hash:sha1", "host"
    if re.match(r"^[a-fA-F0-9]{32}$", v):
        return "file:hash:md5", "host"
    stripped = re.sub(r"[:/]\d{1,5}$", "", v)
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", stripped):
        octets = stripped.split(".")
        if all(0 <= int(o) <= 255 for o in octets):
            return "ipv4-addr", "network"
    if re.match(r"^[0-9a-fA-F:]{6,}$", v) and v.count(":") >= 2:
        return "ipv6-addr", "network"
    if re.match(r"^HK(EY_|LM|CU|CR|U\\)", v, re.IGNORECASE):
        return "registry-key", "system"
    if re.match(r"^[a-zA-Z0-9._-]+\\[a-zA-Z0-9._-]+$", v):
        return "user-account", "identity"
    exe_exts = (".exe", ".sys", ".dll", ".bat", ".ps1", ".cmd", ".vbs", ".js", ".msi", ".scr")
    if "." in v and v.lower().endswith(exe_exts) and "/" not in v and "\\" not in v:
        return "file:name", "host"
    if re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9-]*\.)+[a-zA-Z]{2,}$", v):
        return "domain-name", "network"
    return "unknown", "unknown"


class CaseManager:
    """Manages case directory state — findings, timeline, evidence, IOCs, TODOs."""

    def __init__(self) -> None:
        self._active_case_id: str | None = None
        self._active_case_path: Path | None = None

    @property
    def examiner(self) -> str:
        return resolve_examiner()

    def resolve_case_dir(self, case_id: str = "") -> Path:
        """Resolve case directory path without requiring active case."""
        if case_id:
            from nexus.discipline import validate_case_id
            err = validate_case_id(case_id)
            if err:
                raise ValueError(err)
            case_dir = settings.cases_root / case_id
            if not case_dir.exists():
                raise ValueError(f"Case not found: {case_id}")
            return case_dir

        active_file = Path.home() / ".nexus" / "active_case"
        if active_file.exists():
            try:
                content = active_file.read_text().strip()
            except OSError:
                content = ""
            if content:
                case_dir = Path(content) if os.path.isabs(content) else settings.cases_root / content
                if case_dir.is_dir() and (case_dir / "CASE.yaml").exists():
                    return case_dir

        env_dir = os.environ.get("NEXUS_CASE_DIR")
        if env_dir:
            p = Path(env_dir)
            if p.is_dir():
                return p

        raise ValueError("No active case. Use case_init or case_activate first.")

    def require_active_case(self) -> Path:
        """Same as resolve_case_dir but also checks case is not closed."""
        case_dir = self.resolve_case_dir()
        meta_file = case_dir / "CASE.yaml"
        if meta_file.exists():
            try:
                meta = yaml.safe_load(meta_file.read_text()) or {}
                if meta.get("status") == "closed":
                    raise ValueError(
                        f"Case {case_dir.name} is closed. "
                        f"Run case_activate to work on a different case."
                    )
            except yaml.YAMLError:
                pass
        return case_dir

    # ── Findings ──────────────────────────────────────────────────────

    def _load_findings(self, case_dir: Path) -> list[dict]:
        path = case_dir / "findings.json"
        data = _load_json_file(path, [])
        return data if isinstance(data, list) else data.get("findings", [])

    def _save_findings(self, case_dir: Path, findings: list[dict]) -> None:
        path = case_dir / "findings.json"
        content = json.dumps(findings, indent=2, default=str)
        _atomic_write(path, content)

    def record_finding(
        self,
        finding: dict,
        examiner_override: str = "",
        supporting_commands: list[dict] | None = None,
        artifacts: list[dict] | None = None,
        audit: Any = None,
    ) -> dict:
        case_dir = self.require_active_case()
        if supporting_commands is None and isinstance(finding.get("supporting_commands"), list):
            supporting_commands = finding.pop("supporting_commands")
        if artifacts is None and isinstance(finding.get("artifacts"), list):
            artifacts = finding.pop("artifacts")

        validation = validate_finding(finding)
        if not validation.get("valid", False):
            return {"status": "VALIDATION_FAILED", "errors": validation.get("errors", [])}
        warnings = validation.get("warnings", [])

        exam = (examiner_override.strip().lower()
                if examiner_override and examiner_override.strip()
                else self.examiner)

        findings = self._load_findings(case_dir)
        seq = _next_seq(findings, "id", "F", exam)
        finding_id = f"F-{exam}-{seq:03d}"
        now = datetime.now(UTC).isoformat()

        sanitized = {k: v for k, v in finding.items()
                     if k in {"title", "observation", "interpretation", "confidence",
                              "confidence_justification", "type", "mitre_ids",
                              "mitre_techniques", "host", "event_timestamp",
                              "affected_account", "attack_ids", "audit_ids", "iocs",
                              "event_type", "artifact_ref", "related_findings"}}
        if sanitized.get("host"):
            sanitized["host"] = str(sanitized["host"])[:200]
        if sanitized.get("affected_account"):
            sanitized["affected_account"] = str(sanitized["affected_account"])[:200]

        audit_ids = list(sanitized.get("audit_ids") or [])

        validated_artifacts: list[dict] = []
        raw_artifacts = artifacts
        if isinstance(raw_artifacts, str):
            try:
                raw_artifacts = json.loads(raw_artifacts)
            except (json.JSONDecodeError, TypeError):
                raw_artifacts = []
        if raw_artifacts and not isinstance(raw_artifacts, list):
            raw_artifacts = []
        if raw_artifacts:
            for art in raw_artifacts[:10]:
                if not isinstance(art, dict):
                    continue
                aid = art.get("audit_id", "")
                if not aid:
                    continue
                validated_artifacts.append({
                    "type": str(art.get("type", ""))[:100],
                    "value": str(art.get("value", ""))[:500],
                    "audit_id": aid,
                    "source": str(art.get("source", ""))[:500],
                })
                audit_ids.append(aid)
        if not validated_artifacts and audit_ids:
            for aid in audit_ids[:10]:
                validated_artifacts.append({
                    "type": "audit",
                    "value": str(aid)[:500],
                    "audit_id": str(aid)[:100],
                    "source": "",
                })

        validated_commands: list[dict] = []
        shell_audit_ids: list[str] = []
        if supporting_commands:
            for cmd in supporting_commands[:5]:
                if not isinstance(cmd, dict):
                    continue
                command = cmd.get("command", "")
                purpose = cmd.get("purpose", "")
                if command and purpose:
                    validated_commands.append({
                        "command": command[:1000],
                        "purpose": purpose[:500],
                        "output_excerpt": str(cmd.get("output_excerpt", ""))[:2000],
                    })
                    if audit:
                        logged_id = audit.log(tool="supporting_command",
                                              params={"command": command, "purpose": purpose},
                                              result_summary={
                                                  "output_excerpt": str(cmd.get("output_excerpt", ""))[:200]
                                              },
                                              source="shell_self_report")
                        if logged_id:
                            validated_commands[-1]["audit_id"] = logged_id
                            shell_audit_ids.append(logged_id)

        audit_ids.extend(shell_audit_ids)
        audit_ids = list(dict.fromkeys(str(aid) for aid in audit_ids if aid))

        entry = {
            "id": finding_id,
            "case_id": case_dir.name,
            "status": "DRAFT",
            "title": sanitized.get("title", ""),
            "observation": sanitized.get("observation", ""),
            "interpretation": sanitized.get("interpretation", ""),
            "confidence": sanitized.get("confidence", "MEDIUM").upper(),
            "type": sanitized.get("type", ""),
            "host": sanitized.get("host", ""),
            "affected_account": sanitized.get("affected_account", ""),
            "event_timestamp": sanitized.get("event_timestamp", ""),
            "attack_ids": sanitized.get("attack_ids") or sanitized.get("mitre_ids") or [],
            "audit_ids": audit_ids,
            "mitre_techniques": sanitized.get("mitre_techniques") or [],
            "iocs": sanitized.get("iocs") or [],
            "artifacts": validated_artifacts,
            "supporting_commands": validated_commands,
            "content_hash": "",
            "examiner": exam,
            "created_by": exam,
            "created_at": now,
            "modified_at": now,
            "staged": True,
        }
        entry["content_hash"] = _compute_content_hash(entry)
        # Check provenance BEFORE saving — reject findings with no audit trail
        provenance = self._score_provenance(entry, case_dir)
        if provenance.get("summary") == "NONE" or provenance.get("none"):
            missing = provenance.get("none") or audit_ids
            return {
                "status": "REJECTED",
                "error": "Finding rejected: invalid or missing evidence trail. "
                         "Every finding must reference audit_id values that exist "
                         "in the active case audit log.",
                "provenance_detail": provenance,
                "missing_audit_ids": missing,
            }

        timeline_event_id = self._auto_timeline_for_finding(case_dir, entry)
        if timeline_event_id:
            entry["timeline_event_id"] = timeline_event_id
            entry["content_hash"] = _compute_content_hash(entry)

        findings.append(entry)
        self._save_findings(case_dir, findings)

        merged_iocs = []
        for text_field in ("observation", "interpretation", "title"):
            text = sanitized.get(text_field, "")
            if not text:
                continue
            for pattern, (iotype, cat) in [
                (r"\b[a-fA-F0-9]{64}\b", ("file:hash:sha256", "host")),
                (r"\b[a-fA-F0-9]{40}\b", ("file:hash:sha1", "host")),
                (r"\b[a-fA-F0-9]{32}\b", ("file:hash:md5", "host")),
                (r"\b(?:\d{1,3}\.){3}\d{1,3}\b", ("ipv4-addr", "network")),
            ]:
                for match in re.finditer(pattern, text):
                    val = match.group(0)
                    if iotype == "ipv4-addr":
                        octets = val.split(".")
                        if not all(0 <= int(o) <= 255 for o in octets):
                            continue
                        if val.startswith("127.") or val.startswith("169.254."):
                            continue
                    merged_iocs.append({
                        "value": val, "type": iotype, "category": cat,
                        "source_finding": finding_id,
                    })

        explicit_iocs = self._normalize_explicit_iocs(entry)
        merged_iocs.extend(explicit_iocs)
        if merged_iocs:
            self._merge_iocs(case_dir, merged_iocs)

        # Provenance scoring (already checked above)
        result = {
            "status": "STAGED",
            "finding_id": finding_id,
            "finding_status": "DRAFT -- requires human approval via nexus approve",
            "warnings": warnings,
            "iocs_auto_extracted": len(merged_iocs) - len(explicit_iocs),
            "iocs_recorded": len(merged_iocs),
            "provenance_detail": dict(provenance),
            "provenance_grade": provenance.get("grade", "NONE"),
            "provenance": {"summary": provenance["summary"],
                           "detail": provenance["detail"]},
        }
        if timeline_event_id:
            result["timeline_event_id"] = timeline_event_id

        from nexus.discipline import _build_finding_considerations
        considerations = _build_finding_considerations(finding)
        if considerations:
            result["considerations"] = considerations

        if provenance["grade"] == "FULL":
            pass
        else:
            result["provenance_gaps"] = []
            if provenance.get("none"):
                result["provenance_gaps"].append({
                    "type": "unverified_audit_ids",
                    "ids": provenance["none"],
                    "action": "Re-run the tool and update artifacts with valid audit_ids",
                })
            if result["warnings"]:
                for w in result["warnings"]:
                    result["provenance_gaps"].append({
                        "type": "validation_warning",
                        "detail": w,
                    })

        if merged_iocs:
            result["iocs_extracted"] = len(merged_iocs)

        # Track first evidence source
        if raw_artifacts:
            for art in raw_artifacts:
                if art.get("source"):
                    result["source_evidence"] = art["source"]
                    break

        # Conflict detection — check against existing APPROVED findings
        conflicts = self._detect_conflicts(entry, findings)
        if conflicts:
            result["conflicts_with"] = conflicts

        # Corroboration suggestions when provenance is weak
        if provenance.get("summary") in ("NONE", "PARTIAL"):
            try:
                from nexus.knowledge import loader as fk
                finding_type = sanitized.get("type", "")
                if finding_type:
                    corr = fk.get_corroboration(finding_type)
                    if corr:
                        result["corroboration_suggestions"] = corr
            except ImportError:
                pass

        # SQLite dual-write (populates case stack for CLI and push server)
        try:
            from nexus.case.compat import dict_to_case, dict_to_finding, get_sqlite_manager
            sql_mgr = get_sqlite_manager()
            if sql_mgr.get_case(case_dir.name) is None:
                case_dict = {"id": case_dir.name, "case_id": case_dir.name,
                             "name": case_dir.name, "status": "open"}
                meta_path = case_dir / "CASE.yaml"
                if meta_path.exists():
                    import yaml as _yaml
                    try:
                        meta = _yaml.safe_load(meta_path.read_text(encoding="utf-8")) or {}
                        case_dict.update(meta)
                    except Exception:
                        pass
                case_obj = dict_to_case(case_dict)
                sql_mgr.store.save_case(case_obj)
            finding_dict = dict(entry)
            finding_dict["case_id"] = case_dir.name
            finding_obj = dict_to_finding(finding_dict)
            sql_mgr.store.save_finding(finding_obj)
        except Exception:
            pass  # dual-write is best-effort; never break the flat-JSON path

        return result

    def _detect_conflicts(self, new_finding: dict, existing_findings: list) -> list[dict]:
        """Detect if a new finding contradicts an existing APPROVED one.

        Checks same host + overlapping time window + incompatible verdicts.
        Returns list of conflict descriptions, or empty list if none found.
        """
        conflicts = []
        new_host = (new_finding.get("host") or "").lower()
        new_ts = new_finding.get("event_timestamp", "")
        new_conf = (new_finding.get("confidence") or "MEDIUM").upper()
        new_type = (new_finding.get("type") or "").lower()

        if not new_host and not new_ts:
            return conflicts

        for existing in existing_findings:
            if existing.get("id") == new_finding.get("id"):
                continue
            if existing.get("status") != "APPROVED":
                continue
            e_host = (existing.get("host") or "").lower()
            if new_host and e_host and new_host != e_host:
                continue
            e_type = (existing.get("type") or "").lower()
            if new_type and e_type and new_type == e_type:
                continue
            e_ts = existing.get("event_timestamp", "")
            if new_ts and e_ts:
                try:
                    nt = datetime.fromisoformat(new_ts)
                    et = datetime.fromisoformat(e_ts)
                    diff = abs((nt - et).total_seconds())
                    if diff > 3600:
                        continue
                except (ValueError, TypeError):
                    pass
            e_conf = (existing.get("confidence") or "MEDIUM").upper()
            conf_ranks = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
            if (new_type in ("exclusion", "conclusion") or e_type in ("exclusion", "conclusion")) \
                    and abs(conf_ranks.get(new_conf, 1) - conf_ranks.get(e_conf, 1)) >= 1:
                conflicts.append({
                    "existing_finding": existing.get("id", ""),
                    "existing_title": existing.get("title", "")[:100],
                    "existing_confidence": e_conf,
                    "new_confidence": new_conf,
                    "basis": (
                        f"'{new_type}' finding on same host conflicts with "
                        f"APPROVED '{e_type}' finding ({existing.get('id', '')}). "
                        "Resolve before proceeding."
                    ),
                })
                break
            if new_type == "exclusion" and e_type in ("execution", "persistence", "attribution"):
                conflicts.append({
                    "existing_finding": existing.get("id", ""),
                    "existing_title": existing.get("title", "")[:100],
                    "basis": (
                        f"Exclusion finding conflicts with APPROVED "
                        f"'{e_type}' finding ({existing.get('id', '')}). "
                        f"An exclusion cannot coexist with evidence of "
                        f"{e_type} activity on the same host."
                    ),
                })
                break

        return conflicts

    def _score_provenance(self, finding: dict, case_dir: Path) -> dict:
        audit_ids = set()
        for aid in finding.get("audit_ids", []):
            if aid:
                audit_ids.add(str(aid))
        for art in finding.get("artifacts", []):
            if art.get("audit_id"):
                audit_ids.add(str(art["audit_id"]))
        if not audit_ids:
            return {"summary": "NONE", "detail": "No audit trail references"}
        audit_dir = case_dir / "audit"
        if not audit_dir.is_dir():
            return {"summary": "NONE", "detail": "No audit directory"}
        found_ids: set[str] = set()
        mcp_ids, hook_ids, shell_ids, none_ids = [], [], [], []
        source_by_id: dict[str, str] = {}
        for jsonl_file in audit_dir.glob("*.jsonl"):
            try:
                with open(jsonl_file, encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            entry = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        aid = entry.get("audit_id", "")
                        if aid in audit_ids:
                            src = entry.get("source", "mcp")
                            if src in ("orchestrator_hook", "orchestrator_verified"):
                                source_by_id[aid] = "hook"
                            elif src in ("orchestrator_voluntary", "shell_self_report"):
                                source_by_id[aid] = "shell"
                            else:
                                source_by_id[aid] = "mcp"
                            found_ids.add(aid)
            except OSError:
                continue
        for aid in sorted(audit_ids):
            if not _AUDIT_ID_PATTERN.match(aid):
                none_ids.append(aid)
                continue
            source = source_by_id.get(aid)
            if source == "mcp":
                mcp_ids.append(aid)
            elif source == "hook":
                hook_ids.append(aid)
            elif source == "shell":
                shell_ids.append(aid)
            else:
                none_ids.append(aid)

        found = len(found_ids)
        if len(none_ids) == 0 and found > 0:
            summary = "MIXED" if hook_ids or shell_ids else "MCP"
            grade = "FULL"
        elif found > 0:
            summary = "MIXED" if (hook_ids or shell_ids) else "PARTIAL"
            grade = "PARTIAL"
        else:
            summary = "NONE"
            grade = "NONE"

        return {
            "summary": summary,
            "detail": f"{found}/{len(audit_ids)} audit IDs verified",
            "mcp": mcp_ids, "hook": hook_ids, "shell": shell_ids, "none": none_ids,
            "grade": grade,
        }

    def get_findings(self, status: str | None = None) -> list[dict]:
        try:
            case_dir = self.resolve_case_dir()
        except ValueError:
            return []
        findings = self._load_findings(case_dir)
        if status:
            findings = [f for f in findings if f.get("status", "").upper() == status.upper()]
        return findings

    # ── Timeline ──────────────────────────────────────────────────────

    def _load_timeline(self, case_dir: Path) -> list[dict]:
        path = case_dir / "timeline.json"
        data = _load_json_file(path, [])
        return data if isinstance(data, list) else data.get("events", [])

    def _save_timeline(self, case_dir: Path, events: list[dict]) -> None:
        path = case_dir / "timeline.json"
        content = json.dumps(events, indent=2, default=str)
        _atomic_write(path, content)

    def record_timeline_event(self, event: dict, examiner_override: str = "") -> dict:
        case_dir = self.require_active_case()
        exam = (examiner_override.strip().lower()
                if examiner_override and examiner_override.strip()
                else self.examiner)
        event_id = self._stage_timeline_event(case_dir, event, exam)
        return {"status": "STAGED", "event_id": event_id}

    def _stage_timeline_event(self, case_dir: Path, event: dict, exam: str) -> str:
        events = self._load_timeline(case_dir)
        seq = _next_seq(events, "id", "T", exam)
        event_id = f"T-{exam}-{seq:03d}"
        now = datetime.now(UTC).isoformat()
        entry = {
            "id": event_id,
            "status": "DRAFT",
            "timestamp": event.get("timestamp", now),
            "description": str(event.get("description", ""))[:5000],
            "event_type": event.get("event_type", "other") or "other",
            "source": event.get("source", ""),
            "artifact_ref": event.get("artifact_ref", ""),
            "related_findings": event.get("related_findings", []),
            "host": event.get("host", ""),
            "affected_account": event.get("affected_account", ""),
            "examiner": exam,
            "created_at": now,
            "modified_at": now,
            "staged": True,
        }
        events.append(entry)
        self._save_timeline(case_dir, events)
        return event_id

    def _auto_timeline_for_finding(self, case_dir: Path, finding: dict) -> str:
        timestamp = finding.get("event_timestamp", "")
        if not timestamp:
            return ""
        event = {
            "timestamp": timestamp,
            "description": finding.get("title") or finding.get("observation", ""),
            "event_type": finding.get("type") or finding.get("event_type") or "finding",
            "source": finding.get("artifact_ref", ""),
            "related_findings": [finding.get("id", "")],
            "host": finding.get("host", ""),
            "affected_account": finding.get("affected_account", ""),
        }
        return self._stage_timeline_event(case_dir, event, finding.get("examiner", self.examiner))

    def get_timeline(self, status: str | None = None, event_type: str | None = None,
                     start_date: str | None = None, end_date: str | None = None) -> list[dict]:
        try:
            case_dir = self.resolve_case_dir()
        except ValueError:
            return []
        events = self._load_timeline(case_dir)
        if status:
            events = [e for e in events if e.get("status", "").upper() == status.upper()]
        if event_type:
            events = [e for e in events if e.get("event_type", "") == event_type]
        if start_date:
            events = [e for e in events if e.get("timestamp", "") >= start_date]
        if end_date:
            events = [e for e in events if e.get("timestamp", "") <= end_date]
        return events

    # ── TODOs ─────────────────────────────────────────────────────────

    def _load_todos(self, case_dir: Path) -> list[dict]:
        path = case_dir / "todos.json"
        data = _load_json_file(path, [])
        return data if isinstance(data, list) else data.get("todos", [])

    def _save_todos(self, case_dir: Path, todos: list[dict]) -> None:
        path = case_dir / "todos.json"
        content = json.dumps(todos, indent=2, default=str)
        _atomic_write(path, content)

    def add_todo(self, description: str, assignee: str = "",
                 priority: str = "medium",
                 related_findings: list[str] | None = None,
                 examiner_override: str = "") -> dict:
        case_dir = self.require_active_case()
        exam = (examiner_override.strip().lower()
                if examiner_override and examiner_override.strip()
                else self.examiner)
        todos = self._load_todos(case_dir)
        seq = _next_seq(todos, "id", "TODO", exam)
        todo_id = f"TODO-{exam}-{seq:03d}"
        now = datetime.now(UTC).isoformat()
        entry = {
            "id": todo_id,
            "todo_id": todo_id,
            "description": description[:2000],
            "assignee": assignee[:100],
            "priority": priority.lower() if priority in ("high", "medium", "low") else "medium",
            "status": "open",
            "related_findings": related_findings or [],
            "examiner": exam,
            "created_at": now,
            "modified_at": now,
        }
        todos.append(entry)
        self._save_todos(case_dir, todos)
        return {"status": "created", "todo_id": todo_id}

    def list_todos(self, status: str = "open", assignee: str = "") -> list[dict]:
        try:
            case_dir = self.resolve_case_dir()
        except ValueError:
            return []
        todos = self._load_todos(case_dir)
        if status and status != "all":
            todos = [t for t in todos if t.get("status", "") == status]
        if assignee:
            todos = [t for t in todos if t.get("assignee", "") == assignee]
        return todos

    def update_todo(self, todo_id: str, status: str = "", note: str = "",
                    assignee: str = "", priority: str = "",
                    examiner_override: str = "") -> dict:
        case_dir = self.require_active_case()
        todos = self._load_todos(case_dir)
        for todo in todos:
            if todo.get("id") == todo_id or todo.get("todo_id") == todo_id:
                if status:
                    todo["status"] = status
                    if status == "completed":
                        todo["completed_at"] = datetime.now(UTC).isoformat()
                if note:
                    todo.setdefault("notes", []).append(note)
                if assignee:
                    todo["assignee"] = assignee
                if priority and priority in ("high", "medium", "low"):
                    todo["priority"] = priority
                todo["modified_at"] = datetime.now(UTC).isoformat()
                self._save_todos(case_dir, todos)
                return {"status": "updated", "todo_id": todo_id}
        return {"status": "not_found", "todo_id": todo_id}

    def complete_todo(self, todo_id: str, examiner_override: str = "") -> dict:
        return self.update_todo(todo_id, status="completed", examiner_override=examiner_override)

    # ── IOCs ──────────────────────────────────────────────────────────

    def _load_iocs(self, case_dir: Path) -> list[dict]:
        path = case_dir / "iocs.json"
        data = _load_json_file(path, [])
        return data if isinstance(data, list) else data.get("iocs", [])

    def _save_iocs(self, case_dir: Path, iocs: list[dict]) -> None:
        path = case_dir / "iocs.json"
        content = json.dumps(iocs, indent=2, default=str)
        _atomic_write(path, content)

    def _merge_iocs(self, case_dir: Path, new_iocs: list[dict]) -> None:
        existing = self._load_iocs(case_dir)
        existing_by_value = {}
        for ioc in existing:
            val = ioc.get("value", "").lower().strip()
            if val:
                existing_by_value[val] = ioc
        for ioc in new_iocs:
            val = ioc.get("value", "").lower().strip()
            if not val:
                continue
            if val in existing_by_value:
                sf = ioc.get("source_finding", "")
                if sf and sf not in existing_by_value[val].get("source_findings", []):
                    existing_by_value[val].setdefault("source_findings", []).append(sf)
                existing_by_value[val]["modified_at"] = datetime.now(UTC).isoformat()
            else:
                ioc["status"] = "DRAFT"
                ioc["source_findings"] = [ioc.get("source_finding", "")]
                now = datetime.now(UTC).isoformat()
                ioc["created_at"] = now
                existing.append(ioc)
        self._save_iocs(case_dir, existing)

    def _normalize_explicit_iocs(self, finding: dict) -> list[dict]:
        raw_iocs = finding.get("iocs", [])
        if isinstance(raw_iocs, dict):
            raw_iocs = [
                {"type": key, "value": value}
                for key, values in raw_iocs.items()
                for value in (values if isinstance(values, list) else [values])
            ]
        if not isinstance(raw_iocs, list):
            return []
        records = []
        for raw in raw_iocs[:100]:
            if isinstance(raw, dict):
                value = str(raw.get("value", raw.get("indicator", ""))).strip()
                ioc_type = str(raw.get("type", "")).strip()
                category = str(raw.get("category", "")).strip()
            else:
                value = str(raw).strip()
                ioc_type = ""
                category = ""
            if not value:
                continue
            if not ioc_type:
                ioc_type, category = _detect_ioc_type(value)
            elif not category:
                category = "identity" if "account" in ioc_type else "host"
            records.append({
                "value": value,
                "type": ioc_type,
                "category": category,
                "source_finding": finding.get("id", ""),
                "host": finding.get("host", ""),
                "confidence": finding.get("confidence", ""),
                "mitre_techniques": finding.get("attack_ids", []),
            })
        return records

    def get_iocs(self) -> list[dict]:
        try:
            case_dir = self.resolve_case_dir()
        except ValueError:
            return []
        return self._load_iocs(case_dir)

    # ── Evidence ──────────────────────────────────────────────────────

    def _load_evidence_registry(self, case_dir: Path) -> list[dict]:
        path = case_dir / "evidence.json"
        data = _load_json_file(path, [])
        return data if isinstance(data, list) else data.get("files", [])

    def _save_evidence(self, case_dir: Path, evidence: list[dict]) -> None:
        path = case_dir / "evidence.json"
        content = json.dumps(evidence, indent=2, default=str)
        _atomic_write(path, content)

    def register_evidence(self, path_str: str, description: str = "", examiner_override: str = "") -> dict:
        case_dir = self.require_active_case()
        exam = (examiner_override.strip().lower()
                if examiner_override and examiner_override.strip()
                else self.examiner)
        evidence_path = Path(path_str).resolve()
        if not evidence_path.exists():
            raise FileNotFoundError(f"Evidence path not found: {path_str}")

        sha256_hash = ""
        if evidence_path.is_file():
            h = hashlib.sha256()
            with open(evidence_path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            sha256_hash = h.hexdigest()

        now = datetime.now(UTC).isoformat()
        entry = {
            "path": str(evidence_path),
            "sha256": sha256_hash,
            "description": description[:500] if description else "",
            "examiner": exam,
            "registered_at": now,
            "status": "registered",
        }

        evidence = self._load_evidence_registry(case_dir)
        evidence.append(entry)
        self._save_evidence(case_dir, evidence)
        return {
            "status": "registered",
            "path": str(evidence_path),
            "sha256": sha256_hash,
            "files": 1,
        }

    def list_evidence(self) -> list[dict]:
        try:
            case_dir = self.resolve_case_dir()
        except ValueError:
            return []
        return self._load_evidence_registry(case_dir)

    def verify_evidence(self) -> dict:
        try:
            case_dir = self.resolve_case_dir()
        except ValueError:
            return {"status": "no_active_case"}
        evidence = self._load_evidence_registry(case_dir)
        results = []
        all_ok = True
        for entry in evidence:
            ep = Path(entry["path"])
            if not ep.exists():
                results.append({"path": entry["path"], "status": "MISSING"})
                all_ok = False
                continue
            if ep.is_file():
                h = hashlib.sha256()
                try:
                    with open(ep, "rb") as f:
                        for chunk in iter(lambda: f.read(65536), b""):
                            h.update(chunk)
                    current_hash = h.hexdigest()
                    if current_hash == entry["sha256"]:
                        results.append({"path": entry["path"], "status": "OK"})
                    else:
                        results.append({"path": entry["path"], "status": "MODIFIED"})
                        all_ok = False
                except OSError:
                    results.append({"path": entry["path"], "status": "ERROR"})
                    all_ok = False
            else:
                results.append({"path": entry["path"], "status": "OK", "note": "directory"})
        return {"status": "verified" if all_ok else "issues_found", "files": results}

    # ── Case Status ──────────────────────────────────────────────────

    def get_case_status(self, case_dir: Path | None = None) -> dict:
        if case_dir is None:
            try:
                case_dir = self.resolve_case_dir()
            except ValueError:
                return {"status": "no_active_case"}
        findings = self._load_findings(case_dir)
        timeline = self._load_timeline(case_dir)
        todos = self._load_todos(case_dir)
        evidence = self._load_evidence_registry(case_dir)
        iocs = self._load_iocs(case_dir)

        return {
            "case_id": case_dir.name,
            "findings": {
                "total": len(findings),
                "draft": sum(1 for f in findings if f.get("status") == "DRAFT"),
                "approved": sum(1 for f in findings if f.get("status") == "APPROVED"),
                "rejected": sum(1 for f in findings if f.get("status") == "REJECTED"),
            },
            "timeline_events": len(timeline),
            "todos": {
                "total": len(todos),
                "open": sum(1 for t in todos if t.get("status") == "open"),
                "completed": sum(1 for t in todos if t.get("status") == "completed"),
            },
            "evidence_files": len(evidence),
            "iocs": len(iocs),
        }
