"""Compat bridge between flat-JSON case state and SQLite case stack.

Provides:
- dict↔dataclass converters for Case, Finding, EvidenceRecord
- LegacyJsonImporter — migrate flat-JSON cases into SQLite
- get_sqlite_manager() — convenience factory that picks up the default DB path
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from nexus.case.manager import CaseManager
from nexus.case.schemas import (
    ApprovalState,
    Case,
    CaseStatus,
    EvidenceRecord,
    Finding,
    FindingSeverity,
)
from nexus.config import settings

log = logging.getLogger(__name__)

_DEFAULT_DB_FILENAME = "cases.db"


def get_sqlite_manager(db_path: Path | str | None = None) -> CaseManager:
    """Return a CaseManager wired to the default SQLite database."""
    path = db_path or settings.cases_root / _DEFAULT_DB_FILENAME
    return CaseManager(path)


def _atomic_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    tmp.replace(path)


def sync_sqlite_to_flat(
    case_id: str,
    mgr: CaseManager | None = None,
    case_dir: Path | None = None,
) -> Path | None:
    """Mirror SQLite findings/evidence into flat JSON for portal + MCP report.

    LangGraph / ``nexus.case.CaseManager`` persist to SQLite. MCP
    ``generate_report`` and the Examiner Portal read ``findings.json`` /
    ``evidence.json`` / ``timeline.json`` under the case directory.
    Without this sync, an orchestrated case has approved findings in SQLite
    and an empty examiner report.
    """
    close_mgr = False
    if mgr is None:
        mgr = get_sqlite_manager()
        close_mgr = True
    try:
        case = mgr.get_case(case_id)
        if case is None:
            return None
        dest = Path(case_dir) if case_dir else settings.cases_root / case_id
        dest.mkdir(parents=True, exist_ok=True)

        from nexus.case.manager import materialize_case_dir
        try:
            materialize_case_dir(case)
        except OSError as exc:
            log.warning("materialize_case_dir failed for %s: %s", case_id, exc)

        findings_out: list[dict[str, Any]] = []
        for f in mgr.list_findings(case_id):
            status = f.approval_state.value.upper()
            meta = dict(f.metadata or {})
            obs = str(meta.get("observation") or "").strip()
            interp = str(meta.get("interpretation") or "").strip()
            if not obs and not interp:
                obs = f.description or ""
                interp = f.description or ""
            elif not obs:
                obs = f.description if f.description != interp else ""
            elif not interp:
                interp = f.description if f.description != obs else ""
            findings_out.append({
                "id": f.id,
                "case_id": f.case_id,
                "status": status,
                "approval_state": status,
                "title": f.title,
                "observation": obs,
                "interpretation": interp,
                "confidence": str(meta.get("confidence") or "MEDIUM"),
                "confidence_justification": str(
                    meta.get("confidence_justification") or ""
                ),
                "severity": f.severity.value,
                "type": str(meta.get("type") or "finding"),
                "host": str(meta.get("host") or ""),
                "attack_ids": list(f.technique_ids),
                "mitre_ids": list(f.technique_ids),
                "mitre_techniques": list(f.technique_ids),
                "audit_ids": list(meta.get("audit_ids") or []),
                "itm_stage": str(meta.get("itm_stage") or ""),
                "itm_objects": list(meta.get("itm_objects") or []),
                "iocs": list(meta.get("iocs") or []),
                "created_by": f.created_by,
                "created_at": f.created_at.isoformat() if f.created_at else "",
                "approved_by": f.approved_by,
                "approved_at": f.approved_at.isoformat() if f.approved_at else None,
                "hmac_signature": bool(f.hmac_signature),
            })

        evidence_out: list[dict[str, Any]] = []
        timeline_out: list[dict[str, Any]] = []
        iocs: dict[str, list[dict[str, Any]]] = {"ip": [], "host": [], "hash": []}
        seen_ioc: set[str] = set()

        for i, ev in enumerate(mgr.list_evidence(case_id), start=1):
            meta = dict(ev.metadata or {})
            evidence_out.append({
                "id": ev.id,
                "path": ev.file_path or "",
                "sha256": ev.file_hash_sha256 or "",
                "description": ev.description or ev.name,
                "examiner": ev.collected_by,
                "registered_at": ev.collected_at.isoformat() if ev.collected_at else "",
                "status": "registered",
                "name": ev.name,
                "host": meta.get("host") or "",
                "user": meta.get("user") or "",
                "source_ip": meta.get("source_ip") or "",
                "dest_ip": meta.get("dest_ip") or "",
                "process_name": meta.get("process_name") or "",
                "technique_ids": meta.get("technique_ids") or [],
            })
            ts = meta.get("timestamp") or (ev.collected_at.isoformat() if ev.collected_at else "")
            timeline_out.append({
                "id": f"T-EV-{i:03d}",
                "status": "APPROVED",
                "timestamp": ts,
                "description": ev.description or ev.name,
                "event_type": "evidence",
                "source": (ev.name.split(":")[0] if ev.name else ""),
                "artifact_ref": ev.artifact_id or "",
                "related_findings": [],
                "host": meta.get("host") or "",
                "affected_account": meta.get("user") or "",
                "examiner": ev.collected_by,
                "created_at": ev.collected_at.isoformat() if ev.collected_at else "",
                "staged": True,
            })
            for key, ioc_type in (("dest_ip", "ip"), ("source_ip", "ip"), ("host", "host")):
                val = meta.get(key)
                if val and str(val) not in seen_ioc:
                    seen_ioc.add(str(val))
                    iocs[ioc_type].append({"value": str(val), "source_findings": [], "source": "evidence"})
            if ev.file_hash_sha256:
                hv = ev.file_hash_sha256
                if hv not in seen_ioc:
                    seen_ioc.add(hv)
                    iocs["hash"].append({"value": hv, "source_findings": [], "source": "evidence"})

        _atomic_json(dest / "findings.json", findings_out)
        _atomic_json(dest / "evidence.json", evidence_out)
        _atomic_json(dest / "timeline.json", timeline_out)
        _atomic_json(dest / "iocs.json", iocs)
        if not (dest / "todos.json").exists():
            _atomic_json(dest / "todos.json", [])
        return dest
    finally:
        if close_mgr:
            mgr.close()


# ------------------------------------------------------------------
# Dict → Dataclass converters (legacy flat JSON → SQLite)
# ------------------------------------------------------------------

def _opt_iso_to_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except (ValueError, TypeError):
        return None


def dict_to_case(d: dict[str, Any]) -> Case:
    """Convert a flat-JSON case dict to a Case dataclass."""
    case_id = d.get("case_id") or d.get("id") or ""
    name = d.get("name") or d.get("title") or ""
    raw_status = d.get("status", "open")
    raw_sev = d.get("severity", "medium")
    try:
        status = CaseStatus(raw_status)
    except ValueError:
        status = CaseStatus.OPEN
    try:
        severity = FindingSeverity(raw_sev)
    except ValueError:
        severity = FindingSeverity.MEDIUM
    created_at = _opt_iso_to_dt(d.get("created_at")) or datetime.now(UTC)
    created_by = d.get("created_by") or d.get("examiner") or "system"
    return Case(
        id=case_id,
        name=name,
        description=d.get("description", ""),
        status=status,
        severity=severity,
        created_at=created_at,
        created_by=created_by,
        closed_at=_opt_iso_to_dt(d.get("closed_at")),
        closed_by=d.get("closed_by"),
        tags=d.get("tags", []),
        metadata=d.get("metadata", {}),
        approval_password_hash=d.get("approval_password_hash"),
        approval_password_salt=d.get("approval_password_salt"),
        approval_iterations=d.get("approval_iterations", 600000),
    )


def dict_to_finding(d: dict[str, Any]) -> Finding:
    """Convert a flat-JSON finding dict to a Finding dataclass."""
    fid = d.get("id") or d.get("finding_id") or ""
    raw_sev = d.get("severity") or d.get("confidence") or "medium"
    try:
        severity = FindingSeverity.normalize(raw_sev)
    except (ValueError, TypeError):
        severity = FindingSeverity.MEDIUM
    raw_state = d.get("status") or d.get("approval_state") or "draft"
    try:
        approval_state = ApprovalState(raw_state.lower())
    except ValueError:
        approval_state = ApprovalState.DRAFT
    created_at = _opt_iso_to_dt(d.get("created_at")) or datetime.now(UTC)
    created_by = d.get("created_by") or d.get("examiner") or "system"
    obs = str(d.get("observation") or "")
    interp = str(d.get("interpretation") or "")
    meta = dict(d.get("metadata") or {})
    if obs:
        meta.setdefault("observation", obs)
    if interp:
        meta.setdefault("interpretation", interp)
    if d.get("confidence"):
        meta.setdefault("confidence", d.get("confidence"))
    if d.get("confidence_justification"):
        meta.setdefault("confidence_justification", d.get("confidence_justification"))
    if d.get("host"):
        meta.setdefault("host", d.get("host"))
    if d.get("type"):
        meta.setdefault("type", d.get("type"))
    if d.get("audit_ids"):
        meta.setdefault("audit_ids", d.get("audit_ids"))
    if d.get("itm_stage"):
        meta.setdefault("itm_stage", d.get("itm_stage"))
    if d.get("itm_objects"):
        meta.setdefault("itm_objects", d.get("itm_objects"))
    if d.get("iocs"):
        meta.setdefault("iocs", d.get("iocs"))
    tech = d.get("attack_ids") or d.get("mitre_ids") or d.get("technique_ids") or []
    if not tech:
        mt = d.get("mitre_techniques") or []
        if mt and isinstance(mt[0], str):
            tech = mt
        elif mt and isinstance(mt[0], dict):
            tech = [x.get("id") for x in mt if isinstance(x, dict) and x.get("id")]
    return Finding(
        id=fid,
        case_id=d.get("case_id", ""),
        title=d.get("title") or d.get("observation", ""),
        description=interp or obs or d.get("description") or "",
        severity=severity,
        artifact_id=d.get("artifact_ref"),
        technique_ids=list(tech or []),
        created_at=created_at,
        created_by=created_by,
        metadata=meta,
        approval_state=approval_state,
        approved_by=d.get("approved_by"),
        approved_at=_opt_iso_to_dt(d.get("approved_at")),
        rejected_by=d.get("rejected_by"),
        rejected_at=_opt_iso_to_dt(d.get("rejected_at")),
        rejection_reason=d.get("rejection_reason"),
        hmac_signature=d.get("hmac_signature"),
        hmac_salt=d.get("hmac_salt"),
    )


def dict_to_evidence(d: dict[str, Any]) -> EvidenceRecord:
    """Convert a flat-JSON evidence dict to an EvidenceRecord dataclass."""
    eid = d.get("id") or EvidenceRecord.new_id()
    registered_at = _opt_iso_to_dt(d.get("registered_at")) or datetime.now(UTC)
    examiner = d.get("examiner") or d.get("collected_by") or "system"
    return EvidenceRecord(
        id=eid,
        case_id=d.get("case_id", ""),
        artifact_id=d.get("artifact_id"),
        name=str(Path(d.get("path", "")).name) or d.get("name", ""),
        description=d.get("description", ""),
        file_path=d.get("path"),
        file_hash_md5=d.get("file_hash_md5"),
        file_hash_sha1=d.get("file_hash_sha1"),
        file_hash_sha256=d.get("sha256"),
        collected_at=registered_at,
        collected_by=examiner,
        chain_of_custody=d.get("chain_of_custody", []),
        metadata=d.get("metadata", {}),
    )


# ------------------------------------------------------------------
# Legacy JSON importer
# ------------------------------------------------------------------

class LegacyJsonImporter:
    """Import a flat-JSON case directory into the SQLite case stack.

    Usage:
        importer = LegacyJsonImporter(mgr)
        importer.import_case(case_dir)
    """

    def __init__(self, mgr: CaseManager | None = None) -> None:
        self._mgr = mgr or get_sqlite_manager()

    @property
    def mgr(self) -> CaseManager:
        return self._mgr

    def import_case(self, case_dir: Path) -> Case | None:
        """Import all data from a flat-JSON case directory into SQLite.

        Reads CASE.yaml (metadata), findings.json, evidence.json, and
        evidence_registry.json. Timeline, TODOs, and IOCs are NOT imported
        (those remain flat-JSON only until the SQLite schema is extended).
        """
        if not case_dir.is_dir():
            log.warning("Case directory not found: %s", case_dir)
            return None

        case_id = case_dir.name
        case = self._import_case_meta(case_dir, case_id)
        if case is None:
            return None

        self._import_findings(case_dir, case_id)
        self._import_evidence(case_dir, case_id)
        return case

    def _import_case_meta(self, case_dir: Path, case_id: str) -> Case | None:
        """Create or update the SQLite case from CASE.yaml or minimal defaults."""
        meta_path = case_dir / "CASE.yaml"
        if meta_path.exists():
            import yaml as _yaml
            try:
                meta = _yaml.safe_load(meta_path.read_text(encoding="utf-8")) or {}
            except Exception:
                meta = {}
            d = {**meta, "id": case_id, "case_id": case_id}
        else:
            d = {"id": case_id, "case_id": case_id, "name": case_id, "status": "open"}

        case = dict_to_case(d)
        self.mgr.store.save_case(case)
        return case

    def _import_findings(self, case_dir: Path, case_id: str) -> list[Finding]:
        findings_path = case_dir / "findings.json"
        if not findings_path.exists():
            return []
        try:
            raw = json.loads(findings_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return []
        items = raw if isinstance(raw, list) else raw.get("findings", [])
        out: list[Finding] = []
        for item in items:
            item["case_id"] = case_id
            finding = dict_to_finding(item)
            self.mgr.store.save_finding(finding)
            out.append(finding)
        return out

    def _import_evidence(self, case_dir: Path, case_id: str) -> list[EvidenceRecord]:
        results: list[EvidenceRecord] = []
        for filename in ("evidence.json", "evidence_registry.json"):
            path = case_dir / filename
            if not path.exists():
                continue
            try:
                raw = json.loads(path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                continue
            items = raw if isinstance(raw, list) else raw.get("files", [])
            for item in items:
                item["case_id"] = case_id
                ev = dict_to_evidence(item)
                self.mgr.store.save_evidence(ev)
                results.append(ev)
        return results

    def import_all_cases(self, cases_root: Path | None = None) -> dict[str, int]:
        """Import ALL flat-JSON cases under the given root.

        Returns a dict mapping case_id → number of imported findings.
        """
        root = cases_root or settings.cases_root
        stats: dict[str, int] = {}
        if not root.is_dir():
            return stats
        for case_dir in sorted(root.iterdir()):
            if not case_dir.is_dir():
                continue
            if not (case_dir / "findings.json").exists() and not (case_dir / "CASE.yaml").exists():
                continue
            case = self.import_case(case_dir)
            if case:
                findings = self.mgr.list_findings(case.id)
                stats[case.id] = len(findings)
        return stats
