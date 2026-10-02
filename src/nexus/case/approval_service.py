"""The examiner approval for a flat finding.

CLI and portal both call this. The seal check, the record write, the
verification ledger, and the transparency entry happen here, so the two
surfaces cannot drift.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def signing_key_from_stored_hash(stored_hash_hex: str) -> bytes | None:
    """The same purpose key the portal derives after a successful challenge."""
    if not str(stored_hash_hex or "").strip():
        return None
    from nexus.auth import SIGNING_PURPOSE, derive_purpose_key

    return derive_purpose_key(bytes.fromhex(stored_hash_hex), SIGNING_PURPOSE)


def _load(case_dir: Path) -> list[dict[str, Any]] | None:
    path = case_dir / "findings.json"
    if not path.is_file():
        return None
    loaded = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, list):
        return None
    return loaded


def _finding_id(doc: dict[str, Any]) -> str:
    return str(doc.get("id") or doc.get("finding_id") or "")


def cited_event_ids(finding: dict[str, Any]) -> list[str]:
    """Timeline event ids this finding names. Empty when it cites none."""
    found: list[str] = []
    for key in ("event_id", "event_ids"):
        value = finding.get(key)
        if isinstance(value, str) and value.strip():
            found.append(value.strip())
        elif isinstance(value, list):
            found.extend(str(item).strip() for item in value if str(item).strip())
    for artifact in finding.get("artifacts") or []:
        if isinstance(artifact, dict):
            event_id = str(artifact.get("event_id") or "").strip()
            if event_id:
                found.append(event_id)
    return list(dict.fromkeys(found))


def commit_approval(
    case_dir: Path | str,
    finding_id: str,
    examiner: str,
    *,
    l1_verdict: str = "",
    override_reason: str = "",
    note: str = "",
    signing_key: bytes | None = None,
    salt: str = "",
) -> dict[str, Any]:
    """Approve one DRAFT. A broken seal is refused and the file is unchanged."""
    case_dir = Path(case_dir)
    findings = _load(case_dir)
    if findings is None:
        return {"finding_id": finding_id, "status": "error", "error": "No findings file found", "message": "No findings file"}

    for finding in findings:
        if _finding_id(finding) != finding_id or finding.get("status") != "DRAFT":
            continue
        try:
            from nexus.analysis.integrity import verify_seal

            seal_ok, seal_reason = verify_seal(finding)
        except Exception as exc:  # noqa: BLE001
            seal_ok, seal_reason = False, f"seal check failed: {exc}"
        has_seal = bool(finding.get("seal") or finding.get("content_hash"))
        if has_seal and not seal_ok:
            message = (
                f"Refused: finding {finding_id} failed its submission seal — {seal_reason}. "
                "It was edited after staging; re-stage it so the digest matches the content."
            )
            return {
                "finding_id": finding_id,
                "status": "error",
                "error": message,
                "message": message,
                "seal_reason": seal_reason,
            }
        seal_state = "verified" if (has_seal and seal_ok) else "absent"
        finding["status"] = "APPROVED"
        finding["approved_by"] = examiner
        finding["approved_at"] = datetime.now(UTC).isoformat()
        finding["l1_verdict_at_approval"] = l1_verdict or "UNVERIFIABLE"
        finding["seal_state"] = seal_state
        if override_reason:
            finding["override_reason"] = override_reason
        if note:
            finding.setdefault("notes", []).append(
                {"text": note, "author": examiner, "at": finding["approved_at"]}
            )

        from nexus.case.records import save_findings

        save_findings(case_dir, findings)
        cited = cited_event_ids(finding)
        if cited:
            try:
                from nexus.dashboard.timeline_api import TimelineStore

                TimelineStore(case_dir.name).link_finding(finding_id, cited)
            except Exception:  # noqa: BLE001 - approval stands if the index is down
                pass

        if signing_key is not None:
            from nexus.auth import compute_hmac, write_verification_entry

            content = json.dumps(finding, sort_keys=True, default=str)
            write_verification_entry(case_dir.name, {
                "finding_id": finding_id,
                "type": "finding",
                "approved_by": examiner,
                "approved_at": finding["approved_at"],
                "content_snapshot": content,
                "hmac": compute_hmac(signing_key, content),
                "salt": salt,
                "l1_verdict_at_approval": finding["l1_verdict_at_approval"],
                "seal_state": seal_state,
                "override_reason": override_reason,
            })
        from nexus.transparency import transparency_append

        transparency_append(case_dir.name, {
            "action": "approve",
            "finding_id": finding_id,
            "approved_by": examiner,
            "l1_verdict_at_approval": finding["l1_verdict_at_approval"],
            "override_reason": override_reason,
        })
        return {
            "finding_id": finding_id,
            "status": "APPROVED",
            "note": note,
            "seal_state": seal_state,
        }

    message = f"Finding {finding_id} not found or not DRAFT"
    return {"finding_id": finding_id, "status": "error", "error": message, "message": message}


def commit_rejection(
    case_dir: Path | str,
    finding_id: str,
    examiner: str,
    reason: str,
) -> dict[str, Any]:
    """Reject one DRAFT and record the dismissal."""
    case_dir = Path(case_dir)
    findings = _load(case_dir)
    if findings is None:
        return {"finding_id": finding_id, "status": "error", "error": "No findings file found", "message": "No findings file"}

    for finding in findings:
        if _finding_id(finding) != finding_id or finding.get("status") != "DRAFT":
            continue
        finding["status"] = "REJECTED"
        finding["rejected_by"] = examiner
        finding["rejected_at"] = datetime.now(UTC).isoformat()
        finding["rejection_reason"] = reason
        from nexus.case.records import save_findings

        save_findings(case_dir, findings)
        try:
            from nexus.analysis.negative_space import record

            record(case_dir, "false_positive_dismissed", finding_id, reason, refs=[finding_id])
        except Exception:  # noqa: BLE001 — the rejection stands if the side log fails
            pass
        return {"finding_id": finding_id, "status": "REJECTED"}

    message = f"Finding {finding_id} not found or not DRAFT"
    return {"finding_id": finding_id, "status": "error", "error": message, "message": message}
