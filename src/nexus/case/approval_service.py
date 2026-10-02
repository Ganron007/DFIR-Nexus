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


class ApprovalError(RuntimeError):
    """An approval or rejection could not be performed."""


class ApprovalPasswordError(ApprovalError):
    """The examiner password did not match."""


class ApprovalLockedError(ApprovalError):
    """Too many failed attempts for this examiner."""


def require_examiner(examiner: str, password: str) -> dict[str, Any]:
    """Verify the examiner password with the shared lockout.

    Returns that examiner's password entry, so the caller can derive the
    signing key. This is the one place a password is checked for an approval
    performed outside the CLI or the portal.
    """
    from nexus.auth import (
        _load_password_entry,
        check_lockout,
        clear_failures,
        record_failure,
        verify_password,
    )

    if check_lockout(examiner):
        raise ApprovalLockedError(
            f"{examiner} is locked out after too many failed attempts"
        )
    if not verify_password(examiner, password):
        record_failure(examiner)
        raise ApprovalPasswordError("Invalid approval password")
    clear_failures(examiner)
    return _load_password_entry(examiner) or {}


def approval_ledger_status(case_dir: Path | str) -> tuple[bool, list[str]]:
    """Every APPROVED finding must have a verification-ledger entry.

    The signature lives in the ledger, not on the finding, so this is what
    replaces verifying an HMAC stored on the record.
    """
    from nexus.auth import read_verification_ledger

    case_dir = Path(case_dir)
    findings = _load(case_dir) or []
    ledger = read_verification_ledger(case_dir.name)
    logged = {
        str(entry.get("finding_id") or "")
        for entry in ledger
        if str(entry.get("type") or "") == "finding"
    }
    errors: list[str] = []
    for finding in findings:
        if str(finding.get("status") or "").upper() != "APPROVED":
            continue
        fid = _finding_id(finding)
        if fid and fid not in logged:
            errors.append(f"Finding {fid} approved but has no verification-ledger entry")
    return (not errors, errors)


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


def _canonical(doc: dict[str, Any]) -> str:
    return json.dumps(doc, sort_keys=True, default=str)


def _authoritative(case_dir: Path) -> tuple[list[dict[str, Any]] | None, str]:
    """The findings to act on, and a refusal when the mirror has drifted.

    D3 = B made the ``case_records`` document canonical and ``findings.json`` a
    generated mirror, but only the sync path ever read the store — approvals
    still worked off the mirror, so a hand-edited flat file was approved as if
    it were the record. The store wins when it holds anything for this case; a
    mirror that does not match it exactly is a tamper signal, not something to
    quietly overwrite.
    """
    recorded: list[dict[str, Any]] = []
    try:
        from nexus.case.records import load_records

        recorded = [
            doc for doc in load_records(case_dir, "finding") if isinstance(doc, dict)
        ]
    except Exception:  # noqa: BLE001 — fall back to the mirror
        recorded = []

    mirrored = _load(case_dir)
    if not recorded:
        return mirrored, ""
    if mirrored is None:
        return recorded, ""

    by_id = {_finding_id(doc): doc for doc in recorded if _finding_id(doc)}
    mirror_ids = {_finding_id(doc) for doc in mirrored if _finding_id(doc)}
    if set(by_id) != mirror_ids:
        return None, (
            "mirror differs from the record store: the flat file and the case "
            "record list different findings. findings.json is a generated "
            "mirror, so a difference means it was edited outside the case store."
        )
    for doc in mirrored:
        fid = _finding_id(doc)
        if _canonical(doc) != _canonical(by_id[fid]):
            return None, (
                f"mirror differs from the record store for finding {fid}: "
                "findings.json is a generated mirror, so a difference means it "
                "was edited outside the case store."
            )
    return recorded, ""


def _refusal(finding_id: str, message: str, **extra: Any) -> dict[str, Any]:
    return {
        "finding_id": finding_id,
        "status": "error",
        "error": message,
        "message": message,
        **extra,
    }


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
    """Approve one DRAFT.

    Three refusals live here rather than in the callers, so the CLI, the portal
    and ``CaseManager`` cannot diverge: a broken seal, a mirror that disagrees
    with the record store, and a non-PROVEN verdict without an override reason.
    """
    case_dir = Path(case_dir)
    findings, refusal = _authoritative(case_dir)
    if refusal:
        return _refusal(finding_id, refusal)
    if findings is None:
        return _refusal(finding_id, "No findings file found")

    verdict = str(l1_verdict or "UNVERIFIABLE").strip().upper() or "UNVERIFIABLE"

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
        # Tier 1's rule: every approved claim is verified or explicitly
        # overridden. The callers enforced it; the service now does, so a
        # programmatic approval cannot bypass it by passing nothing. Checked
        # after the seal, so integrity is what a tampered finding is refused for.
        if verdict != "PROVEN" and not str(override_reason).strip():
            return _refusal(
                finding_id,
                (
                    f"Refused: finding {finding_id} is L1 {verdict} and has no "
                    "override_reason. An approved claim is either verified or "
                    "explicitly overridden — record why the examiner accepts it."
                ),
                l1_verdict=verdict,
                needs_override_reason=True,
            )
        finding["status"] = "APPROVED"
        finding["approved_by"] = examiner
        finding["approved_at"] = datetime.now(UTC).isoformat()
        finding["l1_verdict_at_approval"] = verdict
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
            "l1_verdict": verdict,
        }

    message = f"Finding {finding_id} not found or not DRAFT"
    return _refusal(finding_id, message)
def commit_rejection(
    case_dir: Path | str,
    finding_id: str,
    examiner: str,
    reason: str,
) -> dict[str, Any]:
    """Reject one DRAFT and record the dismissal."""
    case_dir = Path(case_dir)
    findings, refusal = _authoritative(case_dir)
    if refusal:
        return _refusal(finding_id, refusal)
    if findings is None:
        return _refusal(finding_id, "No findings file found")

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
