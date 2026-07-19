"""Approve staged findings with password auth and HMAC verification.

Every approval requires password confirmation via terminal (no echo).
This blocks AI-via-Bash from approving without human involvement.

Supports: specific IDs, interactive review, HMAC signed verification ledger.
"""

import getpass
import json
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from nexus.auth import (
    has_password, verify_password, check_lockout, record_failure, clear_failures,
    setup_password, derive_hmac_key, derive_purpose_key, compute_hmac,
    write_verification_entry, SIGNING_PURPOSE,
)
from nexus.config import settings
from nexus.cli.main import _resolve_case


def _require_approval_auth(analyst: str) -> str | None:
    """Require password confirmation. Returns None on failure, password on success."""
    if not has_password(analyst):
        print("No approval password configured. Run: nexus config --setup-password")
        return None

    if check_lockout(analyst):
        print("Too many failed attempts. Locked out for 15 minutes.")
        return None

    for attempt in range(3):
        try:
            pw = getpass.getpass("Approval password: ")
        except (EOFError, KeyboardInterrupt):
            print("\nApproval cancelled.")
            return None

        if verify_password(analyst, pw):
            clear_failures(analyst)
            return pw
        record_failure(analyst)
        remaining = 2 - attempt
        if remaining > 0:
            print(f"Incorrect password. {remaining} attempt(s) remaining.")
        else:
            print("Locked out for 15 minutes.")

    return None


def _hmac_signing_key(password: str, analyst: str) -> bytes | None:
    """Derive HMAC key from stored_hash + purpose tag (matches portal)."""
    from nexus.auth import _load_password_entry
    entry = _load_password_entry(analyst)
    if not entry:
        return None
    stored_hash = entry.get("hash", "")
    if not stored_hash:
        return None
    return derive_purpose_key(bytes.fromhex(stored_hash), SIGNING_PURPOSE)


def approve_finding(
    case_dir: Path,
    finding_id: str,
    analyst: str,
    password: str,
    note: str = "",
) -> dict:
    """Approve a single finding with HMAC signing."""
    findings_path = case_dir / "findings.json"
    if not findings_path.exists():
        return {"error": "No findings file found"}

    findings = json.loads(findings_path.read_text())
    for f in findings:
        fid = f.get("id") or f.get("finding_id", "")
        if fid == finding_id and f.get("status") == "DRAFT":
            f["status"] = "APPROVED"
            f["approved_by"] = analyst
            f["approved_at"] = datetime.now(timezone.utc).isoformat()
            if note:
                f.setdefault("notes", []).append({"text": note, "author": analyst, "at": f["approved_at"]})

            findings_path.write_text(json.dumps(findings, indent=2, default=str))

            hmac_key = _hmac_signing_key(password, analyst)
            if hmac_key:
                content = json.dumps(f, sort_keys=True, default=str)
                hmac_val = compute_hmac(hmac_key, content)
                from nexus.auth import _load_password_entry
                entry = _load_password_entry(analyst)
                salt = entry.get("salt", "") if entry else ""
                write_verification_entry(f.get("case_id", "unknown"), {
                    "finding_id": finding_id,
                    "type": "finding",
                    "approved_by": analyst,
                    "approved_at": f["approved_at"],
                    "content_snapshot": content,
                    "hmac": hmac_val,
                    "salt": salt,
                })
            return {"finding_id": finding_id, "status": "APPROVED", "note": note}

    return {"error": f"Finding {finding_id} not found or not DRAFT"}


def approve_timeline_event(
    case_dir: Path,
    event_id: str,
    analyst: str,
    password: str,
    note: str = "",
) -> dict:
    """Approve a single timeline event."""
    tl_path = case_dir / "timeline.json"
    if not tl_path.exists():
        return {"error": "No timeline file found"}
    events = json.loads(tl_path.read_text())
    for e in events:
        eid = e.get("id") or e.get("event_id", "")
        if eid == event_id and e.get("status") in ("DRAFT", None):
            e["status"] = "APPROVED"
            e["approved_by"] = analyst
            e["approved_at"] = datetime.now(timezone.utc).isoformat()
            tl_path.write_text(json.dumps(events, indent=2, default=str))
            return {"event_id": event_id, "status": "APPROVED"}
    return {"error": f"Event {event_id} not found or not DRAFT"}


def _display_item(item: dict, kind: str) -> str:
    """Display a finding or timeline event for interactive review."""
    lines = []
    if kind == "finding":
        lines.append(f"  Finding: {item.get('title', '?')}")
        lines.append(f"    ID: {item.get('id', item.get('finding_id', '?'))}")
        lines.append(f"    Confidence: {item.get('confidence', '?')}")
        lines.append(f"    Type: {item.get('type', '?')}")
        desc = item.get('observation', item.get('description', ''))
        if desc:
            lines.append(f"    Description: {desc[:200]}")
    else:
        lines.append(f"  Timeline: {item.get('description', '?')[:100]}")
        lines.append(f"    ID: {item.get('id', item.get('event_id', '?'))}")
        lines.append(f"    Type: {item.get('event_type', '?')}")
        lines.append(f"    Timestamp: {item.get('timestamp', '?')}")
    return "\n".join(lines)
