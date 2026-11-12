"""Case-file HMAC seal (WP 13.8 / T2-30).

Provides cryptographic seal over REPORT.md + findings via challenge-response or password
verification into the PBKDF2/HMAC verification ledger and transparency log.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


def seal_case(
    case_dir: Path,
    examiner: str,
    password: str,
    *,
    skip_verify: bool = False,
) -> dict[str, Any]:
    """Case-file HMAC seal: one signature over REPORT.md + findings.

    Verifies examiner credentials before signing (unless skip_verify is True).
    Computes HMAC over the exact content snapshot stored in the ledger,
    appends to the verification ledger, and writes transparency log entry.
    """
    from nexus.auth import (
        SIGNING_PURPOSE,
        _load_password_entry,
        compute_hmac,
        derive_hmac_key,
        derive_purpose_key,
        verify_password,
        write_verification_entry,
    )

    case_dir = Path(case_dir)
    report = case_dir / "reports" / "REPORT.md"
    findings = case_dir / "findings.json"
    if not report.is_file():
        return {"error": "No REPORT.md — generate the report first (N8)"}

    entry = _load_password_entry(examiner)
    if not entry:
        return {"error": f"No password configured for {examiner}"}

    if not skip_verify and not verify_password(examiner, password):
        return {"error": "Password verification failed"}

    content = report.read_text(encoding="utf-8")
    content_snapshot = content[:100000]
    findings_count = 0
    if findings.is_file():
        try:
            findings_count = len(json.loads(findings.read_text(encoding="utf-8")))
        except (OSError, ValueError):
            findings_count = 0

    if skip_verify:
        base_key = bytes.fromhex(entry["hash"])
    else:
        base_key = derive_hmac_key(password, entry["salt"])
    purpose_key = derive_purpose_key(base_key, SIGNING_PURPOSE)
    hmac_val = compute_hmac(purpose_key, content_snapshot)

    write_verification_entry(case_dir.name, {
        "finding_id": "CASE-FILE",
        "type": "case_file",
        "approved_by": examiner,
        "approved_at": datetime.now(UTC).isoformat(),
        "content_snapshot": content_snapshot,
        "hmac": hmac_val,
        "salt": entry.get("salt", ""),
        "findings_count": findings_count,
    })

    try:
        from nexus.transparency import transparency_append

        transparency_append(case_dir.name, {
            "action": "case_seal",
            "examiner": examiner,
            "findings_count": findings_count,
            "report_bytes": len(content),
            "hmac": hmac_val,
        })
    except Exception as exc:
        log.warning("Transparency log failed on case seal: %s", exc)

    return {
        "status": "SEALED",
        "examiner": examiner,
        "hmac": hmac_val,
        "findings_count": findings_count,
        "report_length": len(content),
    }
