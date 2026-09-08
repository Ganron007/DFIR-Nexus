"""Regression tests for the Phase 0-3 re-audit fixes (2026-09-08).

Covers bugs found by the independent re-audit subagent:
- 1.1 verify_hmac_entries used the wrong derived key (blocker)
- 1.3 CaseManager.record_finding dropped confidence_justification + evidence
- 1.4 _AUDIT_ID_PATTERN rejected underscored MCP names (e.g. claude_code-*)
- 1.5 verify_bearer_token allowed any token when expected was empty
- 1.6 load_chat ignored its limit parameter
- 1.8 llm_pipeline resume hardcoded ~/.nexus/cases instead of settings.cases_root
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


# ---------------------------------------------------------------------------
# 1.1 — verify_hmac_entries must use the purpose-separated signing key
# ---------------------------------------------------------------------------


def test_verify_hmac_entries_uses_purpose_key(tmp_path, monkeypatch):
    """A signed entry must verify True against the password that signed it.

    Before the fix, verify_hmac_entries derived only derive_hmac_key(password,
    salt) while every signing path used derive_purpose_key(..., SIGNING_PURPOSE),
    so verification always returned False for legitimate ledgers.
    """
    # Redirect VERIFICATION_DIR to tmp so we don't touch the real ledger.
    import nexus.auth as auth_mod
    from nexus.auth import (
        SIGNING_PURPOSE,
        compute_hmac,
        derive_hmac_key,
        derive_purpose_key,
        verify_hmac_entries,
        write_verification_entry,
    )

    monkeypatch.setattr(auth_mod, "VERIFICATION_DIR", tmp_path / "verification")

    case_id = "CASE-AUDIT-1"
    examiner = "lead"
    password = "correct-horse-battery-staple"
    salt = "salty-mc-saltface"

    # Sign the way the real approval path signs.
    derived = derive_purpose_key(derive_hmac_key(password, salt), SIGNING_PURPOSE)
    content = json.dumps({"id": "F-1", "status": "APPROVED"}, sort_keys=True)
    write_verification_entry(case_id, {
        "finding_id": "F-1",
        "type": "finding",
        "approved_by": examiner,
        "content_snapshot": content,
        "hmac": compute_hmac(derived, content),
        "salt": salt,
    })

    results = verify_hmac_entries(case_id, password, salt, examiner)
    assert len(results) == 1
    assert results[0]["verified"] is True


def test_verify_hmac_entries_rejects_wrong_password(tmp_path, monkeypatch):
    """A wrong password must verify False (sanity check the test above)."""
    import nexus.auth as auth_mod
    from nexus.auth import (
        SIGNING_PURPOSE,
        compute_hmac,
        derive_hmac_key,
        derive_purpose_key,
        verify_hmac_entries,
        write_verification_entry,
    )

    monkeypatch.setattr(auth_mod, "VERIFICATION_DIR", tmp_path / "verification")

    case_id = "CASE-AUDIT-2"
    examiner = "lead"
    password = "correct"
    wrong = "incorrect"
    salt = "salt"

    derived = derive_purpose_key(derive_hmac_key(password, salt), SIGNING_PURPOSE)
    content = "snapshot"
    write_verification_entry(case_id, {
        "finding_id": "F-2",
        "approved_by": examiner,
        "content_snapshot": content,
        "hmac": compute_hmac(derived, content),
        "salt": salt,
    })

    results = verify_hmac_entries(case_id, wrong, salt, examiner)
    assert len(results) == 1
    assert results[0]["verified"] is False


# ---------------------------------------------------------------------------
# 1.3 — record_finding must persist confidence_justification + evidence
# ---------------------------------------------------------------------------


def test_record_finding_persists_confidence_justification_and_evidence(tmp_path, monkeypatch):
    """FD-005 requires confidence_justification; Mode 1 promotion passes
    evidence rows. Both must survive the save/load cycle."""
    from nexus.case_manager import CaseManager

    # Point CaseManager at a tmp cases root.
    monkeypatch.setenv("NEXUS_CASES_ROOT", str(tmp_path / "cases"))
    case_dir = tmp_path / "cases" / "CASE-CJ"
    case_dir.mkdir(parents=True)
    (case_dir / "CASE.yaml").write_text("case_id: CASE-CJ\ncase_name: CJ test\n")

    mgr = CaseManager()
    # Create an audit log entry so provenance passes (FD-001).
    # The audit_id must match _AUDIT_ID_PATTERN (mcp_name-examiner-date-seq).
    audit_dir = case_dir / "audit"
    audit_dir.mkdir(exist_ok=True)
    audit_id = "hayabusa-examiner-20260908-001"
    (audit_dir / "tool.jsonl").write_text(
        json.dumps({"audit_id": audit_id, "source": "mcp", "tool": "test"}) + "\n"
    )
    finding = {
        "title": "T",
        "observation": "O",
        "interpretation": "I",
        "confidence": "HIGH",
        "confidence_justification": "Three independent tool outputs agree.",
        "evidence": [{"audit_id": audit_id, "path": "/x", "note": "n"}],
        "audit_ids": [audit_id],
    }
    result = mgr.record_finding(
        finding=finding,
        examiner_override="lead",
        case_dir=case_dir,
    )
    assert result.get("status") != "REJECTED", result

    findings = json.loads((case_dir / "findings.json").read_text())
    assert findings, "findings.json should not be empty"
    f = findings[0]
    assert f.get("confidence_justification") == "Three independent tool outputs agree."
    assert f.get("evidence") == [{"audit_id": audit_id, "path": "/x", "note": "n"}]


# ---------------------------------------------------------------------------
# 1.4 — _AUDIT_ID_PATTERN must accept underscored MCP names
# ---------------------------------------------------------------------------


def test_audit_id_pattern_accepts_underscored_mcp_name():
    """audit.py emits IDs like claude_code-examiner-20260810-001 via
    mcp_name.replace('-', '_'). The pattern must accept the underscore."""
    from nexus.case_manager import _AUDIT_ID_PATTERN

    assert _AUDIT_ID_PATTERN.match("claude_code-examiner-20260810-001")
    # Sanity: still rejects garbage.
    assert _AUDIT_ID_PATTERN.match("not-an-audit-id") is None


# ---------------------------------------------------------------------------
# 1.5 — verify_bearer_token must deny when no expected token is configured
# ---------------------------------------------------------------------------


def test_verify_bearer_token_denies_when_unconfigured():
    """An empty expected token must NOT authenticate any supplied token.
    Before the fix, an unconfigured NEXUS_BEARER_TOKEN silently allowed
    every request."""
    from nexus.auth import verify_bearer_token

    assert verify_bearer_token("anything", "") is False
    assert verify_bearer_token("", "") is False
    # Configured token still compares correctly.
    assert verify_bearer_token("real", "real") is True
    assert verify_bearer_token("fake", "real") is False


# ---------------------------------------------------------------------------
# 1.6 — load_chat must honor its limit parameter
# ---------------------------------------------------------------------------


def test_load_chat_honors_limit(tmp_path):
    """load_chat(limit=N) must return at most N entries, not a hardcoded 500."""
    from nexus.case.chat import append_chat, load_chat

    case_dir = tmp_path / "CASE-LIMIT"
    case_dir.mkdir()
    for i in range(10):
        append_chat(case_dir, "examiner", "ask", f"q{i}")

    # limit=3 → only the last 3
    msgs = load_chat(case_dir, limit=3)
    assert len(msgs) == 3
    assert msgs[-1]["text"] == "q9"

    # limit=0 → all (no bounding)
    all_msgs = load_chat(case_dir, limit=0)
    assert len(all_msgs) == 10


# ---------------------------------------------------------------------------
# 1.8 — llm_pipeline resume must use settings.cases_root, not ~/.nexus/cases
# ---------------------------------------------------------------------------


def test_llm_pipeline_resume_uses_settings_cases_root(tmp_path, monkeypatch):
    """The resume branch must resolve the case dir under
    settings.cases_root, not a hardcoded Path.home() / .nexus / cases."""
    from nexus.config import settings

    custom_root = tmp_path / "custom-cases"
    custom_root.mkdir()
    monkeypatch.setattr(settings, "cases_root", custom_root)

    case_id = "CASE-RESUME"
    case_dir = custom_root / case_id
    case_dir.mkdir()
    (case_dir / "approvals.jsonl").write_text(
        json.dumps({"finding_id": "F-1", "status": "APPROVED"}) + "\n"
    )

    # Read the resume branch source and assert it no longer hardcodes the path.
    src = (Path(__file__).parent.parent / "src" / "nexus" / "langgraph" / "llm_pipeline.py").read_text()
    assert "Path.home() / \".nexus\" / \"cases\"" not in src, (
        "llm_pipeline.py still hardcodes ~/.nexus/cases in the resume branch"
    )
