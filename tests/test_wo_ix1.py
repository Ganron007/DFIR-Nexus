"""WO-IX1 (RB-B4): Approval and custody integrity before publication.

Tests for:
- Third-eye R02: Canonical root binding and global uniqueness in case_init.
- Third-eye R08: Password rotation uses purpose key derivation to preserve approval verifiability.
- Third-eye R14: Process-safe temporary file during records mirror publication.
- D140: Tools accept explicit case_id without falling back to require_active_case().
- D150 / T2-45: SIFT MCP executor-only profile exposes only executor and lifecycle tools.
"""
from __future__ import annotations

import json

from mcp.server.fastmcp import FastMCP

from nexus.audit import AuditWriter
from nexus.auth import (
    SIGNING_PURPOSE,
    _load_password_entry,
    compute_hmac,
    derive_hmac_key,
    derive_purpose_key,
    reset_password,
    setup_password,
    verify_hmac_entries,
)
from nexus.case.records import _publish
from nexus.config import settings
from nexus.tools.case import register_case_lifecycle_tools, register_tools


def test_r02_case_init_rejects_alternate_root_and_duplicate_id(tmp_path, monkeypatch):
    """R02: An alternate root directory is rejected; duplicate case IDs are blocked."""
    cases_root = tmp_path / "cases"
    cases_root.mkdir(exist_ok=True)
    monkeypatch.setattr(settings, "cases_root", cases_root)

    server = FastMCP("test")
    audit = AuditWriter("test", audit_dir=tmp_path / "audit")
    register_case_lifecycle_tools(server, audit)
    case_init_fn = server._tool_manager._tools["case_init"].fn

    # 1. Reject custom cases_dir outside canonical root
    alt_dir = tmp_path / "alt_cases"
    alt_dir.mkdir(exist_ok=True)
    res = case_init_fn(name="Alt Case", case_id="CASE-R02-ALT", cases_dir=str(alt_dir))
    assert "error" in res
    assert "Custom cases_dir is not permitted" in res["error"]
    assert not (alt_dir / "CASE-R02-ALT").exists()

    # 2. Normal creation succeeds under canonical root
    res_ok = case_init_fn(name="Canonical Case", case_id="CASE-R02-CANON")
    assert res_ok.get("status") == "created"
    assert (cases_root / "CASE-R02-CANON").is_dir()

    # 3. Duplicate ID is rejected before any write
    res_dup = case_init_fn(name="Duplicate Case", case_id="CASE-R02-CANON")
    assert "error" in res_dup
    assert "already exists" in res_dup["error"]


def test_r08_password_rotation_purpose_key_re_signs_approvals(tmp_path, monkeypatch):
    """R08: reset_password re-signs approvals using purpose-derived keys."""
    pw_dir = tmp_path / "passwords"
    pw_dir.mkdir(exist_ok=True)
    monkeypatch.setattr("nexus.auth._PASSWORDS_DIR", pw_dir)
    verif_dir = tmp_path / "verification"
    verif_dir.mkdir(exist_ok=True)
    monkeypatch.setattr("nexus.auth.VERIFICATION_DIR", verif_dir)
    monkeypatch.setattr("nexus.auth._LOCKOUT_FILE", tmp_path / "lockout.json")

    examiner = "analyst1"
    old_pw = "OldPassword123!"
    new_pw = "NewPassword456!"

    # 1. Initialize examiner password
    set_res = setup_password(examiner, old_pw)
    assert set_res.get("status") == "ok"
    salt = _load_password_entry(examiner)["salt"]

    # 2. Create an approval entry signed with purpose key
    case_id = "CASE-R08-01"
    content_desc = "Finding F-001: Malicious process execution"
    raw_key = derive_hmac_key(old_pw, salt)
    purpose_key = derive_purpose_key(raw_key, SIGNING_PURPOSE)
    sig = compute_hmac(purpose_key, content_desc)

    ledger_path = verif_dir / f"{case_id}.jsonl"
    entry = {
        "finding_id": "F-001",
        "type": "finding",
        "approved_by": examiner,
        "content_snapshot": content_desc,
        "hmac": sig,
    }
    ledger_path.write_text(json.dumps(entry) + "\n", encoding="utf-8")

    # 3. Verify before reset
    results_before = verify_hmac_entries(case_id, old_pw, salt, examiner)
    assert len(results_before) == 1
    assert results_before[0]["verified"] is True

    # 4. Rotate password
    reset_res = reset_password(examiner, old_pw, new_pw)
    assert reset_res.get("status") == "ok"
    assert reset_res.get("re_signed") == 1
    new_salt = _load_password_entry(examiner)["salt"]

    # 5. Verify after reset with new password
    results_after = verify_hmac_entries(case_id, new_pw, new_salt, examiner)
    assert len(results_after) == 1
    assert results_after[0]["verified"] is True, "Approval must verify with new password"

    # Old password fails
    results_old = verify_hmac_entries(case_id, old_pw, new_salt, examiner)
    assert len(results_old) == 1
    assert results_old[0]["verified"] is False


def test_r14_records_publish_unique_temp_file(tmp_path):
    """R14: _publish writes to a process-unique temporary path before atomic replacement."""
    mirror = tmp_path / "findings.json"
    content = [{"id": "F-001", "title": "Test"}]
    _publish(mirror, json.dumps(content))
    assert mirror.is_file()
    assert json.loads(mirror.read_text(encoding="utf-8")) == content
    # No dangling .tmp file
    assert not (tmp_path / "findings.json.tmp").exists()


def test_d140_tools_accept_explicit_case_id(tmp_path, monkeypatch):
    """D140: Tools accept an explicit case_id and operate on it without active case."""
    cases_root = tmp_path / "cases"
    cases_root.mkdir(exist_ok=True)
    monkeypatch.setattr(settings, "cases_root", cases_root)
    # Ensure active_case pointer points elsewhere or is unset
    active_file = tmp_path / "active_case"
    active_file.write_text("CASE-INACTIVE", encoding="utf-8")
    monkeypatch.setattr("nexus.tools.case._active_case_file", lambda: active_file)

    server = FastMCP("test")
    audit = AuditWriter("test", audit_dir=tmp_path / "audit")
    register_tools(server, audit)

    case_id = "CASE-D140-01"
    case_init_fn = server._tool_manager._tools["case_init"].fn
    res = case_init_fn(name="D140 Case", case_id=case_id)
    assert res.get("status") == "created"

    # 1. evidence_list with explicit case_id
    evidence_list_fn = server._tool_manager._tools["evidence_list"].fn
    assert evidence_list_fn(case_id=case_id) == []

    # 2. record_action and get_case_actions with explicit case_id
    record_action_fn = server._tool_manager._tools["record_action"].fn
    act_res = record_action_fn(description="Action 1", tool="probe", case_id=case_id)
    assert act_res.get("status") == "recorded"

    get_actions_fn = server._tool_manager._tools["get_case_actions"].fn
    actions = get_actions_fn(case_id=case_id)
    assert len(actions) == 1
    assert actions[0]["description"] == "Action 1"

    # 3. export_case with explicit case_id
    export_case_fn = server._tool_manager._tools["export_case"].fn
    bundle = export_case_fn(case_id=case_id)
    assert bundle["case_id"] == case_id

    # 4. backup_case with explicit case_id
    backup_case_fn = server._tool_manager._tools["backup_case"].fn
    backup_dest = tmp_path / "backups"
    bk_res = backup_case_fn(destination=str(backup_dest), case_id=case_id)
    assert bk_res.get("status") == "backed_up"


def test_d150_executor_only_profile(monkeypatch):
    """D150: Executor-only profile exposes only executor tools and lifecycle tools."""
    from nexus.app import create_server

    monkeypatch.setenv("NEXUS_EXECUTOR_ONLY", "1")
    server = create_server()

    tool_names = set(server._tool_manager._tools.keys())

    # Case lifecycle tools must be present
    assert "case_init" in tool_names
    assert "case_activate" in tool_names

    # Mutating / knowledge / query tools must NOT be present
    excluded_tools = {
        "record_finding",
        "import_case",
        "findings_list",
        "es_search",
        "es_aggregate",
        "rag_search",
        "opencti_search",
        "triage_summary",
        "generate_report",
    }
    assert not (tool_names & excluded_tools), f"Executor-only exposed forbidden tools: {tool_names & excluded_tools}"
