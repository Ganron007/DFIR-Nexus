"""Quick integration test for DFIR-Nexus — tests all tool modules end-to-end."""

import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
os.environ["NEXUS_CASES_ROOT"] = tempfile.mkdtemp(prefix="nexus_test_")

from nexus.app import create_server

server = create_server()
tools = server._tool_manager._tools
passed = 0
failed = 0


def check(label, condition, detail=""):
    global passed, failed
    if condition:
        passed += 1
        print(f"  PASS: {label}" + (f" — {detail}" if detail else ""))
    else:
        failed += 1
        print(f"  FAIL: {label}" + (f" — {detail}" if detail else ""))


# 1. case_init
r = tools["case_init"].fn("Test Investigation", case_id="TEST-001")
check("case_init", r["status"] == "created", f"ID={r['case_id']}")

# 2. case_status
r = tools["case_status"].fn("TEST-001")
check("case_status", "findings" in r)

# 3. Create audit trail first (required for provenance chain)
r = tools["log_external_action"].fn(
    command="MFTECmd -f C:\\Evidence\\MFT",
    output_summary="MFT parsed successfully",
    purpose="MFT analysis for evidence",
)
_audit_id = r.get("audit_id", "")
check("log_external_action (for finding)", _audit_id is not None and _audit_id != "", f"audit_id={_audit_id}")

# 4. record_finding with provenance
r = tools["record_finding"].fn(
    title="Suspicious execution from AppData",
    observation="MFT shows EVIL.EXE launched from AppData",
    interpretation="EVIL.EXE launched from a user-writable directory is consistent with initial access via phishing",
    confidence="MEDIUM",
    confidence_justification="MFT $STANDARD_INFORMATION and $FILE_NAME timestamps corroborate execution",
    host="DC-01",
    event_timestamp="2026-01-15T14:32:00Z",
    artifacts=[{"audit_id": _audit_id, "type": "mft", "value": "C:\\Evidence\\MFT"}],
)
check("record_finding", r.get("status") == "STAGED", f"status={r.get('status')} id={r.get('finding_id', r.get('error', ''))}")

# 5. record_timeline_event
r = tools["record_timeline_event"].fn(
    timestamp="2026-01-15T14:32:00Z",
    description="EVIL.EXE executed from Temp",
    event_type="execution",
)
check("record_timeline_event", r["status"] == "STAGED", f"ID={r['event_id']}")

# 6. get_findings
r = tools["get_findings"].fn(status="DRAFT")
check("get_findings", r["total"] == 1, f"{r['total']} findings (expected 1)")

# 7. add_todo
r = tools["add_todo"].fn("Review MFT analysis", priority="high")
check("add_todo", r["status"] == "created", f"ID={r['todo_id']}")

# 7. list_todos
r = tools["list_todos"].fn()
check("list_todos", len(r) == 1, f"{len(r)} open")

# 8. complete_todo
r = tools["complete_todo"].fn(r[0]["id"])
check("complete_todo", r["status"] == "updated")

# 9. update_todo
r = tools["update_todo"].fn(r["todo_id"], status="completed")
check("update_todo", r["status"] == "updated")

# 10. generate_report
r = tools["generate_report"].fn(profile="full", case_id="TEST-001")
check("generate_report", "profile" in r, f"profile={r.get('profile')}")

# 11. list_profiles
r = tools["list_profiles"].fn()
profile_count = r.get("count") if isinstance(r, dict) else len(r)
check("list_profiles", profile_count == 6, f"{profile_count} profiles")

# 12. get_environment (SIFT/Linux only)
if "get_environment" in tools:
    r = tools["get_environment"].fn()
    check("get_environment", "platform" in r, r.get("platform", ""))
else:
    check("get_environment", True, "(skipped - not on Linux)")

# 13. SIFT/Linux-specific tools
def _try_tool(name, *args, **kwargs):
    if name in tools:
        r = tools[name].fn(*args, **kwargs)
        check(name, True, "ok")
        return r
    else:
        check(name, True, f"(skipped - {name} not available on this platform)")
        return None

# 13. log_reasoning
r = tools["log_reasoning"].fn("Choosing prefetch analysis next")
check("log_reasoning", r["status"] == "logged")

# 14. SIFT-specific tools (conditional)
_try_tool("list_available_tools")
_try_tool("suggest_tools", "prefetch")
_try_tool("check_tools", ["mftecmd", "hayabusa"])
_try_tool("get_tool_help", "mftecmd")
if "run_command" in tools:
    r = _try_tool("run_command", "python --version")
    if r:
        check("run_command has data", bool(r.get("data")), "")
else:
    check("run_command", True, "(skipped - not on Linux)")

# 15. evidence_register
ev_path = os.path.join(tempfile.gettempdir(), "nexus_test_evidence.bin")
with open(ev_path, "wb") as f:
    f.write(b"fake evidence content " * 100)
r = tools["evidence_register"].fn(ev_path, "Test evidence")
check("evidence_register", r["status"] == "registered", f"sha256={r['sha256'][:16]}...")

# 15. evidence_list
r = tools["evidence_list"].fn()
check("evidence_list", len(r) == 1, f"{len(r)} files")

# 16. evidence_verify
r = tools["evidence_verify"].fn()
check("evidence_verify", r["status"] == "verified")

# 17. case_list
r = tools["case_list"].fn()
check("case_list", len(r) == 1, f"{len(r)} cases")

# 18. set_case_metadata
r = tools["set_case_metadata"].fn("incident_type", "ransomware")
check("set_case_metadata", r["status"] == "set", f"{r['field']}={r['value']}")

# 19. get_case_metadata
r = tools["get_case_metadata"].fn()
check("get_case_metadata", "incident_type" in r, f"type={r.get('incident_type')}")

# 20. backup_case
backup_dir = tempfile.mkdtemp(prefix="nexus_backup_")
r = tools["backup_case"].fn(backup_dir)
check("backup_case", r["status"] == "backed_up", r.get("backup_path", ""))

# 21. export_case
r = tools["export_case"].fn()
check("export_case", "findings" in r, f"{len(r['findings'])} findings")

# 22-26. SIFT/Linux-specific tools (conditional)
_check_tools = ["list_available_tools", "suggest_tools", "check_tools", "run_command", "get_tool_help"]
for _name in _check_tools:
    if _name in tools:
        _try_tool(_name, "prefetch" if _name == "suggest_tools" else (["mftecmd", "hayabusa"] if _name == "check_tools" else "python --version" if _name == "run_command" else "mftecmd" if _name == "get_tool_help" else ""))
    else:
        check(_name, True, "(skipped - not on Linux)")

# 27. record_action
r = tools["record_action"].fn("Reviewed initial findings")
check("record_action", r["status"] == "recorded")

# 28. get_case_actions
r = tools["get_case_actions"].fn()
check("get_case_actions", len(r) >= 1, f"{len(r)} actions")

# 29. case_close
r = tools["case_close"].fn("TEST-001")
check("case_close", r["status"] == "closed")

# 30. case_list (closed)
r = tools["case_list"].fn()
check("case_list after close", len(r) == 1)

# 31. log_external_action
r = tools["log_external_action"].fn(
    command="python --version",
    output_summary="Python 3.x",
    purpose="Check Python version",
)
check("log_external_action", r["status"] == "logged", f"audit_id={r.get('audit_id', '')}")

# 32. save_report
r = tools["save_report"].fn("test_report.md", "# Test Report\n\nApproved findings here.")
check("save_report", r["status"] == "saved", f"path={r.get('path', '')}")

# 33. list_reports
r = tools["list_reports"].fn()
check("list_reports", len(r) == 1, f"{len(r)} reports")

# 34. reset_counters (SIFT-only)
if "reset_counters" in tools:
    r = tools["reset_counters"].fn()
    check("reset_counters", r["status"] == "reset")
else:
    check("reset_counters", True, "(skipped - not on Linux)")

# 35. get_findings (with no status = all)
r = tools["get_findings"].fn()
check("get_findings (all)", r["total"] == 1, f"{r['total']} total (expected 1)")

# Cleanup
os.unlink(ev_path)
shutil.rmtree(os.environ["NEXUS_CASES_ROOT"], ignore_errors=True)

print()
print(f"=== {passed} PASSED, {failed} FAILED (out of {passed + failed}) ===")
print(f"Total tools registered: {len(tools)}")
