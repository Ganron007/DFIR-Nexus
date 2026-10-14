"""A lane command's audit row is written to the case the call names (2026-10-14, D178).

`run_windows_command` took `case_id` and never put it in its audit row, so the row went wherever
the active pointer pointed. CASE-C5B04D31's lane ledgers cite 229 audit ids that its own log gives
to other calls (es_search, ingest_auto ...), because each log numbered its ids on its own.
"""
from __future__ import annotations

import json

import yaml


def _rows(path):
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def test_a_lane_command_is_audited_in_the_case_it_names(tmp_path, monkeypatch):
    from mcp.server.fastmcp import FastMCP

    import nexus.tools.windows as win
    from nexus.audit import AuditWriter
    from nexus.config import settings

    cases = tmp_path / "cases"
    for name in ("CASE-A", "CASE-B"):
        (cases / name).mkdir(parents=True)
        (cases / name / "CASE.yaml").write_text(yaml.safe_dump({"case_id": name, "status": "open"}),
                                                encoding="utf-8")
    pointer = tmp_path / "active_case"
    pointer.write_text("CASE-B", encoding="utf-8")  # another case is active
    monkeypatch.setattr(settings, "cases_root", cases)
    monkeypatch.setenv("NEXUS_ACTIVE_CASE_FILE", str(pointer))
    for name in ("NEXUS_CASE_DIR", "NEXUS_AUDIT_DIR", "NEXUS_ACTIVE_CASE"):
        monkeypatch.delenv(name, raising=False)

    class _Result:
        returncode = 0
        stdout = "ok"
        stderr = ""

    monkeypatch.setattr(win.subprocess, "run", lambda *_a, **_k: _Result())
    server = FastMCP("audit-case")
    win.register_tools(server, AuditWriter("nexus"))
    run = server._tool_manager._tools["run_windows_command"].fn
    result = run(command=["mftecmd", "--help"], purpose="routing", save_output=False,
                 case_id="CASE-A")
    assert result.get("audit_id"), result
    rows = _rows(cases / "CASE-A" / "audit" / "nexus.jsonl")
    # Run or refused (a checkout without the tool binaries refuses it), the row is CASE-A's.
    assert [r["audit_id"] for r in rows] == [result["audit_id"]]
    assert rows[0]["tool"].startswith("run_windows_command") and rows[0]["case_id"] == "CASE-A"
    assert _rows(cases / "CASE-B" / "audit" / "nexus.jsonl") == []
