"""What the first live Mode 1 run on CASE-C5B04D31 showed (2026-10-14).

The run printed nothing for about 40 minutes and was stopped; its manifest then said
'running' with no process behind it; its DRAFTs had no run id; and two TI providers printed
full tracebacks for answers that were not failures (YARAify's endpoint was wrong, and Shodan's
404 means it has no record for the address).
"""
from __future__ import annotations

import asyncio
import json
import logging
import subprocess
import sys

import pytest
import yaml
from _audit_rows import cite_rows


def _case(case_id: str):
    from nexus.config import settings

    case = settings.cases_root / case_id
    (case / "analysis").mkdir(parents=True)
    (case / "audit").mkdir()
    (case / "CASE.yaml").write_text(
        yaml.safe_dump({"case_id": case_id, "status": "open"}), encoding="utf-8")
    return case


def test_a_run_whose_process_exited_is_reaped_as_interrupted():
    from nexus.langgraph.pipeline_runs import create_run, reap_dead_runs

    case = _case("CASE-REAP01")
    dead = create_run(case, "interpret")
    live = create_run(case, "interpret")
    gone = subprocess.run([sys.executable, "-c", "import os; print(os.getpid())"],
                          capture_output=True, text=True, check=True)
    manifest = json.loads((dead.path / "manifest.json").read_text(encoding="utf-8"))
    manifest["pid"] = int(gone.stdout.strip())
    (dead.path / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    assert reap_dead_runs(case) == [dead.run_id]
    after = json.loads((dead.path / "manifest.json").read_text(encoding="utf-8"))
    assert after["status"] == "interrupted"
    assert "exited before the run finished" in after["error"]
    still = json.loads((live.path / "manifest.json").read_text(encoding="utf-8"))
    assert still["status"] == "running"  # this process is alive


def test_a_mode1_draft_names_its_run():
    from mcp.server.fastmcp import FastMCP

    from nexus.audit import AuditWriter
    from nexus.case_manager import CaseManager
    from nexus.tools import forensic

    case = _case("CASE-RUNID01")
    aid = cite_rows(case, [{"loc": "evtx.csv:3", "detail": "4688 cmd.exe", "host": "ws01"}])
    server = FastMCP("runid-test")
    forensic.register_tools(server, AuditWriter("t", audit_dir=case / "audit"))
    tool = server._tool_manager._tools["record_finding"].fn
    out = tool(title="cmd.exe launched", observation="one 4688 row", interpretation="execution",
               confidence="LOW", confidence_justification="one row", audit_ids=[aid],
               artifacts=[{"audit_id": aid}], case_id=case.name, run_id="RUN-TEST-interpret-1")
    assert out.get("finding_id"), out
    stored = next(f for f in CaseManager()._load_findings(case) if f["id"] == out["finding_id"])
    assert stored["run_id"] == "RUN-TEST-interpret-1"
    assert stored["provenance"]["run_id"] == "RUN-TEST-interpret-1"
    assert stored["provenance"]["mode"] == 1


def test_stage_findings_sends_the_run_id():
    from nexus.langgraph.llm_pipeline import stage_findings

    case = _case("CASE-RUNID02")
    sent: list[dict] = []

    class _Tool:
        name = "record_finding"

        async def ainvoke(self, payload):
            sent.append(dict(payload))
            return {"finding_id": "F-1"}

    finding = {"title": "t", "observation": "o", "interpretation": "i", "confidence": "LOW",
               "confidence_justification": "j", "audit_ids": ["nexus-x-20261014-001"]}
    state = {"case_id": case.name, "run_id": "RUN-TEST-interpret-2", "tool_run_ledger": [],
             "case_context": {}, "evidence_audit_ids": [],
             "messages": [{"role": "assistant", "content": "```json\n" + json.dumps([finding]) + "\n```"}]}
    asyncio.run(stage_findings(state, {"record_finding": _Tool()}))
    assert sent and sent[0]["run_id"] == "RUN-TEST-interpret-2"


def test_every_stage_speaks_on_the_progress_channel(caplog):
    from nexus.langgraph.llm_pipeline import emit_stage

    with caplog.at_level(logging.INFO, logger="nexus.progress"):
        emit_stage({}, "interpret", "round 2/3", "5 ok, 0 error(s), 120 row(s); verifying")
    assert any(r.name == "nexus.progress" and "round 2/3" in r.getMessage() for r in caplog.records)


def test_yaraify_reads_the_documented_lookup_hash_reply():
    """https://yaraify.abuse.ch/api/: matches are in data.tasks[].static_results[] and in
    data.tasks[].unpack_results[].unpacked_yara_matches[]."""
    from nexus.ti.providers.abuse_ch import _yaraify_rules

    reply = {"query_status": "ok", "data": {"metadata": {}, "tasks": [
        {"static_results": [{"rule_name": "a"}],
         "unpack_results": [{"unpacked_yara_matches": [{"rule_name": "b"}]}]},
        {"static_results": [{"rule_name": "c"}], "unpack_results": []},
    ]}}
    assert [m["rule_name"] for m in _yaraify_rules(reply)] == ["a", "b", "c"]
    assert _yaraify_rules({"query_status": "hash_not_found", "data": None}) == []


@pytest.mark.parametrize("status,expect_error", [(404, False), (500, True)])
def test_shodan_404_is_no_information_and_other_errors_still_fail(monkeypatch, status, expect_error):
    import httpx

    from nexus.ti.providers import optional

    class _Client:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def get(self, url, params=None):
            return httpx.Response(status, request=httpx.Request("GET", url), json={"error": "x"})

    monkeypatch.setenv(optional.ENV_SHODAN_API_KEY, "test-key")
    monkeypatch.setattr(optional.httpx, "AsyncClient", _Client)
    if expect_error:
        with pytest.raises(httpx.HTTPStatusError):
            asyncio.run(optional.query_shodan("10.0.0.1", mock=False))
    else:
        result = asyncio.run(optional.query_shodan("10.0.0.1", mock=False))
        assert result.summary == "Shodan: no information for this IP"
