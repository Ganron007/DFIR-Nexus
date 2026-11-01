"""D516: a named SIFT lane cannot acquire another run's output or active case."""
import json
import shutil
import subprocess
from pathlib import Path

import pytest
from mcp.server.fastmcp import FastMCP

from nexus.audit import AuditWriter
from nexus.case import outputs, sift_sync
from nexus.config import settings
from nexus.tools import sift

FIXTURES = Path(__file__).parent / "fixtures" / "d289_tool_headers"
RUN = "RUN-20261030T214623683042Z-tools-b152c459"


@pytest.fixture
def bound_sift(tmp_path, monkeypatch):
    cases = tmp_path / "cases"
    for name in ("CASE-NAMED", "CASE-OTHER"):
        folder = cases / name
        folder.mkdir(parents=True)
        (folder / "CASE.yaml").write_text(f"case_id: {name}\nstatus: open\n", encoding="utf-8")
    monkeypatch.setattr(settings, "cases_root", cases)
    monkeypatch.setattr(outputs, "resolve_active_case_dir", lambda: cases / "CASE-OTHER")
    monkeypatch.setenv("NEXUS_ACTIVE_CASE", "CASE-OTHER")
    monkeypatch.delenv("NEXUS_AUDIT_DIR", raising=False)
    monkeypatch.setattr(sift, "_IS_LINUX", True)
    monkeypatch.setattr(sift, "_find_binary", lambda _name: "nfdump")
    body = (FIXTURES / "jlecmd-auto.csv").read_text(encoding="utf-8-sig")
    calls = []

    def execute(argv, **kwargs):
        calls.append(argv)
        return {"success": True, "exit_code": 0, "stdout": body, "stdout_full": body,
                "stderr": "", "elapsed_seconds": 0.01, "persist_truncated": False}

    monkeypatch.setattr(sift, "_execute", execute)
    server = FastMCP("sift-run-binding")
    sift.register_tools(server, AuditWriter("nexus"))
    return server._tool_manager._tools["run_command"].fn, cases, calls, body


def test_named_sift_output_and_audit_ignore_the_remote_active_case(bound_sift):
    command, cases, calls, body = bound_sift
    result = command(command="nfdump", case_id="CASE-NAMED", run_id=RUN)
    assert result.get("success") is True, result
    assert calls
    root = cases / "CASE-NAMED" / "runs" / RUN / "extractions"
    assert result["output_files"]
    for item in result["output_files"]:
        assert Path(item["path"]).is_relative_to(root)
    assert Path(result["output_saved_to"]).read_text(encoding="utf-8") == body
    rows = [json.loads(line) for line in (cases / "CASE-NAMED" / "audit/nexus.jsonl").read_text(encoding="utf-8").splitlines()]
    assert rows[-1]["audit_id"] == result["audit_id"]
    assert rows[-1]["case_id"] == "CASE-NAMED"
    assert rows[-1]["params"]["run_id"] == RUN
    assert not (cases / "CASE-NAMED" / "extractions").exists()
    assert not (cases / "CASE-OTHER" / "extractions").exists()
    assert not (cases / "CASE-OTHER" / "audit").exists()


@pytest.mark.parametrize("case_id,run_id", [("CASE-MISSING", RUN), ("CASE-NAMED", "../outside"), ("", RUN)])
def test_invalid_explicit_sift_binding_is_refused_before_execution(bound_sift, case_id, run_id):
    command, cases, calls, _ = bound_sift
    result = command(command="nfdump", case_id=case_id, run_id=run_id)
    assert result.get("success") is False and result.get("error"), result
    assert calls == []
    assert not (cases / "CASE-OTHER" / "extractions").exists()
    assert not (cases / "CASE-MISSING").exists()


def test_pull_reads_only_the_named_remote_run_and_preserves_previous_outputs(tmp_path, monkeypatch):
    remote_root = tmp_path / "remote"
    case = remote_root / "CASE-NAMED"
    old = case / "extractions" / "jlecmd" / "old.csv"
    current = case / "runs" / RUN / "extractions" / "jlecmd" / "current.csv"
    old.parent.mkdir(parents=True)
    current.parent.mkdir(parents=True)
    shutil.copyfile(FIXTURES / "jlecmd-auto.csv", old)
    shutil.copyfile(FIXTURES / "jlecmd-custom.csv", current)
    key = tmp_path / "test-key"
    key.touch()
    monkeypatch.setenv("NEXUS_SIFT_SYNC", "1")
    monkeypatch.setattr(sift_sync, "_ssh_opts", lambda: {
        "host": "test-host", "user": "test-user", "key": str(key), "remote_cases": remote_root.as_posix(),
    })
    seen = []

    def copy_remote(cmd, **kwargs):
        source = Path(cmd[-2].split(":", 1)[1])
        seen.append(source)
        shutil.copytree(source, Path(cmd[-1]))
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(sift_sync.subprocess, "run", copy_remote)
    local = tmp_path / "local" / "CASE-NAMED"
    dest = local / "runs" / RUN / "sift" / "extractions"
    assert sift_sync.pull_sift_extractions("CASE-NAMED", local, dest, run_id=RUN) == dest
    assert seen == [current.parents[1]]
    assert (dest / "jlecmd/current.csv").read_bytes() == current.read_bytes()
    assert not (dest / "jlecmd/old.csv").exists()
    assert old.read_bytes() == (FIXTURES / "jlecmd-auto.csv").read_bytes()


def test_remote_output_preparation_keeps_case_run_identity_and_is_not_evidence():
    import asyncio

    from nexus.langgraph.tool_lane import ToolJob, _create_sift_output_dirs

    calls = []

    class Remote:
        async def ainvoke(self, args):
            calls.append(args)
            return {"success": True}

    job = ToolJob(host="sift", tool="zeek", argv=["zeek"], purpose="prepare",
                  timeout=60, prep_dirs=[f"/cases/CASE-NAMED/runs/{RUN}/extractions/zeek"])
    assert asyncio.run(_create_sift_output_dirs(
        job, Remote(), lambda value: value, case_id="CASE-NAMED", run_id=RUN,
    )) == ""
    assert len(calls) == 1
    assert calls[0]["case_id"] == "CASE-NAMED"
    assert calls[0]["run_id"] == RUN
    assert calls[0]["save_output"] is False


def test_missing_run_pull_is_a_visible_failed_transfer_and_blocks_the_gate(tmp_path, monkeypatch):
    from dataclasses import asdict

    from nexus.langgraph import tool_lane
    from nexus.langgraph.lane_gate import write_lane_gate

    case = tmp_path / "CASE-NAMED"
    case.mkdir()
    job = tool_lane.ToolJob(host="sift", tool="nfdump", argv=["nfdump"],
                            purpose="run output", status="OK")
    ledger = [asdict(job)]
    monkeypatch.setattr(sift_sync, "pull_sift_extractions", lambda *args, **kwargs: None)
    note = tool_lane._pull_sift_run_outputs(case, RUN, [job], ledger)
    assert "sift_pull_error" in note
    assert job.status == ledger[0]["status"] == "OK", "retain the actual remote command result"
    assert ledger[-1]["tool"] == "sift_pull"
    assert ledger[-1]["host"] == "operator"
    assert ledger[-1]["status"] == "FAIL"
    assert "pull" in ledger[-1]["reason"].lower()
    gate = write_lane_gate(case, RUN, ledger)
    assert gate["status"] == "blocked"
    assert gate["blocked_count"] == 1
    assert gate["waiting_count"] == 0


@pytest.mark.parametrize("feature", ["plaso", "bulk"])
def test_opt_in_sift_file_products_use_the_named_output_root(feature, monkeypatch):
    """Planning control only: no file contents are fabricated or tools executed."""
    from nexus.langgraph.tool_lane import sift_jobs_for_lane

    for name in ("NEXUS_SIFT_MEMORY_FILE", "NEXUS_SIFT_E01", "NEXUS_SIFT_DISK"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("NEXUS_SIFT_PLASO", "1" if feature == "plaso" else "0")
    monkeypatch.setenv("NEXUS_SIFT_BULK", "1" if feature == "bulk" else "0")
    evidence = "/srv/cases/CASE-NAMED/evidence"
    output = f"/srv/cases/CASE-NAMED/runs/{RUN}/extractions"
    jobs = sift_jobs_for_lane(evidence, has_sift_mcp=True, disk_image=f"{evidence}/disk.dd",
                             remote_extractions=output)
    if feature == "plaso":
        plaso = next(job for job in jobs if job.tool == "log2timeline")
        store = plaso.argv[plaso.argv.index("--storage-file") + 1]
        assert store == f"{output}/plaso.plaso"
        psort = next(job for job in jobs if job.tool == "psort")
        assert psort.argv[-1] == store
        assert psort.argv[psort.argv.index("-w") + 1] == f"{output}/plaso.csv"
        assert plaso.prep_dirs == [output]
    else:
        bulk = next(job for job in jobs if job.tool == "bulk_extractor")
        assert bulk.argv[bulk.argv.index("-o") + 1] == f"{output}/bulk_extractor"
        assert bulk.prep_dirs == [output], "bulk_extractor creates its own child directory"
