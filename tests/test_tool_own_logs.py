"""D229: what a tool writes about its own run is not evidence, and is neither promoted nor indexed.

CASE-C5B04D31's index held LogFileParser's `debug.log` (5,135 lines: its banner, settings and
progress) and a promoted copy of its console output (5,138 lines). The lane promotes a job's console
output when the job wrote nothing else, and it judged that from argv flags it knows, which do not
include LogFileParser's `/OutputPath:` or maldump's and bmc-tools' `-d`; so it promoted beside their
CSVs (4 LogFileParser, 4 maldump and 2 bmc-tools jobs across the case's lane runs).
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

# The first lines of LogFileParser 2.0.0.53's debug.log in CASE-C5B04D31's lane run of 2026-10-11.
DEBUG_LOG = (
    "NTFS $LogFile Parser 2.0.0.53\n"
    "Using $LogFile: H:\\C\\$LogFile\n"
    "Unicode: 0\n"
    "Using precision separator: .\n"
    "LSN Validation level: 0.1 (10 %)\n"
    "Timestamps presented in UTC: 0.00\n"
)
LOGFILE_CSV = "lf_Offset,lf_MFTReference,lf_RealMFTReference,lf_MFTBaseRecRef\n0x00002000,41,41,0\n"


@pytest.fixture()
def run_case(tmp_path, monkeypatch):
    from nexus.langgraph import pipeline_runs

    case_dir = tmp_path / "CASE-OWNLOG-0001"
    extractions = case_dir / "runs" / "RUN-1" / "extractions"
    extractions.mkdir(parents=True)
    monkeypatch.setattr(pipeline_runs, "resolve_tools_extractions",
                        lambda case_dir, run_id="": extractions)
    return case_dir, extractions


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _limit_plan_to_logfileparser(monkeypatch) -> None:
    """Keep these lane-path tests focused on the one real planned parser job."""
    from nexus.langgraph import tool_lane

    plan = tool_lane.plan_windows_triage

    def logfileparser_only(*args, **kwargs):
        return [job for job in plan(*args, **kwargs) if job.tool == "logfileparser"]

    monkeypatch.setattr(tool_lane, "plan_windows_triage", logfileparser_only)


def _configure_lane_test(monkeypatch) -> None:
    """Isolate the output gate from evidence freshness and optional SIFT work."""
    from nexus.analysis import freshness
    from nexus.langgraph import case_index, tool_lane

    monkeypatch.setattr(case_index, "es_available", lambda: False)
    monkeypatch.setattr(
        freshness,
        "capture_freshness",
        lambda *_args, **_kwargs: {"items": [], "result": "unknown"},
    )
    monkeypatch.setattr(tool_lane, "sift_jobs_for_lane", lambda *_args, **_kwargs: [])
    _limit_plan_to_logfileparser(monkeypatch)


def test_the_index_leaves_out_logfileparsers_own_log(run_case):
    from nexus.langgraph.case_index import iter_index_doc_batches
    from nexus.langgraph.query_pack import iter_extraction_files

    case_dir, extractions = run_case
    out = extractions / "logfileparser" / "LogFile_2026-10-11_16-36-43"
    _write(out / "debug.log", DEBUG_LOG)
    _write(out / "LogFile.csv", LOGFILE_CSV)
    # A file of the same name that another source holds is that source's content.
    _write(extractions / "pstranscript" / "debug.log", "PS C:\\> Get-Process\n")
    files = {str(p.relative_to(extractions)).replace("\\", "/")
             for p, _root, _fam in iter_extraction_files(case_dir)}
    assert files == {"logfileparser/LogFile_2026-10-11_16-36-43/LogFile.csv", "pstranscript/debug.log"}
    docs = [doc for batch in iter_index_doc_batches(case_dir) for doc in batch]
    assert not any("LogFile Parser 2.0.0.53" in str(doc.get("text") or "") for doc in docs)


@pytest.fixture()
def lane_case(tmp_path, monkeypatch) -> Path:
    from nexus.case.manager import CaseManager
    from nexus.case.schemas import FindingSeverity
    from nexus.config import settings

    monkeypatch.setattr(settings, "cases_root", tmp_path)
    monkeypatch.setenv("NEXUS_EXAMINER", "ownlog_test")
    monkeypatch.delenv("NEXUS_TOOL_LANE_QUICK", raising=False)
    root = tmp_path / "CASE-OWNLOG-0002"
    root.mkdir()
    mgr = CaseManager(settings.cases_root / "cases.db")
    mgr.create_case(name="Own log fixture", description="a tool's own log is not evidence",
                    severity=FindingSeverity.LOW, created_by="ownlog_test",
                    metadata={"synthetic": True}, case_id=root.name)
    mgr.close()
    return root


def test_default_lane_sends_logfile_to_mftecmd_and_plans_no_logfileparser_row(lane_case, monkeypatch):
    """TA-Z (operator OD-T13, 2026-10-24): the default lane's $LogFile job is MFTECmd's, run through the executor.

    This replaced the test of the LogFileParser default-skip policy, which OD-T13 retired. The stub executor fails
    explicitly; it never reads the placeholder or writes MFTECmd output.
    """
    from nexus.analysis import freshness
    from nexus.case.evidence_service import register_evidence
    from nexus.langgraph import case_index, tool_lane
    from nexus.langgraph.tool_lane import run_tool_lane

    monkeypatch.setattr(case_index, "es_available", lambda: False)
    monkeypatch.setattr(freshness, "capture_freshness", lambda *_a, **_k: {"items": [], "result": "unknown"})
    monkeypatch.setattr(tool_lane, "sift_jobs_for_lane", lambda *_a, **_k: [])
    real_plan = tool_lane.plan_windows_triage

    def logfile_only(*args, **kwargs):
        return [j for j in real_plan(*args, **kwargs) if "$LogFile" in j.purpose or j.tool == "logfileparser"]

    monkeypatch.setattr(tool_lane, "plan_windows_triage", logfile_only)
    volume = lane_case / "evidence" / "C"
    (volume / "Windows" / "System32").mkdir(parents=True)
    (volume / "$LogFile").write_bytes(b"RSTR" + b"\0" * 8188)
    register_evidence(lane_case, str(volume), description="own-log fixture", examiner="ownlog_test")
    run_id = "R-20261015-000000-ownlog"
    run_dir = lane_case / "runs" / run_id
    run_dir.mkdir(parents=True)
    (run_dir / "manifest.json").write_text(json.dumps({
        "run_id": run_id, "mode": "tools", "case_id": lane_case.name, "status": "running"}), encoding="utf-8")

    class Executor:
        commands: list[list[str]] = []

        async def ainvoke(self, args):
            self.commands.append(list(args.get("command") or []))
            return json.dumps({"success": False, "exit_code": 1, "error": "simulated executor failure"})

    executor = Executor()
    lane = asyncio.run(run_tool_lane(
        tools={"run_windows_command": executor, "run_command": executor},
        evidence_path=str(volume), case_id=lane_case.name, run_id=run_id,
        parse_result=json.loads, pipeline_mode="tools"))
    ledger = lane.get("tool_run_ledger") if isinstance(lane, dict) else lane
    assert not [r for r in ledger if isinstance(r, dict) and r.get("tool") == "logfileparser"]
    rows = [r for r in ledger if isinstance(r, dict) and "$LogFile" in str(r.get("purpose") or "")]
    assert [r["tool"] for r in rows] == ["mftecmd"]
    assert executor.commands and executor.commands[0][0] == "mftecmd"
    assert executor.commands[0][executor.commands[0].index("-f") + 1] == str(volume / "$LogFile")


def test_logfileparser_run_logs_and_stdout_do_not_count_as_extraction(tmp_path):
    """D312: a parser's own log or executor capture cannot satisfy its output target."""
    from nexus.langgraph.tool_lane import (
        ToolJob,
        _empty_output_status,
        _has_declared_output_target,
        _new_output_files,
        _produced_expected_output,
        _should_promote_stdout,
        _structured_output_present,
        _tool_wrote_structured_output,
    )

    out = tmp_path / "logfileparser"
    debug_log = out / "LogFile_2026-10-15_12-00-00" / "debug.log"
    saved = out / "20261015T120001_logfileparser_stdout.txt"
    job = ToolJob(
        host="windows",
        tool="logfileparser",
        argv=["logfileparser", "/LogFileFile:input:$LogFile", f"/OutputPath:{out}"],
        purpose="NTFS $LogFile",
        output_saved_to=str(saved),
        output_files=[
            {"path": str(debug_log), "kind": "file"},
            {"path": str(saved), "kind": "stdout"},
        ],
    )
    _write(debug_log, DEBUG_LOG)
    _write(saved, DEBUG_LOG)

    assert _has_declared_output_target(job)
    assert _new_output_files([out], set(), tool=job.tool) == []
    assert not _structured_output_present(job)
    assert not _tool_wrote_structured_output(job)
    assert not _produced_expected_output(job)
    assert not _should_promote_stdout(job, [])
    status, reason = _empty_output_status(job, {"success": True})
    assert status == "FAIL"
    assert "produced no output file" in reason.lower()
    assert "declared output target" in reason.lower()

    csv = debug_log.with_name("LogFile.csv")
    _write(csv, LOGFILE_CSV)
    job.output_files.append({"path": str(csv), "kind": "file"})
    fresh = _new_output_files([out], set(), tool=job.tool)
    assert fresh == [str(csv)]
    assert _structured_output_present(job)
    assert _tool_wrote_structured_output(job)
    assert _produced_expected_output(job)
    assert not _should_promote_stdout(job, fresh)


def test_sbecmd_messages_log_is_not_a_parser_product():
    from nexus.langgraph.tool_output_policy import is_tool_own_log_name

    assert is_tool_own_log_name("sbecmd", Path("!SBECmd_Messages.txt"))
    assert not is_tool_own_log_name("recmd", Path("!SBECmd_Messages.txt"))


def test_memprocfs_run_manifest_is_neither_evidence_nor_a_parser_product(run_case):
    """TA-5.0: all 569 residual wrapper rows were forensic.json's invocation metadata.

    The excerpt is cut verbatim from T22-R1z4's wrapper manifest. The shared output policy must
    agree across the lane, the retrieval walk and the index's document/freshness walks.
    """
    from nexus.langgraph.case_index import iter_index_doc_batches, iter_index_files
    from nexus.langgraph.query_pack import iter_extraction_files
    from nexus.langgraph.tool_lane import ToolJob, _new_output_files, _produced_expected_output

    case_dir, extractions = run_case
    excerpt = (Path(__file__).parent / "fixtures/memprocfs_run_manifest_excerpt.txt").read_bytes()
    out = extractions / "memprocfs" / "image.raw"
    out.mkdir(parents=True)
    manifest = out / "forensic.json"
    manifest.write_bytes(excerpt)
    other = extractions / "generic_jsonl" / "forensic.json"
    other.parent.mkdir()
    other.write_bytes(excerpt)
    job = ToolJob(host="windows", tool="memprocfs", purpose="memory forensic output",
                  argv=["memprocfs", "--out", str(out)],
                  output_files=[{"path": str(manifest), "kind": "file"}])

    assert _new_output_files([out], set(), tool="memprocfs") == []
    assert not _produced_expected_output(job)
    assert {p for p, _root, _fam in iter_extraction_files(case_dir)} == {other}
    assert set(iter_index_files(case_dir)) == {other}
    docs = [doc for batch in iter_index_doc_batches(case_dir) for doc in batch]
    assert docs and {doc["family"] for doc in docs} == {"generic_jsonl"}


def test_progress_rows_keep_durations_for_repeated_supported_tool_jobs(lane_case, monkeypatch):
    from nexus.case.evidence_service import register_evidence
    from nexus.langgraph import tool_lane
    from nexus.langgraph.pipeline_runs import create_run
    from nexus.langgraph.tool_lane import ToolJob, run_tool_lane

    _configure_lane_test(monkeypatch)
    volume = lane_case / "evidence" / "hosts"
    sources = [volume / host / "C" / "$MFT" for host in ("host-a", "host-b")]
    for source in sources:
        source.parent.mkdir(parents=True)
        # Empty path placeholders are sufficient for this timing test; the stubbed executor
        # fails explicitly and never reads or manufactures MFTECmd output records.
        source.write_bytes(b"")
    register_evidence(lane_case, str(volume), description="duration fixture", examiner="ownlog_test")

    run_id = "R-20261021-000001-duration"
    run = create_run(lane_case, "tools", run_id=run_id)
    run_dir = run.path
    assert run.extractions.is_dir(), "the run bootstrap creates the lane output directory"
    outputs = [run.extractions / "mftecmd" / host for host in ("host-a", "host-b")]
    jobs = [
        ToolJob(
            host="windows",
            tool="mftecmd",
            argv=["mftecmd", "--body", str(source), "--csvf", str(out / "MFT.csv")],
            purpose="NTFS $MFT file records (MFTECmd)",
            source=str(source),
        )
        for source, out in zip(sources, outputs, strict=True)
    ]
    monkeypatch.setattr(tool_lane, "plan_windows_triage", lambda *_args, **_kwargs: jobs)

    class Executor:
        async def ainvoke(self, args):
            argv = list(args.get("command") or [])
            source_arg = next(a for a in argv if a.endswith("$MFT"))
            delay = 0.1 if "host-a" in source_arg else 0.7
            await asyncio.sleep(delay)
            return json.dumps({"success": False, "exit_code": 1, "error": "simulated executor failure"})

    lane = asyncio.run(run_tool_lane(
        tools={"run_windows_command": Executor(), "run_command": Executor()},
        evidence_path=str(volume), case_id=lane_case.name, run_id=run_id,
        parse_result=json.loads, pipeline_mode="tools"))
    ledger = lane.get("tool_run_ledger") if isinstance(lane, dict) else lane
    rows = [row for row in ledger if isinstance(row, dict) and row.get("tool") == "mftecmd"]
    progress = json.loads((run_dir / "extractions" / "_tool_lane_progress.json").read_text(encoding="utf-8"))
    progress_rows = [row for row in progress["entries"] if row.get("tool") == "mftecmd"]

    ledger_durations = sorted(row["duration_s"] for row in rows)
    progress_durations = sorted(row["duration_s"] for row in progress_rows)
    assert len(rows) == len(progress_rows) == 2
    assert all(row["status"] == "FAIL" for row in rows)
    assert all(duration > 0 for duration in ledger_durations)
    assert ledger_durations[0] < ledger_durations[1]
    assert progress_durations == ledger_durations
