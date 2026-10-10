"""WO-TA item 12: a retry re-runs only the failed jobs of its run, and the lane reuses OK rows.

Reproduced on SC1 (2026-10-10): ``apply_prior_ok`` had no caller, so the lane never reused a
prior OK job; ``nexus lane retry`` read only the flat case-level ledger, which a run-based lane
never writes, and so reported "No lane ledger". The reuse and the ledger lookup now read the
run's own ledger and manifest.
"""
from __future__ import annotations

import json
from pathlib import Path

from nexus.cli import lane_retry_cmd
from nexus.langgraph.tool_lane import ToolJob, apply_prior_ok


def _ledger_row(tool: str, status: str, output: str = "") -> dict:
    return {
        "host": "windows", "tool": tool, "purpose": f"{tool} purpose",
        "argv": [tool], "status": status, "reason": "" if status == "OK" else "failed",
        "output_saved_to": output, "output_files": [], "audit_id": f"aud-{tool}",
        # An OK row records the version of the binary that wrote it (WO-TA item 8).
        "lineage": {"tool": tool, "file_version": "1.2.3", "version_source": "pe-version-resource"}
        if status == "OK" else {},
    }


def _run_case(tmp_path: Path, rows: list[dict], manifest_paths: list[str]) -> tuple[Path, Path]:
    case_dir = tmp_path / "CASE-RETRY01"
    run_dir = case_dir / "runs" / "RUN-20261010T000000Z-tools-retry"
    extractions = run_dir / "extractions"
    extractions.mkdir(parents=True)
    (extractions / "evtxecmd").mkdir()
    (extractions / "evtxecmd" / "rows.csv").write_text("a,b\n1,2\n", encoding="utf-8")
    (extractions / "_tool_lane_ledger.json").write_text(json.dumps(rows), encoding="utf-8")
    (run_dir / "manifest.json").write_text(
        json.dumps({"status": "completed", "evidence_paths": manifest_paths}), encoding="utf-8")
    return case_dir, extractions


def test_apply_prior_ok_reuses_the_run_ledgers_ok_rows_and_not_its_failures(tmp_path, monkeypatch):
    monkeypatch.delenv("NEXUS_TOOL_LANE_RERUN", raising=False)
    output = tmp_path / "evtxecmd_ok.csv"
    output.write_text("x", encoding="utf-8")
    case_dir, extractions = _run_case(tmp_path, [
        _ledger_row("evtxecmd", "OK", str(output)),
        _ledger_row("sbecmd", "FAIL"),
    ], [str(tmp_path / "H")])

    ok_job = ToolJob(host="windows", tool="evtxecmd", argv=["evtxecmd"], purpose="evtxecmd purpose")
    failed_job = ToolJob(host="windows", tool="sbecmd", argv=["sbecmd"], purpose="sbecmd purpose")
    reused = apply_prior_ok([ok_job, failed_job], case_dir, extractions=extractions)

    assert reused == 1
    assert ok_job.status == "OK" and ok_job.reason.startswith("reused prior OK")
    assert failed_job.status == "PENDING", "a FAIL row is run again, never reused"


def test_an_ok_row_whose_output_has_gone_is_run_again(tmp_path, monkeypatch):
    monkeypatch.delenv("NEXUS_TOOL_LANE_RERUN", raising=False)
    gone = tmp_path / "deleted.csv"
    case_dir, extractions = _run_case(tmp_path, [_ledger_row("evtxecmd", "OK", str(gone))], [])
    job = ToolJob(host="windows", tool="evtxecmd", argv=["evtxecmd"], purpose="evtxecmd purpose")

    assert apply_prior_ok([job], case_dir, extractions=extractions) == 0
    assert job.status == "PENDING"


def test_an_ok_row_without_a_declared_version_is_run_again(tmp_path, monkeypatch):
    """Reproduced on SC1 (2026-10-10): reuse copied the audit id and output path but not
    lineage, so 420 reused rows reached the committed run with no tool version. A row
    must carry what a fresh row carries, so one with no version runs again."""
    monkeypatch.delenv("NEXUS_TOOL_LANE_RERUN", raising=False)
    output = tmp_path / "evtxecmd_ok.csv"
    output.write_text("x", encoding="utf-8")
    row = _ledger_row("evtxecmd", "OK", str(output))
    row["lineage"] = {}
    case_dir, extractions = _run_case(tmp_path, [row], [])
    job = ToolJob(host="windows", tool="evtxecmd", argv=["evtxecmd"], purpose="evtxecmd purpose")

    assert apply_prior_ok([job], case_dir, extractions=extractions) == 0
    assert job.status == "PENDING"


def test_a_reused_row_carries_its_lineage(tmp_path, monkeypatch):
    monkeypatch.delenv("NEXUS_TOOL_LANE_RERUN", raising=False)
    output = tmp_path / "evtxecmd_ok.csv"
    output.write_text("x", encoding="utf-8")
    case_dir, extractions = _run_case(tmp_path, [_ledger_row("evtxecmd", "OK", str(output))], [])
    job = ToolJob(host="windows", tool="evtxecmd", argv=["evtxecmd"], purpose="evtxecmd purpose")

    assert apply_prior_ok([job], case_dir, extractions=extractions) == 1
    assert job.lineage["file_version"] == "1.2.3"


def test_the_retry_finds_the_run_ledger_and_the_run_folder(tmp_path):
    case_dir, extractions = _run_case(tmp_path, [_ledger_row("sbecmd", "FAIL")], [str(tmp_path / "H")])

    rows, run_dir = lane_retry_cmd._load_ledger(case_dir)

    assert [r["tool"] for r in rows] == ["sbecmd"]
    assert run_dir == extractions.parent, "the retry runs inside the same run folder"
    assert lane_retry_cmd._run_evidence_paths(run_dir) == [str(tmp_path / "H")]


def test_a_flat_legacy_ledger_has_no_run_folder_to_retry_into(tmp_path):
    case_dir = tmp_path / "CASE-FLAT01"
    (case_dir / "extractions").mkdir(parents=True)
    (case_dir / "extractions" / "_tool_lane_ledger.json").write_text(
        json.dumps([_ledger_row("sbecmd", "FAIL")]), encoding="utf-8")

    rows, run_dir = lane_retry_cmd._load_ledger(case_dir)

    assert rows and run_dir is None


def test_a_sift_row_is_reused_though_its_output_lives_on_the_sift_host(tmp_path, monkeypatch):
    """Reproduced on SC1 (2026-10-10): the existence check read a SIFT row's output path on this
    machine, so fifteen Volatility jobs that were OK were run again on the SIFT host."""
    monkeypatch.delenv("NEXUS_TOOL_LANE_RERUN", raising=False)
    remote = "/home/sansforensics/.nexus/cases/CASE-RETRY01/extractions/vol/x_vol_stdout.txt"
    row = {**_ledger_row("vol", "OK", remote), "host": "sift"}
    case_dir, extractions = _run_case(tmp_path, [row], [])
    job = ToolJob(host="sift", tool="vol", argv=["vol"], purpose="vol purpose")

    assert apply_prior_ok([job], case_dir, extractions=extractions) == 1
    assert job.status == "OK"


def test_the_retry_indexes_what_it_wrote_when_elasticsearch_answers(tmp_path, monkeypatch, capsys):
    from nexus.langgraph import case_index

    calls: list[tuple] = []
    monkeypatch.setattr(case_index, "es_available", lambda: True)
    monkeypatch.setattr(
        case_index, "index_case",
        lambda case_dir, incremental=False: calls.append((case_dir, incremental))
        or {"docs": 12, "index": "nexus-case-retry01"},
    )
    lane_retry_cmd._index_retried_output(tmp_path)

    assert calls == [(tmp_path, True)], "an incremental index, as the lane does after a batch"
    assert "Indexed: 12 docs" in capsys.readouterr().out


def test_the_retry_says_plainly_when_elasticsearch_is_down(tmp_path, monkeypatch, capsys):
    from nexus.langgraph import case_index

    called: list[int] = []
    monkeypatch.setattr(case_index, "es_available", lambda: False)
    monkeypatch.setattr(case_index, "index_case", lambda *a, **k: called.append(1))
    lane_retry_cmd._index_retried_output(tmp_path)

    assert called == []
    assert "not indexed yet" in capsys.readouterr().err
