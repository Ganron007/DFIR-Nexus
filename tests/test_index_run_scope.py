"""The index reads the tools run it is given, not whichever run is committed (2026-10-11).

Reproduced on CASE-C5B04D31: a second tools run was indexed while it was still running, and its report
step indexed before it was committed. The index then held the previous committed run's outputs, and
``analysis/index_state.json`` named that run's extractions folder. The lane and the report step now name
the run they build. An unnamed call still reads the committed run, as the readers do.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

OLD_RUN = "RUN-20261010T100000000001Z-tools-aaaa0001"
NEW_RUN = "RUN-20261010T110000000002Z-tools-bbbb0002"


def _run(case_dir: Path, rid: str, status: str, file_name: str) -> Path:
    run_dir = case_dir / "runs" / rid
    family = run_dir / "extractions" / "evtxecmd"
    family.mkdir(parents=True)
    (family / file_name).write_text("Channel,EventId\nSecurity,4624\n", encoding="utf-8")
    (run_dir / "manifest.json").write_text(json.dumps({
        "run_id": rid, "mode": "tools", "status": status, "parent_run_id": "",
        "created_at": "2026-10-10T10:00:00+00:00",
        "completed_at": "2026-10-10T10:30:00+00:00" if status == "completed" else "",
    }), encoding="utf-8")
    return run_dir / "extractions"


@pytest.fixture()
def two_runs(tmp_path):
    """The committed run is the earlier one. A second run is in progress and is the active run."""
    case_dir = tmp_path / "CASE-SCOPE01"
    old_ext = _run(case_dir, OLD_RUN, "completed", "OLD_EvtxECmd.csv")
    new_ext = _run(case_dir, NEW_RUN, "running", "NEW_EvtxECmd.csv")
    (case_dir / "active_runs.json").write_text(json.dumps({"tools": NEW_RUN}), encoding="utf-8")
    return case_dir, old_ext, new_ext


def test_an_unnamed_resolution_still_reads_the_committed_run(two_runs):
    from nexus.langgraph.pipeline_runs import resolve_tools_extractions

    case_dir, old_ext, _new_ext = two_runs

    assert resolve_tools_extractions(case_dir) == old_ext


def test_a_named_run_resolves_to_its_own_output_while_it_runs(two_runs):
    from nexus.langgraph.pipeline_runs import resolve_tools_extractions

    case_dir, _old_ext, new_ext = two_runs

    assert resolve_tools_extractions(case_dir, NEW_RUN) == new_ext


def test_the_index_walks_the_named_run_and_not_the_committed_one(two_runs):
    from nexus.langgraph import case_index

    case_dir, _old_ext, _new_ext = two_runs

    assert {rel for rel, _path in case_index._index_file_keys(case_dir, NEW_RUN)} == {
        "evtxecmd/NEW_EvtxECmd.csv"}
    assert {rel for rel, _path in case_index._index_file_keys(case_dir)} == {
        "evtxecmd/OLD_EvtxECmd.csv"}


def test_the_document_stream_carries_the_named_runs_rows(two_runs):
    from nexus.langgraph import case_index

    case_dir, _old_ext, _new_ext = two_runs

    files = {doc["file"] for batch in case_index.iter_index_doc_batches(case_dir, run_id=NEW_RUN)
             for doc in batch}

    assert files == {"evtxecmd/NEW_EvtxECmd.csv"}


def test_the_index_state_records_the_run_it_indexed(two_runs):
    from nexus.langgraph import case_index

    case_dir, _old_ext, new_ext = two_runs

    case_index.write_index_state(case_dir, {"docs": 1, "index": "nexus-case-scope01"}, run_id=NEW_RUN)
    state = json.loads((case_dir / "analysis" / "index_state.json").read_text(encoding="utf-8"))

    assert state["source_extractions"] == str(new_ext)
    assert set(state["file_mtimes"]) == {"evtxecmd/NEW_EvtxECmd.csv"}


def test_the_extraction_listing_takes_the_named_run(two_runs):
    from nexus.langgraph.query_pack import iter_extraction_files

    case_dir, _old_ext, _new_ext = two_runs

    names = {path.name for path, _root, _fam in iter_extraction_files(case_dir, run_id=NEW_RUN)}

    assert names == {"NEW_EvtxECmd.csv"}


def test_the_report_step_names_the_run_it_completes(two_runs, monkeypatch):
    from nexus.langgraph import case_index, llm_pipeline

    case_dir, _old_ext, _new_ext = two_runs
    monkeypatch.setenv("NEXUS_ES_URL", "http://127.0.0.1:9200")
    monkeypatch.delenv("NEXUS_ES_AUTOINDEX", raising=False)
    seen: list[dict] = []

    def fake_index_case(case_dir_arg, extra_needles=None, *, incremental=False, run_id=""):
        seen.append({"run_id": run_id, "incremental": incremental})
        return {"docs": 1, "index": "nexus-case-scope01"}

    monkeypatch.setattr(case_index, "index_case", fake_index_case)

    llm_pipeline._autoindex_case(case_dir, run_id=NEW_RUN)
    llm_pipeline._autoindex_case(case_dir)

    assert seen == [
        {"run_id": NEW_RUN, "incremental": True},
        {"run_id": "", "incremental": True},
    ]
