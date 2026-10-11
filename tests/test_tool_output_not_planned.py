"""A tool's output is never planned as evidence, however a run's evidence list was built (2026-10-11).

CASE-C5B04D31's run inherited 184 stdout files of an earlier run as evidence. Each one was planned, and each one
became a "no recognized evidence shape" row in the ledger.
"""

from __future__ import annotations

import json
from pathlib import Path

from nexus.config import settings
from nexus.langgraph import llm_pipeline
from nexus.langgraph.pipeline_runs import drop_tool_outputs, is_tool_output

EVIDENCE = r"H:\C\Windows\System32\winevt\Logs\Security.evtx"


def _case(tmp_path):
    case = tmp_path / "CASE-OUT-0001"
    case.mkdir()
    return case


def test_a_stdout_of_an_earlier_run_is_tool_output(tmp_path):
    case = _case(tmp_path)
    stdout = case / "runs" / "RUN-OLD" / "extractions" / "hayabusa" / "20261010T220735_hayabusa_stdout.txt"
    assert is_tool_output(stdout, case)


def test_evidence_outside_the_tool_output_folders_is_not_tool_output(tmp_path):
    case = _case(tmp_path)
    assert not is_tool_output(Path(EVIDENCE), case)
    assert not is_tool_output(case / "evidence" / "rd01-memory.img", case)


def test_drop_tool_outputs_keeps_the_evidence_in_order(tmp_path):
    case = _case(tmp_path)
    out = str(case / "runs" / "RUN-OLD" / "extractions" / "x_stdout.txt")
    ev_local = str(case / "evidence" / "a.evtx")
    assert drop_tool_outputs([out, ev_local, out, EVIDENCE], case) == [ev_local, EVIDENCE]


def test_an_inherited_list_keeps_only_the_evidence(tmp_path, monkeypatch):
    case = _case(tmp_path)
    monkeypatch.setattr(settings, "cases_root", tmp_path)
    out = str(case / "runs" / "RUN-OLD" / "extractions" / "x_stdout.txt")
    assert llm_pipeline.inherit_evidence_paths("CASE-OUT-0001", "", [out, EVIDENCE]) == [EVIDENCE]


def test_when_only_tool_output_is_inherited_the_registry_stands_in(tmp_path, monkeypatch):
    case = _case(tmp_path)
    monkeypatch.setattr(settings, "cases_root", tmp_path)
    out = str(case / "runs" / "RUN-OLD" / "extractions" / "x_stdout.txt")
    registered = tmp_path / "registered.evtx"
    registered.write_bytes(b"evtx")
    (case / "evidence.json").write_text(
        json.dumps({"evidence": [{"path": str(registered), "kind": "file"}]}), encoding="utf-8")
    assert llm_pipeline.inherit_evidence_paths("CASE-OUT-0001", "", [out]) == [str(registered)]
