"""WO-TA item 1 / D41 on the lane path: the case-pipeline guard reads the run's own case.

Reproduced on the real lane (2026-10-10): with the examiner's active case holding no
evidence, every lane command named in the run's own case was refused. The guard read
the active case, not the run's. These tests put the active case and the run's case in
different states, and the helper must follow the run's case.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from nexus.config import settings
from nexus.tools import windows


def _case(root: Path, case_id: str, evidence: list[str]) -> Path:
    case = root / case_id
    case.mkdir(parents=True)
    (case / "CASE.yaml").write_text(f"case_id: {case_id}\n", encoding="utf-8")
    (case / "evidence.json").write_text(
        json.dumps([{"path": p} for p in evidence]), encoding="utf-8")
    return case


@pytest.fixture
def cases(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "cases_root", tmp_path / "cases")
    triage = tmp_path / "H"
    triage.mkdir()
    # The active case is empty; the run's case holds the triage.
    empty = _case(tmp_path / "cases", "CASE-ACTIVE", [])
    bound = _case(tmp_path / "cases", "CASE-RUN", [str(triage)])
    monkeypatch.setattr(windows, "_active_case_dir", lambda: empty)
    return {"bound": bound, "triage": triage, "active": empty}


def test_a_command_inside_the_runs_own_case_is_allowed_when_another_case_is_active(cases):
    roots = windows._case_pipeline_roots("CASE-RUN")
    argv = ["deepbluecli", str(cases["triage"] / "Security.evtx"), "out.json"]
    assert windows.case_pipeline_refusal("deepbluecli", argv, roots) is None


def test_the_active_case_alone_would_refuse_the_same_command(cases):
    """The old behaviour, kept for external MCP callers that bind no case."""
    roots = windows._case_pipeline_roots("")
    argv = ["deepbluecli", str(cases["triage"] / "Security.evtx"), "out.json"]
    assert windows.case_pipeline_refusal("deepbluecli", argv, roots)


def test_a_path_outside_the_runs_evidence_is_still_refused(cases, tmp_path):
    roots = windows._case_pipeline_roots("CASE-RUN")
    outside = tmp_path / "elsewhere" / "Security.evtx"
    argv = ["deepbluecli", str(outside), "out.json"]
    assert windows.case_pipeline_refusal("deepbluecli", argv, roots)


def test_an_unknown_case_refuses_everything(cases):
    roots = windows._case_pipeline_roots("CASE-DOES-NOT-EXIST")
    assert roots == []
    argv = ["deepbluecli", str(cases["triage"] / "Security.evtx"), "out.json"]
    assert windows.case_pipeline_refusal("deepbluecli", argv, roots)


def test_an_invalid_case_id_refuses_everything(cases):
    assert windows._case_pipeline_roots("../CASE-RUN") == []


@pytest.mark.parametrize("tool", ["netstat", "tasklist", "autorunsc", "winpmem", "handle"])
def test_live_and_sysinternals_tools_are_refused_even_on_registered_evidence(cases, tool):
    """WO-TA item 1: live, system, Sysinternals and memory-acquisition tools never run in a
    case pipeline, even when the command names a path inside the run's evidence."""
    roots = windows._case_pipeline_roots("CASE-RUN")
    argv = [tool, str(cases["triage"] / "Security.evtx")]
    assert windows.case_pipeline_refusal(tool, argv, roots), tool


def _windows_tool(tmp_path):
    from mcp.server.fastmcp import FastMCP

    from nexus.audit import AuditWriter

    server = FastMCP("binding-output-test")
    windows.register_tools(server, AuditWriter("t", audit_dir=tmp_path / "audit"))
    return server._tool_manager._tools["run_windows_command"].fn


def test_a_run_saves_its_output_into_its_own_case_not_the_active_one(cases, tmp_path, monkeypatch):
    """Reproduced 2026-10-10: a run bound to one case registered its stdout as evidence in the
    active case (run_windows_command passed _active_case_dir() to persist_tool_output)."""
    import subprocess

    from nexus.case import outputs

    saved: list = []

    class _Result:
        returncode = 0
        stdout = "ok"
        stderr = ""

    def _record(**kwargs):
        saved.append(kwargs["case_dir"])
        return {"output_files": [], "warning": ""}

    monkeypatch.setattr(subprocess, "run", lambda *_a, **_k: _Result())
    monkeypatch.setattr(outputs, "persist_tool_output", _record)
    tool = _windows_tool(tmp_path)
    argv = ["mftecmd", "-f", str(cases["triage"] / "Security.evtx")]

    bound = tool(command=argv, purpose="bound run", case_id="CASE-RUN")
    assert bound.get("success") is True, bound
    assert saved[-1] == cases["bound"], saved

    # The active case gets its own registered input, so an unbound run is allowed to run.
    active_input = tmp_path / "active-input"
    active_input.mkdir()
    (cases["active"] / "evidence.json").write_text(
        json.dumps([{"path": str(active_input)}]), encoding="utf-8")
    unbound = tool(command=["mftecmd", "-f", str(active_input / "a.evtx")], purpose="unbound run")
    assert unbound.get("success") is True, unbound
    assert saved[-1] == cases["active"], "a run that names no case saves into the active one"


def test_a_lane_staged_copy_in_its_own_run_is_allowed_and_only_with_that_run(cases):
    """Reproduced on SC1 (2026-10-10): the lane stages copies of evidence under its run's
    extractions and names them in the command; the guard allowed only the case-level
    extractions, so eight real jobs (SBECmd, SIDR, bmc-tools, bitsparser) were refused."""
    run_id = "RUN-20261010T000000Z-tools-abcd"
    run = cases["bound"] / "runs" / run_id
    staged = run / "extractions" / "sbecmd" / "stage-Administrator"
    staged.mkdir(parents=True)
    argv = ["sbecmd", "-d", str(staged), "--csv", str(run / "extractions" / "sbecmd")]

    with_run = windows._case_pipeline_roots("CASE-RUN", run_id)
    assert windows.case_pipeline_refusal("sbecmd", argv, with_run) is None
    case_only = windows._case_pipeline_roots("CASE-RUN")
    assert windows.case_pipeline_refusal("sbecmd", argv, case_only), "the case alone must not admit a run's copy"


def test_a_run_id_that_is_not_a_plain_run_name_adds_no_root(cases):
    assert windows._case_pipeline_roots("CASE-RUN", "../CASE-ACTIVE") == windows._case_pipeline_roots("CASE-RUN")
    assert windows._case_pipeline_roots("CASE-RUN", "RUN-a/../../x") == windows._case_pipeline_roots("CASE-RUN")


def test_a_lane_runs_output_goes_into_its_own_run_folder(cases, tmp_path, monkeypatch):
    """Reproduced on SC1 (2026-10-10): the eight jobs a retry re-ran wrote their output into the
    case-level extractions, which the run never reads, so the index did not contain them."""
    import subprocess

    from nexus.case import outputs

    run_id = "RUN-20261010T000000Z-tools-out1"
    run = cases["bound"] / "runs" / run_id
    run.mkdir(parents=True)
    seen: dict = {}

    class _Result:
        returncode = 0
        stdout = "ok"
        stderr = ""

    def _record(**kwargs):
        seen.update(kwargs)
        return {"output_files": [], "warning": ""}

    monkeypatch.setattr(subprocess, "run", lambda *_a, **_k: _Result())
    monkeypatch.setattr(outputs, "persist_tool_output", _record)
    tool = _windows_tool(tmp_path)
    argv = ["mftecmd", "-f", str(cases["triage"] / "Security.evtx")]

    result = tool(command=argv, purpose="run output", case_id="CASE-RUN", run_id=run_id)
    assert result.get("success") is True, result
    assert seen["case_dir"] == cases["bound"]
    assert seen["extractions_root"] == run / "extractions"


def test_a_run_name_that_is_not_on_disk_keeps_the_case_folder_and_creates_no_run(
        cases, tmp_path, monkeypatch):
    import subprocess

    from nexus.case import outputs

    seen: dict = {}

    class _Result:
        returncode = 0
        stdout = "ok"
        stderr = ""

    monkeypatch.setattr(subprocess, "run", lambda *_a, **_k: _Result())
    monkeypatch.setattr(outputs, "persist_tool_output", lambda **kw: seen.update(kw) or {"output_files": []})
    tool = _windows_tool(tmp_path)
    argv = ["mftecmd", "-f", str(cases["triage"] / "Security.evtx")]

    tool(command=argv, purpose="no run", case_id="CASE-RUN", run_id="RUN-20261010T000000Z-tools-none")
    assert seen["extractions_root"] is None
    assert not (cases["bound"] / "runs" / "RUN-20261010T000000Z-tools-none").exists()
