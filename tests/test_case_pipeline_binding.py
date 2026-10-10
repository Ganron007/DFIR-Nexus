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
