"""Mode 1 (interpret) is refused when the case has no finished tools run to interpret.

Reproduced on the picker's journey (2026-10-10, e2e): a case with evidence but no lane run was
started as Mode 1. The run found "No active tools run" and then called the model over nothing;
its record stayed "running" for minutes. The start is now refused before any run record exists.
"""
from __future__ import annotations

import json

import pytest
from starlette.applications import Starlette
from starlette.testclient import TestClient


def _case(root, case_id: str):
    case = root / case_id
    (case / "audit").mkdir(parents=True)
    (case / "CASE.yaml").write_text(f"case_id: {case_id}\n", encoding="utf-8")
    (case / "evidence.json").write_text("[]", encoding="utf-8")
    return case


def _committed_run(case, run_name: str, *, with_data: bool, committed: bool = True):
    run = case / "runs" / run_name
    (run / "extractions").mkdir(parents=True)
    if with_data:
        (run / "extractions" / "rows.csv").write_text("a,b\n1,2\n", encoding="utf-8")
    status = "completed" if committed else "running"
    (run / "manifest.json").write_text(json.dumps({"status": status}), encoding="utf-8")


@pytest.fixture
def root(tmp_path, monkeypatch):
    from nexus.config import settings

    monkeypatch.setattr(settings, "cases_root", tmp_path / "cases")
    (tmp_path / "cases").mkdir(exist_ok=True)
    return tmp_path / "cases"


def test_interpret_is_refused_with_the_reason_when_no_tools_run_exists(root, tmp_path):
    """A case with registered evidence but no lane run: refused with the reason, nothing started."""
    from nexus.dashboard import app as app_mod
    from nexus.dashboard.app import create_dashboard

    client = TestClient(Starlette(routes=create_dashboard()))
    created = client.post("/portal/api/case/create", json={
        "name": "Interpret refusal", "description": "d", "mode": "1", "activate": False,
    })
    assert created.status_code in (200, 201), created.text
    case_id = created.json()["case_id"]
    evidence = tmp_path / "evidence.txt"
    evidence.write_text("evidence\n", encoding="utf-8")
    registered = client.post("/portal/api/evidence", json={"path": str(evidence), "case_id": case_id})
    assert registered.status_code in (200, 201), registered.text

    before = set(app_mod._pipeline_runs)
    response = client.post("/portal/api/pipeline/run", json={"mode": "interpret", "case_id": case_id})

    assert response.status_code == 409, response.text
    assert "Run the evidence lane first" in response.json()["error"]
    assert set(app_mod._pipeline_runs) == before, "a refused start leaves no run record"


def test_interpret_with_no_evidence_is_still_the_evidence_refusal(root):
    """Evidence is checked first: a case with nothing registered is refused for that."""
    from nexus.dashboard.app import create_dashboard

    client = TestClient(Starlette(routes=create_dashboard()))
    created = client.post("/portal/api/case/create", json={
        "name": "No evidence", "description": "d", "mode": "1", "activate": False,
    })
    case_id = created.json()["case_id"]
    response = client.post("/portal/api/pipeline/run", json={"mode": "interpret", "case_id": case_id})
    assert response.status_code == 400
    assert "register evidence" in response.json()["error"]


def test_a_committed_tools_run_with_output_is_what_interpret_needs(root):
    from nexus.langgraph.pipeline_runs import has_completed_tools_run

    case = _case(root, "CASE-INTERP02")
    assert has_completed_tools_run(case) is False
    _committed_run(case, "RUN-20261010T000000Z-tools-empty", with_data=False)
    assert has_completed_tools_run(case) is False, "a committed run with no output is not interpretable"
    _committed_run(case, "RUN-20261010T000000Z-tools-ready", with_data=True)
    assert has_completed_tools_run(case) is True


def test_a_run_still_running_is_not_interpretable(root):
    from nexus.langgraph.pipeline_runs import has_completed_tools_run

    case = _case(root, "CASE-INTERP03")
    _committed_run(case, "RUN-20261010T000000Z-tools-live", with_data=True, committed=False)
    assert has_completed_tools_run(case) is False


def test_a_case_with_no_tools_run_is_a_load_error_that_stops_the_graph(root):
    """The graph used to go on to interpret after load_existing failed, and call the model over an
    empty case. A load error now routes to the end of the graph, with the reason."""
    import asyncio

    from nexus.langgraph.llm_pipeline import _route_after_load_existing, load_existing_case

    case = _case(root, "CASE-INTERP04")
    state = asyncio.run(load_existing_case({"case_id": case.name}, {}))

    assert state.get("load_error"), state
    assert "tools" in state["load_error"].lower()
    assert _route_after_load_existing(state) == "end"
    assert _route_after_load_existing({"case_id": case.name}) == "interpret"


def test_nexus_interpret_refuses_a_context_it_does_not_know(root):
    from typer.testing import CliRunner

    from nexus.cli.main import app

    _case(root, "CASE-INTERP05")
    result = CliRunner().invoke(app, ["interpret", "--case", "CASE-INTERP05", "--context", "bogus"])
    assert result.exit_code == 1
    assert "--context must be independent or informed" in result.output
