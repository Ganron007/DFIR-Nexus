"""D132: Modes 2 and 3 are LLM runs and never start without a model.

Every entry point used to swallow `get_model()`'s error and pass `model=None`. Mode 3 then
ran deterministic seats that investigated nothing and ended `completed / settled`; Mode 2
ran every work order through its fallback before reporting the model as unavailable.
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import yaml
from starlette.applications import Starlette
from starlette.testclient import TestClient
from typer.testing import CliRunner


def _case(root: Path, case_id: str) -> Path:
    case = root / case_id
    (case / "analysis").mkdir(parents=True)
    (case / "audit").mkdir()
    (case / "CASE.yaml").write_text(
        yaml.safe_dump({"case_id": case_id, "status": "created"}), encoding="utf-8")
    return case


def _no_model(*_args, **_kwargs):
    raise RuntimeError("No LLM configured (test)")


def test_mode3_runtime_refuses_a_run_without_a_model():
    from nexus.config import settings
    from nexus.modes.multi_agent import read_run_record, run_mode3

    case = _case(settings.cases_root, "CASE-NOMODEL3")
    record = run_mode3(case, "Compromise suspected.", model=None, es_ok=True,
                       families=[("evtxecmd", 10)])
    assert record["status"] == "failed"
    assert record["stop_reason"] == "no model configured"
    assert record["board"] == []
    assert read_run_record(case, record["run_id"])["status"] == "failed"


def test_mode2_runtime_refuses_a_run_without_a_model():
    from nexus.config import settings
    from nexus.modes.multi_role import run_mode2

    case = _case(settings.cases_root, "CASE-NOMODEL2")
    state = run_mode2(case, "Compromise suspected.", model=None, es_ok=True)
    assert state["status"] == "failed"
    assert state["stop_reason"] == "no model configured"
    assert state["results"] == []


def test_mode3_cli_ends_with_the_reason_and_starts_no_run():
    from nexus.cli.main import app
    from nexus.config import settings

    case = _case(settings.cases_root, "CASE-NOMODELCLI")
    with patch("nexus.langgraph.llm_pipeline.get_model", side_effect=_no_model):
        result = CliRunner().invoke(app, ["mode3", "run", "--case", case.name, "-q", "x"])
    assert result.exit_code == 1
    assert "No model: No LLM configured (test)" in result.output
    assert not list((case / "analysis").glob("mode3_runs/M3-*.json"))


def test_mode2_cli_ends_with_the_reason_and_starts_no_run():
    from nexus.cli.main import app
    from nexus.config import settings

    case = _case(settings.cases_root, "CASE-NOMODELCLI2")
    with patch("nexus.langgraph.llm_pipeline.get_model", side_effect=_no_model):
        result = CliRunner().invoke(app, ["mode2", "run", "--case", case.name, "-q", "x"])
    assert result.exit_code == 1
    assert "No model: No LLM configured (test)" in result.output
    assert not list((case / "analysis").glob("mode2_runs/M2-*.json"))


def test_portal_routes_answer_503_with_the_reason():
    from nexus.config import settings
    from nexus.dashboard.app import create_dashboard

    case = _case(settings.cases_root, "CASE-NOMODELAPI")
    started: list[str] = []
    with patch("nexus.dashboard.app._get_case_dir", return_value=case), \
         patch("nexus.langgraph.llm_pipeline.get_model", side_effect=_no_model), \
         patch("nexus.dashboard.app._start_mode2_thread",
               side_effect=lambda *a, **k: started.append("m2")), \
         patch("nexus.dashboard.app._start_mode3_thread",
               side_effect=lambda *a, **k: started.append("m3")):
        client = TestClient(Starlette(routes=create_dashboard()))
        for route in ("/portal/api/mode2/run", "/portal/api/mode3/run"):
            response = client.post(route, json={"question": "x"})
            assert response.status_code == 503, (route, response.text)
            assert "No LLM configured (test)" in response.json()["error"]
    assert started == []
