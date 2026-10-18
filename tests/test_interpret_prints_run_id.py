"""D290: `nexus interpret` names the run it made, as `nexus mode2 run` and `nexus mode3 run` do (2026-10-18).

The sample runner had to infer a Mode 1 run from the newest run folder; a failed run printed only its error.
`run_pipeline` is replaced by a recorder, as in `test_analysis_preflight`, so nothing runs.
"""
from __future__ import annotations

import json
import logging
from unittest.mock import patch

import pytest
import yaml
from typer.testing import CliRunner


@pytest.fixture(autouse=True)
def _progress_logger_restored():
    """The CLI gives `nexus.progress` its own handler and stops it propagating, as a process should; a test that runs
    the CLI in-process puts the logger back, or every later test reading progress lines through caplog sees none."""
    progress = logging.getLogger("nexus.progress")
    saved = (list(progress.handlers), progress.propagate, progress.level)
    yield
    progress.handlers[:] = saved[0]
    progress.propagate, progress.level = saved[1], saved[2]


def _case(case_id: str):
    from nexus.config import settings

    case = settings.cases_root / case_id
    (case / "analysis").mkdir(parents=True)
    (case / "audit").mkdir()
    (case / "CASE.yaml").write_text(yaml.safe_dump({"case_id": case_id, "status": "created"}), encoding="utf-8")
    (case / "analysis" / "lane_gate.json").write_text(json.dumps({"schema": 1, "status": "clear"}), encoding="utf-8")
    return case


def _interpret(case, final_state):
    from nexus.cli.main import app

    async def _run(**_kwargs):
        return final_state

    with patch("nexus.langgraph.llm_pipeline.run_pipeline", _run):
        return CliRunner().invoke(app, ["interpret", "--case", case.name])


def test_a_finished_run_names_itself():
    case = _case("CASE-RUNID-OK")
    result = _interpret(case, {"run_id": "RUN-20261018T120000000000Z-interpret-0a1b2c3d"})
    assert result.exit_code == 0
    assert "run_id=RUN-20261018T120000000000Z-interpret-0a1b2c3d status=completed mode=interpret" in result.output


def test_a_failed_run_names_itself_and_exits_non_zero():
    case = _case("CASE-RUNID-FAIL")
    result = _interpret(case, {"run_id": "RUN-20261018T120000000000Z-interpret-0a1b2c3e", "error": "model refused"})
    assert result.exit_code == 1
    assert "run_id=RUN-20261018T120000000000Z-interpret-0a1b2c3e status=failed mode=interpret" in result.output
