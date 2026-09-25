"""Mode 3 CLI parity tests (M7.1)."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from nexus.cli.main import app
from nexus.langgraph import mode3_runtime as m3

runner = CliRunner()


def _case(tmp_path: Path) -> Path:
    case = tmp_path / "CASE-M3CLI"
    case.mkdir(parents=True)
    (case / "CASE.yaml").write_text("name: m3cli\nstatus: active\n", encoding="utf-8")
    (case / "audit").mkdir()
    (case / "analysis").mkdir()
    return case


def test_cli_plan_prints_work_orders(tmp_path):
    case = _case(tmp_path)
    order = m3.WorkOrder(order_id="wo-cli", role="evidence", task="inspect")
    with patch("nexus.cli.main._resolve_case", return_value=case), \
         patch("nexus.langgraph.mode3_runtime.plan_work_orders",
               return_value=[order]):
        result = runner.invoke(app, ["mode3", "plan", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["orders"][0]["order_id"] == "wo-cli"


def test_cli_status_reads_run_record(tmp_path):
    case = _case(tmp_path)
    m3._persist_state(case, "M3-cli", {
        "run_id": "M3-cli", "status": "completed", "stop_reason": "completed",
        "orders": [], "order_index": 0, "results": [], "candidates": [],
        "gaps": [],
    })
    with patch("nexus.cli.main._resolve_case", return_value=case):
        result = runner.invoke(app, ["mode3", "status", "--run-id", "M3-cli", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["status"] == "completed"


def test_cli_stage_uses_real_runtime(tmp_path):
    case = _case(tmp_path)
    from nexus.audit import AuditWriter

    audit_id = AuditWriter("nexus", audit_dir=case / "audit").log(
        tool="es_search",
        params={"family": "evtxecmd", "file": "a.csv"},
        result_summary={"total": 1},
        source="portal",
    )
    m3._persist_state(case, "M3-cli-stage", {
        "run_id": "M3-cli-stage", "case_id": case.name, "question": "q",
        "status": "completed", "orders": [], "order_index": 0, "results": [],
        "verdicts": [],
        "candidates": [{
            "title": "CLI candidate", "observation": "o", "interpretation": "i",
            "confidence": "LOW", "confidence_justification": "audited",
            "audit_ids": [audit_id],
            "evidence": [{"source": "evtxecmd/a.csv", "line": "3"}],
        }],
        "gaps": [],
    })
    with patch("nexus.cli.main._resolve_case", return_value=case):
        result = runner.invoke(app, ["mode3", "stage", "--run-id", "M3-cli-stage"])
    assert result.exit_code == 0
    assert "Staged 1 DRAFT" in result.stdout
    rows = json.loads((case / "findings.json").read_text(encoding="utf-8"))
    assert any(f.get("run_id") == "M3-cli-stage" for f in rows)


def test_cli_steer_and_pause(tmp_path):
    case = _case(tmp_path)
    m3._persist_state(case, "M3-cli2", {
        "run_id": "M3-cli2", "status": "running", "orders": [], "order_index": 0,
        "results": [], "candidates": [], "gaps": [],
    })
    with patch("nexus.cli.main._resolve_case", return_value=case):
        steer = runner.invoke(app, ["mode3", "steer", "chase WS01",
                                    "--run-id", "M3-cli2"])
        pause = runner.invoke(app, ["mode3", "pause", "--run-id", "M3-cli2"])
    assert steer.exit_code == 0
    assert pause.exit_code == 0
    assert m3.read_steering(case, "M3-cli2")[0]["text"] == "chase WS01"
    record = m3.read_run_record(case, "M3-cli2")
    assert record and record.get("pause_requested") is True
