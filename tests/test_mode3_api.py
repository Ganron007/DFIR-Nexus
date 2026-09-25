"""Mode 3 run API tests (M5.3/M7 foundation)."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from starlette.applications import Starlette
from starlette.testclient import TestClient

from nexus.dashboard.app import create_dashboard
from nexus.langgraph import mode3_runtime as m3


def _case(tmp_path: Path) -> Path:
    case = tmp_path / "CASE-M3API"
    case.mkdir(parents=True)
    (case / "CASE.yaml").write_text("name: m3api\nstatus: active\n", encoding="utf-8")
    (case / "audit").mkdir()
    (case / "analysis").mkdir()
    return case


def _client() -> TestClient:
    return TestClient(Starlette(routes=create_dashboard()))


def test_mode3_run_plan_endpoint(tmp_path):
    case = _case(tmp_path)
    order = m3.WorkOrder(order_id="wo-1", role="evidence", task="t")
    with patch("nexus.dashboard.app._get_case_dir", return_value=case), \
         patch("nexus.langgraph.mode3_runtime.plan_work_orders",
               return_value=[order]):
        response = _client().post(
            "/portal/api/mode3/run/plan", json={"question": "what happened"})
    assert response.status_code == 200
    body = response.json()
    assert body["orders"][0]["order_id"] == "wo-1"
    assert body["orders"][0]["role"] == "evidence"


def test_mode3_run_start_status_steer_pause_resume(tmp_path):
    case = _case(tmp_path)
    run_id = "M3-api-test"
    started: list[tuple] = []

    def _fake_start(case_dir, question, model, rid, resume):
        started.append((str(case_dir.name), question, rid, resume))

    with patch("nexus.dashboard.app._get_case_dir", return_value=case), \
         patch("nexus.dashboard.app._start_mode3_thread", side_effect=_fake_start), \
         patch("nexus.dashboard.app._mode3_resolve_model", return_value=None):
        client = _client()
        start = client.post("/portal/api/mode3/run",
                            json={"question": "who did it", "run_id": run_id})
        assert start.status_code == 202
        assert start.json()["run_id"] == run_id
        assert started and started[0][3] is False

        # Seed a persisted record so status/steer/pause/resume can act.
        m3._persist_state(case, run_id, {
            "run_id": run_id, "case_id": case.name, "question": "who did it",
            "status": "running", "orders": [], "order_index": 0,
            "results": [], "candidates": [], "gaps": [], "steering": [],
        })

        status = client.get("/portal/api/mode3/run/status", params={"run_id": run_id})
        assert status.status_code == 200
        assert status.json()["status"] == "running"

        steer = client.post("/portal/api/mode3/run/steer",
                            json={"run_id": run_id, "text": "chase WS01"})
        assert steer.status_code == 200
        assert m3.read_steering(case, run_id)[0]["text"] == "chase WS01"

        pause = client.post("/portal/api/mode3/run/pause",
                            json={"run_id": run_id, "paused": True})
        assert pause.status_code == 200
        assert m3.read_controls(case, run_id)["pause_requested"] is True

        resume = client.post("/portal/api/mode3/run/resume",
                             json={"run_id": run_id})
        assert resume.status_code == 202
        assert any(call[3] is True for call in started)


def test_mode3_run_stage_endpoint(tmp_path):
    case = _case(tmp_path)
    from nexus.audit import AuditWriter

    audit_id = AuditWriter("nexus", audit_dir=case / "audit").log(
        tool="es_search",
        params={"family": "evtxecmd", "file": "a.csv", "query": "logon"},
        result_summary={"total": 1},
        source="portal",
    )
    m3._persist_state(case, "M3-stage-api", {
        "run_id": "M3-stage-api", "case_id": case.name, "question": "q",
        "status": "completed", "orders": [], "order_index": 0, "results": [],
        "verdicts": [],
        "candidates": [{
            "title": "Staged candidate", "observation": "o",
            "interpretation": "i", "confidence": "LOW",
            "confidence_justification": "one audited query",
            "audit_ids": [audit_id],
            "evidence": [{"source": "evtxecmd/a.csv", "line": "7"}],
        }],
        "gaps": [],
    })
    with patch("nexus.dashboard.app._get_case_dir", return_value=case):
        response = _client().post("/portal/api/mode3/run/stage",
                                  json={"run_id": "M3-stage-api"})
    assert response.status_code == 200
    body = response.json()
    assert body["staged_count"] == 1
    assert body["staged"][0]["input_call_ids"] == [audit_id]
    rows = json.loads((case / "findings.json").read_text(encoding="utf-8"))
    assert any(f.get("run_id") == "M3-stage-api"
               and f.get("status") == "DRAFT" for f in rows)


def test_mode3_run_stop_sets_flag(tmp_path):
    case = _case(tmp_path)
    m3._persist_state(case, "M3-stop-api", {
        "run_id": "M3-stop-api", "case_id": case.name, "question": "q",
        "status": "running", "orders": [], "order_index": 0, "results": [],
        "candidates": [], "gaps": [],
    })
    with patch("nexus.dashboard.app._get_case_dir", return_value=case):
        response = _client().post("/portal/api/mode3/run/stop",
                                  json={"run_id": "M3-stop-api"})
    assert response.status_code == 200
    assert response.json()["stop_requested"] is True
    assert m3.read_controls(case, "M3-stop-api")["stop_requested"] is True


def test_mode3_run_plan_rejects_sealed_case(tmp_path):
    from starlette.responses import JSONResponse

    case = _case(tmp_path)
    sealed = JSONResponse({"error": "case is sealed"}, status_code=409)
    with patch("nexus.dashboard.app._get_case_dir", return_value=case), \
         patch("nexus.dashboard.app._sealed_case_error", return_value=sealed):
        response = _client().post("/portal/api/mode3/run/plan",
                                  json={"question": "x"})
    assert response.status_code == 409
