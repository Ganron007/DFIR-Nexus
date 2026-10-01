"""Report generation and case seal stay closed while the evidence gate is blocked."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from starlette.applications import Starlette
from starlette.testclient import TestClient

from nexus.dashboard.app import create_dashboard


def test_blocked_gate_refuses_report_and_seal(tmp_path: Path):
    case = tmp_path / "CASE-GATE"
    case.mkdir()
    (case / "CASE.yaml").write_text("name: gate\nstatus: active\n", encoding="utf-8")
    (case / "analysis").mkdir()
    (case / "analysis" / "lane_gate.json").write_text(
        json.dumps({
            "status": "blocked",
            "unprocessed": [{"tool": "EvtxECmd", "purpose": "parse evtx", "reason": "timeout"}],
        }),
        encoding="utf-8",
    )
    client = TestClient(Starlette(routes=create_dashboard()))
    with patch("nexus.dashboard.app._get_case_dir", return_value=case):
        report = client.post("/portal/api/report/generate", json={"llm": False})
        seal = client.post(
            "/portal/api/case/seal",
            json={"challenge_id": "c", "response": "r", "examiner": "t"},
        )
    assert report.status_code == 409
    assert seal.status_code == 409
    assert report.json()["error"] == "evidence gate blocked"
    assert seal.json()["error"] == "evidence gate blocked"
