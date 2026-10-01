"""U3: one status, three readers (WO-U3 / WP 14.3, UD8).

The defect this pins is a disagreement, not a crash: the stepper, the gate
banner and a page header each derived their own state, so an examiner could
look at two of them and get two answers about the same case. The status
endpoint is the only place state is computed; every test here is about what it
says, and about saying ``unknown`` rather than guessing.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from starlette.applications import Starlette
from starlette.testclient import TestClient

from nexus.dashboard.case_status_api import build_case_status


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_CASES_ROOT", str(tmp_path / "cases"))
    monkeypatch.setenv("NEXUS_DATA_ROOT", str(tmp_path / "data"))
    (tmp_path / "cases").mkdir(parents=True, exist_ok=True)
    (tmp_path / "data").mkdir(parents=True, exist_ok=True)

    from nexus.dashboard.app import create_dashboard

    return TestClient(Starlette(routes=create_dashboard()))


def _case(tmp_path, *, case_id: str = "CASE-STATUS001") -> Path:
    case = tmp_path / "cases" / case_id
    (case / "analysis").mkdir(parents=True, exist_ok=True)
    (case / "extractions").mkdir(parents=True, exist_ok=True)
    (case / "CASE.yaml").write_text(
        f"case_id: {case_id}\nstatus: open\nintake:\n  question: what ran?\n",
        encoding="utf-8",
    )
    (case / "findings.json").write_text(
        json.dumps([
            {"id": "F1", "status": "DRAFT"},
            {"id": "F2", "status": "APPROVED"},
            {"id": "F3", "status": "REJECTED"},
        ]),
        encoding="utf-8",
    )
    return case


def test_status_reports_stages_counts_and_absences(tmp_path):
    """Everything asked for is present; what is missing reads unknown, not fail."""
    case = _case(tmp_path)
    status = build_case_status(case)

    assert status["case_id"] == case.name
    # stages are derived from artifacts, never invented
    assert status["stages"], "N1-N8 must come from lane_stages()"
    assert {"stage", "status", "detail"} <= set(status["stages"][0])

    assert status["findings"]["total"] == 3
    assert status["findings"]["by_status"] == {
        "DRAFT": 1, "APPROVED": 1, "REJECTED": 1,
    }

    # no index, no report, no runs: each says so, and none of them says "failed"
    assert status["index"]["state"] == "unknown"
    assert status["report"]["state"] == "absent"
    assert status["runs"]["mode2"]["state"] == "none"
    assert status["runs"]["mode3"]["state"] == "none"
    assert status["runs"]["pipeline"]["state"] == "unknown"
    assert status["gate"]["blocked"] is False


def test_status_reports_a_built_index_and_a_present_report(tmp_path):
    case = _case(tmp_path)
    (case / "analysis" / "es_index.json").write_text(
        json.dumps({"docs": 128213, "caps": {"capped": False}, "errors": 0}),
        encoding="utf-8",
    )
    reports = case / "reports"
    reports.mkdir(exist_ok=True)
    (reports / "REPORT.md").write_text("# Case report\n", encoding="utf-8")

    status = build_case_status(case)
    assert status["index"] == {
        "state": "built", "docs": 128213, "capped": False, "errors": 0,
        "index": None, "generated_at": None,
    }
    assert status["report"]["state"] == "present"
    assert "REPORT.md" in status["report"]["files"]


def test_status_surfaces_a_blocked_gate_with_its_count(tmp_path):
    """A blocked gate is the one state that must never read as quiet."""
    case = _case(tmp_path)
    # the gate's own file (lane_gate.GATE_FILENAME under analysis/) - the
    # status reader goes through read_lane_gate, so it cannot drift to a path
    (case / "analysis" / "lane_gate.json").write_text(
        json.dumps({
            "status": "blocked",
            "unprocessed": [
                {
                    "tool": "evtxecmd",
                    "purpose": "Security.evtx",
                    "reason": "SKIP: parser unavailable",
                },
            ],
        }),
        encoding="utf-8",
    )
    status = build_case_status(case)
    assert status["gate"]["blocked"] is True
    assert status["gate"]["blocked_count"] == 1
    assert "EVIDENCE GATE BLOCKED" in status["gate"]["message"]
    assert status["gate"]["items"][0]["tool"] == "evtxecmd"


def test_status_reports_the_latest_run_per_mode(tmp_path):
    case = _case(tmp_path)
    for family, run_id, state in (
        ("mode2", "M2-1", "settled"),
        ("mode3", "M3-1", "running"),
    ):
        directory = case / "analysis" / f"{family}_runs"
        directory.mkdir(parents=True, exist_ok=True)
        (directory / f"{run_id}.json").write_text(
            json.dumps({
                "run_id": run_id, "status": state,
                "orders": [{"order_id": "W1"}, {"order_id": "W2"}],
            }),
            encoding="utf-8",
        )
    status = build_case_status(case)
    assert status["runs"]["mode2"] == {
        "state": "settled", "run_id": "M2-1", "reason": "", "staged": 2,
    }
    assert status["runs"]["mode3"]["state"] == "running"
    assert status["runs"]["mode3"]["run_id"] == "M3-1"


def test_endpoint_serves_the_single_status(client, tmp_path):
    case = _case(tmp_path)
    r = client.get(f"/portal/api/case/status?case_id={case.name}")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["case_id"] == case.name
    assert body["requested_case_id"] == case.name
    # the three signals the stepper, banner and header used to compute apart
    assert "stages" in body and "gate" in body and "findings" in body
    assert body["generated_at"]


def test_endpoint_refuses_a_missing_id(client):
    assert client.get("/portal/api/case/status").status_code == 400