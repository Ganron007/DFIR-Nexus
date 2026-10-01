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


def test_endpoint_without_a_case_reports_no_active_case(client):
    """No id and no active case is a missing resource (404), not a bad
    request (400) - and never a status for some other case."""
    resp = client.get("/portal/api/case/status")
    assert resp.status_code == 404
    assert "active case" in resp.json()["error"]


# --------------------------------------------------------------------------
# audit findings (2026-10-01): three defects, pinned
# --------------------------------------------------------------------------

def test_an_unknown_case_id_is_404_not_the_active_case(tmp_path, monkeypatch):
    """A stale link must never answer with another case's findings."""
    import nexus.dashboard.case_status_api as api

    real = tmp_path / "CASE-REAL001"
    (real / "analysis").mkdir(parents=True)
    (real / "findings.json").write_text(
        json.dumps([{"status": "DRAFT", "title": "real case finding"}]),
        encoding="utf-8",
    )

    def _resolve(case_id: str):
        return real if case_id == "CASE-REAL001" else None

    import nexus.analysis.finding_exhibit as exhibit
    import nexus.case.outputs as outputs

    monkeypatch.setattr(exhibit, "resolve_case_dir", _resolve)
    monkeypatch.setattr(outputs, "resolve_active_case_dir", lambda: real)

    from starlette.applications import Starlette
    from starlette.testclient import TestClient

    client = TestClient(Starlette(routes=api.case_status_routes()))
    resp = client.get("/portal/api/case/status", params={"case_id": "CASE-GHOST99"})
    assert resp.status_code == 404
    assert "CASE-GHOST99" in resp.json()["error"]
    # and the real case still answers for itself
    ok = client.get("/portal/api/case/status", params={"case_id": "CASE-REAL001"})
    assert ok.status_code == 200
    assert ok.json()["case_id"] == "CASE-REAL001"


def test_no_case_id_and_no_active_case_is_404_not_a_blank(tmp_path, monkeypatch):
    from starlette.applications import Starlette
    from starlette.testclient import TestClient

    import nexus.case.outputs as outputs
    import nexus.dashboard.case_status_api as api

    monkeypatch.setattr(outputs, "resolve_active_case_dir", lambda: None)
    client = TestClient(Starlette(routes=api.case_status_routes()))
    resp = client.get("/portal/api/case/status")
    assert resp.status_code == 404
    assert "active case" in resp.json()["error"]


def test_two_runs_in_one_filesystem_tick_report_the_later_run(tmp_path):
    """Run ids are timestamp-prefixed, so the name breaks an mtime tie."""
    case = _case(tmp_path)
    directory = case / "analysis" / "mode2_runs"
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "M2-20260101T000000-aaaa.json").write_text(
        json.dumps({"status": "complete", "run_id": "M2-20260101T000000-aaaa"}),
        encoding="utf-8",
    )
    (directory / "M2-20260101T000001-bbbb.json").write_text(
        json.dumps({"status": "failed", "run_id": "M2-20260101T000001-bbbb"}),
        encoding="utf-8",
    )
    # force the tie: same mtime to the byte
    stamp = 1_800_000_000.0
    for path in directory.glob("*.json"):
        import os
        os.utime(path, (stamp, stamp))

    status = build_case_status(case)
    assert status["runs"]["mode2"]["run_id"] == "M2-20260101T000001-bbbb"
    assert status["runs"]["mode2"]["state"] == "failed"


def test_a_run_that_staged_nothing_reports_zero_not_unknown(tmp_path):
    """Zero is an answer; None means the record does not say."""
    case = _case(tmp_path)
    directory = case / "analysis" / "mode3_runs"
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "M3-x.json").write_text(
        json.dumps({"status": "complete", "run_id": "M3-x", "candidates": []}),
        encoding="utf-8",
    )
    status = build_case_status(case)
    assert status["runs"]["mode3"]["staged"] == 0

    # and a record that says nothing about staging reports None
    (directory / "M3-x.json").write_text(
        json.dumps({"status": "complete", "run_id": "M3-x"}), encoding="utf-8"
    )
    assert build_case_status(case)["runs"]["mode3"]["staged"] is None
