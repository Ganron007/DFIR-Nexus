"""TA-7: work completion, not a quiet board, owns every Mode 3 convergence route.

Forensic work metadata is cut from two native R1 runs. Graph tests control seat
execution metadata, not evidence or model conclusions; the production-reader
replay and later R2 runs provide the separate real-case proof.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from nexus.modes import multi_agent as mode3

CAPTURES = json.loads((Path(__file__).parent / "fixtures/mode3_work_r1.json").read_text(encoding="utf-8"))


def _case(tmp_path, leads):
    case = tmp_path / "CASE-WORK"
    (case / "analysis").mkdir(parents=True)
    (case / "CASE.yaml").write_text("case_id: CASE-WORK\nstatus: created\n", encoding="utf-8")
    (case / "analysis/leads.jsonl").write_text("".join(json.dumps(lead) + "\n" for lead in leads), encoding="utf-8")
    return case


@pytest.mark.parametrize("capture", CAPTURES, ids=["evtx", "memory"])
def test_every_lead_enters_remaining_work_in_producer_order(tmp_path, capture):
    case = _case(tmp_path, capture["leads"])
    agenda = mode3._open_agenda(case, [])
    assert agenda.get("leads") == capture["leads"], "ordinary leads cannot disappear behind a severity filter"


@pytest.mark.parametrize("capture", CAPTURES, ids=["evtx", "memory"])
def test_failed_blind_and_undispositioned_seats_do_not_close_a_lead(capture):
    valid = capture["outcome"]
    key = mode3._norm_key(valid["lead"])
    assert key in mode3._dispositioned_keys([valid])
    for change in ({"evidence_attempted": True, "evidence_read": False}, {"finish_reason": "model_error"}):
        invalid = {**copy.deepcopy(valid), **change}
        assert key not in mode3._dispositioned_keys([invalid])
    assigned_only = {k: v for k, v in valid.items() if k != "lead_disposition"}
    assert key not in mode3._dispositioned_keys([assigned_only])


@pytest.mark.parametrize("capture", CAPTURES, ids=["evtx", "memory"])
def test_parser_and_ledger_require_an_explicit_status_and_basis(capture):
    raw = copy.deepcopy(capture["outcome"]["lead_disposition"])
    parsed = mode3._parse_seat_fields(json.dumps({"lead_disposition": raw}))
    assert parsed["lead_disposition"]["status"] == raw["status"]
    assert parsed["lead_disposition"]["basis"] == raw["basis"]
    for change in ({"status": "unrecognized"}, {"status": ""}, {"basis": ""}):
        invalid = {**raw, **change}
        assert "lead_disposition" not in mode3._parse_seat_fields(json.dumps({"lead_disposition": invalid}))
        entry = {**capture["outcome"], "lead_disposition": invalid}
        assert mode3._norm_key(entry["lead"]) not in mode3._dispositioned_keys([entry])


@pytest.mark.parametrize("capture", CAPTURES, ids=["evtx", "memory"])
def test_verification_is_work_and_a_blind_verifier_does_not_settle_it(tmp_path, capture):
    case = _case(tmp_path, [])
    claim = capture["claim_entry"]
    verdict = capture["verdict_entry"]
    assert mode3._unverified_claims([claim])
    assert mode3._open_agenda(case, [claim]).get("verification") == mode3._unverified_claims([claim])
    assert mode3._unverified_claims([claim, verdict]) == []
    blind = {**verdict, "evidence_attempted": True, "evidence_read": False}
    assert mode3._unverified_claims([claim, blind])


@pytest.mark.parametrize("capture", CAPTURES, ids=["evtx", "memory"])
def test_quiet_disputes_do_not_bypass_pending_work(tmp_path, capture):
    case = _case(tmp_path, capture["leads"])
    agenda = mode3._open_agenda(case, [])
    controls = {"has_disputes": True, "quiet": 3, "step_no": 3, "min_supersteps": 2, "settle_k": 2}
    assert mode3._open_work_count(agenda) >= len(capture["leads"])
    assert mode3._convergence_reason(agenda, **controls) == ""
    assert mode3._convergence_reason({}, **controls) == "disputes settled"
    assert mode3._convergence_reason({}, **{**controls, "has_disputes": False, "min_supersteps": 6}) == ""


def _run_control_graph(tmp_path, monkeypatch, *, answers, minimum):
    capture = CAPTURES[0]
    case = _case(tmp_path, capture["leads"][:1])
    # Keep the actual cut lead input fixed while testing the graph's control plane.
    monkeypatch.setattr("nexus.langgraph.case_digest.build_case_digest", lambda *a, **k: {})
    monkeypatch.setenv("NEXUS_MODE3_MIN_SUPERSTEPS", str(minimum))
    monkeypatch.setenv("NEXUS_MODE3_MAX_SUPERSTEPS", "6")
    calls = []

    def seat(spawn, _board, step):
        entry = copy.deepcopy(capture["outcome"])
        calls.append(spawn)
        entry.update(entry_id=f"entry-{len(calls)}", agent_id=f"seat-{len(calls)}", superstep=step,
                     role=spawn["role"], family=spawn.get("family") or "")
        entry.pop("lead", None)
        if not answers or not spawn.get("lead"):
            entry.pop("lead_disposition", None)
        return entry

    return mode3.run_mode3(case, "Compromise suspected.", families=[], seat_fn=seat, es_ok=True)


def test_assignment_without_outcome_stays_pending_and_is_not_reported_complete(tmp_path, monkeypatch):
    record = _run_control_graph(tmp_path, monkeypatch, answers=False, minimum=2)
    subject = CAPTURES[0]["leads"][0]["subject"]
    assert "budget" in record["stop_reason"]
    assert subject in record["open_agenda"]["leads"]
    assert subject not in record["lead_dispositions"], "the report must not invent an insufficient disposition"


def test_supervisor_cannot_bypass_the_join_minimum_when_work_finishes(tmp_path, monkeypatch):
    record = _run_control_graph(tmp_path, monkeypatch, answers=True, minimum=4)
    assert record["stop_reason"] == "settled"
    assert record["superstep"] == 4
    assert not any(record["open_agenda"].values())
