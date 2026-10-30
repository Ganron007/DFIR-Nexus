"""Task scope changes the prompt view; full run work and mandatory facts remain intact."""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from nexus.modes import multi_agent as mode3
from nexus.modes import multi_role as mode2

FIXTURES = Path(__file__).parent / "fixtures"
BOARD = json.loads((FIXTURES / "mode3_work_r1.json").read_text(encoding="utf-8"))
WORK = json.loads((FIXTURES / "mode2_context_r1.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("index", [0, 1], ids=["evtx", "memory"])
def test_family_and_pivot_views_keep_their_verdict_but_omit_unrelated_work(index):
    own, other = BOARD[index], BOARD[1 - index]
    board = [own["claim_entry"], other["claim_entry"], own["verdict_entry"]]
    unchanged = copy.deepcopy(board)
    claim = own["claim_entry"]["claims"][0]
    unrelated = other["claim_entry"]["claims"][0]
    assert own["claim_entry"]["family"] != other["claim_entry"]["family"]
    etype, value = mode3._context_subject(claim)
    spawns = [
        {"role": "evidence", "family": own["claim_entry"]["family"]},
        {"role": "correlation", "pivot_entity": {"entity_type": etype, "entity_value": value}},
        {"role": "evidence", "lead_audit_ids": claim["audit_ids"]},
        mode3._verifier_spawn([claim], question="Compromise suspected.", superstep=2),
    ]
    for spawn in spawns:
        view = mode3._seat_board_view(board, spawn)
        assert claim["entity_value"] in view
        assert unrelated["entity_value"] not in view
        assert f"verifier: {own['verdict_entry']['verdicts'][0]['class']}" in view
    assert board == unchanged
    assert mode3._seat_board_view(board, {"role": "correlation"}) == mode3.board_view(board)


def test_blind_verifier_class_is_not_presented_as_completed_work():
    capture = BOARD[0]
    verdict = {**capture["verdict_entry"], "evidence_attempted": True, "evidence_read": False}
    view = mode3._seat_board_view([capture["claim_entry"], verdict], {"family": capture["claim_entry"]["family"]})
    assert "verifier:" not in view


def test_question_scope_keeps_the_global_settlement_from_another_seat():
    capture = BOARD[0]
    board = [capture["question_source"], capture["question_settler"]]
    qid = capture["question_id"]
    assert mode3._question_ledger(board)[qid]["status"] == "investigated"
    view = mode3._seat_board_view(board, {"role": "evidence", "question_ids": [qid]})
    assert f"question {qid} investigated:" in view
    assert f"open question {qid}:" not in view


def test_mode2_family_scope_preserves_case_wide_perspectives_and_unknown_origins():
    state = {"orders": WORK["orders"], "results": WORK["results"]}
    first = next(o for o in state["orders"] if o.get("family"))
    order = mode2.WorkOrder(order_id=first["order_id"], role="evidence", family=first["family"], task="Inspect assigned evidence.")
    selected = mode2._previous_results_for_order(state, order)
    by_id = {o["order_id"]: o for o in state["orders"]}
    assert 0 < len(selected) < len(state["results"])
    for result in selected:
        origin = by_id.get(result["order_id"])
        assert origin is None or origin.get("role") in {"correlation", "pattern"} or origin.get("family") == order.family
    wide = mode2.WorkOrder(order_id="cross-family", role="correlation", task="Correlate case evidence.")
    assert mode2._previous_results_for_order(state, wide) == state["results"]


def test_mode2_followup_routes_its_actual_question_and_pivot_origins():
    state = {"orders": WORK["orders"], "results": WORK["results"]}
    unchanged = copy.deepcopy(state)
    questions, pivots = mode2._replan_inputs(state)
    assert questions or pivots
    origins = mode2._followup_sources(state, questions[:6], pivots[:6], [])
    assert origins
    order = mode2.WorkOrder(order_id="followup", role="evidence", task="Settle assigned work.", source_orders=origins)
    restored = mode2.WorkOrder.from_dict(json.loads(json.dumps(order.to_dict())))
    selected = mode2._previous_results_for_order(state, restored)
    assert {r["order_id"] for r in selected} == set(origins)
    # Missing dependency metadata retains the run context; it cannot silently discard prior work.
    assert mode2._followup_sources({"results": []}, questions[:1], pivots[:1], []) is None
    assert state == unchanged
