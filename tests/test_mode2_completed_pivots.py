"""D503: dispatch identity survives persistence and completed work is not assigned again.

Inputs are verbatim field projections of two native R1 runs. These tests do not
invoke a model or turn captured conclusions into ground truth.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from nexus.modes import multi_role

CAPTURES = json.loads((Path(__file__).parent / "fixtures/mode2_replan_r1.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("capture", CAPTURES, ids=["evtx", "memory"])
def test_completed_pivots_are_removed_before_the_pending_window_is_selected(capture):
    orders = {o["order_id"]: o for o in capture["orders"]}
    index = next(i for i, r in enumerate(capture["results"])
                 if orders.get(r["order_id"], {}).get("task", "").startswith("Follow-up corroboration round"))
    before = {"results": capture["results"][:index]}
    _, available = multi_role._replan_inputs(before)
    assigned = available[:6]
    raw = orders[capture["results"][index]["order_id"]]
    assert assigned and all(p in raw["task"] for p in assigned), "the captured native order dispatched these pivots"
    order = multi_role.WorkOrder.from_dict(raw)
    order.pivot_entities = tuple(assigned)
    # Persist/resume through the real order writer/reader, then consume the actual native result.
    restored = multi_role.WorkOrder.from_dict(json.loads(json.dumps(order.to_dict())))
    state = {"orders": [restored.to_dict()], "results": capture["results"][:index + 1]}
    _, pending = multi_role._replan_inputs(state)
    assert not set(assigned) & set(pending)
    assert available[6] in pending, "completed items must not hide the rest of the pending window"
    assert capture["results"][index]["status"] == "ok" and not capture["results"][index]["partial"]

    # Incomplete work stays open. Changing execution metadata does not author evidence rows.
    incomplete = copy.deepcopy(state)
    incomplete["results"][-1]["partial"] = True
    assert set(assigned) <= set(multi_role._replan_inputs(incomplete)[1])
    blind = copy.deepcopy(state)
    blind["results"][-1]["tool_calls"] = []
    assert set(assigned) <= set(multi_role._replan_inputs(blind)[1])
    failed = copy.deepcopy(state)
    failed["results"][-1]["status"] = "fallback"
    assert set(assigned) <= set(multi_role._replan_inputs(failed)[1])


@pytest.mark.parametrize("capture", CAPTURES, ids=["evtx", "memory"])
def test_restoring_an_order_preserves_its_lead_and_method_contract(capture):
    raw = next(o for o in capture["orders"] if o.get("lead_subjects"))
    order = multi_role.WorkOrder.from_dict(raw)
    restored = multi_role.WorkOrder.from_dict(json.loads(json.dumps(order.to_dict())))
    for key in raw:
        assert json.loads(json.dumps(getattr(restored, key))) == raw[key], key
    assert restored.lead_subjects and restored.hypothesis


def test_native_graph_delivers_the_complete_order_and_does_not_drop_pending_pivots(tmp_path, monkeypatch):
    capture = CAPTURES[1]
    raw = next(o for o in capture["orders"] if o.get("lead_subjects"))
    initial = multi_role.WorkOrder.from_dict(raw)
    result = next(r for r in capture["results"] if r["order_id"] == initial.order_id)
    case = tmp_path / "case"
    (case / "analysis").mkdir(parents=True)
    received = []

    def captured_worker(order, **kwargs):
        received.append(order)
        if order.role in {"synthesis", "verifier"}:
            return multi_role.AgentResult(order_id=order.order_id, role=order.role, status="ok")
        return multi_role.AgentResult(**{**copy.deepcopy(result), "order_id": order.order_id, "role": order.role})

    monkeypatch.setattr(multi_role, "plan_work_orders", lambda *a, **k: [initial])
    monkeypatch.setattr(multi_role, "run_work_order", captured_worker)
    monkeypatch.setattr(multi_role, "_case_family_groups", lambda *a, **k: [])
    state = multi_role.run_mode2(case, "Compromise suspected.", model=object(), es_ok=True)
    assert received[0].to_dict() == initial.to_dict(), "the graph must restore the writer's entire contract"
    followups = [o for o in received if o.pivot_entities]
    assert len(followups) > 1, "an unchanged verdict must not bypass still-unassigned entities"
    assigned = [multi_role.norm_key(p) for o in followups for p in o.pivot_entities]
    assert len(assigned) == len(set(assigned)), "no completed pivot can be dispatched twice"
    assert multi_role._replan_inputs(state)[1] == [], "every captured pivot was investigated before convergence"
