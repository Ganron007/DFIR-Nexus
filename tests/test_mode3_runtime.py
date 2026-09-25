"""M1/M2/M5 — Mode 3 agent runtime foundation tests."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from nexus.langgraph import mode3_runtime as m3


def _case(tmp_path: Path) -> Path:
    case = tmp_path / "CASE-M3"
    (case / "analysis").mkdir(parents=True)
    (case / "audit").mkdir()
    (case / "CASE.yaml").write_text("name: m3\nstatus: active\n", encoding="utf-8")
    return case


def test_event_envelope_has_run_and_actor_ids():
    event = m3.new_event(
        "M3-test", "tool.call", actor="agent", agent_id="evidence-1",
        call_id="c1", tool="es_search", why="find rows", audit_id="a-1",
    )
    payload = event.to_dict()
    assert payload["event_id"].startswith("evt-")
    assert payload["run_id"] == "M3-test"
    assert payload["actor"] == "agent"
    assert payload["agent_id"] == "evidence-1"
    assert payload["tool"] == "es_search"
    assert payload["audit_id"] == "a-1"


def test_role_allowlists_are_scoped_and_work_orders_validated():
    evidence = m3.role_for("evidence")
    assert "es_search" in evidence.tools
    assert "web_search" not in evidence.tools
    order = m3.WorkOrder(
        order_id="wo-1", role="evidence", task="t",
        priority_tools=("es_search", "not_a_tool"),
    )
    problems = m3.validate_work_order(order)
    assert any("allowlist" in problem for problem in problems)
    ok = m3.WorkOrder(order_id="wo-2", role="evidence", task="t",
                      priority_tools=("es_search",))
    assert m3.validate_work_order(ok) == []


def test_plan_work_orders_covers_families_and_roles(tmp_path):
    case = _case(tmp_path)
    with patch("nexus.langgraph.backbone.backbone_call",
               return_value={"family_rows": {"hayabusa": 100, "evtxecmd": 50}}):
        orders = m3.plan_work_orders(
            case, "what happened", run_id="M3-plan",
            sink=m3.EventSink(case, "M3-plan"),
        )
    roles = [o.role for o in orders]
    assert roles.count("evidence") == 2
    assert "correlation" in roles and "pattern" in roles
    for order in orders:
        assert m3.validate_work_order(order) == []


def test_run_work_order_emits_events_and_parses_json(tmp_path):
    case = _case(tmp_path)
    order = m3.WorkOrder(
        order_id="wo-run", role="evidence", task="find usb", family="hayabusa",
    )
    reply = json.dumps({
        "notes": [{"statement": "USB found", "audit_ids": ["a-1"]}],
        "candidate_findings": [{"title": "USB", "audit_ids": ["a-1"]}],
        "coverage": {"checked": ["usb"], "not_checked": []},
    })
    events: list[dict] = []
    sink = m3.EventSink(case, "M3-run", callback=events.append)
    def fake_loop(**kwargs):
        callback = kwargs.get("on_event")
        if callback:
            callback({"event": "tool_call", "tool": "es_search",
                      "args": {"query": "usb"}, "why": "find usb"})
            callback({"event": "tool_result", "tool": "es_search",
                      "audit_id": "a-1", "summary": {"total": 1}})
        return {
            "reply": reply,
            "tool_calls": [{"tool": "es_search", "audit_id": "a-1"}],
            "hits": [{"family": "hayabusa", "file": "a.csv", "line": "1"}],
            "aggregations": [], "audit_id": "ctx-1", "partial": False,
            "partial_reason": "",
        }

    with patch.object(m3, "run_context_loop", side_effect=fake_loop) as fake_loop_mock:
        result = m3.run_work_order(
            order, case_dir=case, model=object(), run_id="M3-run", sink=sink)
    assert result.status == "ok"
    assert result.parsed["notes"][0]["statement"] == "USB found"
    assert result.partial is False
    assert fake_loop_mock.call_args.kwargs["allowed_tools"] == m3.role_for("evidence").tools
    kinds = [e["event_type"] for e in events]
    assert "work_order.started" in kinds
    assert "tool.call" in kinds  # emitted from the loop callback only in real loop
    assert "work_order.completed" in kinds
    stored = m3.read_run_events(case, "M3-run")
    assert any(e["event_type"] == "work_order.completed" for e in stored)


def test_run_work_order_falls_back_without_black_box(tmp_path):
    case = _case(tmp_path)
    order = m3.WorkOrder(order_id="wo-fb", role="evidence", task="find x")
    sink = m3.EventSink(case, "M3-fallback")
    with patch.object(m3, "run_context_loop", side_effect=RuntimeError("no model")):
        result = m3.run_work_order(
            order, case_dir=case, model=None, run_id="M3-fallback", sink=sink)
    assert result.status == "fallback"
    assert result.partial is True
    assert "no model" in result.partial_reason
    assert order.status == "fallback"


def test_run_mode3_supervisor_runs_and_persists(tmp_path):
    case = _case(tmp_path)

    def fake_work(order, *, case_dir, model, run_id, sink, agent_id="", context=None):
        parsed = {
            "notes": [{"statement": "n", "audit_ids": ["a-1"]}],
            "candidate_findings": [{
                "title": "Candidate", "observation": "o",
                "interpretation": "i", "confidence": "LOW",
                "audit_ids": ["a-1"],
            }],
            "coverage": {"checked": ["x"], "not_checked": []},
        }
        sink.emit(m3.new_event(run_id, "work_order.completed", actor="agent",
                               agent_id=agent_id, status="ok"))
        return m3.AgentResult(
            order_id=order.order_id, role=order.role, status="ok",
            reply=json.dumps(parsed), parsed=parsed, audit_id="ctx-1",
        )

    with patch.object(m3, "run_work_order", side_effect=fake_work), \
         patch.object(m3, "plan_work_orders", return_value=[m3.WorkOrder(
             order_id="wo-1", role="evidence", task="t", family="hayabusa")]):
        state = m3.run_mode3(case, "what happened", model=object())

    assert state["status"] == "completed"
    assert state["orders"]
    assert state["results"], "worker result must be recorded"
    assert state["candidates"], "supervisor must carry candidates forward"
    stored = m3.read_run_record(case, state["run_id"])
    assert stored is not None and stored["status"] == "completed"
    events = m3.read_run_events(case, state["run_id"])
    assert any(e["event_type"] == "run.completed" for e in events)
