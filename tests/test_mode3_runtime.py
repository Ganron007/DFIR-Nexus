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


def test_every_skill_maps_to_one_role():
    from nexus.knowledge.loader import get_skills

    skills = [s for s in get_skills() if str(s.get("skill") or "").strip()]
    assert len(skills) == 37
    seen = set()
    for skill in skills:
        skill_id = str(skill["skill"])
        role = m3.skill_role(skill_id)
        assert role in m3.ROLES
        assert role != "reporter"
        seen.add(skill_id)
    assert seen == set(m3.SKILL_ROLES)


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


def test_plan_work_orders_attaches_kb_skill_refs(tmp_path):
    case = _case(tmp_path)
    ref = {"skill": "evtx-logon", "title": "Logon analysis", "version": "abc123",
           "score": 3, "why": ["family evtxecmd"], "citations": ["kb-1"]}
    with patch("nexus.langgraph.backbone.backbone_call",
               return_value={"family_rows": {"evtxecmd": 10}}), \
         patch.object(m3, "_retrieve_skill_refs", return_value=[ref]):
        orders = m3.plan_work_orders(
            case, "rdp logons", run_id="M3-sk",
            sink=m3.EventSink(case, "M3-sk"),
        )
    assert orders and all(order.skill_refs for order in orders)
    plan_events = [e for e in m3.read_run_events(case, "M3-sk")
                   if e["event_type"] == "plan.work_order"]
    assert plan_events
    assert plan_events[0]["data"]["skills"][0]["skill"] == "evtx-logon"
    assert plan_events[0]["data"]["skills"][0]["version"] == "abc123"


def test_skill_procedure_block_reports_version_and_citations():
    fake_skill = {
        "skill": "evtx-logon",
        "title": "Logon analysis",
        "steps": [{"name": "4624", "query": "terms event_id 4624",
                   "look_for": "logons"}],
        "caveats": ["system noise"],
        "negative": "no logons means check parsing first",
    }
    order = m3.WorkOrder(
        order_id="wo-sk", role="evidence", task="t",
        skill_refs=[{"skill": "evtx-logon", "version": "abc123",
                     "citations": ["kb-1"], "title": "Logon analysis"}],
    )
    with patch.object(m3, "_skill_lookup", return_value={"evtx-logon": fake_skill}):
        block = m3._skill_procedure_block(order)
    assert "evtx-logon vabc123" in block
    assert "kb-1" in block
    assert "terms event_id 4624" in block
    assert "no logons means check parsing first" in block


def test_supervisor_followup_then_converges(tmp_path):
    case = _case(tmp_path)

    def fake_work(order, *, case_dir, model, run_id, sink, agent_id="", context=None):
        if order.role == "verifier":
            parsed = {"verdicts": [{
                "title": "Suspicious logon", "class": "inferred",
                "basis": "single family", "audit_ids": ["a-1"],
            }]}
        elif order.role == "synthesis":
            parsed = {
                "narrative": "n",
                "findings": [{
                    "title": "Suspicious logon", "observation": "o",
                    "interpretation": "i", "confidence": "LOW",
                    "audit_ids": ["a-1"],
                }],
                "gaps": [], "coverage": {},
            }
        elif order.role == "correlation":
            parsed = {"corroborated_entities": [], "notes": [], "coverage": {}}
        else:
            parsed = {
                "notes": [{"statement": "seen", "audit_ids": ["a-1"]}],
                "candidate_findings": [{
                    "title": "Suspicious logon", "observation": "o",
                    "interpretation": "i", "confidence": "LOW",
                    "audit_ids": ["a-1"],
                }],
                "coverage": {},
            }
        return m3.AgentResult(
            order_id=order.order_id, role=order.role, status="ok",
            reply=json.dumps(parsed), parsed=parsed, audit_id="ctx-1",
        )

    with patch.object(m3, "run_work_order", side_effect=fake_work), \
         patch.object(m3, "plan_work_orders", return_value=[m3.WorkOrder(
             order_id="wo-1", role="evidence", task="t", family="evtxecmd")]):
        state = m3.run_mode3(case, "what happened", model=object())

    assert [o["role"] for o in state["orders"]] == ["evidence", "correlation"]
    assert state["followup_rounds"] == 1
    assert state["status"] == "completed"
    assert state["stop_reason"] == "converged_no_new_evidence"
    event_types = [e["event_type"] for e in m3.read_run_events(case, state["run_id"])]
    assert "run.followup" in event_types
    assert "run.converged" in event_types


def test_stage_run_candidates_lineage_and_filters(tmp_path):
    case = _case(tmp_path)
    from nexus.audit import AuditWriter

    audit_id = AuditWriter("nexus", audit_dir=case / "audit").log(
        tool="es_search",
        params={"family": "evtxecmd", "file": "a.csv", "query": "logon"},
        result_summary={"total": 1},
        source="portal",
    )
    assert audit_id, "fixture must create a real case audit entry"
    m3._persist_state(case, "M3-stage", {
        "run_id": "M3-stage", "case_id": case.name, "question": "q",
        "status": "completed", "orders": [], "order_index": 0, "results": [],
        "verdicts": [{"title": "Refuted thing", "class": "refuted"}],
        "candidates": [
            {"title": "Valid candidate", "observation": "o",
             "interpretation": "i", "confidence": "LOW",
             "confidence_justification": "one audited query",
             "audit_ids": [audit_id],
             "evidence": [{"source": "evtxecmd/a.csv", "line": "7"}]},
            {"title": "No audit", "observation": "o", "interpretation": "i",
             "confidence": "LOW", "audit_ids": []},
            {"title": "Refuted thing", "observation": "o", "interpretation": "i",
             "confidence": "LOW", "audit_ids": [audit_id]},
        ],
        "gaps": [],
    })
    result = m3.stage_run_candidates(case, "M3-stage")
    assert result["staged_count"] == 1
    assert result["skipped_count"] == 2
    assert result["staged"][0]["input_call_ids"] == [audit_id]
    rows = json.loads((case / "findings.json").read_text(encoding="utf-8"))
    staged = [f for f in rows if f.get("run_id") == "M3-stage"]
    assert staged, "the valid candidate must be staged as DRAFT"
    assert staged[0]["status"] == "DRAFT"
    assert staged[0]["input_call_ids"] == [audit_id]
    assert staged[0].get("source") == "mode3"
    events = m3.read_run_events(case, "M3-stage")
    assert any(e["event_type"] == "finding.staged" for e in events)


def test_run_work_order_formats_prose_answer(tmp_path):
    case = _case(tmp_path)
    order = m3.WorkOrder(order_id="wo-fmt", role="evidence", task="t")
    prose = "Found 29,211 failed logons (4625), audit nexus-ci-test-1."
    with patch.object(m3, "run_context_loop", return_value={
            "reply": prose, "tool_calls": [], "hits": [], "aggregations": [],
            "audit_id": "", "partial": False, "partial_reason": ""}), \
         patch.object(m3, "_format_final_answer", return_value={
             "notes": [{"statement": "failed logons",
                        "audit_ids": ["nexus-ci-test-1"]}]}) as fmt:
        result = m3.run_work_order(
            order, case_dir=case, model=object(), run_id="M3-fmt",
            sink=m3.EventSink(case, "M3-fmt"))
    assert result.status == "ok"
    assert result.parsed["notes"][0]["statement"] == "failed logons"
    assert result.reply == prose
    fmt.assert_called_once()
    types = [e["event_type"] for e in m3.read_run_events(case, "M3-fmt")]
    assert "agent.formatted" in types


def test_run_work_order_stays_unparsed_when_format_fails(tmp_path):
    case = _case(tmp_path)
    order = m3.WorkOrder(order_id="wo-nf", role="evidence", task="t")
    with patch.object(m3, "run_context_loop", return_value={
            "reply": "prose without json", "tool_calls": [], "hits": [],
            "aggregations": [], "audit_id": "", "partial": False,
            "partial_reason": ""}), \
         patch.object(m3, "_format_final_answer", return_value={}):
        result = m3.run_work_order(
            order, case_dir=case, model=object(), run_id="M3-nf",
            sink=m3.EventSink(case, "M3-nf"))
    assert result.status == "unparsed"
    assert result.parsed == {}


def test_role_budget_defaults_are_respected(tmp_path):
    case = _case(tmp_path)
    order = m3.WorkOrder(order_id="wo-b", role="correlation", task="t")
    reply = json.dumps({"corroborated_entities": [], "coverage": {}})
    with patch.object(m3, "run_context_loop", return_value={
            "reply": reply, "tool_calls": [], "hits": [], "aggregations": [],
            "audit_id": "", "partial": False, "partial_reason": ""}) as fake:
        m3.run_work_order(order, case_dir=case, model=object(), run_id="M3-b",
                          sink=m3.EventSink(case, "M3-b"))
    budget = fake.call_args.kwargs["budget"]
    role = m3.role_for("correlation")
    assert budget.rounds == role.max_rounds
    assert budget.calls == role.max_calls
    assert budget.seconds == role.max_seconds


def test_plan_work_orders_adds_examiner_feedback_order(tmp_path):
    case = _case(tmp_path)
    with patch("nexus.langgraph.backbone.backbone_call",
               return_value={"family_rows": {"evtxecmd": 10, "hayabusa": 5}}):
        orders = m3.plan_work_orders(
            case, "what happened", run_id="M3-fb", sink=m3.EventSink(case, "M3-fb"),
            max_orders=4,
            known_findings={
                "approved": [{"id": "F-1", "title": "USB seen"}],
                "draft": [{"id": "F-2", "title": "RDP guessing"}],
                "rejected": [{"id": "F-3", "title": "False lead"}],
            },
        )
    assert len(orders) <= 4
    feedback = orders[-1]
    assert feedback.role == "correlation"
    assert "EXAMINER-APPROVED" in feedback.task
    assert "EXAMINER-REJECTED" in feedback.task
    assert "F-1 USB seen" in feedback.task
    assert "False lead" in feedback.task
    assert m3.validate_work_order(feedback) == []


def test_supervisor_stop_halts_before_next_order(tmp_path):
    case = _case(tmp_path)
    executed: list[str] = []

    def fake_work(order, *, case_dir, model, run_id, sink, agent_id="", context=None):
        executed.append(order.order_id)
        # The examiner stops the run while the first order is executing.
        m3.request_stop(case_dir, run_id)
        return m3.AgentResult(
            order_id=order.order_id, role=order.role, status="ok",
            parsed={"notes": [], "candidate_findings": [], "coverage": {}},
        )

    with patch.object(m3, "run_work_order", side_effect=fake_work), \
         patch.object(m3, "plan_work_orders", return_value=[
             m3.WorkOrder(order_id="wo-1", role="evidence", task="t1", family="evtxecmd"),
             m3.WorkOrder(order_id="wo-2", role="evidence", task="t2", family="hayabusa"),
         ]):
        state = m3.run_mode3(case, "what happened", model=object())

    assert executed == ["wo-1"], "the second order must not execute after stop"
    assert state["stop_reason"] == "examiner_stop"
    assert state["status"] == "stopped"
    events = [e["event_type"] for e in m3.read_run_events(case, state["run_id"])]
    assert events.count("run.stopped") == 1


def test_stop_before_verify_does_not_run_verifier(tmp_path):
    case = _case(tmp_path)
    roles: list[str] = []

    def fake_work(order, *, case_dir, model, run_id, sink, agent_id="", context=None):
        roles.append(order.role)
        m3.request_stop(case_dir, run_id)
        return m3.AgentResult(
            order_id=order.order_id, role=order.role, status="ok",
            parsed={"notes": [], "candidate_findings": [], "coverage": {}},
        )

    with patch.object(m3, "run_work_order", side_effect=fake_work), \
         patch.object(m3, "plan_work_orders", return_value=[
             m3.WorkOrder(order_id="wo-1", role="evidence", task="t1", family="evtxecmd"),
         ]):
        state = m3.run_mode3(case, "what happened", model=object())

    assert roles == ["evidence"]
    assert state["status"] == "stopped"
    assert "completed_at" in state


def test_resume_of_completed_run_does_not_reexecute(tmp_path):
    case = _case(tmp_path)
    m3._persist_state(case, "M3-done", {
        "run_id": "M3-done", "case_id": case.name, "question": "q",
        "status": "completed", "orders": [{"order_id": "wo-1"}],
        "order_index": 1, "results": [{"role": "evidence"}],
        "candidates": [{"title": "kept"}], "stop_reason": "completed",
    })
    with patch.object(m3, "run_work_order") as work:
        state = m3.run_mode3(case, "q", model=object(), run_id="M3-done", resume=True)
    work.assert_not_called()
    assert state["status"] == "completed"
    assert state["candidates"] == [{"title": "kept"}]


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
