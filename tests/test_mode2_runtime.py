"""M1/M2/M5 — Mode 2 multi-role runtime foundation tests."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from nexus.modes import multi_role as m3


def _case(tmp_path: Path) -> Path:
    case = tmp_path / "CASE-M3"
    (case / "analysis").mkdir(parents=True)
    (case / "audit").mkdir()
    (case / "CASE.yaml").write_text("name: m3\nstatus: active\n", encoding="utf-8")
    return case


def test_event_envelope_has_run_and_actor_ids():
    event = m3.new_event(
        "M2-test", "tool.call", actor="agent", agent_id="evidence-1",
        call_id="c1", tool="es_search", why="find rows", audit_id="a-1",
    )
    payload = event.to_dict()
    assert payload["event_id"].startswith("evt-")
    assert payload["run_id"] == "M2-test"
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
            case, "what happened", run_id="M2-plan",
            sink=m3.EventSink(case, "M2-plan"),
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
    sink = m3.EventSink(case, "M2-run", callback=events.append)
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
            order, case_dir=case, model=object(), run_id="M2-run", sink=sink)
    assert result.status == "ok"
    assert result.parsed["notes"][0]["statement"] == "USB found"
    assert result.partial is False
    assert fake_loop_mock.call_args.kwargs["allowed_tools"] == m3.role_for("evidence").tools
    kinds = [e["event_type"] for e in events]
    assert "work_order.started" in kinds
    assert "tool.call" in kinds  # emitted from the loop callback only in real loop
    assert "work_order.completed" in kinds
    stored = m3.read_run_events(case, "M2-run")
    assert any(e["event_type"] == "work_order.completed" for e in stored)


def test_run_work_order_marks_replayed_tool_result_and_keeps_one_audit(tmp_path, monkeypatch):
    from nexus.langgraph import es_native

    case = _case(tmp_path / "cases")
    order = m3.WorkOrder(order_id="wo-replay", role="evidence", task="count rows")
    call = {
        "tool": "es_search",
        "args": {"query": {"match_all": {}}, "size": 5},
        "why": "check whether rows exist",
    }
    answer = json.dumps({"notes": [], "candidate_findings": [],
                         "coverage": {"checked": [], "not_checked": []}})

    class ScriptedModel:
        def __init__(self):
            self.responses = [
                {"tool_calls": [call]},
                {"tool_calls": [call]},
                {"answer": answer},
            ]

        def invoke(self, _messages):
            return type("Response", (), {"content": json.dumps(self.responses.pop(0))})()

    def empty_search(_case_id, **_kwargs):
        return {"case_id": case.name, "total": 0, "returned": 0, "hits": [],
                "has_more": False, "next_search_after": None}

    monkeypatch.setattr(es_native, "es_search", empty_search)
    events = []
    result = m3.run_work_order(
        order, case_dir=case, model=ScriptedModel(), run_id="M2-replay",
        sink=m3.EventSink(case, "M2-replay", callback=events.append),
    )

    assert result.status == "ok"
    calls = [event for event in events if event["event_type"] == "tool.call"]
    results = [event for event in events if event["event_type"] == "tool.result"]
    assert len(calls) == 1, "the identical query must execute once"
    assert len(results) == 2
    assert results[0]["audit_id"] == results[1]["audit_id"]
    assert results[0]["data"]["replayed"] is False
    assert results[1]["data"]["replayed"] is True
    audit_rows = [json.loads(line) for line in (case / "audit" / "nexus.jsonl").read_text().splitlines()]
    assert len([row for row in audit_rows if row.get("tool") == "es_search"]) == 1


def test_run_work_order_records_failed_search_status_and_audit_provenance(tmp_path, monkeypatch):
    from nexus.langgraph import es_native

    case = _case(tmp_path / "cases")
    order = m3.WorkOrder(order_id="wo-error", role="evidence", task="search rows")
    answer = json.dumps({"notes": [], "candidate_findings": [],
                         "coverage": {"checked": [], "not_checked": []}})

    class ScriptedModel:
        def __init__(self):
            self.responses = [
                {"tool_calls": [{
                    "tool": "es_search",
                    "args": {"query": {"match_all": {}}, "size": 5},
                    "why": "exercise audited query failure",
                }]},
                {"answer": answer},
            ]

        def invoke(self, _messages):
            return type("Response", (), {"content": json.dumps(self.responses.pop(0))})()

    def fail_search(_case_id, **_kwargs):
        raise es_native.ESQueryError("wildcard takes exactly one field")

    monkeypatch.setattr(es_native, "es_search", fail_search)
    events = []
    result = m3.run_work_order(
        order, case_dir=case, model=ScriptedModel(), run_id="M2-error",
        sink=m3.EventSink(case, "M2-error", callback=events.append),
    )

    assert result.status == "ok"
    failed_calls = [call for call in result.tool_calls if call["tool"] == "es_search"]
    assert len(failed_calls) == 1
    call = failed_calls[0]
    assert call["read_evidence"] is False
    assert "ESQueryError: wildcard takes exactly one field" in call["summary"]["error"]
    assert call["audit_id"]
    tool_result = next(event for event in events if event["event_type"] == "tool.result")
    assert tool_result["status"] == "error"
    assert tool_result["audit_id"] == call["audit_id"]
    assert "ESQueryError: wildcard takes exactly one field" in tool_result["detail"]
    assert tool_result["data"]["replayed"] is False
    assert tool_result["data"]["summary"]["error"] == call["summary"]["error"]
    audit_rows = [json.loads(line) for line in (case / "audit" / "nexus.jsonl").read_text().splitlines()]
    search_rows = [row for row in audit_rows if row.get("tool") == "es_search"]
    assert len(search_rows) == 1
    assert search_rows[0]["audit_id"] == call["audit_id"]
    assert search_rows[0]["result_summary"]["error"]


def test_run_work_order_falls_back_without_black_box(tmp_path):
    case = _case(tmp_path)
    order = m3.WorkOrder(order_id="wo-fb", role="evidence", task="find x")
    sink = m3.EventSink(case, "M2-fallback")
    with patch.object(m3, "run_context_loop", side_effect=RuntimeError("no model")):
        result = m3.run_work_order(
            order, case_dir=case, model=None, run_id="M2-fallback", sink=sink)
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
            case, "rdp logons", run_id="M2-sk",
            sink=m3.EventSink(case, "M2-sk"),
        )
    assert orders and all(order.skill_refs for order in orders)
    plan_events = [e for e in m3.read_run_events(case, "M2-sk")
                   if e["event_type"] == "plan.work_order"]
    assert plan_events
    assert plan_events[0]["data"]["skills"][0]["skill"] == "evtx-logon"
    assert plan_events[0]["data"]["skills"][0]["version"] == "abc123"


def test_skill_procedure_block_reports_version_and_citations():
    """WO-KR2: the worker prompt shows the step, never the query.

    The skill carries a legacy `query` string on purpose, so the test fails if a
    prompt ever renders it again - the prompt must show the step name, `look_for`,
    `corroborate` and the result, and no query text in either form.
    """
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
    # Provenance and the procedure itself are present.
    assert "evtx-logon vabc123" in block
    assert "kb-1" in block
    assert "4624" in block
    assert "look_for: logons" in block
    assert "no logons means check parsing first" in block
    # WO-KR2: never the query text, in either form.
    assert "terms event_id 4624" not in block
    assert "| run:" not in block


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

    observed_active_states: set[str] = set()

    def inspect_persisted_state(event: dict) -> None:
        record = m3.read_run_record(case, event["run_id"])
        status = str((record or {}).get("status") or "")
        if status in {"verified", "assessed"}:
            busy_ids = {entry["run_id"] for entry in m3.busy_runs(case)}
            assert event["run_id"] in busy_ids, (
                f"the live Mode 2 {status} phase did not keep the case busy")
            observed_active_states.add(status)

    with patch.object(m3, "run_work_order", side_effect=fake_work), \
         patch.object(m3, "plan_work_orders", return_value=[m3.WorkOrder(
             order_id="wo-1", role="evidence", task="t", family="evtxecmd")]):
        state = m3.run_mode2(
            case, "what happened", model=object(), es_ok=True,
            on_event=inspect_persisted_state)

    assert observed_active_states == {"verified", "assessed"}
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
    m3._persist_state(case, "M2-stage", {
        "run_id": "M2-stage", "case_id": case.name, "question": "q",
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
    result = m3.stage_run_candidates(case, "M2-stage")
    assert result["staged_count"] == 1
    assert result["skipped_count"] == 2
    assert result["staged"][0]["input_call_ids"] == [audit_id]
    rows = json.loads((case / "findings.json").read_text(encoding="utf-8"))
    staged = [f for f in rows if f.get("run_id") == "M2-stage"]
    assert staged, "the valid candidate must be staged as DRAFT"
    assert staged[0]["status"] == "DRAFT"
    assert staged[0]["input_call_ids"] == [audit_id]
    assert staged[0].get("source") == "mode2"
    # WO-1C item 5 / D40: the DRAFT names the mode that produced it.
    assert staged[0]["provenance"] == {
        "mode": 2, "origin": "llm", "path": "multi-role", "run_id": "M2-stage"}
    events = m3.read_run_events(case, "M2-stage")
    assert any(e["event_type"] == "finding.staged" for e in events)


def test_backfill_audit_ids_from_matching_titles():
    verdicts = [
        {"title": "WMI Consumer Persistence", "class": "confirmed", "audit_ids": []},
        {"title": "Already has ids", "class": "confirmed", "audit_ids": ["nexus-a"]},
    ]
    pool = [
        {"title": "wmi consumer persistence", "audit_ids": ["nexus-074", "nexus-075"]},
        {"title": "Already has ids", "audit_ids": ["nexus-b"]},
    ]
    assert m3._backfill_audit_ids(verdicts, pool) == 1
    assert verdicts[0]["audit_ids"] == ["nexus-074", "nexus-075"]
    assert verdicts[1]["audit_ids"] == ["nexus-a"]


def test_backfill_never_invents_ids_for_unmatched_rows():
    rows = [{"title": "no source for this", "audit_ids": []}]
    assert m3._backfill_audit_ids(rows, [{"title": "different", "audit_ids": ["x"]}]) == 0
    assert rows[0]["audit_ids"] == []


def test_stage_run_candidates_never_invents_a_severity(tmp_path):
    """A staged finding carries the severity its claim was rated, never an invented one.

    Staging used to fill a missing severity with LOW, so run 6's CobaltStrike finding, whose
    synthesis dropped the workers' rating, staged LOW (D211). Mode 1 keeps an unrated severity empty
    for the examiner (D47), and so does Mode 2.
    """
    case = _case(tmp_path)
    from nexus.audit import AuditWriter

    audit_id = AuditWriter("nexus", audit_dir=case / "audit").log(
        tool="es_search", params={"query": "x"}, result_summary={"total": 1},
        source="portal",
    )
    m3._persist_state(case, "M2-sev", {
        "run_id": "M2-sev", "case_id": case.name, "question": "q",
        "status": "completed", "orders": [], "order_index": 0, "results": [],
        "verdicts": [{"title": "Candidate without severity", "class": "confirmed"},
                     {"title": "Rated candidate", "class": "confirmed"}],
        "candidates": [{"title": "Candidate without severity", "observation": "o",
                        "interpretation": "i", "confidence": "LOW",
                        "audit_ids": [audit_id]},
                       {"title": "Rated candidate", "observation": "o2", "interpretation": "i2",
                        "confidence": "HIGH", "severity": "critical", "audit_ids": [audit_id]}],
        "gaps": [],
    })
    result = m3.stage_run_candidates(case, "M2-sev")
    assert result["staged_count"] == 2
    rows = json.loads((case / "findings.json").read_text(encoding="utf-8"))
    staged = {f["title"]: f for f in rows if f.get("run_id") == "M2-sev"}
    assert staged["Candidate without severity"].get("severity") == ""
    assert staged["Rated candidate"].get("severity") == "critical"


def test_a_merged_claim_is_as_severe_as_the_claims_it_absorbs():
    """D211: run 6's synthesis returned its five findings with no severity; its workers had rated
    the claims it merged CRITICAL, HIGH and MEDIUM."""
    finals = [{"title": "SRLUpdate.exe beacon under the SRL User Maintenance task",
               "audit_ids": ["a-1", "a-2", "a-3"]},
              {"title": "rated by synthesis", "severity": "MEDIUM", "audit_ids": ["a-1"]},
              {"title": "no source", "audit_ids": ["a-9"]}]
    sources = [{"title": "Defender CobaltStrike detections", "severity": "HIGH", "audit_ids": ["a-1"]},
               {"title": "task runs SRLUpdate.exe as SYSTEM", "severity": "critical", "audit_ids": ["a-2", "a-3"]},
               {"title": "unrated", "audit_ids": ["a-3"]}]
    m3._carry_claim_tests(finals, sources)
    assert finals[0]["severity"] == "CRITICAL"
    assert finals[1]["severity"] == "MEDIUM", "a severity synthesis gave is kept"
    assert "severity" not in finals[2]


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
            order, case_dir=case, model=object(), run_id="M2-fmt",
            sink=m3.EventSink(case, "M2-fmt"))
    assert result.status == "ok"
    assert result.parsed["notes"][0]["statement"] == "failed logons"
    assert result.reply == prose
    fmt.assert_called_once()
    types = [e["event_type"] for e in m3.read_run_events(case, "M2-fmt")]
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
            order, case_dir=case, model=object(), run_id="M2-nf",
            sink=m3.EventSink(case, "M2-nf"))
    assert result.status == "unparsed"
    assert result.parsed == {}


def test_role_budget_defaults_are_respected(tmp_path):
    case = _case(tmp_path)
    order = m3.WorkOrder(order_id="wo-b", role="correlation", task="t")
    reply = json.dumps({"corroborated_entities": [], "coverage": {}})
    with patch.object(m3, "run_context_loop", return_value={
            "reply": reply, "tool_calls": [], "hits": [], "aggregations": [],
            "audit_id": "", "partial": False, "partial_reason": ""}) as fake:
        m3.run_work_order(order, case_dir=case, model=object(), run_id="M2-b",
                          sink=m3.EventSink(case, "M2-b"))
    budget = fake.call_args.kwargs["budget"]
    shared = m3.mode2_loop_budget(case)
    assert budget.rounds == shared.rounds
    assert budget.calls == shared.calls
    assert budget.seconds == shared.seconds
    assert budget.call_chars == shared.call_chars
    assert budget.call_chars > 100_000


def test_plan_work_orders_adds_examiner_feedback_order(tmp_path):
    case = _case(tmp_path)
    with patch("nexus.langgraph.backbone.backbone_call",
               return_value={"family_rows": {"evtxecmd": 10, "hayabusa": 5}}):
        orders = m3.plan_work_orders(
            case, "what happened", run_id="M2-fb", sink=m3.EventSink(case, "M2-fb"),
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
        state = m3.run_mode2(case, "what happened", model=object(), es_ok=True)

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
        state = m3.run_mode2(case, "what happened", model=object(), es_ok=True)

    assert roles == ["evidence"]
    assert state["status"] == "stopped"
    assert "completed_at" in state


def test_resume_of_completed_run_does_not_reexecute(tmp_path):
    case = _case(tmp_path)
    m3._persist_state(case, "M2-done", {
        "run_id": "M2-done", "case_id": case.name, "question": "q",
        "status": "completed", "orders": [{"order_id": "wo-1"}],
        "order_index": 1, "results": [{"role": "evidence"}],
        "candidates": [{"title": "kept"}], "stop_reason": "completed",
    })
    with patch.object(m3, "run_work_order") as work:
        state = m3.run_mode2(case, "q", model=object(), run_id="M2-done", resume=True, es_ok=True)
    work.assert_not_called()
    assert state["status"] == "completed"
    assert state["candidates"] == [{"title": "kept"}]


def test_run_mode2_supervisor_runs_and_persists(tmp_path):
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
        state = m3.run_mode2(case, "what happened", model=object(), es_ok=True)

    assert state["status"] == "completed"
    assert state["orders"]
    assert state["results"], "worker result must be recorded"
    assert state["candidates"], "supervisor must carry candidates forward"
    stored = m3.read_run_record(case, state["run_id"])
    assert stored is not None and stored["status"] == "completed"
    events = m3.read_run_events(case, state["run_id"])
    assert any(e["event_type"] == "run.completed" for e in events)


def test_run_mode2_refuses_without_elasticsearch(tmp_path):
    """A Mode 2 run must refuse before any work when ES is unavailable —
    the workers query the N3 index, so a run without it would be hollow."""
    case = _case(tmp_path)
    ran: list[str] = []

    def fake_work(*args, **kwargs):
        ran.append("work")
        raise AssertionError("no work order may run without Elasticsearch")

    with patch.object(m3, "run_work_order", side_effect=fake_work):
        state = m3.run_mode2(
            case, "what happened", model=object(), es_ok=False, run_id="M2-no-es")

    assert state["status"] == "failed"
    assert state["stop_reason"] == "elasticsearch_required"
    assert not ran, "the supervisor must not dispatch work orders"
    stored = m3.read_run_record(case, "M2-no-es")
    assert stored is not None and stored["stop_reason"] == "elasticsearch_required"


def test_stage_takes_evidence_from_the_cited_rows_not_the_model_text(tmp_path):
    """D70: a candidate's evidence is the rows its cited audit entry returned, the same rows
    Mode 1 drafts carry. Text the model wrote is not evidence and is only a fallback."""
    case = _case(tmp_path)
    stored_row = {
        "time": "", "source": "evtxecmd/a.csv", "artifact": "a.csv",
        "detail": "EventId 1004 Microsoft-Windows-Security-SPP", "loc": "a.csv:7",
    }
    from nexus.audit import AuditWriter

    cited = AuditWriter("nexus", audit_dir=case / "audit").log(
        tool="es_search",
        params={"query": {"match_all": {}}},
        result_summary={"total": 1, "returned": 1, "evidence_rows": [stored_row]},
        source="portal",
    )
    assert cited, "fixture must create a real audit entry"
    m3._persist_state(case, "M2-rows", {
        "run_id": "M2-rows", "case_id": case.name, "question": "q",
        "status": "completed", "orders": [], "order_index": 0, "results": [],
        "verdicts": [],
        "candidates": [{
            "title": "Rows claim", "observation": "o", "interpretation": "i",
            "confidence": "LOW", "confidence_justification": "one audited query",
            "audit_ids": [cited],
            "evidence": [{"source": "model/invented", "detail": "text the model wrote"}],
        }],
        "gaps": [],
    })
    result = m3.stage_run_candidates(case, "M2-rows")
    assert result["staged_count"] == 1, result
    rows = json.loads((case / "findings.json").read_text(encoding="utf-8"))
    staged = [f for f in rows if f.get("run_id") == "M2-rows"]
    assert staged[0]["evidence"] == [stored_row]


def test_a_follow_up_verifies_only_new_or_re_cited_candidates(tmp_path):
    """2026-10-14, Mode 2 run 3: after each follow-up round the verifier re-verified the whole
    candidate pool, unchanged candidates included (~10 minutes a pass, up to 8 rounds)."""
    case = _case(tmp_path)
    verifier_tasks: list[str] = []
    first = {"title": "Suspicious logon", "observation": "o", "interpretation": "i",
             "confidence": "LOW", "audit_ids": ["a-1"]}
    second = {"title": "Service installed", "observation": "o", "interpretation": "i",
              "confidence": "LOW", "audit_ids": ["a-2"]}

    def fake_work(order, *, case_dir, model, run_id, sink, agent_id="", context=None):
        if order.role == "verifier":
            verifier_tasks.append(order.task)
            parsed = {"verdicts": [{"title": c["title"], "class": "inferred", "basis": "one family",
                                    "audit_ids": c["audit_ids"]} for c in context["candidates"]]}
        elif order.role == "synthesis":
            parsed = {"narrative": "n", "findings": [], "gaps": [], "coverage": {}}
        elif order.role == "correlation":
            parsed = {"notes": [], "candidate_findings": [second], "coverage": {}}
        else:
            parsed = {"notes": [], "candidate_findings": [first], "coverage": {}}
        return m3.AgentResult(order_id=order.order_id, role=order.role, status="ok",
                              reply=json.dumps(parsed), parsed=parsed, audit_id="ctx-1")

    with patch.object(m3, "run_work_order", side_effect=fake_work), \
         patch.object(m3, "plan_work_orders", return_value=[m3.WorkOrder(
             order_id="wo-1", role="evidence", task="t", family="evtxecmd")]):
        state = m3.run_mode2(case, "what happened", model=object(), es_ok=True)

    assert len(verifier_tasks) >= 2
    assert "Suspicious logon" in verifier_tasks[0]
    assert "Service installed" in verifier_tasks[1] and "Suspicious logon" not in verifier_tasks[1]
    assert {v["title"] for v in state["verdicts"]} == {"Suspicious logon", "Service installed"}


def test_a_follow_up_that_only_adds_calls_and_notes_converges(tmp_path):
    """2026-10-14, Mode 2 run 3: the convergence signature counted notes and tool calls, which
    every round adds, so the run went on to round 4 after a round that changed nothing."""
    case = _case(tmp_path)
    claim = {"title": "Suspicious logon", "observation": "o", "interpretation": "i",
             "confidence": "LOW", "audit_ids": ["a-1"]}

    def fake_work(order, *, case_dir, model, run_id, sink, agent_id="", context=None):
        if order.role == "verifier":
            parsed = {"verdicts": [{"title": "Suspicious logon", "class": "inferred",
                                    "basis": "one family", "audit_ids": ["a-1"]}]}
        elif order.role == "synthesis":
            parsed = {"narrative": "n", "findings": [], "gaps": [], "coverage": {}}
        elif order.role == "correlation":
            parsed = {"notes": [{"statement": "looked again", "audit_ids": ["a-1"]}],
                      "candidate_findings": [], "coverage": {}}
        else:
            parsed = {"notes": [], "candidate_findings": [claim], "coverage": {}}
        result = m3.AgentResult(order_id=order.order_id, role=order.role, status="ok",
                                reply=json.dumps(parsed), parsed=parsed, audit_id="ctx-1")
        result.tool_calls = [{"tool": "es_search", "audit_id": f"q-{order.order_id}"}]
        return result

    with patch.object(m3, "run_work_order", side_effect=fake_work), \
         patch.object(m3, "plan_work_orders", return_value=[m3.WorkOrder(
             order_id="wo-1", role="evidence", task="t", family="evtxecmd")]):
        state = m3.run_mode2(case, "what happened", model=object(), es_ok=True)

    assert state["followup_rounds"] == 1
    assert state["stop_reason"] == "converged_no_new_evidence"


def test_a_follow_up_that_re_cites_a_claim_without_moving_its_verdict_converges(tmp_path):
    """2026-10-14, Mode 2 run 4: each follow-up re-cited the same 'inferred' claims with new audit
    ids, the verifier ruled them 'inferred' again, and the run went on round after round."""
    case = _case(tmp_path)
    rounds = {"n": 0}

    def fake_work(order, *, case_dir, model, run_id, sink, agent_id="", context=None):
        if order.role == "verifier":
            parsed = {"verdicts": [{"title": c["title"], "class": "inferred", "basis": "AMSI only",
                                    "audit_ids": c["audit_ids"]} for c in context["candidates"]]}
        elif order.role == "synthesis":
            parsed = {"narrative": "n", "findings": [], "gaps": [], "coverage": {}}
        else:
            rounds["n"] += 1
            parsed = {"notes": [], "coverage": {}, "candidate_findings": [{
                "title": "Kekeo detection is AMSI-only", "observation": "o", "interpretation": "i",
                "confidence": "LOW", "audit_ids": [f"q-{rounds['n']}"]}]}
        return m3.AgentResult(order_id=order.order_id, role=order.role, status="ok",
                              reply=json.dumps(parsed), parsed=parsed, audit_id="ctx-1")

    with patch.object(m3, "run_work_order", side_effect=fake_work), \
         patch.object(m3, "plan_work_orders", return_value=[m3.WorkOrder(
             order_id="wo-1", role="evidence", task="t", family="evtxecmd")]):
        state = m3.run_mode2(case, "what happened", model=object(), es_ok=True)

    assert state["followup_rounds"] == 1
    assert state["stop_reason"] == "converged_no_new_evidence"


def test_a_candidates_alternative_and_refutation_reach_the_draft_with_it(tmp_path):
    """Mode 2 run 5 (2026-10-14): 8 of 12 candidates were 'Benign alternative ...' and 'What would
    refute ...' items, because the work order asked for both with nowhere to put them. They are
    now fields of the claim they belong to, and staging carries them into its interpretation."""
    from _audit_rows import cite_rows

    case = _case(tmp_path)
    aid = cite_rows(case, [{"loc": "hayabusa/evtx-timeline.csv:58385", "host": "rd01",
                            "detail": "RuleTitle: Antivirus - Exploitation Framework Signature"}])
    m3._persist_state(case, "M2-alt", {
        "run_id": "M2-alt", "case_id": case.name, "question": "q", "status": "completed",
        "orders": [], "order_index": 0, "results": [], "verdicts": [], "gaps": [],
        "candidates": [{
            "title": "CobaltStrike detection is a true positive", "observation": "10 x 1116",
            "interpretation": "beacon on rd01", "confidence": "LOW", "audit_ids": [aid],
            "benign_alternative": "authorized adversary simulation",
            "refutation": "an engagement record covering 2023-01-24"}],
    })
    result = m3.stage_run_candidates(case, "M2-alt")
    assert result["staged_count"] == 1
    draft = next(f for f in json.loads((case / "findings.json").read_text(encoding="utf-8"))
                 if f.get("run_id") == "M2-alt")
    assert "Benign alternative weighed: authorized adversary simulation" in draft["interpretation"]
    assert "What would refute it: an engagement record covering 2023-01-24" in draft["interpretation"]


def test_the_worker_contract_puts_the_alternative_and_refutation_inside_the_candidate():
    contract = m3.ROLES["evidence"].system_prompt
    assert '"benign_alternative":"...","refutation":"..."' in contract
    assert "never as candidates of their own" in contract


def _audited_rows(case: Path, rows: list[dict]) -> str:
    from nexus.audit import AuditWriter

    aid = AuditWriter("nexus", audit_dir=case / "audit").log(
        tool="es_search", params={"case_id": case.name, "query": {"match_all": {}}},
        result_summary={"total": len(rows), "evidence_rows": rows})
    assert aid
    return aid


LOGON_ROWS = [{"source": "evtxecmd/Security.csv", "artifact": "Security.csv", "loc": "Security.csv:41",
               "host": "ws01", "user": "corp\\jdoe", "detail": "EventId 4624 LogonType 10 corp\\jdoe"}]


def test_a_re_worded_claim_on_the_same_rows_keeps_one_verdict(tmp_path):
    """D189: verdicts were keyed by title, and follow-up rounds re-word titles. Mode 2 run 3's 16
    verdicts held one claim six times with different classes, and synthesis read six claims."""
    case = _case(tmp_path)
    first_call = _audited_rows(case, LOGON_ROWS)
    second_call = _audited_rows(case, LOGON_ROWS)  # a follow-up query returning the same row
    rounds = {"n": 0}

    def fake_work(order, *, case_dir, model, run_id, sink, agent_id="", context=None):
        if order.role == "verifier":
            parsed = {"verdicts": [{"title": c["title"],
                                    "class": "confirmed" if rounds["n"] > 1 else "inferred",
                                    "basis": "b", "audit_ids": c["audit_ids"]}
                                   for c in context["candidates"]]}
        elif order.role == "synthesis":
            parsed = {"narrative": "n", "findings": [], "gaps": [], "coverage": {}}
        else:
            rounds["n"] += 1
            title, cited = (("RDP logon by jdoe", first_call) if rounds["n"] == 1
                            else ("Remote interactive logon by corp\\jdoe confirmed", second_call))
            parsed = {"notes": [], "coverage": {}, "candidate_findings": [{
                "title": title, "observation": "o", "interpretation": "i",
                "confidence": "LOW", "audit_ids": [cited]}]}
        return m3.AgentResult(order_id=order.order_id, role=order.role, status="ok",
                              reply=json.dumps(parsed), parsed=parsed, audit_id="ctx-1")

    with patch.object(m3, "run_work_order", side_effect=fake_work), \
         patch.object(m3, "plan_work_orders", return_value=[m3.WorkOrder(
             order_id="wo-1", role="evidence", task="t", family="evtxecmd")]):
        state = m3.run_mode2(case, "what happened", model=object(), es_ok=True)

    assert rounds["n"] >= 2
    assert len(state["verdicts"]) == 1, state["verdicts"]
    assert state["verdicts"][0]["class"] == "confirmed"


def test_staging_finds_the_verdict_of_a_re_worded_claim_by_its_rows(tmp_path):
    """D189: synthesis re-words titles; a refuted claim looked up by title was staged anyway."""
    case = _case(tmp_path)
    cited = _audited_rows(case, LOGON_ROWS)
    claim = m3._claim_keys(case, [{"title": "RDP logon by jdoe", "audit_ids": [cited]}])[0]
    m3._persist_state(case, "M2-claim", {
        "run_id": "M2-claim", "case_id": case.name, "question": "q", "status": "completed",
        "orders": [], "order_index": 0, "results": [], "gaps": [],
        "verdicts": [{"title": "RDP logon by jdoe", "class": "refuted", "basis": "b",
                      "audit_ids": [cited], "claim_key": claim}],
        "candidates": [{"title": "Interactive remote logon by corp\\jdoe", "observation": "o",
                        "interpretation": "i", "confidence": "LOW",
                        "confidence_justification": "one query", "audit_ids": [cited]}],
    })
    result = m3.stage_run_candidates(case, "M2-claim")
    assert result["staged_count"] == 0, result
    assert result["skipped"] == [{"title": "Interactive remote logon by corp\\jdoe",
                                  "reason": "verifier refuted"}]


def test_synthesis_keeps_the_alternative_and_refutation_of_the_claims_it_merges(tmp_path):
    """D203: Mode 2 run 6's workers carried each claim's benign alternative and refutation test
    (D190), and 0 of synthesis's 5 candidates did, so staging had nothing to append."""
    case = _case(tmp_path)
    worker_claim = {"title": "Task runs SRLUpdate.exe", "observation": "o", "interpretation": "i",
                    "confidence": "LOW", "audit_ids": ["a-1"],
                    "benign_alternative": "an IT maintenance task",
                    "refutation": "a signed vendor binary with a deployment record"}

    def fake_work(order, *, case_dir, model, run_id, sink, agent_id="", context=None):
        if order.role == "verifier":
            parsed = {"verdicts": [{"title": c["title"], "class": "confirmed", "basis": "b",
                                    "audit_ids": c["audit_ids"]} for c in context["candidates"]]}
        elif order.role == "synthesis":
            parsed = {"narrative": "n", "gaps": [], "coverage": {}, "findings": [{
                "title": "Cobalt Strike anchored to a scheduled task", "observation": "o",
                "interpretation": "i", "confidence": "MEDIUM", "audit_ids": ["a-1", "a-2"]}]}
        else:
            parsed = {"notes": [], "candidate_findings": [worker_claim], "coverage": {}}
        return m3.AgentResult(order_id=order.order_id, role=order.role, status="ok",
                              reply=json.dumps(parsed), parsed=parsed, audit_id="ctx-1")

    with patch.object(m3, "run_work_order", side_effect=fake_work), \
         patch.object(m3, "plan_work_orders", return_value=[m3.WorkOrder(
             order_id="wo-1", role="evidence", task="t", family="evtxecmd")]):
        state = m3.run_mode2(case, "what happened", model=object(), es_ok=True)

    (final,) = state["candidates"]
    assert final["benign_alternative"] == "an IT maintenance task"
    assert final["refutation"] == "a signed vendor binary with a deployment record"


def test_a_final_candidate_absorbs_only_claims_whose_every_call_it_cites():
    finals = [{"title": "merged", "audit_ids": ["a-1", "a-2"], "refutation": "kept"}]
    sources = [{"audit_ids": ["a-1"], "benign_alternative": "alt one", "refutation": "ref one"},
               {"audit_ids": ["a-2"], "benign_alternative": "alt two"},
               {"audit_ids": ["a-2", "a-9"], "benign_alternative": "not absorbed"}]
    assert m3._carry_claim_tests(finals, sources) == 1
    assert finals[0]["benign_alternative"] == "alt one\nalt two"
    assert finals[0]["refutation"] == "kept"


def test_a_merged_finding_cites_the_calls_of_the_claims_it_names(tmp_path):
    """D225: DRAFT 045's task facts came from a Task Scheduler query its synthesis did not cite; a
    finding cited fewer calls than the claims it merged rest on."""
    case = _case(tmp_path)
    task_claim = {"title": "Task SRL User Maintenance launches SRLUpdate.exe", "observation": "o",
                  "interpretation": "i", "confidence": "MEDIUM", "audit_ids": ["a-task"],
                  "severity": "HIGH", "benign_alternative": "an IT maintenance task"}
    detection_claim = {"title": "Defender CobaltStrike detections on SRLUpdate.exe", "observation": "o",
                       "interpretation": "i", "confidence": "HIGH", "audit_ids": ["a-defender"]}
    seen: dict = {}

    def fake_work(order, *, case_dir, model, run_id, sink, agent_id="", context=None):
        if order.role == "verifier":
            parsed = {"verdicts": [{"title": c["title"], "class": "confirmed", "basis": "b",
                                    "audit_ids": c["audit_ids"]} for c in context["candidates"]]}
        elif order.role == "synthesis":
            seen["task"] = order.task
            parsed = {"narrative": "n", "gaps": [], "coverage": {}, "findings": [{
                "title": "Scheduled-task persistence for the beacon", "observation": "o",
                "interpretation": "i", "confidence": "MEDIUM", "audit_ids": ["a-defender"],
                "merges": ["C1", "C2"]}]}
        else:
            parsed = {"notes": [], "candidate_findings": [task_claim, detection_claim], "coverage": {}}
        return m3.AgentResult(order_id=order.order_id, role=order.role, status="ok",
                              reply=json.dumps(parsed), parsed=parsed, audit_id="ctx-1")

    with patch.object(m3, "run_work_order", side_effect=fake_work), \
         patch.object(m3, "plan_work_orders", return_value=[m3.WorkOrder(
             order_id="wo-1", role="evidence", task="t", family="evtxecmd")]):
        state = m3.run_mode2(case, "what happened", model=object(), es_ok=True)

    assert '"candidate_id": "C1"' in seen["task"] and '"candidate_id": "C2"' in seen["task"]
    (final,) = state["candidates"]
    assert final["audit_ids"] == ["a-defender", "a-task"]
    assert final["severity"] == "HIGH" and final["benign_alternative"] == "an IT maintenance task"


def test_synthesis_is_asked_for_a_severity_and_the_claims_it_merges():
    contract = m3.ROLES["synthesis"].system_prompt
    assert '"severity":"LOW|MEDIUM|HIGH|CRITICAL"' in contract and '"merges":["<candidate_id>"]' in contract
