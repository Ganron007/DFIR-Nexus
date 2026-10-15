"""D231 and D222: a Mode 3 seat is given one output contract, and a restated question is not a new one.

Mode 3 run 2 (CASE-C5B04D31, 2026-10-15) sent every seat three return formats: the context loop's
{"answer": ...} envelope, Mode 2's role schema (notes / candidate_findings / next_questions) in the
system message, and the seat's own claims object. 17 of its 51 claim seats answered in prose, an
answer envelope or notes, and their question dispositions were lost. Its verifier seats ran as
evidence agents. And 23 of the 79 questions its seats raised restated an open one by id, each
opening a new question, so 41 were open at the superstep cap.
"""
from __future__ import annotations

import json
from pathlib import Path

import yaml


def _case(tmp_path: Path) -> Path:
    case = tmp_path / "CASE-M3CONTRACT"
    ext = case / "runs" / "RUN-1" / "extractions"
    ext.mkdir(parents=True)
    (ext / "a.csv").write_text("x\n1\n", encoding="utf-8")
    (ext / "_tool_lane_ledger.json").write_text(json.dumps([{"tool": "hayabusa", "status": "OK"}]),
                                                encoding="utf-8")
    (case / "CASE.yaml").write_text(yaml.safe_dump({"case_id": case.name, "status": "created"}),
                                    encoding="utf-8")
    (case / "analysis").mkdir(exist_ok=True)
    return case


class _Content:
    def __init__(self, text: str) -> None:
        self.content = text


class _RecordingModel:
    """Answers each call with the next reply and keeps the messages it was sent."""

    model_name = "scripted-seat"
    provider = "test"

    def __init__(self, *replies: str) -> None:
        self.replies = list(replies)
        self.sent: list[list[dict]] = []

    def invoke(self, messages):
        self.sent.append([dict(m) for m in messages])
        return _Content(self.replies[min(len(self.sent) - 1, len(self.replies) - 1)])


class _Sink:
    def emit(self, event):
        return None


def _seat(tmp_path, monkeypatch, spawn: dict, *replies: str):
    from nexus.modes.multi_agent import _seat_with_model

    monkeypatch.setenv("NEXUS_MODE3_ROUNDS", "3")
    monkeypatch.setenv("NEXUS_MODE3_CALLS", "2")
    monkeypatch.setenv("NEXUS_MODE3_SECONDS", "60")
    model = _RecordingModel(*replies)
    entry = _seat_with_model(spawn, case_dir=_case(tmp_path), model=model, run_id="M3-contract",
                             sink=_Sink(), board_digest="(empty)", superstep=2)
    return entry, model


def _messages(call: list[dict]) -> tuple[str, str]:
    system = next(m["content"] for m in call if m["role"] == "system")
    user = next(m["content"] for m in call if m["role"] == "user")
    return system, user


SEAT_REPLY = json.dumps({"claims": [], "open_questions": [],
                         "question_dispositions": [{"question": "Q1a2b3c", "status": "unanswerable",
                                                    "basis": "the host is not in this case"}]})


def test_a_claim_seat_is_given_one_return_format(tmp_path, monkeypatch):
    entry, model = _seat(tmp_path, monkeypatch, {
        "role": "evidence", "family": "", "why": "open question from a seat", "question_id": "Q1a2b3c",
        "question": "Compromise suspected.\nA seat asked: what did dc01 log?"}, SEAT_REPLY)
    system, user = _messages(model.sent[0])
    assert "You are an evidence agent" in system
    for mode2_key in ('"notes"', '"candidate_findings"', '"next_questions"'):
        assert mode2_key not in system, f"Mode 2's {mode2_key} reached a Mode 3 seat"
    assert '{"answer":"...","citations"' not in user
    assert 'To answer: return the JSON object the task defines (with its "claims"' in user
    assert len(model.sent) == 1, "a seat object with no new claim is still the seat's answer"
    assert entry["question_dispositions"][0]["status"] == "unanswerable"
    assert not entry.get("corrective_retry_used")


def test_the_verifier_seat_runs_as_the_verifier(tmp_path, monkeypatch):
    from nexus.modes.multi_role import ROLES

    _entry, model = _seat(tmp_path, monkeypatch, {
        "role": "verifier", "family": "", "why": "verify 2 new claim(s) from superstep 1",
        "question": "Compromise suspected.\nRe-check these claims: process=c:\\windows\\srlupdate.exe"},
        json.dumps({"verdicts": []}))
    system, user = _messages(model.sent[0])
    assert "You are the verifier" in system and "evidence agent" not in system
    allow = next(line for line in system.splitlines() if line.startswith("ROLE TOOL ALLOWLIST"))
    assert allow == "ROLE TOOL ALLOWLIST: " + ", ".join(ROLES["verifier"].tools) + \
        ". Any other tool is rejected by the runtime."
    assert '"verdicts"' in user and '{"answer":"...","citations"' not in user


def test_the_retry_asks_for_the_whole_seat_object_and_both_replies_are_kept(tmp_path, monkeypatch):
    prose = "The detections are the responder's tooling; nothing further to check."
    entry, model = _seat(tmp_path, monkeypatch, {
        "role": "evidence", "family": "hayabusa", "why": "unexplained high lead",
        "question": "Compromise suspected.\nInvestigate the lead: Defender Alert (Severe)",
        "lead": "Defender Alert (Severe)"}, prose, json.dumps({
            "claims": [], "coverage_gaps": ["no Sysmon EID 1 rows in the evidence"],
            "lead_disposition": {"lead": "Defender Alert (Severe)", "status": "benign",
                                 "basis": "the responder's tool"}}))
    system, retry = _messages(model.sent[-1])
    assert "You are an evidence agent" in system and '"notes"' not in system
    assert '"question_dispositions"' in retry and '"coverage_gaps"' in retry and '"lead_disposition"' in retry
    assert entry["corrective_retry_used"]
    assert entry["lead_disposition"]["status"] == "benign"
    assert entry["reply_excerpt"].startswith(prose)
    assert '"benign"' in entry["corrected_excerpt"]


def test_a_loop_without_a_task_object_keeps_the_answer_envelope(tmp_path, monkeypatch):
    from nexus.langgraph.context_loop import LoopBudget, run_context_loop

    model = _RecordingModel(json.dumps({"answer": "nothing to report"}))
    case = _case(tmp_path)
    run_context_loop(case_dir=case, case_id=case.name, question="What ran?", model=model,
                     budget=LoopBudget(rounds=1, seconds=60, calls=1, call_chars=0))
    _system, user = _messages(model.sent[0])
    assert 'To answer: {"answer":"...","citations"' in user
    assert 'FINAL ROUND: do NOT call another tool. Return {"answer":"..."} now' in user


def test_the_final_round_names_the_task_object(tmp_path, monkeypatch):
    from nexus.langgraph.context_loop import LoopBudget, run_context_loop

    model = _RecordingModel(json.dumps({"queries": []}))
    case = _case(tmp_path)
    loop = run_context_loop(case_dir=case, case_id=case.name, question="Plan the hunt.", model=model,
                            budget=LoopBudget(rounds=1, seconds=60, calls=1, call_chars=0),
                            terminal_keys=("queries", "aggregations"))
    _system, user = _messages(model.sent[0])
    assert 'To answer: {"answer"' not in user
    assert 'To answer: return the JSON object the task defines' in user
    assert 'FINAL ROUND: do NOT call another tool. Return the JSON object the task defines ' \
           '(with its "queries" / "aggregations" key)' in user
    assert loop["finish_reason"] == "answer_terminal"


# Verbatim from Mode 3 run 2's board: the question as raised in superstep 4, then as two seats
# restated it in supersteps 8 and 9.
RAISED = ("Can the absence of sextortion-related URLs in browser history be distinguished from a collection "
          "gap (browser profile not collected, or history cleared) rather than true absence of browser "
          "interaction with the sextortion emails?")
RESTATED = [
    "Q8ce78f remains open: the absence of sextortion URLs in browser history is based on 1886 parsed "
    "HistoryVisits rows; if the user opened a sextortion email link in InPrivate/Incognito mode or cleared "
    "history between the sextortion window and acquisition, the browser-layer evidence would be incomplete. "
    "The sqlecmd parser ran and captured all retained history, but Incognito residue (cache/cookies/sessions) "
    "was not separately enumerated.",
    "Q8ce78f: Can the absence of sextortion URLs in browser history be distinguished from a collection gap "
    "(InPrivate/Incognito mode, history cleared between sextortion window and acquisition)? The 1886 "
    "HistoryVisits rows represent retained history; Incognito cache/cookie/session residue was not "
    "separately enumerated.",
]


def _entry(agent: str, step: int, **fields) -> dict:
    return {"entry_id": f"{agent}-{step}", "agent_id": agent, "role": "evidence", "family": "",
            "superstep": step, "claims": [], "open_questions": [], **fields}


def test_a_question_restated_by_its_id_is_the_same_question():
    from nexus.modes.multi_agent import _question_ledger, question_id

    assert question_id(RAISED) == "Q8ce78f"
    board = [_entry("seat-a", 4, open_questions=[RAISED]),
             _entry("seat-b", 8, open_questions=[RESTATED[0]]),
             _entry("seat-c", 9, open_questions=[RESTATED[1], "Q0f00ba: a question naming no board id"])]
    ledger = _question_ledger(board)
    assert sorted(ledger) == sorted(["Q8ce78f", question_id("Q0f00ba: a question naming no board id")])
    board.append(_entry("seat-d", 10, question_dispositions=[
        {"question": "Q8ce78f", "status": "unanswerable", "basis": "private browsing leaves no history row"}]))
    assert _question_ledger(board)["Q8ce78f"]["status"] == "unanswerable"


def test_a_run_stopped_at_its_budget_records_the_roles_that_worked(tmp_path, monkeypatch):
    from nexus.modes.multi_agent import run_mode3

    monkeypatch.setenv("NEXUS_MODE3_MAX_AGENTS", "2")
    monkeypatch.setenv("NEXUS_MODE3_MAX_SUPERSTEPS", "1")

    def seat(spawn, _board, step):
        return _entry(f"{spawn['role']}-{step}", step, role=spawn["role"], finish_reason="answer",
                      open_questions=["Which account created the task?"])

    record = run_mode3(_case(tmp_path), "Compromise suspected.", families=[("hayabusa", 10)],
                       seat_fn=seat, es_ok=True)
    assert record["stop_reason"] == "budget: max supersteps"
    assert record["roles_used"] and record["roles_used"] == sorted({e["role"] for e in record["board"]})


def test_a_seats_severity_reaches_the_draft_and_an_unrated_claim_stays_unrated(tmp_path):
    """D227: Mode 3 DRAFTs carried no severity because seats were never asked for one."""
    from nexus.audit import AuditWriter
    from nexus.modes.multi_agent import _persist, settled_candidates, stage_mode3

    case = _case(tmp_path)
    (case / "audit").mkdir(exist_ok=True)
    audit_id = AuditWriter("nexus", audit_dir=case / "audit").log(
        tool="es_search", params={"family": "evtxecmd", "query": {"match": {"event_id": "129"}}},
        result_summary={"total": 1}, source="portal")
    claim = {"entity_type": "process", "entity_value": "SRLUpdate.exe", "claim_kind": "presence",
             "polarity": "affirm", "value": "launched by the task SRL User Maintenance",
             "audit_ids": [audit_id], "confidence": "MEDIUM", "confidence_justification": "event 129 cited"}
    board = [_entry("seat-a", 1, claims=[{**claim, "severity": "high"},
                                         {**claim, "entity_value": "svchost.exe", "value": "a service host"}])]
    candidates, _gaps = settled_candidates(board, [], case_dir=case)
    assert [c["severity"] for c in candidates] == ["HIGH", ""]
    _persist(case, "M3-severity", {"run_id": "M3-severity", "case_id": case.name, "question": "q",
                                   "status": "completed", "product_mode": "multi-agent", "board": board,
                                   "disputes": [], "candidates": candidates, "gaps": []})
    assert stage_mode3(case, "M3-severity")["staged_count"] == 2
    drafts = [f for f in json.loads((case / "findings.json").read_text(encoding="utf-8"))
              if f.get("run_id") == "M3-severity"]
    assert sorted(str(f.get("severity") or "").upper() for f in drafts) == ["", "HIGH"]


def test_the_seat_is_asked_to_rate_its_claims(tmp_path, monkeypatch):
    _entry, model = _seat(tmp_path, monkeypatch, {
        "role": "evidence", "family": "evtxecmd", "why": "domain seat",
        "question": "Compromise suspected."}, json.dumps({"claims": []}))
    _system, user = _messages(model.sent[0])
    assert '"severity":"LOW|MEDIUM|HIGH|CRITICAL"' in user
