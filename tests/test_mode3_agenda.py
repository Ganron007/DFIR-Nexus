"""D208: Mode 3 settles when its open questions and pivots are settled, not only at its budget.

Mode 3 run 1 (CASE-C5B04D31, 2026-10-15) raised 95 open questions. A question closed only when a
seat was spawned with its exact wording, at most five a superstep, so 73 were open at the cap; and
every claimed entity stayed a pivot, none seated after superstep 2, because the set of entities
later seats picked up was built and discarded.
"""
from __future__ import annotations

import json
from pathlib import Path

import yaml


def _case(tmp_path: Path) -> Path:
    case = tmp_path / "CASE-M3AGENDA"
    ext = case / "runs" / "RUN-1" / "extractions"
    ext.mkdir(parents=True)
    (ext / "a.csv").write_text("x\n1\n", encoding="utf-8")
    (ext / "_tool_lane_ledger.json").write_text(json.dumps([{"tool": "hayabusa", "status": "OK"}]),
                                                encoding="utf-8")
    (case / "CASE.yaml").write_text(yaml.safe_dump({"case_id": case.name, "status": "created"}),
                                    encoding="utf-8")
    (case / "analysis").mkdir(exist_ok=True)
    return case


def _entry(agent: str, step: int, **fields) -> dict:
    return {"entry_id": f"{agent}-{step}", "agent_id": agent, "role": "evidence", "family": "",
            "superstep": step, "claims": [], "open_questions": [], **fields}


def _on(kind: str, value: str) -> dict:
    return {"claim_kind": "presence", "polarity": "affirm",
            "subject": {"type": kind, "value": value, "category": "other"}}


Q1, Q2, Q3, Q4 = ("What wrote SRLUpdate.exe?", "Is rd01 the same host as rd01.shieldbase.com?",
                  "Who ran STUN.exe?", "What did dc01 log at 15:51?")


def test_a_question_closes_with_a_seats_disposition():
    from nexus.modes.multi_agent import _question_ledger, question_id

    board = [
        _entry("seat-a", 1, open_questions=[Q1, Q2, Q3, Q4]),
        _entry("seat-b", 2, question_dispositions=[
            {"question": question_id(Q1), "status": "answered", "basis": "the MFT creator",
             "audit_ids": ["a-1"]},
            {"question": f"[{question_id(Q2).lower()}]", "status": "duplicate", "basis": "repeats Q1"},
            {"question": question_id(Q3), "status": "answered", "basis": "no call cited", "audit_ids": []},
            {"question": Q4, "status": "unanswerable", "basis": "dc01 is not in the evidence"},
        ]),
    ]
    ledger = _question_ledger(board)
    assert {item["text"]: item["status"] for item in ledger.values()} == {
        Q1: "answered", Q2: "duplicate", Q3: "open", Q4: "unanswerable"}, "an answer cites its calls"


def test_a_seat_that_never_answered_settles_nothing():
    from nexus.modes.multi_agent import _question_ledger, question_id

    settle = [{"question": question_id(Q1), "status": "answered", "basis": "x", "audit_ids": ["a-1"]}]
    board = [
        _entry("seat-a", 1, open_questions=[Q1]),
        _entry("seat-b", 2, question_id=question_id(Q1), finish_reason="model_error"),
        _entry("seat-c", 2, evidence_attempted=True, evidence_read=False, question_dispositions=settle),
    ]
    assert _question_ledger(board)[question_id(Q1)]["status"] == "open"
    board.append(_entry("seat-d", 3, question_id=question_id(Q1), finish_reason="answer"))
    assert _question_ledger(board)[question_id(Q1)]["status"] == "investigated"


def test_a_pivot_closes_when_a_later_superstep_works_on_its_entity():
    from nexus.modes.multi_agent import _pivot_entities

    board = [
        _entry("seat-a", 1, claims=[_on("process", "STUN.exe"), _on("file", "c:/windows/srlupdate.exe")]),
        _entry("seat-b", 1, claims=[_on("process", "stun.exe")]),
    ]
    assert {p["entity_value"] for p in _pivot_entities(board)} == {"stun.exe", "c:/windows/srlupdate.exe"}, \
        "a seat of the same superstep never saw the entity on the board"
    board.append(_entry("seat-c", 2, claims=[_on("process", "stun.exe")]))
    assert {p["entity_value"] for p in _pivot_entities(board)} == {"c:/windows/srlupdate.exe"}
    board.append(_entry("seat-d", 2, pivot_entity={"entity_type": "file",
                                                   "entity_value": "C:/Windows/SRLUpdate.exe"}))
    assert _pivot_entities(board) == []


def test_questions_and_pivots_take_turns_for_seats():
    from nexus.modes.multi_agent import _spawns_for_agenda, question_id

    texts = [f"question {n}?" for n in range(10)]
    agenda = {"leads": [],
              "questions": [{"id": question_id(t), "text": t} for t in texts],
              "pivots": [{"entity_type": "process", "entity_value": f"p{n}.exe", "why": "x"} for n in range(10)]}
    spawns = _spawns_for_agenda(agenda, [], max_agents=6, question="Compromise suspected.", superstep=3)
    assert ["q" if s.get("question_ids") else "p" for s in spawns] == ["q", "p", "q", "p", "q", "p"]
    # D222: the question seats share out every open question, so none waits for a seat of its own.
    shares = [s["question_ids"] for s in spawns if s.get("question_ids")]
    assert shares[0] == [question_id(texts[n]) for n in (0, 3, 6, 9)]
    assert sorted(q for share in shares for q in share) == sorted(question_id(t) for t in texts)
    assert f"- {question_id(texts[0])}: question 0?" in spawns[0]["question"]


def _settling_seat(raised: list[str]):
    """Superstep 1 raises twelve questions; a later seat settles every open one it reads on the board.

    A seat's work can answer more than the question it was spawned for, and it says so by id; the
    board view the seat reads lists each open question with its id.
    """
    from nexus.modes.multi_agent import question_id

    def seat(spawn, _board, step):
        entry = _entry(f"{spawn['role']}-{step}-{len(raised)}", step, role=spawn["role"],
                       family=spawn.get("family") or "", finish_reason="answer")
        if step == 1:
            entry["open_questions"] = [f"Which process wrote dropped file {n}?" for n in range(12)]
            raised.extend(entry["open_questions"])
        else:
            entry["question_dispositions"] = [
                {"question": question_id(text), "status": "unanswerable" if n % 4 == 0 else "answered",
                 "basis": "a host this case does not hold" if n % 4 == 0 else "the USN creator rows",
                 "audit_ids": [] if n % 4 == 0 else ["a-usn"]}
                for n, text in enumerate(raised)]
        return entry
    return seat


def test_the_run_settles_once_its_questions_are_settled(tmp_path, monkeypatch):
    """Twelve questions and three seats a superstep: settling by dispatch alone took four more
    supersteps than the budget allows."""
    from nexus.modes.multi_agent import run_mode3

    monkeypatch.setenv("NEXUS_MODE3_MAX_AGENTS", "3")
    monkeypatch.setenv("NEXUS_MODE3_MAX_SUPERSTEPS", "4")
    record = run_mode3(_case(tmp_path), "Compromise suspected.", families=[("hayabusa", 10)],
                       seat_fn=_settling_seat([]), es_ok=True)
    assert record["stop_reason"] == "settled", (record["stop_reason"], record["open_agenda"])
    assert record["superstep"] == 2
    assert record["open_agenda"] == {"questions": [], "leads": [], "pivots": [], "verification": []}
    statuses = sorted(item["status"] for item in record["question_dispositions"].values())
    assert statuses == ["answered"] * 9 + ["unanswerable"] * 3
    assert sum("not answerable from this evidence" in gap for gap in record["gaps"]) == 3


def test_a_capped_run_names_what_kept_it_open(tmp_path, monkeypatch):
    from nexus.modes.multi_agent import run_mode3

    monkeypatch.setenv("NEXUS_MODE3_MAX_AGENTS", "3")
    monkeypatch.setenv("NEXUS_MODE3_MAX_SUPERSTEPS", "1")

    def seat(spawn, _board, step):
        return _entry(f"{spawn['role']}-{step}-{spawn.get('family')}", step,
                      finish_reason="answer", coverage_gaps=["no proxy or DNS logs were collected"],
                      open_questions=[f"Which process wrote dropped file {n}?" for n in range(8)])

    case = _case(tmp_path)
    record = run_mode3(case, "Compromise suspected.", families=[("hayabusa", 10)], seat_fn=seat, es_ok=True)
    assert record["stop_reason"] == "budget: max supersteps"
    assert len(record["open_agenda"]["questions"]) == 8, "raised in the last superstep, never seated"
    assert all(q["id"].startswith("Q") and q["text"] for q in record["open_agenda"]["questions"])
    assert any("no proxy or DNS logs were collected" in gap for gap in record["gaps"])
    events = [json.loads(line) for line in (case / "analysis" / "mode3_runs" / f"{record['run_id']}.jsonl")
              .read_text(encoding="utf-8").splitlines()]
    decision = [e for e in events if e["event_type"] == "join.decision"]
    assert decision and decision[0]["data"]["open_questions"] == 8


def test_a_resumed_run_does_not_requeue_what_its_seats_settled(tmp_path):
    """Join kept the settled questions and pivots in graph state, which a resume did not restore."""
    from nexus.modes.multi_agent import question_id, run_mode3

    spawned: list[dict] = []

    def seat(spawn, _board, step):
        spawned.append(spawn)
        return _entry(f"{spawn['role']}-{step}", step, finish_reason="answer")

    resume = {"board": [_entry("seat-a", 1, open_questions=[Q1], finish_reason="answer"),
                        _entry("seat-b", 2, question_id=question_id(Q1), finish_reason="answer")],
              "superstep": 2, "quiet": 0, "redispatch_used": 0, "steering_seen": 0}
    record = run_mode3(_case(tmp_path), "Compromise suspected.", families=[("hayabusa", 10)],
                       seat_fn=seat, es_ok=True, resume_state=resume)
    assert not [s for s in spawned if s.get("question_id")], spawned
    assert record["question_dispositions"][question_id(Q1)]["status"] == "investigated"


class _Content:
    def __init__(self, text: str) -> None:
        self.content = text


class _ProseThenJsonModel:
    """Answers the seat loop in prose; the corrective re-prompt gets the schema back."""

    model_name = "scripted-seat"
    provider = "test"

    def __init__(self) -> None:
        self.sent: list[str] = []

    def invoke(self, messages):
        blob = "\n".join(str(m.get("content") or "") for m in messages)
        self.sent.append(blob)
        if "Your previous reply was not the JSON object" in blob:
            return _Content(json.dumps({
                "claims": [], "open_questions": ["Which account created the task?"],
                "coverage_gaps": ["no Sysmon EID 1 rows in the evidence"],
                "question_dispositions": [{"question": "Qabcdef", "status": "duplicate", "basis": "Q123456"}],
                "lead_disposition": {"lead": "Defender Alert (Severe)", "status": "benign",
                                     "basis": "the responder's tool"}}))
        return _Content("I looked at the detections and they are the responder's tooling.")


def test_the_seat_is_told_what_an_open_question_is_and_its_retry_keeps_its_fields(tmp_path, monkeypatch):
    from nexus.modes.multi_agent import _seat_with_model

    monkeypatch.setenv("NEXUS_MODE3_ROUNDS", "1")
    monkeypatch.setenv("NEXUS_MODE3_CALLS", "2")
    monkeypatch.setenv("NEXUS_MODE3_SECONDS", "60")
    model = _ProseThenJsonModel()

    class _Sink:
        def emit(self, event):
            return None

    entry = _seat_with_model(
        {"role": "evidence", "family": "", "why": "open question from a seat",
         "question": "Compromise suspected.\nA seat asked: What wrote SRLUpdate.exe?",
         "question_id": "Q1a2b3c", "lead": "Defender Alert (Severe)"},
        case_dir=_case(tmp_path), model=model, run_id="M3-agenda", sink=_Sink(),
        board_digest="(empty)", superstep=2)
    first = model.sent[0]
    assert "indexed evidence can answer" in first and '"coverage_gaps"' in first
    assert "You were spawned for open question Q1a2b3c" in first
    assert entry.get("corrective_retry_used")
    assert entry["lead_disposition"]["status"] == "benign", "the retry's disposition is the seat's answer"
    assert entry["coverage_gaps"] == ["no Sysmon EID 1 rows in the evidence"]
    assert entry["question_dispositions"][0]["status"] == "duplicate"
    assert entry["open_questions"] == ["Which account created the task?"]


def test_question_seats_share_out_every_open_question_and_the_run_settles(tmp_path, monkeypatch):
    """D222: one question per seat and three seats a superstep left Mode 3 run 3 at its cap with 17 open.
    Twelve questions raised in superstep 1 are all seated in superstep 2, and each seat settles its share."""
    from nexus.modes.multi_agent import run_mode3

    monkeypatch.setenv("NEXUS_MODE3_MAX_AGENTS", "3")
    monkeypatch.setenv("NEXUS_MODE3_MAX_SUPERSTEPS", "3")
    shares: list[list[str]] = []

    def seat(spawn, _board, step):
        entry = _entry(f"{spawn['role']}-{step}-{len(shares)}", step, role=spawn["role"], finish_reason="answer")
        if step == 1:
            entry["open_questions"] = [f"Which process wrote dropped file {n}?" for n in range(12)]
        if spawn.get("question_ids"):
            shares.append(list(spawn["question_ids"]))
            entry["question_dispositions"] = [{"question": q, "status": "unanswerable",
                                               "basis": "a host this case does not hold"}
                                              for q in spawn["question_ids"]]
        return entry

    record = run_mode3(_case(tmp_path), "Compromise suspected.", families=[("hayabusa", 10)], seat_fn=seat,
                       es_ok=True)
    assert sorted(len(s) for s in shares) == [4, 4, 4]
    assert record["stop_reason"] == "settled", (record["stop_reason"], record["open_agenda"])
    assert record["superstep"] == 2
