"""WO-R1F item 7b — the Mode 3 investigation loop, on a scripted model.

The WO names three behaviours to pin on the graph itself:

* **wave 2 is spawned from wave 1's open questions** (the supervisor re-plans
  every superstep, instead of spawning once at `step == 1`);
* **correlation never runs on an empty board** (it exists to cross-examine what
  the evidence seats reported);
* **the run does not settle while a crit lead is open** (the stop rule is
  dispositions, never "the board was quiet").

`seat_fn` is the graph's test seam: it replaces the model-driven seat, so the
graph mechanics are exercised without a model.
"""

from __future__ import annotations

import json
from pathlib import Path

import yaml
from _audit_rows import cite_rows


def _case(tmp_path: Path, *, leads: list[dict] | None = None) -> Path:
    case = tmp_path / "CASE-M3LOOP1"
    ext = case / "runs" / "RUN-1" / "extractions"
    ext.mkdir(parents=True)
    (ext / "a.csv").write_text("x\n1\n", encoding="utf-8")
    (ext / "_tool_lane_ledger.json").write_text(
        json.dumps([{"tool": "hayabusa", "status": "OK"}]), encoding="utf-8"
    )
    (case / "CASE.yaml").write_text(
        yaml.safe_dump({"case_id": case.name, "status": "created"}), encoding="utf-8"
    )
    (case / "analysis").mkdir(exist_ok=True)
    if leads is not None:
        (case / "analysis" / "leads.jsonl").write_text(
            "\n".join(json.dumps(lead) for lead in leads) + "\n", encoding="utf-8"
        )
    return case


def _claim(entity: str, audit: str = "audit-1") -> dict:
    return {
        "entity_type": "process",
        "entity_value": entity,
        "claim_kind": "presence",
        "polarity": "affirm",
        "value": f"{entity} seen",
        "audit_ids": [audit],
        "confidence": "LOW",
        "confidence_justification": "one source",
    }


def test_wave_two_is_spawned_from_wave_ones_open_questions(tmp_path, monkeypatch):
    """The old shape spawned only at step 1 and then returned `settled`."""
    from nexus.modes.multi_agent import run_mode3

    monkeypatch.setenv("NEXUS_MODE3_MAX_SUPERSTEPS", "4")
    monkeypatch.setenv("NEXUS_MODE3_SETTLE_SUPERSTEPS", "3")
    seen_steps: list[int] = []

    def seat(spawn, _board, step):
        seen_steps.append(step)
        # Wave 1 leaves an open question only the FIRST evidence seat raises, so
        # wave 2 can only exist by re-planning from the board.
        open_q = ["Who launched cmd.exe on ws01?"] if step == 1 else []
        return {
            "entry_id": f"{spawn['role']}-{step}",
            "agent_id": f"{spawn['role']}-{step}",
            "role": spawn["role"],
            "family": spawn.get("family") or "",
            "superstep": step,
            "claims": [_claim("ws01")] if spawn["role"] == "evidence" else [],
            "open_questions": open_q,
        }

    record = run_mode3(
        _case(tmp_path), "compromise suspected",
        families=[("hayabusa", 10)], seat_fn=seat, es_ok=True,
    )
    assert max(seen_steps) >= 2, f"never re-planned: steps {sorted(set(seen_steps))}"
    assert record["superstep"] >= 2


def test_correlation_never_runs_on_an_empty_board(tmp_path, monkeypatch):
    """It runs from superstep 2 — and superstep 1 has no board to correlate."""
    from nexus.modes.multi_agent import _spawns_for_agenda

    spawns = _spawns_for_agenda(
        {"questions": [], "crit_leads": [], "pivots": []},
        [],  # empty board
        max_agents=6, question="q", superstep=2,
    )
    assert not any(s["role"] == "correlation" for s in spawns), spawns
    assert not any(s["role"] == "pattern" for s in spawns), spawns

    # With a board, superstep 2 does add them.
    with_board = _spawns_for_agenda(
        {"questions": [], "crit_leads": [], "pivots": []},
        [{"role": "evidence", "claims": [_claim("ws01")]}],
        max_agents=6, question="q", superstep=2,
    )
    assert any(s["role"] == "correlation" for s in with_board), with_board


def test_a_crit_lead_keeps_the_run_open(tmp_path, monkeypatch):
    """The stop rule is dispositions, never "the board was quiet"."""
    from nexus.modes.multi_agent import run_mode3

    monkeypatch.setenv("NEXUS_MODE3_MAX_SUPERSTEPS", "5")
    monkeypatch.setenv("NEXUS_MODE3_SETTLE_SUPERSTEPS", "1")

    def seat(spawn, _board, step):
        # Claims nothing that dispositions the crit lead.
        return {
            "entry_id": f"{spawn['role']}-{step}",
            "agent_id": f"{spawn['role']}-{step}",
            "role": spawn["role"],
            "family": spawn.get("family") or "",
            "superstep": step,
            "claims": [_claim("unrelated.exe")],
            "open_questions": [],
        }

    # The lead has to come from the lane output. Briefing rebuilds leads.jsonl
    # from the Hayabusa CSV, so a hand-written leads file does not survive.
    case = _case(tmp_path)
    hayabusa = case / "runs" / "RUN-1" / "extractions" / "hayabusa"
    hayabusa.mkdir(parents=True)
    (hayabusa / "evtx-timeline.csv").write_text(
        "RuleTitle,RuleID,Level,Computer,Timestamp,Details\n"
        "Defender Alert (Severe),r1,crit,RD01,2026-01-01T00:00:00Z,x\n",
        encoding="utf-8",
    )
    record = run_mode3(
        case, "compromise suspected",
        families=[("hayabusa", 10)], seat_fn=seat, es_ok=True,
    )
    # The crit lead is never dispositioned, so the run must hit the BUDGET, not
    # settle on quiet.
    assert record["status"] == "completed"
    assert record["superstep"] >= 2, record["superstep"]
    assert "budget" in str(record.get("stop_reason") or ""), record.get("stop_reason")


def test_a_verifier_seat_runs_each_superstep(tmp_path, monkeypatch):
    from nexus.modes.multi_agent import run_mode3

    monkeypatch.setenv("NEXUS_MODE3_MAX_SUPERSTEPS", "2")
    monkeypatch.setenv("NEXUS_MODE3_SETTLE_SUPERSTEPS", "2")
    roles: list[str] = []

    def seat(spawn, _board, step):
        roles.append(spawn["role"])
        return {
            "entry_id": f"{spawn['role']}-{step}",
            "agent_id": f"{spawn['role']}-{step}",
            "role": spawn["role"],
            "family": spawn.get("family") or "",
            "superstep": step,
            "claims": [_claim("ws01")] if spawn["role"] == "evidence" else [],
            "open_questions": [],
            "verdicts": (
                [{"subject": "ws01", "class": "confirmed", "basis": "checked"}]
                if spawn["role"] == "verifier" else []
            ),
        }

    case = _case(tmp_path)
    cite_rows(case, [{"loc": "hayabusa.csv:1", "detail": "the detection row", "process": "ws01"}],
              audit_id="audit-1")
    run_mode3(
        case, "q", families=[("hayabusa", 10)], seat_fn=seat, es_ok=True,
    )
    assert "verifier" in roles, roles


def test_run_record_names_its_budgets_and_real_tool_calls(tmp_path):
    from nexus.modes.multi_agent import run_mode3

    def seat(spawn, _board, step):
        return {
            "entry_id": f"{spawn['role']}-{step}",
            "agent_id": f"{spawn['role']}-{step}",
            "role": spawn["role"],
            "family": spawn.get("family") or "",
            "superstep": step,
            "claims": [_claim("ws01")],
            "open_questions": [],
            "tool_calls_used": 3,
        }

    record = run_mode3(
        _case(tmp_path), "q", families=[("hayabusa", 10)], seat_fn=seat, es_ok=True,
    )
    budgets = record["budgets"]
    # Named honestly: seats are seats, and tool calls are summed from the seats.
    assert budgets["max_seats_per_superstep"] == 6
    assert budgets["max_supersteps"] == 10
    assert "wall_seconds" in budgets
    assert budgets["seats_used"] >= 1
    assert budgets["tool_calls_used"] >= 3


class _Content:
    def __init__(self, content: str) -> None:
        self.content = content


class _ScriptedSeatModel:
    """invoke() model. Terminal JSON, so the real seat loop stops on round 1.

    ``model_name`` is the identity the run record reads (D48), so it carries
    one the way a real LangChain chat model does.
    """

    model_name = "scripted-seat"
    provider = "test"

    def invoke(self, messages):
        blob = "\n".join(str(m.get("content") or "") for m in messages)
        if "verifier seat" in blob or "Re-check these claims" in blob:
            body = {
                "verdicts": [
                    {
                        "subject": "process=notepad.exe",
                        "class": "refuted",
                        "basis": "no such process in the image",
                        "audit_ids": ["audit-v"],
                    },
                    {
                        "subject": "process=beacon.exe",
                        "class": "confirmed",
                        "basis": "named by the detection",
                        "audit_ids": ["audit-v"],
                    },
                ]
            }
        elif "Investigate the lead:" in blob:
            body = {
                "claims": [_claim("beacon.exe", audit="audit-b"), _claim("notepad.exe", audit="audit-n")],
                "open_questions": ["How did beacon.exe persist?"],
                "lead_disposition": {
                    "lead": "Defender Alert (Severe)",
                    "status": "supported",
                    "basis": "crit detection names beacon.exe",
                },
            }
        elif "A seat asked:" in blob or "Pivot on" in blob:
            body = {"claims": [], "open_questions": []}
        else:
            # audit-d is never written: its call stored no rows, so this claim names no subject and the
            # join does not compare it.
            body = {"claims": [_claim("rd01-host", audit="audit-d")], "open_questions": []}
            body["claims"][0]["entity_type"] = "host"
            body["claims"][0]["entity_value"] = "rd01"
        return _Content(json.dumps(body))


def test_seat_with_model_keeps_questions_disposition_and_verdicts(tmp_path, monkeypatch):
    """WO-R1F-M3 items 1-3 and 6 on the production seat, not seat_fn."""
    from nexus.modes.multi_agent import _seat_with_model

    monkeypatch.setenv("NEXUS_MODE3_ROUNDS", "2")
    monkeypatch.setenv("NEXUS_MODE3_CALLS", "4")
    monkeypatch.setenv("NEXUS_MODE3_SECONDS", "60")
    case = _case(tmp_path)
    model = _ScriptedSeatModel()

    class _Sink:
        def emit(self, event):
            return None

    lead = _seat_with_model(
        {
            "role": "evidence",
            "family": "hayabusa",
            "why": "unexplained crit lead",
            "question": "Compromise suspected.\nInvestigate the lead: Defender Alert (Severe)",
            "lead": "Defender Alert (Severe)",
            "lead_extra": {"attack_ids": ["T1059.001"], "level": "crit"},
        },
        case_dir=case,
        model=model,
        run_id="M3-real-seat",
        sink=_Sink(),
        board_digest="(empty)",
        superstep=1,
    )
    assert lead["open_questions"] == ["How did beacon.exe persist?"]
    assert lead["lead_disposition"]["lead"] == "Defender Alert (Severe)"
    assert lead["lead_disposition"]["status"] == "supported"
    assert {c["entity_value"] for c in lead["claims"]} == {"beacon.exe", "notepad.exe"}
    assert isinstance(lead["skill_refs"], list)

    verifier = _seat_with_model(
        {
            "role": "verifier",
            "family": "",
            "why": "verify new claims",
            "question": "Re-check these claims",
        },
        case_dir=case,
        model=model,
        run_id="M3-real-seat",
        sink=_Sink(),
        board_digest="beacon.exe",
        superstep=1,
    )
    classes = {v["subject"]: v["class"] for v in verifier["verdicts"]}
    assert classes.get("process=notepad.exe") == "refuted"
    assert classes.get("process=beacon.exe") == "confirmed"


class _RecordingSeatModel:
    """Answers every seat with an empty claim list and records what it was sent."""

    model_name = "recording-seat"
    provider = "test"

    def __init__(self) -> None:
        self.sent: list[str] = []

    def invoke(self, messages):
        self.sent.append("\n".join(str(m.get("content") or "") for m in messages))
        return _Content(json.dumps({"claims": [], "open_questions": []}))


def test_every_seat_kind_receives_its_task(tmp_path, monkeypatch):
    """D128: each seat kind's model input carries the objective, role, family, board and schema.

    The lead clause was a conditional expression inside a `+` chain, so every seat without a lead
    was sent only the closing sentence. This drives the real seat and the real context loop.
    """
    from nexus.modes.multi_agent import _seat_with_model

    monkeypatch.setenv("NEXUS_MODE3_ROUNDS", "1")
    monkeypatch.setenv("NEXUS_MODE3_CALLS", "2")
    monkeypatch.setenv("NEXUS_MODE3_SECONDS", "60")
    case = _case(tmp_path)

    class _Sink:
        def emit(self, event):
            return None

    objective = "Compromise suspected (seat-kind test)"
    board = "BOARD-MARKER-D128"
    kinds = {
        "lead": {"role": "evidence", "family": "hayabusa", "why": "crit lead", "lead": "Defender Alert"},
        "correlation": {"role": "correlation", "family": "", "why": "cross-family"},
        "pattern": {"role": "pattern", "family": "", "why": "framework check"},
        "memory domain": {"role": "evidence", "family": "vol", "why": "domain seat: memory"},
        "pivot": {"role": "evidence", "family": "", "why": "pivot on a new entity",
                  "pivot_entity": {"entity_type": "process", "entity_value": "probe.exe"}},
        "dispute": {"role": "evidence", "family": "evtxecmd", "why": "dispute probe.exe presence"},
    }
    for kind, spawn in kinds.items():
        model = _RecordingSeatModel()
        _seat_with_model(
            {**spawn, "question": objective}, case_dir=case, model=model, run_id="M3-D128",
            sink=_Sink(), board_digest=board, superstep=1,
        )
        assert model.sent, kind
        first = model.sent[0]
        assert objective in first, kind
        assert board in first, kind
        assert f"You are the {spawn['role']} seat" in first, kind
        assert '"claims"' in first, kind
        assert f"Family: {spawn['family'] or '(cross-family)'}" in first, kind
        # The lead clause belongs to lead seats only.
        assert ("lead_disposition" in first) == bool(spawn.get("lead")), kind


def test_run_record_keeps_settle_blockers_and_role_gaps(tmp_path):
    """D129: what join finds at settlement reaches the run record.

    The case's digest inventory names two populated families and no query ran against either,
    so the real family ledger names both as unexamined. Join used to write them onto its input
    state, which LangGraph discards, and the record's gaps were then overwritten.
    """
    from nexus.modes.multi_agent import run_mode3

    case = _case(tmp_path)
    (case / "analysis" / "case_digest.json").write_text(
        json.dumps({"inventory": {"evtxecmd": 10, "vol": 5}}), encoding="utf-8"
    )

    def seat_fn(spawn, _board, step):
        return {
            "entry_id": f"be-{step}-{spawn.get('family')}",
            "agent_id": f"evidence:{spawn.get('family') or 'x'}:{step}",
            "role": "evidence", "family": spawn.get("family") or "", "superstep": step,
            "claims": [], "open_questions": [], "finish_reason": "final",
            "evidence_read": True, "evidence_attempted": True,
        }

    rec = run_mode3(case, "Compromise suspected.", seat_fn=seat_fn, es_ok=True,
                    families=[("evtxecmd", 10), ("vol", 5)])
    assert rec["status"] == "completed", rec.get("stop_reason")
    assert set(rec["settle_blockers"]) == {"evtxecmd", "vol"}
    gaps = rec["gaps"]
    assert "unexamined artifact family (run-level): vol" in gaps
    assert "unexamined artifact family (run-level): evtxecmd" in gaps
    assert any("never contributed" in g for g in gaps)


def test_a_claim_whose_rows_name_no_subject_is_still_verified(tmp_path):
    """D154: since the join keys on row-derived subjects (2026-10-12), a claim whose cited
    rows name no subject had no key, so the verifier never saw it, yet it still became a
    candidate. It is now verified under its label, and a refutation excludes it."""
    from nexus.modes.multi_agent import run_mode3

    case = _case(tmp_path)
    no_subject = cite_rows(case, [{"loc": "amcache.csv:3", "detail": "an entry with no subject column"}])
    seen_roles: list[str] = []

    def seat(spawn, _board, step):
        role = spawn["role"]
        seen_roles.append(role)
        entry = {"entry_id": f"be-{step}-{role}-{len(seen_roles)}", "agent_id": f"{role}:x:{step}",
                 "role": role, "family": spawn.get("family") or "", "superstep": step,
                 "claims": [], "open_questions": [], "finish_reason": "final",
                 "evidence_read": True, "evidence_attempted": True}
        if role == "verifier":
            assert "file=dropper.dll" in str(spawn.get("question") or "")
            entry["verdicts"] = [{"subject": "file=dropper.dll", "class": "refuted",
                                  "basis": "no such file", "audit_ids": [no_subject]}]
        elif step == 1 and len(seen_roles) == 1:
            entry["claims"] = [{"entity_type": "file", "entity_value": "dropper.dll",
                                "claim_kind": "presence", "polarity": "affirm",
                                "value": "dropper.dll present", "audit_ids": [no_subject],
                                "confidence": "LOW", "confidence_justification": "one row"}]
            entry["open_questions"] = ["Which process loaded dropper.dll?"]
        return entry

    record = run_mode3(case, "q", seat_fn=seat, es_ok=True, families=[("amcache", 3)])
    assert "verifier" in seen_roles
    assert all("dropper.dll" not in str(c.get("title") or "") for c in record["candidates"])


def test_run_mode3_real_seat_path(tmp_path, monkeypatch):
    """Full graph with a scripted model and no seat_fn (items 4, 5, 7)."""
    from nexus.modes.multi_agent import run_mode3

    monkeypatch.setenv("NEXUS_MODE3_ROUNDS", "2")
    monkeypatch.setenv("NEXUS_MODE3_CALLS", "4")
    monkeypatch.setenv("NEXUS_MODE3_SECONDS", "60")
    monkeypatch.setenv("NEXUS_MODE3_MAX_SUPERSTEPS", "6")
    monkeypatch.setenv("NEXUS_MODE3_MAX_AGENTS", "6")
    monkeypatch.setenv("NEXUS_LLM_MODEL", "scripted-seat")
    monkeypatch.setenv("NEXUS_LLM_PROVIDER", "test")

    case = _case(tmp_path)
    hayabusa = case / "runs" / "RUN-1" / "extractions" / "hayabusa"
    hayabusa.mkdir(parents=True)
    (hayabusa / "evtx-timeline.csv").write_text(
        "RuleTitle,RuleID,Level,Computer,Timestamp,Details,MitreTactics\n"
        "Defender Alert (Severe),r1,crit,RD01,2026-01-01T00:00:00Z,beacon.exe,T1059\n",
        encoding="utf-8",
    )

    cite_rows(case, [{"loc": "beacon.csv:1", "detail": "the detection row", "process": "beacon.exe"}],
              audit_id="audit-b")
    cite_rows(case, [{"loc": "notepad.csv:1", "detail": "a process row", "process": "notepad.exe"}],
              audit_id="audit-n")
    record = run_mode3(
        case,
        "Compromise suspected.",
        model=_ScriptedSeatModel(),
        families=[("hayabusa", 10), ("vol", 20)],
        es_ok=True,
    )
    families = {str(e.get("family") or "") for e in record["board"]}
    assert "vol" in families, families
    assert "Defender Alert (Severe)" in record["lead_dispositions"]
    assert record["lead_dispositions"]["Defender Alert (Severe)"]["status"] == "supported"
    questions = [
        e for e in record["board"]
        if "A seat asked:" in str(e.get("note") or "")
        or "open question" in str(e.get("note") or "")
        or any("beacon.exe persist" in q for q in (e.get("open_questions") or []))
    ]
    # The open question is kept on the lead seat; a later seat is spawned from it.
    assert any(
        "How did beacon.exe persist?" in (e.get("open_questions") or [])
        for e in record["board"]
    )
    assert any("open question" in str(e.get("note") or "") for e in record["board"]) or questions
    roles = {e.get("role") for e in record["board"]}
    assert "verifier" in roles
    blob = json.dumps(record["candidates"])
    assert "beacon.exe" in blob
    assert "notepad.exe" not in blob
    assert record["stop_reason"] == "settled" or "settled" in str(record["stop_reason"])
    assert int(record["superstep"]) < 6
    assert record["model"] == {"provider": "test", "model": "scripted-seat"}
