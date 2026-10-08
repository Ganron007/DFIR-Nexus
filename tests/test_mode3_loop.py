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


def _crit_lead() -> dict:
    return {
        "kind": "rule_engine",
        "subject": "Defender Alert (Severe)",
        "family": "hayabusa",
        "detail": "Hayabusa crit detection: Defender Alert (Severe) - 10 occurrence(s)",
        "score": 1.0,
        "extra": {"engine": "hayabusa", "level": "crit", "crit_high": True},
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

    record = run_mode3(
        _case(tmp_path, leads=[_crit_lead()]), "compromise suspected",
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

    run_mode3(
        _case(tmp_path), "q", families=[("hayabusa", 10)], seat_fn=seat, es_ok=True,
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
