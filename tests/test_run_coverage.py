"""D463: a run's coverage and gaps are what its examining seats recorded, never re-authored by synthesis.

T22-R1z3d Mode 2 (M2-20261028T142946-d9ca87): the pattern seat read all 36 ESTABLISHED connections in
MemProcFS net.csv and reported "no untrusted external C2 channel identified". The synthesis seat, given only
the verdicts and candidates, wrote the record's gaps and coverage and said "No network connection data
(PCAP, Netstat, or equivalent) was available". The seats' own account is now the record's, and the synthesis
seat composes the case with it in hand.
"""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from nexus.modes import multi_role as m2
from nexus.modes.multi_role import run_coverage

T22 = json.loads((Path(__file__).parent / "fixtures" / "t22_mode2_coverage.json").read_text(encoding="utf-8"))
NETWORK = "Network: all 36 ESTABLISHED connections enumerated; no untrusted external C2 channel identified"
FALSE_GAP = next(g for r in T22["results"] if r["role"] == "synthesis" for g in r["parsed"]["gaps"]
                 if "network connection data" in g)


def test_t22_run_coverage_is_the_examining_seats_account():
    coverage = run_coverage(T22["results"])
    assert NETWORK in coverage["checked"]
    assert any("net.csv captures a point-in-time socket table" in c for c in coverage["caveats"])
    # The synthesis seat's own coverage ("detections_resolved", "families_examined") is not the run's.
    synthesis = next(r for r in T22["results"] if r["role"] == "synthesis")["parsed"]["coverage"]
    assert not set(synthesis.get("families_examined") or []) & set(coverage["checked"])
    assert FALSE_GAP not in coverage["not_checked"]
    assert len(coverage["checked"]) == len(set(coverage["checked"]))


def _case(tmp_path: Path) -> Path:
    case = tmp_path / "CASE-D463"
    (case / "analysis").mkdir(parents=True)
    (case / "audit").mkdir()
    (case / "CASE.yaml").write_text("name: d463\nstatus: active\n", encoding="utf-8")
    return case


def test_mode2_synthesis_is_given_the_coverage_and_does_not_author_it(tmp_path):
    case = _case(tmp_path)
    pattern = next(r for r in T22["results"] if r["role"] == "pattern")["parsed"]
    synthesis_reply = next(r for r in T22["results"] if r["role"] == "synthesis")["parsed"]
    seen: dict[str, object] = {}

    def fake_work(order, *, case_dir, model, run_id, sink, agent_id="", context=None):
        if order.role == "synthesis":
            seen["task"], seen["context"] = order.task, context
            parsed = {"narrative": "n", "findings": [{"title": "McAfee YARA matches are signature strings",
                                                      "observation": "o", "interpretation": "i",
                                                      "confidence": "HIGH", "audit_ids": ["a-1"]}],
                      **synthesis_reply}
        elif order.role == "verifier":
            parsed = {"verdicts": [{"title": "McAfee YARA matches are signature strings", "class": "confirmed",
                                    "basis": "b", "audit_ids": ["a-1"]}]}
        else:
            parsed = {**pattern, "candidate_findings": [{"title": "McAfee YARA matches are signature strings",
                                                         "observation": "o", "interpretation": "i",
                                                         "confidence": "HIGH", "audit_ids": ["a-1"]}]}
        return m2.AgentResult(order_id=order.order_id, role=order.role, status="ok",
                              reply=json.dumps(parsed), parsed=parsed, audit_id="ctx-1")

    with patch.object(m2, "run_work_order", side_effect=fake_work), \
         patch.object(m2, "plan_work_orders", return_value=[m2.WorkOrder(
             order_id="wo-1", role="pattern", task="t", family="memprocfs")]):
        state = m2.run_mode2(case, "Compromise suspected.", model=object(), es_ok=True)

    assert NETWORK in str(seen["task"]) and NETWORK in seen["context"]["coverage"]["checked"]
    assert state["coverage"]["checked"] == run_coverage(state["results"])["checked"]
    assert NETWORK in state["coverage"]["checked"]
    assert FALSE_GAP not in state["gaps"]
    assert "families_examined" not in state["coverage"]


def test_the_synthesis_contract_names_the_case_parts_and_no_coverage():
    """One shape: the prompt and the reformat schema name the same keys (rule 16)."""
    prompt = m2.role_for("synthesis").system_prompt
    schema = m2._ROLE_SCHEMAS["synthesis"]
    for key in ("narrative", "findings", "timeline", "attack_chain", "entities", "open_questions"):
        assert f'"{key}"' in prompt and f'"{key}"' in schema, key
    for key in ('"gaps"', '"coverage"'):
        assert key not in prompt and key not in schema, key


def test_mode3_compose_is_given_what_the_seats_could_not_answer_and_adds_no_gaps(tmp_path):
    from test_mode3_compose import SYNTHESIS, _board, _Sink, _Synthesis

    from nexus.modes.multi_agent import compose_case, settled_candidates

    case = tmp_path / "CASE-IC10"
    (case / "analysis").mkdir(parents=True)
    board, _task, _run, _none = _board(case)
    settled, _gaps = settled_candidates(board, [], case_dir=case)
    model = _Synthesis({**SYNTHESIS, "gaps": [FALSE_GAP]})
    seat_gap = "coverage gap (evidence-1): no PCAP was collected"
    out = compose_case(case, "M3-d463", "q", settled, [], model=model, sink=_Sink(), not_answered=[seat_gap])
    assert seat_gap in json.dumps(model.prompts[0], default=str)
    assert out["gaps"] == []  # the seats' gaps reach the record from the board; synthesis adds none
