"""IC-10 (Part 9, D237): Mode 3 composes the case from its settled board through the synthesis seat.

Run 4 of CASE-C5B04D31 staged 63 DRAFTs straight from settled claims and ended on a count line; the examiner
approved none (18 absences, 10 inventories, 15 context, 5 duplicates). The synthesis seat Mode 2 uses now
writes the narrative, timeline, attack chain, entities and open questions, and composes the findings from
the claims it names in `merges`. These tests drive the real work-order loop with a scripted model.
"""
from __future__ import annotations

import json
from pathlib import Path

from _audit_rows import cite_rows

from nexus.modes.multi_agent import compose_case, run_mode3, settled_candidates


class _Synthesis:
    """The synthesis seat's model: one terminal reply, the prompts it was given kept."""

    def __init__(self, reply: dict | str):
        self.reply = reply
        self.prompts: list = []

    def invoke(self, messages):
        self.prompts.append(messages)
        text = self.reply if isinstance(self.reply, str) else json.dumps(self.reply)

        class _R:
            content = text

        return _R()


class _Sink:
    def __init__(self):
        self.events = []

    def emit(self, event):
        self.events.append(event)


def _case(tmp_path: Path) -> Path:
    case = tmp_path / "CASE-IC10"
    (case / "analysis").mkdir(parents=True)
    return case


def _claim(entity: str, kind: str, audit: str, value: str) -> dict:
    return {"entity_type": "host", "entity_value": entity, "claim_kind": kind, "polarity": "affirm",
            "value": value, "audit_ids": [audit], "confidence": "MEDIUM",
            "confidence_justification": "the cited rows show it"}


def _board(case: Path) -> tuple[list[dict], str, str, str]:
    task = cite_rows(case, [{"loc": "tasks.csv:1", "detail": "task SRLUpdate registered, runs a System32 binary",
                             "host": "ws01"}])
    run = cite_rows(case, [{"loc": "evtx.csv:7", "detail": "task launched the binary", "host": "ws01"}])
    none = cite_rows(case, [{"loc": "evtx.csv:9", "detail": "no Sysmon channel", "host": "ws01"}])
    board = [{"agent_id": "evidence-1", "role": "evidence", "family": "evtx", "claims": [
        _claim("ws01", "presence", task, "a scheduled task runs a binary from System32"),
        _claim("ws01", "presence", run, "the task's binary ran at boot"),
        _claim("ws01", "absence", none, "no Sysmon log on the host"),
    ]}]
    return board, task, run, none


SYNTHESIS = {
    "narrative": "A boot-triggered scheduled task on ws01 runs a binary from System32, and the binary ran.",
    "findings": [{"title": "Scheduled task runs an unknown System32 binary at boot",
                  "observation": "task registered and its binary ran", "interpretation": "persistence",
                  "confidence": "MEDIUM", "confidence_justification": "two rows, two sources",
                  "severity": "HIGH", "audit_ids": [], "merges": ["C1", "C2"], "attack_ids": ["T1053.005"]}],
    "timeline": [{"ts": "2023-01-17T15:48:01Z", "event": "task registered", "audit_ids": []}],
    "attack_chain": [{"tactic": "persistence", "technique": "T1053.005", "what": "boot task", "audit_ids": []}],
    "entities": [{"type": "host", "value": "ws01", "role": "victim"}],
    "open_questions": ["who registered the task"],
    "gaps": [],
}


def test_the_case_is_composed_and_an_absence_is_never_a_finding(tmp_path):
    case = _case(tmp_path)
    board, task, run, none = _board(case)
    settled, _gaps = settled_candidates(board, [], case_dir=case)
    model = _Synthesis(SYNTHESIS)
    out = compose_case(case, "M3-ic10", "persistence?", settled, [], model=model, sink=_Sink())

    task_text = json.dumps(model.prompts[0], default=str)
    assert "no Sysmon log on the host" in task_text  # the absence is context for the narrative ...
    assert len(out["findings"]) == 1  # ... and never a finding
    finding = out["findings"][0]
    # The calls of the claims it merges follow it (D225), so the finding stands on its rows.
    assert set(finding["audit_ids"]) == {task, run}
    assert out["absences"] == [{"title": settled[2]["title"], "audit_ids": [none]}]
    assert out["narrative"].startswith("A boot-triggered scheduled task")
    assert out["case"]["timeline"] and out["case"]["attack_chain"] and out["case"]["open_questions"]


def test_no_model_composes_nothing_and_stages_nothing(tmp_path):
    case = _case(tmp_path)
    board, *_ = _board(case)
    settled, _ = settled_candidates(board, [], case_dir=case)
    out = compose_case(case, "M3-ic10", "q", settled, [], model=None, sink=_Sink())
    assert out["findings"] == []
    assert any("was not composed" in g for g in out["gaps"])


def test_an_unreadable_synthesis_is_a_gap_not_a_fallback_to_the_claims(tmp_path):
    case = _case(tmp_path)
    board, *_ = _board(case)
    settled, _ = settled_candidates(board, [], case_dir=case)
    out = compose_case(case, "M3-ic10", "q", settled, [], model=_Synthesis("not json at all"), sink=_Sink())
    assert out["findings"] == []
    assert any("was not composed" in g for g in out["gaps"])


def test_the_run_record_carries_the_narrative_the_case_and_the_settled_claims(tmp_path):
    case = _case(tmp_path)
    board, task, run, _none = _board(case)

    def seat(spawn, _board_now, step):
        claims = board[0]["claims"] if spawn["role"] == "evidence" else []
        return {"entry_id": f"{spawn['role']}-{step}", "agent_id": f"{spawn['role']}-{step}",
                "role": spawn["role"], "family": "evtx", "superstep": step, "claims": claims,
                "open_questions": []}

    record = run_mode3(case, "persistence?", families=[("evtx", 5)], seat_fn=seat,
                       model=_Synthesis(SYNTHESIS), es_ok=True)
    assert record["status"] == "completed"
    assert record["narrative"].startswith("A boot-triggered scheduled task")
    assert "settled claim" not in record["narrative"]  # the count line is the summary, never the narrative
    assert "settled claim(s)" in record["summary"]
    assert len(record["settled_claims"]) == 3
    assert [c["title"] for c in record["candidates"]] == ["Scheduled task runs an unknown System32 binary at boot"]
    assert set(record["candidates"][0]["audit_ids"]) == {task, run}
    assert record["case"]["entities"] == [{"type": "host", "value": "ws01", "role": "victim"}]
    assert len(record["absences"]) == 1
