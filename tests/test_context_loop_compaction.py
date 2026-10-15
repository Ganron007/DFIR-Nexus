"""D206 (operator decision 2026-10-15): an earlier result travels as a compact line, and a repeated
call replays it whole.

Every round of the context loop re-sent every earlier result whole. Mode 3 run 1 sent 130.7 M
characters in 506 calls (one call 839 K characters) and used up the provider's credit at superstep 7.
"""
from __future__ import annotations

from typing import Any

from test_context_loop import _case, _ScriptedModel

from nexus.audit import AuditWriter

ROW = "Defender EID 1116 Behavior:Win32/CobaltStrike.E!sms in SRLUpdate.exe"


def _backbone(monkeypatch, calls: list[str]) -> None:
    import nexus.langgraph.backbone as bb

    def _fake(name, audit=None, **kwargs):
        calls.append(name)
        aid = audit.log(tool=name, params={}, result_summary={}) if audit else None
        return {"total": 2, "returned": 2, "has_more": False,
                "hits": [{"family": "evtxecmd", "file": "Security.csv", "line": str(n),
                          "host": "WS01", "text": f"row {n}: {ROW}"} for n in range(1, 26)],
                "provenance": {"audit_id": aid, "case_id": "CASE-LOOP"}}

    monkeypatch.setattr(bb, "backbone_call", _fake)


def _user(prompt: list[dict[str, str]]) -> str:
    return "\n".join(m["content"] for m in prompt if m["role"] == "user")


SEARCH = {"tool": "es_search", "args": {"query": {"match_phrase": {"text": "cobaltstrike"}}},
          "why": "the detection"}
OTHER = {"tool": "es_search", "args": {"query": {"match_phrase": {"text": "srlupdate"}}},
         "why": "the binary"}


def test_a_result_is_whole_once_then_a_compact_line(tmp_path, monkeypatch):
    from nexus.langgraph.context_loop import run_context_loop

    case = _case(tmp_path)
    _backbone(monkeypatch, [])
    model = _ScriptedModel([{"tool_calls": [SEARCH]}, {"tool_calls": [OTHER]},
                            {"answer": "done"}])
    run_context_loop(case_dir=case, case_id="CASE-LOOP", question="q", model=model,
                     audit=AuditWriter("nexus", audit_dir=case / "audit"))

    round2, round3 = _user(model.prompts[1]), _user(model.prompts[2])
    assert round2.count(ROW) == 25, "the new result is whole in the round after it arrives"
    first = next(line for line in round3.splitlines()
                 if line.startswith("- es_search") and "shown whole in round 1" in line)
    assert '"rows": ["Security.csv:1", "Security.csv:2"' in first and '"total": 2' in first
    assert "[audit_id " in first and ROW not in first
    assert round3.count(ROW) == 25, "only the newest result is whole"


def test_a_repeated_call_replays_the_earlier_result_whole_without_running_it(tmp_path, monkeypatch):
    from nexus.langgraph.context_loop import run_context_loop

    case = _case(tmp_path)
    calls: list[str] = []
    _backbone(monkeypatch, calls)
    model = _ScriptedModel([{"tool_calls": [SEARCH]}, {"tool_calls": [OTHER]},
                            {"tool_calls": [SEARCH]}, {"answer": "done"}])
    result = run_context_loop(case_dir=case, case_id="CASE-LOOP", question="q", model=model,
                              audit=AuditWriter("nexus", audit_dir=case / "audit"))

    assert calls == ["es_search", "es_search"], "the repeat is not run again"
    round4 = _user(model.prompts[3])
    replay = next(line for line in round4.splitlines()
                  if line.startswith("- es_search") and "replayed from the earlier" in line)
    assert replay.count(ROW) == 25
    first_id = next(line for line in _user(model.prompts[1]).splitlines()
                    if line.startswith("- es_search [audit_id")).split("]")[0]
    assert replay.startswith(first_id), "the replay carries the audit id to cite"
    assert result["duplicate_calls"] == 1


def test_a_small_result_stays_whole(tmp_path):
    from nexus.langgraph.context_loop import _observations_block

    small: dict[str, Any] = {"tool": "es_aggregate", "audit_id": "a-1", "round": 1,
                             "summary": {"aggregations": {"v": {"buckets": [{"key": "WS01"}]}}}}
    assert '"buckets"' in _observations_block([small], fresh_round=3)
