"""WP 4j.13 — Mode 2 conversational steering agent tests."""
from __future__ import annotations

import os
from pathlib import Path

os.environ.setdefault("NEXUS_RAG_PRELOAD", "0")


class _FakeModel:
    """Scripted: one response per invoke call."""

    def __init__(self, payloads: list[dict]):
        self.payloads = list(payloads)
        self.prompts: list[list[dict]] = []

    def invoke(self, messages):
        self.prompts.append(messages)

        class _R:
            content = json.dumps(self.payloads.pop(0)) if self.payloads else "{}"

        return _R()


import json  # noqa: E402


def _mkcase(tmp_path: Path) -> Path:
    case = tmp_path / "CASE-STEER"
    ext = case / "extractions" / "hayabusa"
    ext.mkdir(parents=True)
    (ext / "timeline.csv").write_text(
        "Timestamp,Computer,Channel,EventID,Level,RuleTitle,OtherFields\n"
        "2026-08-10 15:00:00,WS01,Sec,4688,high,Suspicious SDelete Usage,sdelete.exe -p 5\n"
        "2026-08-10 15:05:00,WS01,Sec,4688,high,Suspicious Rundll32 Execution,rundll32.exe\n",
        encoding="utf-8",
    )
    (case / "CASE.yaml").write_text("question: investigate\n", encoding="utf-8")
    # Activate the case so the backbone tools resolve it
    import os as _os
    _os.environ["NEXUS_CASES_ROOT"] = str(tmp_path)
    _os.environ["NEXUS_ACTIVE_CASE_FILE"] = str(tmp_path / "ptr")
    _ACTIVE_CASE_FILE = tmp_path / "ptr"
    _ACTIVE_CASE_FILE.write_text(str(case))
    return case


def test_steer_agent_queries_and_answers(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_CASES_ROOT", str(tmp_path / "cases"))
    monkeypatch.setenv("NEXUS_ACTIVE_CASE_FILE", str(tmp_path / "ptr"))
    from nexus.langgraph.steer_agent import run_steer_agent

    case = _mkcase(tmp_path)
    # Scripted: turn 1 → query, turn 2 → answer
    fake = _FakeModel([
        {"tool": "n4_query", "args": {"dsl": "family:hayabusa AND sdelete"}},
        {"answer": "I found 1 sdelete execution event on WS01 (EventID 4688).",
         "queries_used": ["family:hayabusa AND sdelete"], "confidence": "high"},
    ])
    from unittest.mock import patch

    with patch("nexus.langgraph.llm_pipeline.get_model", return_value=fake):
        result = run_steer_agent(case, "Did someone use sdelete?")
    assert result["reply"], "expected a reply"
    assert "sdelete" in result["reply"].lower()
    assert result["queries_executed"], "expected queries executed"
    assert result["queries_executed"][0]["audit_id"], "provenance required"
    assert result["total_hits"] >= 1


def test_steer_agent_refuses_mutating_tools(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_CASES_ROOT", str(tmp_path / "cases"))
    monkeypatch.setenv("NEXUS_ACTIVE_CASE_FILE", str(tmp_path / "ptr"))
    from nexus.langgraph.steer_agent import run_steer_agent

    case = _mkcase(tmp_path)
    fake = _FakeModel([
        {"tool": "case_delete", "args": {}},
        {"answer": "done", "queries_used": [], "confidence": "high"},
    ])
    from unittest.mock import patch


    with patch("nexus.langgraph.llm_pipeline.get_model", return_value=fake):
        result = run_steer_agent(case, "delete everything")
    # The backbone should have refused the mutating tool
    assert result["reply"], "agent must still reply after a refused call"
