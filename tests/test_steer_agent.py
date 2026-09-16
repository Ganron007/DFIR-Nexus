"""WP 4j.13 — Mode 2 conversational steering agent (3-step pipeline) tests."""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any
from unittest.mock import patch


class _FakeModel:
    """Scripted: one response per invoke call."""

    def __init__(self, payloads: list[dict[str, Any]]):
        self.payloads = list(payloads)
        self.prompts: list[list[dict]] = []

    def invoke(self, messages):
        self.prompts.append(messages)

        class _R:
            content = json.dumps(self.payloads.pop(0)) if self.payloads else "{}"

        return _R()


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
    os.environ["NEXUS_CASES_ROOT"] = str(tmp_path)
    os.environ["NEXUS_ACTIVE_CASE_FILE"] = str(tmp_path / "ptr")
    (tmp_path / "ptr").write_text(str(case))
    return case


def test_steer_agent_3_step_pipeline(tmp_path):
    """PLAN → EXECUTE → ANSWER: the LLM plans queries, the backbone executes,
    the LLM reads the results and formulates an answer."""
    from nexus.langgraph.steer_agent import run_steer_agent

    case = _mkcase(tmp_path)
    fake = _FakeModel([
        # Step 1: plan queries
        {"queries": ["family:hayabusa AND sdelete"]},
        # Step 3: formulate answer from the actual evidence rows
        {"reply": "I found 1 sdelete execution event on WS01 (EventID 4688, "
                  "timestamp 2026-08-10 15:00). The process was sdelete.exe with "
                  "a 5-pass parameter, indicating deliberate file deletion."},
    ])
    with patch("nexus.langgraph.llm_pipeline.get_model", return_value=fake):
        result = run_steer_agent(case, "Did someone use sdelete?")

    assert result["reply"], "expected a reply"
    assert "sdelete" in result["reply"].lower() or "found" in result["reply"].lower()
    assert result["queries_executed"], "expected queries executed"
    assert result["queries_executed"][0]["audit_id"], "provenance required"
    assert result["total_hits"] >= 1


def test_steer_agent_deterministic_fallback(tmp_path):
    """Without an LLM, the agent falls back to keyword search + raw rows."""
    from nexus.langgraph.steer_agent import run_steer_agent

    case = _mkcase(tmp_path)
    with patch("nexus.langgraph.llm_pipeline.get_model", return_value=None):
        result = run_steer_agent(case, "sdelete rundll32 execution")
    assert result["reply"], "expected a reply even without LLM"
    assert result["queries_executed"], "deterministic fallback should still query"
    assert result["total_hits"] >= 1, "keyword search should find the rows"


def test_steer_agent_no_evidence_is_honest(tmp_path):
    from unittest.mock import patch

    from nexus.langgraph.steer_agent import run_steer_agent

    case = _mkcase(tmp_path)
    # Deterministic path (no LLM) — the question matches no evidence terms, so
    # the honest no-results reply must come back. Using the real LLM here made
    # the test planner-dependent and flaky.
    with patch("nexus.langgraph.llm_pipeline.get_model", return_value=None):
        result = run_steer_agent(case, "completely unrelated quantum physics")
    assert result["reply"], "expected an honest no-results reply"
    assert result["total_hits"] == 0 or "no evidence" in result["reply"].lower() or \
           "found 0" in result["reply"].lower()


def test_steer_agent_provenance_travels(tmp_path):
    from nexus.langgraph.steer_agent import run_steer_agent

    case = _mkcase(tmp_path)
    result = run_steer_agent(case, "sdelete execution")
    for q in result["queries_executed"]:
        assert q.get("audit_id"), f"query {q['dsl']} missing audit_id"
