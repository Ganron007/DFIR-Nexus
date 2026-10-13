"""D130: Mode 1 stages only the interpret run's own candidates, and says what it refused.

The staging step used to stage N4 needle clusters when the model produced no candidate, when
every model candidate was rejected ("N4 hit salvage"), and beside the model's findings, chosen
by a keyword list from earlier cases (sdelete, pst, Google Drive, usb...). These drive the real
`stage_findings`; `n4_finding_candidates` is made to return a cluster so that any salvage would
show.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest
import yaml

CLUSTER = {"title": "Signal: usbstor - 3 hit(s) across registry",
           "observation": "usbstor matched 3 rows", "interpretation": "needle cluster",
           "confidence": "LOW", "audit_ids": ["nexus-test-20261013-001"]}
LLM = {"title": "Encoded PowerShell launched by a service",
       "observation": "4104 script block decodes to a downloader",
       "interpretation": "execution of a staged payload", "confidence": "MEDIUM",
       "confidence_justification": "two rows", "event_timestamp": "2023-07-10T10:00:00Z",
       "audit_ids": ["nexus-test-20261013-002"]}


class _Tool:
    name = "tool"

    def __init__(self, reply):
        self.reply, self.payloads = reply, []

    async def ainvoke(self, payload):
        self.payloads.append(dict(payload))
        return dict(self.reply)


@pytest.fixture()
def case(monkeypatch):
    import nexus.langgraph.query_pack as query_pack
    from nexus.config import settings
    from nexus.langgraph.pipeline_runs import create_run

    monkeypatch.setattr(query_pack, "n4_finding_candidates", lambda *_a, **_k: [dict(CLUSTER)])
    case_dir = settings.cases_root / "CASE-M1STAGE"
    (case_dir / "analysis").mkdir(parents=True)
    (case_dir / "audit").mkdir()
    (case_dir / "CASE.yaml").write_text(
        yaml.safe_dump({"case_id": case_dir.name, "status": "created"}), encoding="utf-8")
    return case_dir, create_run(case_dir, "interpret")


def _state(case_dir: Path, run_id: str, messages: list) -> dict:
    return {"case_id": case_dir.name, "run_id": run_id, "messages": messages,
            "tool_run_ledger": [], "case_context": {}, "evidence_audit_ids": []}


def _msg(*findings) -> dict:
    return {"role": "assistant", "content": "```json\n" + json.dumps(list(findings)) + "\n```"}


def test_no_candidate_stages_nothing(case):
    from nexus.langgraph.llm_pipeline import stage_findings

    case_dir, run = case
    record = _Tool({"finding_id": "F-1"})
    out = asyncio.run(stage_findings(_state(case_dir, run.run_id, []), {"record_finding": record}))
    assert record.payloads == []
    assert any("no finding candidates" in line for line in out["step_log"])


def test_a_rejected_candidate_is_reported_not_replaced(case):
    from nexus.langgraph.llm_pipeline import stage_findings

    case_dir, run = case
    record = _Tool({"status": "REJECTED", "error": "FD-001: unknown audit id"})
    timeline = _Tool({"event_id": "T-1"})
    out = asyncio.run(stage_findings(_state(case_dir, run.run_id, [_msg(LLM)]),
                                     {"record_finding": record,
                                      "record_timeline_event": timeline}))
    assert [p["title"] for p in record.payloads] == [LLM["title"]]
    assert timeline.payloads == []  # a rejected candidate gets no timeline event
    staging = json.loads((run.analysis / "staging.json").read_text(encoding="utf-8"))
    assert staging["staged"] == []
    assert staging["rejected"] == [{"title": LLM["title"], "reason": "FD-001: unknown audit id"}]
    assert any(line.startswith("Not staged: " + LLM["title"]) for line in out["step_log"])


def test_only_the_models_findings_are_staged(case):
    from nexus.langgraph.llm_pipeline import stage_findings

    case_dir, run = case
    record = _Tool({"finding_id": "F-2"})
    timeline = _Tool({"event_id": "T-2"})
    asyncio.run(stage_findings(_state(case_dir, run.run_id, [_msg(LLM)]),
                               {"record_finding": record, "record_timeline_event": timeline}))
    assert [p["title"] for p in record.payloads] == [LLM["title"]]
    assert len(timeline.payloads) == 1
    staging = json.loads((run.analysis / "staging.json").read_text(encoding="utf-8"))
    assert staging == {"run_id": run.run_id, "candidates": 1, "staged": ["F-2"], "rejected": []}
