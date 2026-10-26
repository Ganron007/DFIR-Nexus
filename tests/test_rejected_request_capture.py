"""D408 recovery: rejected requests must survive verbatim without executing.

These are new controlled requests for the recording contract, not reconstructions
of the nine original requests whose parameters were never retained.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from unittest.mock import patch

import pytest
from test_context_loop import _ScriptedModel

from nexus.audit import AuditWriter
from nexus.langgraph.context_loop import LoopBudget, run_context_loop


@pytest.mark.parametrize("stage", ["arguments", "role_allowlist"])
def test_rejected_request_keeps_full_args_and_actual_case_without_dispatch(tmp_path, stage):
    case = tmp_path / "CASE-CAPTURE"
    (case / "analysis").mkdir(parents=True)
    args = {
        "query": {"terms": {"family": ["x" * 700 + str(i) for i in range(25)]}},
        "case_id": "CASE-MODEL-SUPPLIED",
        "why": "preserve the original annotation too",
    }
    if stage == "arguments":
        args["filter"] = {"term": {"family": "cloudtrail"}}
    model = _ScriptedModel([
        {"tool_calls": [{"tool": "es_search", "args": args}]},
        {"answer": "The request was rejected; no evidence retrieved."},
    ])
    events = []
    with patch("nexus.langgraph.backbone.backbone_call") as dispatch:
        result = run_context_loop(
            case_dir=case, case_id=case.name, question="capture a refused request",
            model=model, allowed_tools=("es_mappings",), on_event=events.append,
            budget=LoopBudget(rounds=2, calls=3, seconds=30, call_chars=120000),
            audit=AuditWriter("nexus", audit_dir=case / "audit"),
        )
    dispatch.assert_not_called()
    assert result["tool_calls"] == []
    assert result["evidence_read"] is False
    assert result["evidence_attempted"] is True
    rejected, = result["rejected_calls"]
    assert rejected["requested_args"] == args
    assert rejected["rejection_stage"] == stage
    rows = [json.loads(line) for line in (case / "audit/nexus.jsonl").read_text().splitlines()]
    audit_row, = [row for row in rows if row["tool"] == "es_search"]
    assert audit_row["case_id"] == case.name
    assert audit_row["params"]["case_id"] == case.name
    assert audit_row["requested_args"] == args, "no 500-character / 20-item audit-summary truncation"
    assert audit_row["params"]["query"] == args["query"]
    assert audit_row["rejection_stage"] == stage
    assert audit_row["turn_id"] == result["turn_id"]
    event, = [event for event in events if event["event"] == "tool_result"]
    assert event["audit_id"] == audit_row["audit_id"] == rejected["audit_id"]
    assert event["requested_args"] == args
    assert event["error"] == audit_row["result_summary"]["error"]
    spec = importlib.util.spec_from_file_location(
        "replay_refused", Path(__file__).resolve().parents[1] / "devtools/runbook/replay_refused.py",
    )
    replay = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(replay)
    with (patch.object(replay.es_native, "es_search") as search,
          pytest.raises(replay.es_native.ESQueryError, match="unsupported argument|outside this role")):
        replay.replay_call(case.name, audit_row)
    search.assert_not_called()


@pytest.mark.parametrize("raw_args", ["{" + "x" * 700, None, ["not", "an", "object"]])
def test_capture_preserves_malformed_arguments_before_the_normalizer_clips_them(tmp_path, raw_args):
    case = tmp_path / "CASE-CAPTURE"
    (case / "analysis").mkdir(parents=True)
    model = _ScriptedModel([
        {"tool_calls": [{"tool": "es_search", "args": raw_args}]},
        {"answer": "invalid request"},
    ])
    with patch("nexus.langgraph.backbone.backbone_call") as dispatch:
        result = run_context_loop(
            case_dir=case, case_id=case.name, question="record original invalid input", model=model,
            budget=LoopBudget(rounds=2, calls=3, seconds=30, call_chars=120000),
            audit=AuditWriter("nexus", audit_dir=case / "audit"),
        )
    dispatch.assert_not_called()
    assert result["rejected_calls"][0]["requested_args"] == raw_args
    rows = [json.loads(line) for line in (case / "audit/nexus.jsonl").read_text().splitlines()]
    row, = [row for row in rows if row["tool"] == "es_search"]
    assert row["requested_args"] == raw_args


def test_mode2_persists_the_loops_rejected_request_in_its_real_event_sink(tmp_path):
    from nexus.modes import multi_role

    case = tmp_path / "CASE-CAPTURE"
    (case / "analysis").mkdir(parents=True)
    args = {"query": {"match_all": {}}, "filter": {"term": {"family": "cloudtrail"}}}
    model = _ScriptedModel([
        {"tool_calls": [{"tool": "es_search", "args": args}]},
        {"answer": json.dumps({"notes": [], "candidate_findings": [], "coverage": {}})},
    ])
    order = multi_role.WorkOrder(order_id="wo-capture", role="evidence", task="record rejection")
    with patch("nexus.langgraph.backbone.backbone_call") as dispatch:
        multi_role.run_work_order(
            order, case_dir=case, model=model, run_id="M2-capture",
            sink=multi_role.EventSink(case, "M2-capture"),
        )
    dispatch.assert_not_called()
    event, = [event for event in multi_role.read_run_events(case, "M2-capture")
              if event["event_type"] == "tool.result"]
    assert event["status"] == "error"
    assert event["audit_id"]
    assert event["data"]["requested_args"] == args
    assert event["data"]["rejection_stage"] == "arguments"
