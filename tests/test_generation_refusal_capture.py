"""A provider violating the reply contract must leave a replayable refusal."""
import copy
import json

import pytest
from langchain_core.messages import AIMessage

from nexus.audit import AuditWriter
from nexus.langgraph import context_loop, es_native
from tests.test_context_loop import _case, _fake_backbone
from tests.test_query_generation_contract import REQUESTS, TYPES
from tests.test_tool_generation import SchemaRecordingModel


def test_schema_refusal_retains_entire_reply_and_exact_args_without_dispatch_or_fallback(tmp_path, monkeypatch):
    case = _case(tmp_path)
    monkeypatch.setattr(es_native, "_field_types", lambda _: TYPES)
    calls = []
    _fake_backbone(monkeypatch, calls)
    original = next(e for e in REQUESTS if e["audit_id"].endswith("-1086"))
    args = {k: copy.deepcopy(v) for k, v in original["params"].items() if k != "case_id"}
    reply = {"tool_calls": [
        {"tool": "es_search", "args": args, "why": "exact retained request"},
        {"tool": "es_search", "args": {"query": {"match_all": {}}, "size": 1}, "why": "same batch"},
    ], "opaque_metadata": {"unicode": "→", "retained": [1, {"all": "keys"}]}}
    text = json.dumps(reply, ensure_ascii=False)
    model = SchemaRecordingModel(script=[
        AIMessage(content=text), AIMessage(content='{"answer":"must not retry without schema"}'),
    ])
    result = context_loop.run_context_loop(
        case_dir=case, case_id=case.name, question="contract control", model=model,
        audit=AuditWriter("nexus", audit_dir=case / "audit"),
        budget=context_loop.LoopBudget(rounds=2, calls=3, seconds=60),
    )
    assert result["finish_reason"] == "generation_contract"
    assert result["partial"] is True and result["evidence_attempted"] is True
    assert result["evidence_read"] is False
    assert calls == [] and len(model.wire_options) == 1
    entries = [json.loads(line) for path in (case / "audit").glob("*.jsonl")
               for line in path.read_text(encoding="utf-8").splitlines()]
    boundary = next(e for e in entries if e["tool"] == "context_loop_reply")
    assert boundary["model_response"] == text
    assert boundary["rejection_stage"] == "generation_contract"
    refused = [e for e in entries if e["tool"] == "es_search"]
    assert len(refused) == 2
    assert refused[0]["params"] == {**args, "case_id": case.name}
    assert refused[0]["requested_args"] == args
    assert refused[1]["requested_args"] == reply["tool_calls"][1]["args"]
    assert all(e["rejection_stage"] == "generation_contract" for e in refused)
    assert all(e["model_response_audit_id"] == boundary["audit_id"] for e in refused)


def test_malformed_json_reply_is_retained_without_inventing_requests(tmp_path, monkeypatch):
    case = _case(tmp_path)
    monkeypatch.setattr(es_native, "_field_types", lambda _: TYPES)
    calls = []
    _fake_backbone(monkeypatch, calls)
    text = '{"tool_calls": ['
    model = SchemaRecordingModel(script=[
        AIMessage(content=text), AIMessage(content='{"answer":"must not retry without schema"}'),
    ])
    result = context_loop.run_context_loop(
        case_dir=case, case_id=case.name, question="contract control", model=model,
        audit=AuditWriter("nexus", audit_dir=case / "audit"),
        budget=context_loop.LoopBudget(rounds=2, calls=3, seconds=60),
    )
    assert result["finish_reason"] == "generation_contract" and result["partial"] is True
    assert calls == [] and result["rejected_calls"] == [] and len(model.wire_options) == 1
    entries = [json.loads(line) for path in (case / "audit").glob("*.jsonl")
               for line in path.read_text(encoding="utf-8").splitlines()]
    assert next(e for e in entries if e["tool"] == "context_loop_reply")["model_response"] == text
    assert not any(e["tool"] == "es_search" for e in entries)


def test_schema_transport_refusal_is_audited_without_a_free_form_retry(tmp_path, monkeypatch):
    class RefusingTransport(SchemaRecordingModel):
        def _generate(self, messages, stop=None, run_manager=None, **kwargs):
            self.wire_options.append(copy.deepcopy(kwargs))
            raise RuntimeError("schema transport refused the request")

    case = _case(tmp_path)
    monkeypatch.setattr(es_native, "_field_types", lambda _: TYPES)
    calls = []
    _fake_backbone(monkeypatch, calls)
    model = RefusingTransport(script=[])
    result = context_loop.run_context_loop(
        case_dir=case, case_id=case.name, question="transport control", model=model,
        audit=AuditWriter("nexus", audit_dir=case / "audit"),
        budget=context_loop.LoopBudget(rounds=2, calls=3, seconds=60),
    )
    assert result["finish_reason"] == "generation_transport" and result["partial"] is True
    assert calls == [] and result["rejected_calls"] == [] and len(model.wire_options) == 1
    entries = [json.loads(line) for path in (case / "audit").glob("*.jsonl")
               for line in path.read_text(encoding="utf-8").splitlines()]
    boundary = next(e for e in entries if e["tool"] == "context_loop_reply")
    assert boundary["rejection_stage"] == "generation_transport"
    assert "schema transport refused the request" in boundary["model_error"]
    assert "model_response" not in boundary


@pytest.mark.parametrize("prefix", ["", "generation contract: ", "generation transport: ", "RuntimeError: "])
def test_only_native_unknown_field_diagnostics_are_normal_hints(prefix):
    native = "query references fields that cannot match: missing (unknown_field)"
    assert es_native.is_unknown_field_hint(prefix + native) is (not prefix)
