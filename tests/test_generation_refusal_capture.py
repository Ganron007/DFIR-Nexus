"""A provider violating the reply contract must leave a replayable refusal."""
import copy
import json
from pathlib import Path

import pytest
from langchain_core.messages import AIMessage

from nexus.audit import AuditWriter
from nexus.langgraph import context_loop, es_native
from tests.test_context_loop import _case, _fake_backbone
from tests.test_query_generation_contract import REQUESTS, TYPES
from tests.test_tool_generation import SchemaRecordingModel


def test_schema_refusal_retains_the_reply_refuses_only_the_invalid_call_and_asks_again_under_the_schema(
        tmp_path, monkeypatch):
    """D435 kept: a refused call is never dispatched and no free-form fallback runs. D464: one invalid call no
    longer takes the reply's valid calls with it, and the next round is asked under the same schema."""
    case = _case(tmp_path)
    monkeypatch.setattr(es_native, "_field_types", lambda _: TYPES)
    calls = []
    _fake_backbone(monkeypatch, calls)
    original = next(e for e in REQUESTS if e["audit_id"].endswith("-1086"))
    args = {k: copy.deepcopy(v) for k, v in original["params"].items() if k != "case_id"}
    reply = {"tool_calls": [
        {"tool": "es_search", "args": args, "why": "exact retained request"},
        {"tool": "es_search", "args": {"query": {"match_all": {}}, "size": 1}, "why": "same batch"},
    ], "opaque_metadata": {"unicode": "\u2192", "retained": [1, {"all": "keys"}]}}
    text = json.dumps(reply, ensure_ascii=False)
    model = SchemaRecordingModel(script=[
        AIMessage(content=text), AIMessage(content='{"tool_calls": [], "answer": "read under the schema"}'),
    ])
    result = context_loop.run_context_loop(
        case_dir=case, case_id=case.name, question="contract control", model=model,
        audit=AuditWriter("nexus", audit_dir=case / "audit"),
        budget=context_loop.LoopBudget(rounds=2, calls=3, seconds=60),
    )
    assert result["finish_reason"] == "answer" and result["reply"].startswith("read under the schema")
    assert len(calls) == 1 and len(model.wire_options) == 2
    assert all(o.get("response_format") == model.wire_options[0]["response_format"] for o in model.wire_options)
    entries = [json.loads(line) for path in (case / "audit").glob("*.jsonl")
               for line in path.read_text(encoding="utf-8").splitlines()]
    boundary = next(e for e in entries if e["tool"] == "context_loop_reply")
    assert boundary["model_response"] == text
    assert boundary["rejection_stage"] == "generation_contract"
    refused = [e for e in entries if e["tool"] == "es_search" and e.get("rejection_stage")]
    assert len(refused) == 1
    assert refused[0]["requested_args"] == args and refused[0]["params"] == {**args, "case_id": case.name}
    assert "args/query/bool/must" in refused[0]["result_summary"]["error"]
    assert refused[0]["model_response_audit_id"] == boundary["audit_id"]
    assert result["rejected_calls"][0]["summary"]["error"].startswith("generation contract: ")


def test_malformed_json_reply_is_retained_without_inventing_requests(tmp_path, monkeypatch):
    case = _case(tmp_path)
    monkeypatch.setattr(es_native, "_field_types", lambda _: TYPES)
    calls = []
    _fake_backbone(monkeypatch, calls)
    text = '{"tool_calls": ['
    model = SchemaRecordingModel(script=[
        AIMessage(content=text), AIMessage(content='{"tool_calls": [], "answer": "read under the schema"}'),
    ])
    result = context_loop.run_context_loop(
        case_dir=case, case_id=case.name, question="contract control", model=model,
        audit=AuditWriter("nexus", audit_dir=case / "audit"),
        budget=context_loop.LoopBudget(rounds=2, calls=3, seconds=60),
    )
    # The unreadable reply invents no request and is not taken as an answer; the round is asked again under the
    # schema (D464), so the second reply, which is readable, is the answer.
    assert result["finish_reason"] == "answer"
    assert calls == [] and result["rejected_calls"] == [] and len(model.wire_options) == 2
    assert model.wire_options[1].get("response_format") == model.wire_options[0]["response_format"]
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


T22 = json.loads((Path(__file__).parent / "fixtures" / "t22_refused_reply.json").read_text(encoding="utf-8"))


def test_t22_a_refused_reply_keeps_its_valid_calls(monkeypatch):
    """T22-R1z3d Mode 3's pattern seat sent four calls; one asked `range` for `eq`. The whole reply was refused and
    the seat ended at round 3. Now the three valid calls run and the fourth is refused with the validator's reason."""
    from nexus.langgraph.tool_generation import refused_calls, response_schema

    monkeypatch.setattr(es_native, "_field_types", lambda _: T22["field_types"])
    reply = json.loads(T22["refused_reply"])
    schema = response_schema("CASE-4387EB47", context_loop._TOOL_ARGS, context_loop._REQUIRED_ARGS,
                             context_loop._STRING_FIELDS_BY_TOOL)
    refused = refused_calls(schema, reply)
    assert [call["why"] for call, _ in refused] == ["Verify WinRM 5985 connection row for T1021.006"]
    reason = refused[0][1]
    assert "eq" in reason and "not valid under any of the given schemas" not in reason


def test_a_reply_stopped_at_the_length_limit_is_kept_and_the_round_asked_again(tmp_path, monkeypatch):
    """D465: four T22-R1z3d Mode 3 replies ran to 65,535 completion tokens and each ended its seat with nothing
    kept. The received text is kept on the audit and the round is asked again under the schema."""
    from openai import LengthFinishReasonError
    from openai.types.chat import ChatCompletion

    truncated = '{"tool_calls": [{"tool": "es_se'

    class LengthLimited(SchemaRecordingModel):
        def _generate(self, messages, stop=None, run_manager=None, **kwargs):
            if not self.wire_options:
                self.wire_options.append(copy.deepcopy(kwargs))
                raise LengthFinishReasonError(completion=ChatCompletion.model_validate({
                    "id": "c", "object": "chat.completion", "created": 0, "model": "m",
                    "choices": [{"index": 0, "finish_reason": "length",
                                 "message": {"role": "assistant", "content": truncated}}]}))
            return super()._generate(messages, stop=stop, run_manager=run_manager, **kwargs)

    case = _case(tmp_path)
    monkeypatch.setattr(es_native, "_field_types", lambda _: TYPES)
    calls = []
    _fake_backbone(monkeypatch, calls)
    model = LengthLimited(script=[AIMessage(content='{"tool_calls": [], "answer": "short reply"}')])
    result = context_loop.run_context_loop(
        case_dir=case, case_id=case.name, question="length control", model=model,
        audit=AuditWriter("nexus", audit_dir=case / "audit"),
        budget=context_loop.LoopBudget(rounds=2, calls=3, seconds=60),
    )
    assert result["finish_reason"] == "answer" and len(model.wire_options) == 2
    entries = [json.loads(line) for path in (case / "audit").glob("*.jsonl")
               for line in path.read_text(encoding="utf-8").splitlines()]
    boundary = next(e for e in entries if e["tool"] == "context_loop_reply")
    assert boundary["rejection_stage"] == "generation_length"
    assert boundary["model_response"] == truncated
