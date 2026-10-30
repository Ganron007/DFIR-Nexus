"""Native callbacks record invocation metadata, never forensic assertions or prompt bodies."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest
from langchain_core.language_models.fake_chat_models import FakeListChatModel

from nexus.analysis import model_calls
from nexus.analysis.knowledge_record import recording
from nexus.langgraph import llm_pipeline, prompt_budget


def _model(monkeypatch):
    monkeypatch.setattr(llm_pipeline, "_construct_model", lambda *a: FakeListChatModel(responses=["{}"]))
    monkeypatch.setattr(llm_pipeline, "built_model_record", lambda: {"provider": "local-test", "model": "fake-chat"})
    return llm_pipeline.get_model()


def _events(case, run_id):
    return [json.loads(line) for line in
            (case / ".trace" / f"model_calls-{run_id}.jsonl").read_text(encoding="utf-8").splitlines()]


def test_real_async_client_calls_are_isolated_and_resume_without_losing_prior_calls(tmp_path, monkeypatch):
    model = _model(monkeypatch)

    async def call(case, run_id, text, *, resuming=False):
        with recording():
            model_calls.bind(case, run_id, model, resuming=resuming)
            await model.bind(response_format={"type": "json_object"}).ainvoke(text)
            return model_calls.section(case, run_id)

    cases = [tmp_path / "CASE-LEFT", tmp_path / "CASE-RIGHT"]

    async def together():
        return await asyncio.gather(call(cases[0], "run-left", "private prompt left"),
                                    call(cases[1], "run-right", "private prompt right"))

    left, right = asyncio.run(together())
    assert left["calls"] == right["calls"] == 1
    assert left["prompt_chars"] == len("private prompt left")
    assert right["prompt_chars"] == len("private prompt right")
    again = asyncio.run(call(cases[0], "run-left", "continued", resuming=True))
    assert again["calls"] == again["finished"] == 2 and again["pending"] == 0
    assert again["prompt_chars"] == len("private prompt leftcontinued")
    for case, rid in zip(cases, ("run-left", "run-right"), strict=True):
        events = _events(case, rid)
        assert {e["case_id"] for e in events} == {case.name}
        assert {e["run_id"] for e in events} == {rid}
        assert "private prompt" not in json.dumps(events)
        assert all(e["model"] == {"provider": "local-test", "model": "fake-chat"}
                   for e in events if e["event"] == "call_started")


def test_error_callback_finishes_its_original_run_without_recording_the_error_body(tmp_path):
    meter = prompt_budget.TokenMeter({"model": "local-test"})
    with recording() as record:
        record.model_meter_available = True
        model_calls.bind(tmp_path, "run-error")
        meter.on_llm_start({}, ["private input"], run_id="call-error")
        calls = record.model_calls
    # Callback completion may outlive the task context; its start ticket owns it.
    meter.on_llm_error(RuntimeError("private provider response"), run_id="call-error")
    summary = calls.section()
    assert summary["calls"] == summary["finished"] == summary["failed"] == 1
    assert summary["pending"] == 0 and summary["model_seconds_sum"] >= 0
    assert "private" not in calls.path.read_text(encoding="utf-8")
    assert _events(tmp_path, "run-error")[-1]["error_type"] == "RuntimeError"


@pytest.mark.parametrize("reason", ["unmetered", "missing_history", "unbound", "write_failure"])
def test_unknown_measurements_are_explicitly_unavailable_not_zero(tmp_path, monkeypatch, reason):
    meter = prompt_budget.TokenMeter()
    with recording() as record:
        record.model_meter_available = reason != "unmetered"
        if reason == "unbound":
            meter.on_llm_start({}, ["before binding"], run_id="unbound")
            meter.on_llm_error(RuntimeError(), run_id="unbound")
        if reason == "write_failure":
            real_open = Path.open

            def refused(path, *args, **kwargs):
                if path.name == "model_calls-run-unknown.jsonl":
                    raise PermissionError("measurement write refused")
                return real_open(path, *args, **kwargs)

            monkeypatch.setattr(Path, "open", refused)
        model_calls.bind(tmp_path, "run-unknown", resuming=reason == "missing_history")
        summary = model_calls.section(tmp_path, "run-unknown")
    assert summary["status"] == "unavailable" and summary["reason"]
    assert summary["calls"] is None and summary["prompt_chars"] is None


def test_foreign_trace_and_invalid_run_names_cannot_be_overwritten_or_escape_case(tmp_path):
    path = tmp_path / ".trace" / "model_calls-run-old.jsonl"
    path.parent.mkdir()
    old = b'{"event":"old trace format"}\n'
    path.write_bytes(old)
    calls = model_calls.ModelCalls(tmp_path, "run-old", metered=True, resuming=True)
    assert calls.section()["status"] == "unavailable" and path.read_bytes() == old
    with pytest.raises(ValueError, match="run_id"):
        model_calls.ModelCalls(tmp_path, "../../escape", metered=True)
    with recording():
        model_calls.bind(tmp_path, "run-bound")
        assert model_calls.section(tmp_path / "other", "run-bound") is None
        with pytest.raises(ValueError, match="another case"):
            model_calls.bind(tmp_path / "other", "run-bound")


def test_inputs_use_exact_index_counts_and_uncapped_briefing_leads_once(tmp_path, monkeypatch):
    capture = json.loads((Path(__file__).parent / "fixtures" / "mode3_work_r1.json").read_text(encoding="utf-8"))[0]
    # Native captured lead metadata supplies a family; these are protocol counts,
    # not invented event rows or an assertion about this fixture's real inventory.
    family = capture["leads"][0]["family"]
    observed = []

    def family_counts(case_id):
        observed.append(case_id)
        return {family: 123}

    monkeypatch.setattr("nexus.langgraph.es_native.family_doc_counts", family_counts)
    with recording():
        model_calls.bind(tmp_path, "run-inputs")
        model_calls.note_inputs(tmp_path, {"lead_counts": {"total": 80}, "leads": capture["leads"][:1]})
        model_calls.note_inputs(tmp_path, {"lead_counts": {"total": 0}})
        inputs = model_calls.section(tmp_path, "run-inputs")["inputs"]
    assert observed == [tmp_path.name]
    assert inputs == {"indexed_rows": 123, "families": {family: 123}, "leads": 80}


def test_missing_input_counts_stay_null_with_their_errors(tmp_path, monkeypatch):
    def unavailable(case_id):
        raise RuntimeError("index unavailable")

    monkeypatch.setattr("nexus.langgraph.es_native.family_doc_counts", unavailable)
    with recording():
        model_calls.bind(tmp_path, "run-input-errors")
        model_calls.note_inputs(tmp_path, {"lead_counts": {"total": 0, "error": "lead build failed"}})
        inputs = model_calls.section(tmp_path, "run-input-errors")["inputs"]
    assert inputs["indexed_rows"] is inputs["leads"] is None
    assert inputs["index_error"] == "index unavailable" and inputs["lead_error"] == "lead build failed"


def test_a_resumed_run_cannot_forget_an_earlier_measurement_write_failure(tmp_path, monkeypatch):
    model = _model(monkeypatch)
    with recording():
        model_calls.bind(tmp_path, "run-incomplete", model)
        real_open = Path.open

        def refused(path, *args, **kwargs):
            if path.name == "model_calls-run-incomplete.jsonl":
                raise PermissionError("measurement append refused")
            return real_open(path, *args, **kwargs)

        with monkeypatch.context() as partial:
            partial.setattr(Path, "open", refused)
            model.invoke("unrecorded invocation")
        earlier = model_calls.section(tmp_path, "run-incomplete")
    assert earlier["status"] == "unavailable"
    with recording():
        model_calls.bind(tmp_path, "run-incomplete", model, resuming=True, previous=earlier)
        model.invoke("recorded continuation")
        resumed = model_calls.section(tmp_path, "run-incomplete")
    assert resumed["status"] == "unavailable" and resumed["calls"] is None
    assert "append refused" in resumed["reason"]
    # The gap remains durable even if a later caller has only the trace.
    reloaded = model_calls.ModelCalls(tmp_path, "run-incomplete", metered=True, resuming=True)
    assert reloaded.section()["status"] == "unavailable"


def test_an_interrupted_call_remains_pending_after_resume(tmp_path, monkeypatch):
    model = _model(monkeypatch)
    meter = next(cb for cb in model.callbacks if isinstance(cb, prompt_budget.TokenMeter))
    with recording():
        model_calls.bind(tmp_path, "run-pending", model)
        meter.on_llm_start({}, ["interrupted invocation"], run_id="interrupted")
    with recording():
        model_calls.bind(tmp_path, "run-pending", model, resuming=True)
        model.invoke("continuation")
        resumed = model_calls.section(tmp_path, "run-pending")
    assert resumed["calls"] == 2 and resumed["finished"] == resumed["pending"] == 1


def test_actual_client_error_is_counted_without_retaining_the_provider_body(tmp_path):
    class Refuses(FakeListChatModel):
        def _call(self, *a, **k):
            raise RuntimeError("private provider response")

    model = Refuses(responses=[], callbacks=[prompt_budget.TokenMeter({"model": "refusing-local-client"})])
    with recording():
        model_calls.bind(tmp_path, "run-refused", model)
        with pytest.raises(RuntimeError, match="private provider"):
            model.invoke("private input")
        summary = model_calls.section(tmp_path, "run-refused")
    assert summary["calls"] == summary["finished"] == summary["failed"] == 1
    assert "private" not in json.dumps(_events(tmp_path, "run-refused"))


@pytest.mark.parametrize("mode", [1, 2, 3])
def test_native_run_writers_persist_the_actual_client_callbacks(tmp_path, monkeypatch, mode):
    case = tmp_path / "CASE-METRICS"
    (case / "analysis").mkdir(parents=True)
    model = _model(monkeypatch)
    monkeypatch.setattr("nexus.langgraph.case_digest.build_case_digest", lambda *a, **k: {})
    if mode == 1:
        from nexus.langgraph import pipeline_runs

        async def no_tools(*a, **k):
            return {}

        async def graph(*a, **k):
            with_model = llm_pipeline.get_model()
            run = pipeline_runs.create_run(case, "interpret")
            await with_model.ainvoke("measurement protocol")
            pipeline_runs.finalize_run(run, "completed")
            return json.loads((run.path / "manifest.json").read_text(encoding="utf-8"))

        monkeypatch.setattr(llm_pipeline, "_load_mcp_tools", no_tools)
        monkeypatch.setattr(llm_pipeline, "_run_pipeline_with_tools", graph)
        saved = asyncio.run(llm_pipeline.run_pipeline(case_id=case.name, mode="interpret"))
    elif mode == 2:
        from nexus.modes import multi_role as m2

        monkeypatch.setattr(m2, "plan_work_orders", lambda *a, **k: [m2.WorkOrder(
            order_id="measurement-order", role="evidence", task="measurement protocol")])

        def work(order, **kwargs):
            model.invoke("measurement protocol")
            m2.request_stop(case, kwargs["run_id"])
            return m2.AgentResult(order_id=order.order_id, role=order.role, status="ok", parsed={})

        monkeypatch.setattr(m2, "run_work_order", work)
        state = m2.run_mode2(case, "measurement protocol", model=model, es_ok=True)
        saved = json.loads((case / "analysis" / "mode2_runs" / f"{state['run_id']}.json").read_text(encoding="utf-8"))
    else:
        from nexus.modes import multi_agent as m3

        run_id = "M3-measurement-protocol"

        def seat(spawn, board, step):
            model.invoke("measurement protocol")
            m3.request_stop_run(case, run_id)
            return {"claims": []}

        state = m3.run_mode3(case, "measurement protocol", run_id=run_id, families=[("evtxecmd", 0)],
                             seat_fn=seat, model=model, es_ok=True)
        saved = json.loads((case / "analysis" / "mode3_runs" / f"{state['run_id']}.json").read_text(encoding="utf-8"))
    measured = saved["model_measurement"]
    starts = [e for e in _events(case, saved["run_id"]) if e["event"] == "call_started"]
    assert measured["status"] == "available" and measured["calls"] == len(starts) > 0
    assert measured["prompt_chars"] == sum(e["prompt_chars"] for e in starts)
    assert measured["finished"] == measured["calls"] and measured["pending"] == 0
