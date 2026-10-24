"""D380 (2026-10-24): prompts are packed with the measured characters per token, and a refused prompt is re-packed.

T09's Mode 3 seats sent prompts of 516k-803k tokens to agnes-3.0-flash, whose window is 524,288: packing assumed 4
characters per token, and on evidence the model counted about 1.9 (a 1,461,571-character prompt was 772,709 tokens).
The refusal texts below are the provider's own, from T09's R1y and R1c Mode 3 logs.
"""
from __future__ import annotations

import json
from typing import Any

import pytest

from nexus.langgraph import prompt_budget as pb

REFUSED_INPUT = "The input (772709 tokens) is longer than the model's context length (524288 tokens)."
REFUSED_TOTAL = ("Requested token count exceeds the model's maximum context length of 524288 tokens. You requested a "
                 "total of 581791 tokens: 516256 tokens from the input messages and 65535 tokens for the completion. "
                 "Please reduce the number of tokens in the input messages or the completion to fit within the limit.")


@pytest.fixture(autouse=True)
def _fresh_measurements():
    pb.reset_token_measurements()
    yield
    pb.reset_token_measurements()


def test_a_refusal_names_the_prompts_real_token_count():
    assert pb.context_overflow_tokens("Error code: 400 - " + REFUSED_INPUT) == 772_709
    assert pb.context_overflow_tokens(REFUSED_TOTAL) == 516_256
    assert pb.context_overflow_tokens("rate limited") is None


def test_the_character_budget_follows_the_measured_ratio_and_never_rises_above_the_start():
    window = 512_000
    assert pb.budget_chars(window, 0.7) == int(window * 0.7 * 4)
    pb.record_token_count(4_000, 500, "short English")  # 8 chars/token: never raises the start
    assert pb.chars_per_token() == 4
    pb.record_token_count(900, 800, "too short to say anything")
    assert pb.chars_per_token() == 4
    pb.record_token_count(1_461_571, 772_709, "T09 refused prompt")
    ratio = 1_461_571 / 772_709
    assert pb.chars_per_token() == pytest.approx(ratio)
    assert pb.budget_chars(window, 0.7) == int(window * 0.7 * ratio)
    # Packed to that budget, the prompt is the fill share of the window in the model's own tokens.
    assert pb.budget_chars(window, 0.7) / ratio == pytest.approx(window * 0.7, rel=1e-5)


def test_the_meter_records_usage_and_a_refusal():
    from langchain_core.messages import AIMessage, HumanMessage
    from langchain_core.outputs import ChatGeneration, LLMResult

    meter = pb.TokenMeter()
    text = "x" * 30_000
    meter.on_chat_model_start({}, [[HumanMessage(content=text)]], run_id="a")
    message = AIMessage(content="{}", usage_metadata={"input_tokens": 10_000, "output_tokens": 5,
                                                       "total_tokens": 10_005})
    meter.on_llm_end(LLMResult(generations=[[ChatGeneration(message=message)]]), run_id="a")
    assert pb.chars_per_token() == pytest.approx(3.0)

    meter.on_chat_model_start({}, [[HumanMessage(content="y" * 1_461_571)]], run_id="b")
    meter.on_llm_error(RuntimeError(REFUSED_INPUT), run_id="b")
    assert pb.chars_per_token() == pytest.approx(1_461_571 / 772_709)


def test_get_model_attaches_the_meter(monkeypatch):
    from nexus.langgraph import llm_pipeline

    monkeypatch.setenv("NEXUS_LLM_MODEL", "meter-test")
    monkeypatch.setenv("NEXUS_LLM_BASE_URL", "http://127.0.0.1:9/v1")
    monkeypatch.setenv("NEXUS_LLM_PROVIDER", "openai-compatible")
    model = llm_pipeline.get_model()
    assert any(isinstance(cb, pb.TokenMeter) for cb in (model.callbacks or []))


class _RefusingModel:
    """Refuses the first ``refusals`` prompts with the provider's message, then answers."""

    def __init__(self, refusals: int):
        self.refusals = refusals
        self.prompts: list[list[dict[str, str]]] = []

    def invoke(self, messages):
        self.prompts.append(messages)
        if len(self.prompts) <= self.refusals:
            raise RuntimeError("Error code: 400 - {'error': {'message': \"" + REFUSED_INPUT + "\"}}")

        class _R:
            content = json.dumps({"answer": "done", "citations": []})

        return _R()


def _loop(tmp_path, model) -> dict[str, Any]:
    from nexus.audit import AuditWriter
    from nexus.langgraph.context_loop import run_context_loop

    case = tmp_path / "CASE-D380"
    (case / "analysis").mkdir(parents=True)
    return run_context_loop(case_dir=case, case_id="CASE-D380", question="What ran?", model=model,
                            audit=AuditWriter("nexus", audit_dir=case / "audit"))


def test_the_context_loop_repacks_a_refused_round_once_and_goes_on(tmp_path):
    model = _RefusingModel(refusals=1)
    result = _loop(tmp_path, model)
    assert result["finish_reason"] == "answer"
    assert len(model.prompts) == 2
    assert pb.chars_per_token() < 4  # the refusal's own count was recorded
    assert any(s.get("status") == "repacked" for s in result.get("stages") or [])


def test_a_second_refusal_of_the_same_round_ends_the_loop_as_a_model_error(tmp_path):
    model = _RefusingModel(refusals=5)
    result = _loop(tmp_path, model)
    assert result["finish_reason"] == "model_error"
    rounds = [p for p in model.prompts if "Return the next JSON object now." in p[-1]["content"]]
    assert len(rounds) == 2  # one re-pack, never a retry loop (the force-answer pass is separate)


def test_the_force_answer_prompt_is_clipped_to_the_budget_measured_now():
    from nexus.langgraph.context_loop import _force_answer

    seen: list[str] = []

    class _M:
        def invoke(self, messages):
            seen.append(messages[-1]["content"])

            class _R:
                content = json.dumps({"answer": "ok"})

            return _R()

    observations = [{"tool": "es_search", "why": "w", "audit_id": "a1", "summary": {"rows": "r" * 50_000}}]
    _force_answer(model=_M(), base_system="s", question="q", observations=observations,
                  call_chars=10_000_000, prompt_chars=20_000)
    assert len(seen[0]) < 21_000
