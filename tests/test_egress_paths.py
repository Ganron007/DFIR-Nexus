"""WO-V3: egress covers async, streaming and tool-call arguments.

These run the real dispatch: a ``BaseChatModel`` subclass records the exact
payload each entry point receives, so a path that skips anonymization shows up
as raw text in the recorder instead of passing a mock's assertion.

The defect this guards (2026-10-02): ``attach_egress`` patched only
``_generate``. ``ChatOpenAI`` overrides ``_agenerate``, ``_stream`` and
``_astream``, so a react agent's ``ainvoke`` sent the raw host and the raw
private IP to the provider while the sync path was correctly tokenized.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("langchain_core")

from langchain_core.language_models.chat_models import BaseChatModel  # noqa: E402
from langchain_core.messages import (  # noqa: E402
    AIMessage,
    AIMessageChunk,
    HumanMessage,
    ToolMessage,
)
from langchain_core.outputs import (  # noqa: E402
    ChatGeneration,
    ChatGenerationChunk,
    ChatResult,
)
from pydantic import Field  # noqa: E402

from nexus.llm.egress import attach_egress, egress_required  # noqa: E402

HOST = "WS01.corp.local"
PRIVATE_IP = "10.1.2.3"


def _flatten(messages) -> str:
    """Everything the provider would see, as one string."""
    parts: list[str] = []
    for message in messages:
        content = getattr(message, "content", None)
        if isinstance(content, str):
            parts.append(content)
        elif isinstance(content, list):
            parts.append(json.dumps(content, default=str))
        calls = getattr(message, "tool_calls", None)
        if calls:
            parts.append(json.dumps(calls, default=str))
    return "\n".join(parts)


class RecordingChatModel(BaseChatModel):
    """A real chat model that records the payload every path hands it."""

    script: list = Field(default_factory=list)
    seen: list = Field(default_factory=list)
    stream_pieces: list = Field(default_factory=list)

    @property
    def _llm_type(self) -> str:
        return "recording"

    def bind_tools(self, tools, **kwargs):
        """Ignore the schemas: this recorder is not a tool-calling transport."""
        return self

    def _take(self, messages) -> AIMessage:
        self.seen.append(_flatten(messages))
        if self.script:
            return self.script.pop(0)
        return AIMessage(content="no script")

    def _generate(self, messages, stop=None, run_manager=None, **kwargs) -> ChatResult:
        return ChatResult(generations=[ChatGeneration(message=self._take(messages))])

    async def _agenerate(self, messages, stop=None, run_manager=None, **kwargs) -> ChatResult:
        return self._generate(messages, stop=stop, run_manager=run_manager, **kwargs)

    def _stream(self, messages, stop=None, run_manager=None, **kwargs):
        message = self._take(messages)
        text = message.content if isinstance(message.content, str) else ""
        for piece in (self.stream_pieces or [text]):
            yield ChatGenerationChunk(message=AIMessageChunk(content=piece))

    async def _astream(self, messages, stop=None, run_manager=None, **kwargs):
        message = self._take(messages)
        text = message.content if isinstance(message.content, str) else ""
        for piece in (self.stream_pieces or [text]):
            yield ChatGenerationChunk(message=AIMessageChunk(content=piece))


@pytest.fixture
def egress_case(tmp_path: Path) -> Path:
    """An active case, so the token file has somewhere real to live.

    The conftest already points ``NEXUS_ACTIVE_CASE_FILE`` and
    ``settings.cases_root`` at this tmp tree; the case just has to exist.
    """
    case = tmp_path / "cases" / "CASE-EGRESS"
    (case / "analysis").mkdir(parents=True)
    # resolve_case_dir() requires CASE.yaml next to the case, not just the dir.
    (case / "CASE.yaml").write_text("id: CASE-EGRESS\n", encoding="utf-8")
    (tmp_path / "active_case").write_text("CASE-EGRESS", encoding="utf-8")
    return case


def _probe_messages() -> list:
    """Inbound text that must never leave raw, in every shape that can carry it."""
    return [
        HumanMessage(content=f"Host {HOST} at {PRIVATE_IP}"),
        HumanMessage(content=[{"type": "text", "text": f"also {HOST}"}]),
        ToolMessage(content=f"row from {HOST}", tool_call_id="t1"),
        AIMessage(
            content="earlier",
            tool_calls=[{
                "name": "es_search",
                "args": {"host": HOST},
                "id": "call-1",
            }],
        ),
    ]


def _assert_clean(payload: str, where: str) -> None:
    assert HOST not in payload, f"{where} leaked the host: {payload[:200]}"
    assert PRIVATE_IP not in payload, f"{where} leaked the private IP: {payload[:200]}"


def test_every_model_entry_point_is_tokenized(egress_case: Path):
    """invoke, ainvoke, stream and astream must all send tokens, not raw text."""
    import asyncio

    model = attach_egress(RecordingChatModel(script=[
        AIMessage(content="a"), AIMessage(content="b"),
        AIMessage(content="c"), AIMessage(content="d"),
    ]))

    model.invoke(_probe_messages())
    asyncio.run(model.ainvoke(_probe_messages()))
    list(model.stream(_probe_messages()))

    async def _drain() -> None:
        async for _chunk in model.astream(_probe_messages()):
            pass

    asyncio.run(_drain())

    assert len(model.seen) == 4, model.seen
    for index, payload in enumerate(model.seen):
        _assert_clean(payload, f"entry point {index} (invoke, ainvoke, stream, astream)")


def test_tool_call_arguments_are_restored_then_re_tokenized(egress_case: Path):
    """Outbound restores the real host; the next turn re-sends the token."""
    import asyncio

    from nexus.llm.egress import anonymize_text

    token = anonymize_text(f"host {HOST}", egress_case).split()[-1]
    assert HOST not in token

    model = attach_egress(RecordingChatModel(script=[
        AIMessage(content="", tool_calls=[{
            "name": "es_search", "args": {"host": token}, "id": "call-1",
        }]),
        AIMessage(content="done"),
    ]))

    first = model.invoke([HumanMessage(content="where?")])
    # ``BaseChatModel.invoke`` returns the message itself in langchain 1.x.
    calls = first.tool_calls
    # Outbound: the caller (and so the tool) sees the real value.
    assert calls[0]["args"]["host"] == HOST

    # Inbound again: the assistant message we just restored must go back out
    # tokenized, or turn two hands the provider the raw host.
    model.invoke([HumanMessage(content="where?"), first])
    _assert_clean(model.seen[1], "second turn")

    # And the async path behaves the same way.
    model2 = attach_egress(RecordingChatModel(script=[
        AIMessage(content="", tool_calls=[{
            "name": "es_search", "args": {"host": token}, "id": "call-2",
        }]),
    ]))
    result = asyncio.run(model2.ainvoke([HumanMessage(content="where?")]))
    assert result.tool_calls[0]["args"]["host"] == HOST


def test_streaming_restores_a_token_split_across_chunks(egress_case: Path):
    """A token can straddle two chunks; the stream must still come out real."""
    from nexus.llm.egress import anonymize_text

    token = anonymize_text(f"at {PRIVATE_IP}", egress_case).split()[-1]
    split = len(token) // 2
    model = attach_egress(RecordingChatModel(
        stream_pieces=["row at ", token[:split], token[split:], " done"],
    ))
    text = "".join(chunk.text for chunk in model.stream([HumanMessage(content="q")]))
    assert text == f"row at {PRIVATE_IP} done", text


def test_loopback_and_raw_are_not_wrapped(monkeypatch: pytest.MonkeyPatch):
    assert egress_required("https://api.example.com/v1") is True
    assert egress_required("http://127.0.0.1:11434/v1") is False
    assert egress_required("http://localhost:1234/v1") is False
    monkeypatch.setenv("NEXUS_LLM_EGRESS", "raw")
    assert egress_required("https://api.example.com/v1") is False


def test_attached_model_is_still_a_chat_model_and_binds_tools():
    """create_react_agent needs a BaseChatModel and calls bind_tools.

    Run against a real ``ChatOpenAI`` (no request is made): the work order's
    constraint is that attaching egress must not change the model's type or
    break the binding the agent builds.
    """
    pytest.importorskip("langchain_openai")
    from langchain_openai import ChatOpenAI

    model = ChatOpenAI(
        model="gpt-4o-mini",
        api_key="egress-test",  # type: ignore[arg-type]
        base_url="https://api.example.com/v1",
    )
    attach_egress(model)
    assert isinstance(model, BaseChatModel)
    bound = model.bind_tools([])
    # The binding wraps this instance, so the patched methods are the ones that
    # run — a binding of a clean copy would silently bypass egress.
    assert getattr(bound, "bound", None) is model


def test_react_agent_tool_gets_real_values_and_the_provider_gets_tokens(
    egress_case: Path, monkeypatch: pytest.MonkeyPatch
):
    """The end-to-end shape: agent -> tool call -> tool -> reply."""
    pytest.importorskip("langgraph.prebuilt")
    import asyncio

    from langchain_core.tools import StructuredTool
    from langgraph.prebuilt import create_react_agent

    from nexus.llm.egress import anonymize_text

    token = anonymize_text(f"host {HOST}", egress_case).split()[-1]
    seen_by_tool: list[dict] = []

    def _search(host: str) -> str:
        """Search the case index for a host."""
        seen_by_tool.append({"host": host})
        return f"searched {host}"

    tool = StructuredTool.from_function(_search, name="es_search")

    model = attach_egress(RecordingChatModel(script=[
        AIMessage(content="", tool_calls=[{
            "name": "es_search", "args": {"host": token}, "id": "call-1",
        }]),
        AIMessage(content="final answer"),
    ]))
    agent = create_react_agent(model, [tool])
    result = asyncio.run(agent.ainvoke({"messages": [HumanMessage(content="where?")]}))

    # The tool ran on the real value, not on a placeholder.
    assert seen_by_tool and seen_by_tool[0]["host"] == HOST, seen_by_tool
    # The provider never saw it.
    for index, payload in enumerate(model.seen):
        _assert_clean(payload, f"react agent turn {index}")
    assert result["messages"][-1].content == "final answer"
