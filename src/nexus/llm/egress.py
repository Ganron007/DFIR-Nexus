"""Anonymize victim identifiers before a non-loopback LLM call.

Tokens persist in the active case at ``analysis/egress_tokens.json`` so the
same host or private IP keeps the same token across turns. The file stays on
disk. ``NEXUS_LLM_EGRESS=raw`` turns this off.

**Every** model entry point is covered: ``_generate``, ``_agenerate``,
``_stream`` and ``_astream``. Patching only ``_generate`` (the first version)
left the async and streaming paths wide open: ``ChatOpenAI`` overrides all four,
so a react agent's ``ainvoke`` sent the raw host and the raw private IP to the
provider while the sync path was correctly tokenized.

Inbound, everything that leaves is tokenized: each message's string content,
the text parts of list content, a ``ToolMessage``'s content, and
``tool_calls[*].args`` — the last one matters because a restored reply puts the
real values back, and the next turn re-sends that assistant message.
"""
from __future__ import annotations

import contextlib
import json
import logging
import os
import tempfile
import threading
from pathlib import Path
from urllib.parse import urlparse

from nexus.ingest.anonymize import Anonymizer, deanonymize

log = logging.getLogger(__name__)

_TOKEN_FILE = "egress_tokens.json"

#: Serializes the read-modify-write of the per-case token file. Two turns on one
#: case share it, and a lost update would hand out a token with no mapping.
_TOKEN_LOCK = threading.Lock()


def egress_required(base_url: str) -> bool:
    """True when the configured endpoint is not on this machine."""
    if os.environ.get("NEXUS_LLM_EGRESS", "").strip().lower() == "raw":
        return False
    host = (urlparse(base_url or "").hostname or "").lower()
    if not host:
        return False
    return host not in {"localhost", "127.0.0.1", "::1"}


def _token_path(case_dir: Path | None) -> Path | None:
    if case_dir is None:
        return None
    path = Path(case_dir) / "analysis" / _TOKEN_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def load_anonymizer(case_dir: Path | None, allowlist: set[str] | None = None) -> Anonymizer:
    """An anonymizer seeded from the case token file, if one exists."""
    engine = Anonymizer(allowlist=set(allowlist or set()))
    for original, token in _load_tokens(case_dir).items():
        inner = token.strip("{}")
        kind = inner.rsplit("_", 1)[0] or "VAL"
        engine._token_dict[f"{kind}:{original}"] = token
        engine._reverse_dict[token] = original
        try:
            n = int(inner.rsplit("_", 1)[-1])
        except ValueError:
            n = 0
        engine._counters[kind] = max(engine._counters.get(kind, 0), n)
    return engine


def _load_tokens(case_dir: Path | None) -> dict[str, str]:
    path = _token_path(case_dir)
    if path is None or not path.is_file():
        return {}
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(loaded, dict):
        return {}
    return {str(k): str(v) for k, v in loaded.items()}


def _write_tokens(path: Path, mapping: dict[str, str]) -> None:
    """Atomic replace: a half-written file loses every earlier token."""
    payload = json.dumps(mapping, indent=2, sort_keys=True)
    fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    try:
        os.close(fd)
        Path(tmp_name).write_text(payload, encoding="utf-8")
        os.replace(tmp_name, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp_name)
        raise


def anonymize_text(text: str, case_dir: Path | None, allowlist: set[str] | None = None) -> str:
    """Tokenize *text* and persist any new tokens for this case."""
    engine = load_anonymizer(case_dir, allowlist)
    rewritten, mapping = engine.anonymize(text, reset=False)
    path = _token_path(case_dir)
    if path is not None and mapping:
        with _TOKEN_LOCK:
            existing = _load_tokens(case_dir)
            existing.update(mapping)
            _write_tokens(path, existing)
    return rewritten


def _anonymize_obj(value, case_dir: Path | None):
    if isinstance(value, str):
        return anonymize_text(value, case_dir)
    if isinstance(value, dict):
        return {str(key): _anonymize_obj(item, case_dir) for key, item in value.items()}
    if isinstance(value, list):
        return [_anonymize_obj(item, case_dir) for item in value]
    return value


def _restore_obj(value, case_dir: Path | None):
    if isinstance(value, str):
        return restore_text(value, case_dir)
    if isinstance(value, dict):
        return {str(key): _restore_obj(item, case_dir) for key, item in value.items()}
    if isinstance(value, list):
        return [_restore_obj(item, case_dir) for item in value]
    return value


def _restore_obj_with(value, mapping: dict[str, str]):
    if isinstance(value, str):
        return deanonymize(value, mapping)
    if isinstance(value, dict):
        return {str(key): _restore_obj_with(item, mapping) for key, item in value.items()}
    if isinstance(value, list):
        return [_restore_obj_with(item, mapping) for item in value]
    return value


def _tokenize_content(content, case_dir: Path | None):
    """Anonymize a message body, including the text parts of list content."""
    if isinstance(content, str):
        return anonymize_text(content, case_dir)
    if isinstance(content, list):
        out = []
        for part in content:
            if isinstance(part, str):
                out.append(anonymize_text(part, case_dir))
            elif isinstance(part, dict) and isinstance(part.get("text"), str):
                out.append({**part, "text": anonymize_text(part["text"], case_dir)})
            else:
                out.append(part)
        return out
    return content


def _anonymize_tool_calls(tool_calls, case_dir: Path | None):
    """Tokenize the arguments a previous turn's reply restored to real values."""
    out = []
    for call in tool_calls:
        if not isinstance(call, dict):
            out.append(call)
            continue
        updated = dict(call)
        if "args" in updated:
            updated["args"] = _anonymize_obj(updated["args"], case_dir)
        function = updated.get("function")
        if isinstance(function, dict) and "arguments" in function:
            updated["function"] = {
                **function,
                "arguments": _anonymize_obj(function.get("arguments"), case_dir),
            }
        out.append(updated)
    return out


def _anonymize_messages(messages, case_dir: Path | None):
    """Tokenize every outbound message. Returns a new list; never mutates."""
    converted = []
    for message in messages:
        updates: dict = {}
        content = getattr(message, "content", None)
        tokenized = _tokenize_content(content, case_dir)
        if tokenized is not content:
            updates["content"] = tokenized
        tool_calls = getattr(message, "tool_calls", None)
        if isinstance(tool_calls, list) and tool_calls:
            updates["tool_calls"] = _anonymize_tool_calls(tool_calls, case_dir)
        converted.append(message.model_copy(update=updates) if updates else message)
    return converted


def restore_tool_calls(tool_calls: list[dict], case_dir: Path | None) -> list[dict]:
    """Put real values back into tool-call arguments (strings or objects)."""
    restored: list[dict] = []
    for call in tool_calls or []:
        if not isinstance(call, dict):
            restored.append(call)
            continue
        updated = dict(call)
        if "args" in updated:
            updated["args"] = _restore_obj(updated["args"], case_dir)
        function = updated.get("function")
        if isinstance(function, dict) and "arguments" in function:
            updated["function"] = {
                **function,
                "arguments": _restore_obj(function.get("arguments"), case_dir),
            }
        restored.append(updated)
    return restored


def restore_text(text: str, case_dir: Path | None) -> str:
    """Put real values back into a model reply."""
    saved = _load_tokens(case_dir)
    if not saved:
        return text
    return deanonymize(text, saved)


def _restored_message(message, case_dir: Path | None):
    """A copy of a returned message with content and tool-call args restored.

    Replacement, not in-place mutation. Once ``chunk.text`` has been assigned,
    reading ``chunk.message`` hands back a message rebuilt from the serialized
    fields, so a mutation applied to the object read a moment earlier is thrown
    away — measured: the tool-call arguments silently reverted to their tokens.
    Building a copy and assigning it onto the generation survives.
    """
    if message is None:
        return message
    updates: dict = {}
    content = getattr(message, "content", None)
    if isinstance(content, str) and content:
        updates["content"] = restore_text(content, case_dir)
    calls = getattr(message, "tool_calls", None)
    if isinstance(calls, list) and calls:
        updates["tool_calls"] = restore_tool_calls(calls, case_dir)
    if not updates:
        return message
    try:
        return message.model_copy(update=updates)
    except Exception:  # noqa: BLE001 — fall back to the mutating path
        return _restore_in_place(message, case_dir)


def _restore_in_place(message, case_dir: Path | None) -> None:
    """Legacy in-place restore. Used only if ``model_copy`` is unavailable."""
    content = getattr(message, "content", None)
    if isinstance(content, str):
        message.content = restore_text(content, case_dir)
    calls = getattr(message, "tool_calls", None)
    if isinstance(calls, list) and calls:
        for call in calls:
            if isinstance(call, dict) and "args" in call:
                call["args"] = _restore_obj(call["args"], case_dir)
    return message


class _StreamRestorer:
    """Restore tokens in a text stream without waiting for the whole reply.

    A token (``{{HOST_1}}``) can straddle two chunks, so the tail from the last
    unterminated ``{{`` is held until the next chunk completes it — or until
    ``flush()`` at the end of the stream. Nothing is dropped, and the delay is
    at most one token.
    """

    _OPEN = "{{"

    def __init__(self, case_dir: Path | None) -> None:
        self._case = case_dir
        self._tail = ""
        self._mapping = _load_tokens(case_dir)

    def push(self, text: str) -> str:
        buffered = self._tail + (text or "")
        cut = len(buffered)
        start = buffered.rfind(self._OPEN)
        if start != -1 and "}}" not in buffered[start:]:
            cut = start
        elif buffered.endswith("{"):
            # A lone brace may become an opening "{{" in the next chunk.
            cut = len(buffered) - 1
        emitted, self._tail = buffered[:cut], buffered[cut:]
        return deanonymize(emitted, self._mapping) if emitted else ""

    def flush(self) -> str:
        remainder, self._tail = self._tail, ""
        return deanonymize(remainder, self._mapping) if remainder else ""


def _active_case_dir() -> Path | None:
    try:
        from nexus.case_manager import CaseManager

        return CaseManager().require_active_case()
    except Exception:  # noqa: BLE001 — no case means an in-memory token map
        return None


def _iter_generations(result):
    """Every generation in a ``ChatResult`` or an ``LLMResult``.

    ``ChatResult.generations`` is a flat list of ``ChatGeneration``;
    ``LLMResult.generations`` is a list of lists. Iterating the wrong one is
    silent, not loud: a ``ChatGeneration`` is a pydantic model, so iterating it
    yields ``(field, value)`` tuples and never raises — which is exactly how the
    outbound restore did nothing while looking like it ran.
    """
    for group in getattr(result, "generations", []) or []:
        if isinstance(group, (list, tuple)):
            yield from group
        else:
            yield group


def _restore_result(result, case_dir: Path | None) -> None:
    for chunk in _iter_generations(result):
        message = getattr(chunk, "message", None)
        restored = _restored_message(message, case_dir)
        if message is not None and restored is not None:
            with contextlib.suppress(Exception):
                chunk.message = restored
        text = getattr(chunk, "text", None)
        if isinstance(text, str):
            with contextlib.suppress(Exception):
                chunk.text = restore_text(text, case_dir)


def attach_egress(model):
    """Tokenize every outbound message and restore every returned one.

    Patching the four ``_*`` methods is deliberate: ``ChatOpenAI`` implements
    all of them, so overriding one leaves the others sending raw text. The
    instance keeps its class, so ``isinstance(model, BaseChatModel)`` stays true
    and ``bind_tools`` (what ``create_react_agent`` calls) keeps working — it
    binds ``self``, so the patched methods are still the ones that run.
    """
    if not hasattr(model, "bind_tools"):
        raise TypeError(
            "attach_egress needs a chat model that implements bind_tools "
            f"(got {type(model).__name__})"
        )
    original_generate = model._generate
    original_agenerate = model._agenerate
    original_stream = model._stream
    original_astream = model._astream

    def _generate(messages, stop=None, run_manager=None, **kwargs):
        case = _active_case_dir()
        result = original_generate(
            _anonymize_messages(messages, case), stop=stop,
            run_manager=run_manager, **kwargs,
        )
        _restore_result(result, case)
        return result

    async def _agenerate(messages, stop=None, run_manager=None, **kwargs):
        case = _active_case_dir()
        result = await original_agenerate(
            _anonymize_messages(messages, case), stop=stop,
            run_manager=run_manager, **kwargs,
        )
        _restore_result(result, case)
        return result

    def _stream(messages, stop=None, run_manager=None, **kwargs):
        case = _active_case_dir()
        restorer = _StreamRestorer(case)
        held = _HeldToolCalls(case)
        last = None
        for chunk in original_stream(
            _anonymize_messages(messages, case), stop=stop,
            run_manager=run_manager, **kwargs,
        ):
            last = chunk
            if held.absorb(chunk):
                continue
            restored = restorer.push(getattr(chunk, "text", "") or "")
            if not restored:
                continue
            _set_chunk_text(chunk, restored)
            yield chunk
        tail = restorer.flush()
        if tail:
            final = _text_chunk(last, tail)
            if final is not None:
                yield final
        yield from held.drain()

    async def _astream(messages, stop=None, run_manager=None, **kwargs):
        case = _active_case_dir()
        restorer = _StreamRestorer(case)
        held = _HeldToolCalls(case)
        last = None
        async for chunk in original_astream(
            _anonymize_messages(messages, case), stop=stop,
            run_manager=run_manager, **kwargs,
        ):
            last = chunk
            if held.absorb(chunk):
                continue
            restored = restorer.push(getattr(chunk, "text", "") or "")
            if not restored:
                continue
            _set_chunk_text(chunk, restored)
            yield chunk
        tail = restorer.flush()
        if tail:
            final = _text_chunk(last, tail)
            if final is not None:
                yield final
        for extra in held.drain():
            yield extra

    model._generate = _generate
    model._agenerate = _agenerate
    model._stream = _stream
    model._astream = _astream
    return model


def _set_chunk_text(chunk, text: str) -> None:
    """Set a streamed chunk's text and its message body together."""
    message = getattr(chunk, "message", None)
    if message is not None and isinstance(getattr(message, "content", None), str):
        message.content = text
    with contextlib.suppress(Exception):
        # ``text`` may be derived from the message rather than stored on it.
        chunk.text = text


def _text_chunk(template, text: str):
    """A final chunk carrying text the restorer held back. None if it cannot."""
    if template is None:
        return None
    try:
        from langchain_core.messages import AIMessageChunk
        from langchain_core.outputs import ChatGenerationChunk

        return ChatGenerationChunk(message=AIMessageChunk(content=text), text=text)
    except Exception:  # noqa: BLE001 — never break a stream over a tail token
        log.warning("egress: could not emit the restored stream tail", exc_info=True)
        return None


class _HeldToolCalls:
    """Hold streamed tool-call fragments so their arguments can be restored.

    A streamed tool call arrives as JSON fragments, so a token inside it can be
    split across chunks and a per-chunk restore cannot work. The fragments are
    accumulated and emitted once at the end of the stream, restored. Trade-off
    recorded in the work order's Deviations section.
    """

    def __init__(self, case_dir: Path | None) -> None:
        self._case = case_dir
        self._slots: dict[int, dict[str, str]] = {}

    def absorb(self, chunk) -> bool:
        """True when the chunk carried tool-call fragments and must not be sent on."""
        message = getattr(chunk, "message", None)
        fragments = getattr(message, "tool_call_chunks", None) if message else None
        if not fragments:
            return False
        if getattr(chunk, "text", "") or getattr(message, "content", ""):
            # A mixed chunk. Dropping it would drop text, and holding only part
            # of it is not possible on a message object, so it goes through as
            # it is. Recorded in the work order's Deviations section.
            return False
        for index, fragment in enumerate(fragments):
            if not isinstance(fragment, dict):
                continue
            slot = self._slots.setdefault(index, {"name": "", "id": "", "args": ""})
            slot["name"] += str(fragment.get("name") or "")
            slot["id"] += str(fragment.get("id") or "")
            slot["args"] += str(fragment.get("args") or "")
        return True

    def drain(self) -> list:
        if not self._slots:
            return []
        try:
            from langchain_core.messages import AIMessageChunk
            from langchain_core.messages.tool import tool_call_chunk
            from langchain_core.outputs import ChatGenerationChunk
        except Exception:  # noqa: BLE001
            return []
        restored = []
        for index in sorted(self._slots):
            slot = self._slots[index]
            restored.append(tool_call_chunk(
                name=slot["name"] or None,
                args=restore_text(slot["args"], self._case),
                id=slot["id"] or None,
                index=index,
            ))
        self._slots = {}
        message = AIMessageChunk(content="", tool_call_chunks=restored)
        return [ChatGenerationChunk(message=message, text="")]
