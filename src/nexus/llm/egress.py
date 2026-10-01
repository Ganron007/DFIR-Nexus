"""Anonymize victim identifiers before a non-loopback LLM call.

Tokens persist in the active case at ``analysis/egress_tokens.json`` so the
same host or private IP keeps the same token across turns. The file stays on
disk. ``NEXUS_LLM_EGRESS=raw`` turns this off.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from urllib.parse import urlparse

from nexus.ingest.anonymize import Anonymizer, deanonymize

_TOKEN_FILE = "egress_tokens.json"


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
    path = _token_path(case_dir)
    if path is None or not path.is_file():
        return engine
    try:
        saved = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return engine
    if not isinstance(saved, dict):
        return engine
    for original, token in saved.items():
        if not isinstance(original, str) or not isinstance(token, str):
            continue
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


def anonymize_text(text: str, case_dir: Path | None, allowlist: set[str] | None = None) -> str:
    """Tokenize *text* and persist any new tokens for this case."""
    engine = load_anonymizer(case_dir, allowlist)
    rewritten, mapping = engine.anonymize(text, reset=False)
    path = _token_path(case_dir)
    if path is not None and mapping:
        existing: dict[str, str] = {}
        if path.is_file():
            try:
                loaded = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    existing = {str(k): str(v) for k, v in loaded.items()}
            except (OSError, ValueError):
                existing = {}
        existing.update(mapping)
        path.write_text(json.dumps(existing, indent=2, sort_keys=True), encoding="utf-8")
    return rewritten


def restore_tool_calls(tool_calls: list[dict], case_dir: Path | None) -> list[dict]:
    """Put real values back into tool-call argument strings."""
    restored: list[dict] = []
    for call in tool_calls or []:
        if not isinstance(call, dict):
            restored.append(call)
            continue
        function = call.get("function")
        if not isinstance(function, dict):
            restored.append(call)
            continue
        arguments = function.get("arguments")
        if not isinstance(arguments, str):
            restored.append(call)
            continue
        restored.append({
            **call,
            "function": {**function, "arguments": restore_text(arguments, case_dir)},
        })
    return restored


def restore_text(text: str, case_dir: Path | None) -> str:
    """Put real values back into a model reply."""
    path = _token_path(case_dir)
    if path is None or not path.is_file():
        return text
    try:
        saved = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return text
    if not isinstance(saved, dict):
        return text
    return deanonymize(text, {str(k): str(v) for k, v in saved.items()})


def _active_case_dir() -> Path | None:
    try:
        from nexus.case_manager import CaseManager

        return CaseManager().require_active_case()
    except Exception:  # noqa: BLE001 — no case means an in-memory token map
        return None


def attach_egress(model):
    """Anonymize outgoing chat text and restore the reply."""
    original = model._generate

    def _generate(messages, stop=None, run_manager=None, **kwargs):
        case = _active_case_dir()
        converted = []
        for message in messages:
            content = getattr(message, "content", None)
            if isinstance(content, str):
                message = message.model_copy(
                    update={"content": anonymize_text(content, case)},
                )
            converted.append(message)
        result = original(converted, stop=stop, run_manager=run_manager, **kwargs)
        for group in getattr(result, "generations", []) or []:
            for chunk in group:
                text = getattr(chunk, "text", None)
                if isinstance(text, str):
                    chunk.text = restore_text(text, case)
                reply = getattr(chunk, "message", None)
                if reply is not None and isinstance(getattr(reply, "content", None), str):
                    reply.content = restore_text(reply.content, case)
                calls = getattr(reply, "tool_calls", None) if reply is not None else None
                if isinstance(calls, list):
                    for call in calls:
                        if isinstance(call, dict) and isinstance(call.get("args"), str):
                            call["args"] = restore_text(call["args"], case)
        return result

    model._generate = _generate
    return model
