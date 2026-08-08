"""Hunt-agent output parser — extracts finding candidates from LLM messages.

Pure-stdlib module. Kept separate from llm_pipeline.py so it can be unit-tested
without importing langgraph / langchain.

The hunt node in llm_pipeline.py invokes a ReAct agent that may emit findings
as: (a) a single JSON object as the whole message, (b) one or more
```json fenced blocks, (c) prose with no machine-readable findings. Cases
(a) and (b) feed real candidates into stage_findings; case (c) triggers
the placeholder fallback.
"""

from __future__ import annotations

import json as _json
import re as _re
from typing import Any

_FENCE_RE = _re.compile(r'```(?:json)?\s*\n?(.*?)```', _re.DOTALL)


def _message_content(msg: Any) -> str:
    """Extract string content from a LangChain message, a dict, or a string."""
    if isinstance(msg, str):
        return msg
    if isinstance(msg, dict):
        content = msg.get("content", "")
        return content if isinstance(content, str) else str(content)
    content = getattr(msg, "content", None)
    if content is None:
        return ""
    return content if isinstance(content, str) else str(content)


def normalize_candidate(data: dict) -> dict:
    """Clamp and coerce a parsed candidate to record_finding's input shape."""
    return {
        "title": str(data.get("title", ""))[:200],
        "observation": str(data.get("observation", data.get("description", "")))[:2000],
        "interpretation": str(data.get("interpretation", ""))[:2000],
        "confidence": str(data.get("confidence", "MEDIUM")).upper(),
        "host": str(data.get("host", ""))[:200],
        "event_timestamp": str(data.get("event_timestamp", data.get("timestamp", ""))),
        "type": str(data.get("type", "")),
        "attack_ids": data.get("attack_ids") or data.get("mitre_ids") or [],
        "iocs": data.get("iocs") or [],
    }


def _looks_like_finding(obj: Any, *, require_observation: bool) -> bool:
    """Reject anything that isn't a dict carrying at least a title."""
    if not isinstance(obj, dict):
        return False
    if not obj.get("title"):
        return False
    return not (require_observation and not obj.get("observation"))


def parse_hunt_candidates(messages: list) -> list[dict]:
    """Extract finding candidates from the last few hunt-agent messages.

    Scans the last 5 messages for either (a) a single JSON object as the
    full content (requires `title` + `observation`), or (b) JSON inside
    markdown ```json``` fences (requires only `title`). Malformed JSON,
    non-dict payloads, and dicts missing the required keys are skipped
    silently so the caller can rely on the empty-list signal to trigger
    the placeholder fallback in stage_findings.
    """
    candidates: list[dict] = []
    if not messages:
        return candidates

    for msg in messages[-5:]:
        content = _message_content(msg)
        if not content:
            continue

        # (a) whole-content JSON — stricter: needs title + observation
        try:
            data = _json.loads(content)
        except (_json.JSONDecodeError, ValueError, TypeError):
            data = None
        if _looks_like_finding(data, require_observation=True):
            candidates.append(normalize_candidate(data))
            continue

        # (b) fenced JSON blocks — title alone is enough
        for match in _FENCE_RE.finditer(content):
            block = match.group(1).strip()
            if not block:
                continue
            try:
                parsed = _json.loads(block)
            except (_json.JSONDecodeError, ValueError):
                continue
            if isinstance(parsed, dict) and _looks_like_finding(parsed, require_observation=False):
                candidates.append(normalize_candidate(parsed))
            elif isinstance(parsed, list):
                for item in parsed:
                    if _looks_like_finding(item, require_observation=False):
                        candidates.append(normalize_candidate(item))

    return candidates
