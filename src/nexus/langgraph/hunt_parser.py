"""Hunt-agent output parser — extracts finding candidates from LLM messages.

Pure-stdlib module. Kept separate from llm_pipeline.py so it can be unit-tested
without importing langgraph / langchain.

The hunt node in llm_pipeline.py invokes a ReAct agent that may emit findings
as: (a) a single JSON object as the whole message, (b) one or more
```json fenced blocks, (c) a JSON array/object buried in prose, (d) no
machine-readable findings. Cases (a)–(c) feed real candidates into
stage_findings; case (d) returns [] so the caller can salvage N4 hits.
"""

from __future__ import annotations

import json as _json
import re as _re
from typing import Any

_FENCE_RE = _re.compile(r'```(?:json)?\s*\n?(.*?)```', _re.DOTALL)


def _recover_json_blob(content: str) -> Any:
    """Parse a JSON array/object buried in prose (LLM often omits fences)."""
    if '"title"' not in content:
        return None
    blobs: list[str] = []
    start_a, end_a = content.find("["), content.rfind("]")
    if start_a != -1 and end_a > start_a:
        blobs.append(content[start_a : end_a + 1])
    start_o, end_o = content.find("{"), content.rfind("}")
    if start_o != -1 and end_o > start_o:
        blobs.append(content[start_o : end_o + 1])
    for blob in blobs:
        try:
            return _json.loads(blob)
        except (_json.JSONDecodeError, ValueError, TypeError):
            continue
    return None


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
    audit_ids = data.get("audit_ids") or []
    if isinstance(audit_ids, str):
        audit_ids = [audit_ids]
    artifacts = data.get("artifacts") or []
    if not isinstance(artifacts, list):
        artifacts = []
    for aid in audit_ids:
        if aid and not any(isinstance(a, dict) and a.get("audit_id") == aid for a in artifacts):
            artifacts.append({"audit_id": str(aid), "type": "audit"})
    # Optional extraction paths from the LLM (output_saved_to / output_files)
    for key in ("output_paths", "extraction_paths", "output_files"):
        raw = data.get(key) or []
        if isinstance(raw, str):
            raw = [raw]
        if not isinstance(raw, list):
            continue
        for item in raw:
            path = item.get("path") if isinstance(item, dict) else item
            if path and not any(
                isinstance(a, dict) and a.get("path") == path for a in artifacts
            ):
                artifacts.append({"path": str(path), "type": "extraction"})
    saved = data.get("output_saved_to")
    if saved and not any(
        isinstance(a, dict) and a.get("path") == saved for a in artifacts
    ):
        artifacts.append({"path": str(saved), "type": "extraction"})
    itm_stage = str(data.get("itm_stage") or data.get("itm") or "").strip()
    itm_objects = data.get("itm_objects") or data.get("itm_ids") or []
    if isinstance(itm_objects, str):
        itm_objects = [itm_objects]
    itm_objects = [str(x) for x in itm_objects if x][:12]
    interpretation = str(
        data.get("interpretation")
        or data.get("observation")
        or data.get("description")
        or "See observation / tool outputs."
    )
    if itm_stage or itm_objects:
        mapped = ", ".join(itm_objects) if itm_objects else "(objects not named)"
        interpretation = (
            f"{interpretation.rstrip()}\n\n"
            f"Insider Threat Matrix ({itm_stage or 'unspecified'}): {mapped}. "
            "https://insiderthreatmatrix.org/"
        )
    return {
        "title": str(data.get("title", ""))[:200],
        "observation": str(data.get("observation", data.get("description", "")))[:8000],
        "interpretation": interpretation[:8000],
        "confidence": str(data.get("confidence", "MEDIUM")).upper(),
        "confidence_justification": str(
            data.get("confidence_justification")
            or "Grounded in MCP tool audit_ids from this investigation."
        )[:2000],
        "host": str(data.get("host", ""))[:200],
        "event_timestamp": str(data.get("event_timestamp", data.get("timestamp", ""))),
        "type": str(data.get("type", "") or "finding"),
        "attack_ids": data.get("attack_ids") or data.get("mitre_ids") or [],
        "iocs": data.get("iocs") or [],
        "audit_ids": [str(a) for a in audit_ids if a][:20],
        "artifacts": artifacts[:20],
        "itm_stage": itm_stage[:80],
        "itm_objects": itm_objects,
        "evidence": [
            item for item in (data.get("evidence") or [])
            if isinstance(item, dict)
        ][:12],
    }


def _looks_like_finding(obj: Any, *, require_observation: bool) -> bool:
    """Reject anything that isn't a dict carrying at least a title."""
    if not isinstance(obj, dict):
        return False
    if not obj.get("title"):
        return False
    return not (require_observation and not obj.get("observation"))


def parse_hunt_candidates(messages: list, *, scan_last: int = 20) -> list[dict]:
    """Extract finding candidates from the last hunt-agent messages.

    Scans the last ``scan_last`` messages (default 20 — long ReAct hunts
    bury the final findings JSON) for either (a) a single JSON object as
    the full content (requires `title` + `observation`), (b) a JSON array
    of finding objects as the full content, or (c) JSON inside markdown
    ```json``` fences (requires only `title`), or (d) a JSON array/object
    buried in prose. Malformed JSON, non-dict payloads, and dicts missing
    the required keys are skipped silently so the caller can rely on the
    empty-list signal to salvage N4 hits (never parser-OK placeholders).
    """
    candidates: list[dict] = []
    if not messages:
        return candidates

    window = max(1, int(scan_last))
    for msg in messages[-window:]:
        content = _message_content(msg)
        if not content:
            continue

        # (a) whole-content JSON — object or array of findings
        try:
            data = _json.loads(content)
        except (_json.JSONDecodeError, ValueError, TypeError):
            data = None
        if isinstance(data, list):
            added = False
            for item in data:
                if _looks_like_finding(item, require_observation=True):
                    candidates.append(normalize_candidate(item))
                    added = True
            if added:
                continue
        elif _looks_like_finding(data, require_observation=True):
            candidates.append(normalize_candidate(data))
            continue

        # (b) fenced JSON blocks — title alone is enough
        before = len(candidates)
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
        if len(candidates) > before:
            continue

        # (c) buried JSON in prose (unfenced array/object with title)
        recovered = _recover_json_blob(content)
        if isinstance(recovered, list):
            for item in recovered:
                if _looks_like_finding(item, require_observation=True):
                    candidates.append(normalize_candidate(item))
        elif _looks_like_finding(recovered, require_observation=True):
            candidates.append(normalize_candidate(recovered))

    return candidates
