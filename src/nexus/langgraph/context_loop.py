"""Shared bounded LLM context-engineering loop (WIRING-PLAN 10.53/10.54).

The loop replaces pre-retrieved, one-shot prompt assembly with:

1. **Pointers** — case id, schema access, run record, knowledge tools.
2. **Model-driven tool calls** — the model chooses a read-only tool + args + why.
3. **Bounded iteration** — rounds / tool calls / soft wall clock.
4. **Partial results** — a budget stop returns what was already retrieved.
5. **Audited calls** — every tool action goes through ``backbone_call``.

The loop is deliberately model-agnostic: it uses a strict JSON tool protocol
(``{"tool_calls": [...]}`` / ``{"answer": ...}``) so it works with any
OpenAI-compatible chat model, including the scripted test models.

This module is shared by Mode 2 steering, Mode 1 directions/reporting and
(later) Mode 3 agents. It has no write path: the tools are read-only and the
loop cannot stage a finding or approve anything.
"""
from __future__ import annotations

import json
import logging
import os
import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import uuid4

from nexus.audit import AuditWriter
from nexus.langgraph import backbone as backbone_module
from nexus.langgraph.backbone import tool_contracts_block

log = logging.getLogger(__name__)

_MAX_PREVIEW_ROWS = 25
_MAX_PREVIEW_CHARS = 900
_CALL_CHARS_DEFAULT = 120_000

DEFAULT_SYSTEM = """\
You are a DFIR evidence-analysis agent inside an examiner-led investigation.
You answer only from evidence retrieved through tools in this turn. You never
invent hosts, users, files, timestamps or events.
"""

_TOOL_ARGS: dict[str, set[str]] = {
    "es_mappings": set(),
    "es_search": {"query", "size", "sort", "search_after"},
    "es_aggregate": {"aggs", "query"},
    "sample_rows": {"family", "field", "value", "n"},
    "kb_query": {"query", "folder", "signal", "limit"},
    "rag_search": {"query", "top_k", "source", "source_ids", "technique", "platform"},
    "run_record": set(),
}


@dataclass(frozen=True)
class LoopBudget:
    """Bounded loop limits. Environment-overridable, never silently ignored.

    Defaults are 8 tool rounds / 16 calls / 360 s, adjusted from the original
    6/12/300 proposal after live acceptance: the cross-family RDP trace needed
    eight rounds and a reserved answer-only pass, and ran in ~286 s. The outer
    turn budget (NEXUS_MODE2_TURN_TIMEOUT=900) remains the hard ceiling.
    """

    rounds: int = 8
    seconds: float = 360.0
    calls: int = 16
    call_chars: int = _CALL_CHARS_DEFAULT


def _env_int(name: str, default: int, *, low: int, high: int) -> int:
    try:
        value = int(os.environ.get(name, "") or default)
    except (TypeError, ValueError):
        value = default
    return max(low, min(value, high))


def _env_float(name: str, default: float, *, low: float, high: float) -> float:
    try:
        value = float(os.environ.get(name, "") or default)
    except (TypeError, ValueError):
        value = default
    return max(low, min(value, high))


def load_loop_budget() -> LoopBudget:
    """Read the live-acceptance defaults (8 rounds / 16 calls / 360 s)."""
    return LoopBudget(
        rounds=_env_int("NEXUS_CONTEXT_LOOP_ROUNDS", 8, low=1, high=30),
        seconds=_env_float("NEXUS_CONTEXT_LOOP_SECONDS", 360.0, low=5.0, high=3600.0),
        calls=_env_int("NEXUS_CONTEXT_LOOP_CALLS", 16, low=1, high=100),
        call_chars=_env_int(
            "NEXUS_CONTEXT_LOOP_CALL_CHARS", _CALL_CHARS_DEFAULT,
            low=2_000, high=1_000_000,
        ),
    )


def _call_model(model: Any, messages: list[dict[str, str]]) -> str:
    try:
        response = model.invoke(messages)
    except AttributeError:
        raise
    return str(getattr(response, "content", response))


def _parse_loop_json(text: str) -> dict[str, Any] | None:
    """Parse the strict JSON object from a model response (fences tolerated).

    Reasoning models occasionally emit a trailing comma or a markdown fence
    around an otherwise valid tool call; the parser repairs those instead of
    turning a tool call into a "final answer".
    """
    text = (text or "").strip()
    if not text:
        return None
    raw_candidates = [text]
    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if fence:
        raw_candidates.insert(0, fence.group(1))
    start, end = text.find("{"), text.rfind("}")
    if start != -1 and end > start:
        raw_candidates.append(text[start:end + 1])
    candidates: list[str] = []
    for candidate in raw_candidates:
        candidates.append(candidate)
        # Tolerate trailing commas before a closing brace/bracket.
        candidates.append(re.sub(r",\s*([}\]])", r"\1", candidate))
    for candidate in candidates:
        try:
            parsed = json.loads(candidate)
        except (json.JSONDecodeError, TypeError):
            continue
        if isinstance(parsed, dict):
            return parsed
    return None


def _normalize_tool_calls(parsed: dict[str, Any]) -> list[dict[str, Any]]:
    """Accept ``tool_calls`` list or a single ``tool`` object."""
    raw = parsed.get("tool_calls")
    if not isinstance(raw, list):
        raw = [parsed] if parsed.get("tool") else []
    out: list[dict[str, Any]] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        name = str(item.get("tool") or item.get("name") or "").strip()
        if not name:
            continue
        args = item.get("args") if isinstance(item.get("args"), dict) else {}
        out.append({
            "tool": name,
            "args": args,
            "why": str(item.get("why") or item.get("reason") or "")[:200],
        })
    return out


def _validate_args(tool: str, args: dict[str, Any]) -> tuple[dict[str, Any], str]:
    """Reject unknown keys instead of passing them into the core functions."""
    allowed = _TOOL_ARGS.get(tool)
    if allowed is None:
        return {}, f"unknown tool {tool!r}"
    # The prompt contracts show ``case_id`` for evidence tools. The loop
    # injects the active case itself, so a model-supplied case_id is accepted
    # and ignored rather than treated as an invalid argument.
    unknown = sorted(set(args) - allowed - {"case_id"})
    if unknown:
        return {}, (
            f"{tool}: unsupported argument(s) {', '.join(unknown)}; "
            f"allowed: {', '.join(sorted(allowed)) or '(none)'}"
        )
    clean = {
        key: value for key, value in args.items()
        if key in allowed and value is not None
    }
    if tool == "es_search":
        try:
            size = int(clean.get("size") or 50)
        except (TypeError, ValueError):
            return {}, "es_search: size must be an integer"
        clean["size"] = max(1, min(size, 200))
    if tool == "sample_rows":
        try:
            n = int(clean.get("n") or 12)
        except (TypeError, ValueError):
            return {}, "sample_rows: n must be an integer"
        clean["n"] = max(1, min(n, 60))
    if tool == "kb_query":
        try:
            clean["limit"] = max(1, min(int(clean.get("limit") or 5), 20))
        except (TypeError, ValueError):
            clean["limit"] = 5
    if tool == "rag_search":
        try:
            clean["top_k"] = max(1, min(int(clean.get("top_k") or 8), 50))
        except (TypeError, ValueError):
            clean["top_k"] = 8
    return clean, ""


def _preview_rows(rows: list[dict[str, Any]], limit: int = _MAX_PREVIEW_ROWS) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for row in rows[:limit]:
        if not isinstance(row, dict):
            continue
        fields = row.get("fields") if isinstance(row.get("fields"), dict) else {}
        out.append({
            "family": str(row.get("family") or "")[:80],
            "file": str(row.get("file") or "")[:200],
            "line": str(row.get("line") or "")[:16],
            "ts": str(row.get("ts") or row.get("time") or "")[:40],
            "host": str(row.get("host") or "")[:80],
            "text": str(row.get("text") or "")[:_MAX_PREVIEW_CHARS],
            "fields": {str(k)[:60]: str(v)[:160] for k, v in list(fields.items())[:8]},
        })
    return out


def _result_summary(name: str, result: dict[str, Any]) -> dict[str, Any]:
    """Compact, bounded summary of one tool result for the next model round."""
    if not isinstance(result, dict):
        return {"error": "tool returned a non-dict result"}
    if result.get("error"):
        return {"error": str(result.get("error"))[:400]}
    if name == "es_mappings":
        # Return the FULL catalog: hiding columns behind a small cap made the
        # live model repeat es_mappings because it could not find e.g. USB
        # fields in the first 80 alphabetical names. The context budget (1M
        # tokens by default) is the only cap that should apply.
        families = result.get("families") or {}
        return {
            "case_id": result.get("case_id"),
            "families": list(families.keys()),
            "family_rows": families,
            "core_fields": [f.get("field") for f in (result.get("core_fields") or [])],
            "parsed_columns": [
                f.get("field") for f in (result.get("parsed_columns") or [])
            ],
            "parsed_columns_count": len(result.get("parsed_columns") or []),
            "ts_note": result.get("ts_note"),
        }
    if name in ("es_search", "sample_rows"):
        rows = result.get("hits") or []
        return {
            "total": result.get("total", result.get("matched")),
            "returned": result.get("returned", result.get("sampled")),
            "has_more": result.get("has_more"),
            "next_search_after": result.get("next_search_after"),
            "window_truncated": result.get("window_truncated"),
            "hits": _preview_rows(rows),
        }
    if name == "es_aggregate":
        buckets: list[dict[str, Any]] = []
        for spec in (result.get("aggregations") or {}).values():
            if isinstance(spec, dict):
                buckets = spec.get("buckets") or []
                break
        return {
            "bucket_count": len(buckets),
            "buckets": [
                {"key": b.get("key"), "count": b.get("doc_count")}
                for b in buckets[:40] if isinstance(b, dict)
            ],
            "next_after_key": result.get("next_after_key"),
        }
    if name == "run_record":
        return {
            "available": result.get("available"),
            "counts": result.get("counts"),
            "entries": [
                {k: e.get(k) for k in ("tool", "status", "reason", "purpose", "output", "audit_id")}
                for e in (result.get("entries") or [])[:40]
            ],
            "total": result.get("total"),
        }
    if name == "kb_query":
        hits = result.get("hits") or []
        return {
            "available": result.get("available"),
            "hits": [
                {
                    "title": h.get("title") or h.get("path") or h.get("id"),
                    "chunk_id": h.get("chunk_id") or h.get("id"),
                    "snippet": str(h.get("snippet") or h.get("text") or "")[:400],
                }
                for h in hits[:8] if isinstance(h, dict)
            ],
        }
    if name == "rag_search":
        results = result.get("results") or []
        return {
            "status": result.get("status"),
            "results": [
                {
                    "id": r.get("id"),
                    "collection": r.get("collection"),
                    "score": r.get("score"),
                    "source": r.get("source"),
                    "title": r.get("title"),
                    "text": str(r.get("text") or "")[:500],
                }
                for r in results[:8] if isinstance(r, dict)
            ],
        }
    return {"keys": sorted(result.keys())[:20]}


def _append_tool_observation(
    *,
    tool_calls: list[dict[str, Any]],
    all_hits: list[dict[str, Any]],
    aggregations: list[dict[str, Any]],
    name: str,
    args: dict[str, Any],
    why: str,
    result: dict[str, Any],
    elapsed_ms: float,
) -> dict[str, Any]:
    audit_id = ""
    if isinstance(result, dict):
        audit_id = str((result.get("provenance") or {}).get("audit_id") or "")
        if not audit_id:
            audit_id = str(result.get("audit_id") or "")
    summary = _result_summary(name, result)
    record = {
        "tool": name,
        "args": args,
        "why": why,
        "audit_id": audit_id,
        "elapsed_ms": round(elapsed_ms, 1),
        "summary": summary,
    }
    tool_calls.append(record)
    if name in ("es_search", "sample_rows"):
        seen = {
            (str(h.get("family") or ""), str(h.get("file") or "").replace("\\", "/"), str(h.get("line") or ""))
            for h in all_hits
        }
        for hit in (result.get("hits") or []) if isinstance(result, dict) else []:
            if not isinstance(hit, dict):
                continue
            key = (
                str(hit.get("family") or ""),
                str(hit.get("file") or "").replace("\\", "/"),
                str(hit.get("line") or ""),
            )
            if key not in seen:
                seen.add(key)
                all_hits.append(hit)
    if name == "es_aggregate" and isinstance(result, dict):
        for spec in (result.get("aggregations") or {}).values():
            if isinstance(spec, dict):
                buckets = spec.get("buckets") or []
                aggregations.append({
                    "field": ", ".join(sorted((args.get("aggs") or {}).keys())),
                    "distinct": len(buckets),
                    "top": [
                        {"value": b.get("key"), "count": b.get("doc_count")}
                        for b in buckets[:15] if isinstance(b, dict)
                    ],
                    "audit_id": audit_id,
                })
                break
    return record


def _observations_block(observations: list[dict[str, Any]]) -> str:
    if not observations:
        return "(no tool calls yet)"
    return "\n".join(
        f"- {o['tool']}: " + json.dumps(o.get("summary") or {}, default=str)[:4000]
        for o in observations
    )


def _force_answer(
    *,
    model: Any,
    base_system: str,
    question: str,
    observations: list[dict[str, Any]],
    call_chars: int,
) -> str:
    """One final answer-only model call when the tool rounds are exhausted.

    Tool use is disabled for this call: the model must synthesize from the
    observations already collected. This is what turns "more retrieval until
    timeout" into an actual answer with an honest statement of what remains.
    """
    obs = _observations_block(observations)
    if call_chars > 0:
        obs = obs[:call_chars]
    user = (
        f"Question: {question}\n\n"
        "OBSERVATIONS ALREADY COLLECTED THIS TURN:\n"
        f"{obs}\n\n"
        "Return ONLY JSON: {\"answer\":\"...\"}. Do NOT call tools. "
        "Answer from the observations above; use compact markdown; end with "
        "what remains unchecked. If the observations are insufficient, say so "
        "explicitly rather than inventing evidence."
    )
    try:
        raw = _call_model(model, [
            {"role": "system", "content": base_system},
            {"role": "user", "content": user},
        ])
    except Exception as exc:  # noqa: BLE001 — final pass is best-effort
        log.debug("force-answer call failed: %s", exc)
        return ""
    parsed = _parse_loop_json(raw)
    if parsed:
        answer = parsed.get("answer") or parsed.get("reply")
        if isinstance(answer, str) and answer.strip():
            return answer.strip()[:8000]
    raw = (raw or "").strip()
    if raw and '"tool_calls"' not in raw and '"tool"' not in raw[:80]:
        return raw[:8000]
    return ""


def _fallback_partial_reply(
    question: str,
    observations: list[dict[str, Any]],
    hits: list[dict[str, Any]],
    reason: str,
) -> str:
    """Deterministic honest partial answer when the model produces none."""
    lines = [
        f"**Partial result — {reason}.**",
        "",
        f"The turn stopped before the model produced a complete answer for: "
        f"_{question[:300]}_",
        "",
    ]
    if observations:
        lines.append("**What was checked:**")
        seen: set[str] = set()
        shown = 0
        for obs in observations:
            key = f"{obs.get('tool')}|{json.dumps(obs.get('summary') or {}, sort_keys=True, default=str)}"
            if key in seen:
                continue
            seen.add(key)
            summary = obs.get("summary") or {}
            count = summary.get("total", summary.get("returned", ""))
            suffix = f" — {count} row(s)" if count not in ("", None) else ""
            lines.append(
                f"- `{obs.get('tool')}`{suffix}"
                + (f" (audit_id `{obs.get('audit_id')}`)" if obs.get("audit_id") else "")
            )
            shown += 1
            if shown >= 12:
                break
        lines.append("")
    if hits:
        lines.append(f"**Rows already retrieved ({len(hits)}):**")
        lines.append("")
        lines.append("| Family | File | Line | Detail |")
        lines.append("|---|---|---|---|")
        for hit in hits[:20]:
            text = str(hit.get("text") or "").replace("|", "\\|")[:180]
            lines.append(
                f"| {str(hit.get('family') or '')[:40]} "
                f"| {str(hit.get('file') or '')[:80]} "
                f"| {str(hit.get('line') or '')[:12]} "
                f"| {text} |"
            )
    else:
        lines.append("No rows had been retrieved when the budget expired.")
    lines.append("")
    lines.append("**Not checked:** the model did not finish its planned next step.")
    return "\n".join(lines)


def run_context_loop(
    *,
    case_dir: Path,
    case_id: str,
    question: str,
    model: Any,
    system_prompt: str = "",
    task: str = "steer",
    history: list[dict[str, str]] | None = None,
    on_event: Callable[[dict[str, Any]], None] | None = None,
    budget: LoopBudget | None = None,
    audit: AuditWriter | None = None,
) -> dict[str, Any]:
    """Run one bounded, tool-driving LLM turn.

    Returns a dict with ``reply``, ``tool_calls``, ``hits``, ``aggregations``,
    ``rounds``, ``partial``, ``partial_reason``, ``finish_reason``,
    ``audit_id`` and compatibility timing fields.
    """
    started = time.monotonic()
    case_dir = Path(case_dir)
    budget = budget or load_loop_budget()
    case_id = case_id or case_dir.name
    audit = audit or AuditWriter("nexus", audit_dir=case_dir / "audit")
    turn_id = uuid4().hex[:12]
    deadline = started + budget.seconds

    def _emit(event: dict[str, Any]) -> None:
        if on_event is not None:
            try:
                on_event(event)
            except Exception:  # noqa: BLE001 — streaming must never kill the turn
                log.debug("context loop event callback failed", exc_info=True)

    observations: list[dict[str, Any]] = []
    tool_calls: list[dict[str, Any]] = []
    all_hits: list[dict[str, Any]] = []
    aggregations: list[dict[str, Any]] = []
    stages: list[dict[str, Any]] = []
    seen_call_keys: set[str] = set()
    duplicate_calls = 0
    finish_reason = "rounds"
    partial = True
    reply = ""

    history_block = ""
    if history:
        history_block = "\n".join(
            f"{str(h.get('role') or '').lower()}: {str(h.get('text') or '')[:1200]}"
            for h in history[-8:]
            if isinstance(h, dict) and str(h.get("role") or "").lower() in ("examiner", "llm")
        )
        if history_block:
            history_block = "Prior conversation (context only):\n" + history_block

    base_system = (
        f"ACTIVE CASE: {case_id}\n"
        "The runtime injects case_id into every evidence tool; you do NOT need "
        "to supply it and you must never ask the examiner for it.\n\n"
        + (system_prompt.strip() or DEFAULT_SYSTEM)
        + "\n\n" + tool_contracts_block()
    )
    protocol = (
        "\n\nTOOL PROTOCOL:\n"
        "Return ONLY one JSON object per reply.\n"
        "To call tools: {\"tool_calls\":[{\"tool\":\"es_search\","
        "\"args\":{...},\"why\":\"one clause\"}]}\n"
        "To answer: {\"answer\":\"...\",\"citations\":[{\"family\":\"...\","
        "\"file\":\"...\",\"line\":\"...\"}]}\n"
        "Rules: do not pre-fetch unrelated evidence; use tools to inspect the "
        "schema, the run record and the rows you actually need; a zero-hit "
        "search is not negative evidence until run_record shows the relevant "
        "parser ran; cite only rows returned by tools in this turn.\n"
        "EFFICIENCY: never call the same tool twice with the same arguments — "
        "reuse the observation already returned. Call es_mappings once, then "
        "move to es_search / es_aggregate / sample_rows. For an unknown parsed "
        "column use a multi_match over fields.* rather than re-reading the "
        "whole catalog. If you have enough evidence, answer."
    )

    def _round_nudge(round_no: int) -> str:
        """Keep the loop from spending every round on more retrieval."""
        remaining = budget.rounds - round_no
        if remaining <= 0:
            return (
                "\n\nFINAL ROUND: do NOT call another tool. Return "
                "{\"answer\":\"...\"} now from the observations already collected; "
                "state explicitly what remains unchecked."
            )
        if remaining <= 1:
            return (
                "\n\nYou already have enough evidence for a useful answer. "
                "Prefer {\"answer\":\"...\"} now; call another tool only if it is "
                "essential to avoid a false negative."
            )
        return ""

    def _packed_round(round_no: int) -> str:
        from nexus.langgraph.prompt_budget import (
            case_window,
            log_usage,
            pack_sections,
            persist_context,
        )

        sections = [
            (0, "orientation", base_system + protocol + _round_nudge(round_no)),
            (1, "observations", _observations_block(observations)),
            (2, "question", question),
            (3, "prior_conversation", history_block),
        ]
        window = case_window(case_dir)
        packed, report = pack_sections(sections, window=window)
        persist_context(
            case_dir, f"context-loop-{task}-round-{round_no}", packed, report,
            meta={"case_id": case_id, "turn_id": turn_id, "question": question[:160]},
        )
        log_usage(f"context-loop-{task}", report)
        return packed

    for round_no in range(1, budget.rounds + 1):
        if time.monotonic() >= deadline:
            finish_reason = "time"
            _emit({"event": "partial", "reason": "time", "round": round_no - 1})
            break
        if len(tool_calls) >= budget.calls:
            finish_reason = "calls"
            _emit({"event": "partial", "reason": "calls", "round": round_no - 1})
            break

        _emit({"event": "round", "round": round_no, "max_rounds": budget.rounds})
        t0 = time.monotonic()
        try:
            raw = _call_model(model, [
                {"role": "system", "content": base_system},
                {"role": "user", "content": _packed_round(round_no) +
                 "\n\nReturn the next JSON object now."},
            ])
        except Exception as exc:  # noqa: BLE001 — one model failure is not fatal
            log.warning("context loop model call failed: %s", exc)
            stages.append({"stage": f"round-{round_no}", "status": "error",
                           "detail": str(exc)[:200]})
            finish_reason = "model_error"
            break
        stages.append({"stage": f"round-{round_no}", "ms": round((time.monotonic() - t0) * 1000),
                       "detail": raw[:160]})

        parsed = _parse_loop_json(raw)
        if parsed is None:
            # Never turn a malformed tool call into a final answer: recover
            # next round. Only a genuinely non-tool plain-text reply is a text
            # answer.
            looks_like_tool_call = bool(
                re.search(r'"tool_calls"|"tool"\s*:', raw or "")
            )
            if looks_like_tool_call:
                observations.append({
                    "tool": "system",
                    "why": "",
                    "audit_id": "",
                    "summary": {
                        "error": (
                            "malformed tool-call JSON rejected — resend ONE valid "
                            "JSON object (no trailing commas, no fence)."
                        ),
                    },
                })
                continue
            if raw.strip():
                reply = raw.strip()[:8000]
                finish_reason = "answer_text"
                partial = False
            else:
                finish_reason = "empty_model"
            _emit({"event": "done", "reply": reply, "partial": partial})
            break

        calls = _normalize_tool_calls(parsed)
        if not calls:
            answer = str(parsed.get("answer") or parsed.get("reply") or "").strip()
            if answer:
                reply = answer[:8000]
                finish_reason = "answer"
                partial = False
                _emit({"event": "done", "reply": reply, "partial": False})
                break
            # JSON without tools and without an answer: ask again next round.
            observations.append({
                "tool": "system",
                "why": "",
                "audit_id": "",
                "summary": {"error": "reply contained neither tool_calls nor answer"},
            })
            continue

        attempted_any = False
        for call in calls:
            if len(tool_calls) >= budget.calls:
                finish_reason = "calls"
                break
            attempted_any = True
            name = str(call.get("tool") or "")
            why = str(call.get("why") or "")
            clean_args, problem = _validate_args(name, call.get("args") or {})
            if problem:
                observations.append({
                    "tool": name or "unknown", "why": why, "audit_id": "",
                    "summary": {"error": problem},
                })
                _emit({"event": "tool_result", "tool": name or "unknown",
                       "error": problem})
                continue
            payload = dict(clean_args)
            if name in ("es_mappings", "es_search", "es_aggregate", "sample_rows", "run_record"):
                payload["case_id"] = case_id
            call_key = json.dumps(
                {"tool": name, "args": clean_args}, sort_keys=True, default=str)
            if call_key in seen_call_keys:
                duplicate_calls += 1
                observations.append({
                    "tool": name,
                    "why": why,
                    "audit_id": "",
                    "summary": {
                        "error": (
                            "duplicate call suppressed — the same tool+args was "
                            "already executed this turn; use that observation or "
                            "try a different query."
                        ),
                    },
                })
                _emit({"event": "tool_result", "round": round_no, "tool": name,
                       "error": "duplicate call suppressed"})
                continue
            seen_call_keys.add(call_key)
            _emit({"event": "tool_call", "round": round_no, "tool": name,
                   "args": clean_args, "why": why})
            t1 = time.monotonic()
            try:
                result = backbone_module.backbone_call(name, audit=audit, **payload)
            except Exception as exc:  # noqa: BLE001 — tool errors are observations
                result = {"error": str(exc)}
            elapsed = (time.monotonic() - t1) * 1000
            # A rejected/invalid call is still an attempted action; it must
            # not terminate the loop — the next round can recover.
            obs = _append_tool_observation(
                tool_calls=tool_calls, all_hits=all_hits,
                aggregations=aggregations, name=name, args=clean_args,
                why=why, result=result, elapsed_ms=elapsed,
            )
            # The model must see successful tool results in the next round;
            # previously only errors/duplicates were in ``observations``.
            observations.append(obs)
            _emit({
                "event": "tool_result", "round": round_no, "tool": name,
                "why": why, "audit_id": obs.get("audit_id"),
                "summary": obs.get("summary"), "ms": round(elapsed, 1),
            })
            if time.monotonic() >= deadline:
                finish_reason = "time"
                break
        if finish_reason == "calls" or finish_reason == "time":
            _emit({"event": "partial", "reason": finish_reason, "round": round_no})
            break
        if not attempted_any:
            finish_reason = "no_tools"
            break

    if partial and not reply and time.monotonic() < deadline:
        forced = _force_answer(
            model=model,
            base_system=base_system,
            question=question,
            observations=observations,
            call_chars=budget.call_chars,
        )
        if forced:
            reply = forced
            partial = False
            finish_reason = "answer_forced"
            _emit({"event": "done", "reply": reply, "partial": False,
                   "forced": True})

    if partial and not reply:
        reason = {
            "rounds": "round budget exhausted",
            "calls": "tool-call budget exhausted",
            "time": "time budget exhausted",
            "model_error": "model call failed",
            "no_tools": "model did not call a tool",
            "empty_model": "model returned an empty reply",
        }.get(finish_reason, finish_reason)
        reply = _fallback_partial_reply(question, observations, all_hits, reason)

    elapsed_ms = round((time.monotonic() - started) * 1000, 1)
    audit_id = audit.log(
        tool="context_loop",
        params={"case_id": case_id, "task": task, "question": question[:200],
                "turn_id": turn_id},
        result_summary={
            "rounds": len([s for s in stages if s.get("stage")]),
            "tool_calls": len(tool_calls),
            "duplicate_calls": duplicate_calls,
            "hits": len(all_hits),
            "partial": partial,
            "finish_reason": finish_reason,
        },
        elapsed_ms=elapsed_ms,
        extra={"turn_id": turn_id, "task": task},
    )
    return {
        "reply": reply,
        "tool_calls": tool_calls,
        "hits": all_hits,
        "aggregations": aggregations,
        "rounds": len([s for s in stages if s.get("stage")]),
        "duplicate_calls": duplicate_calls,
        "partial": partial,
        "partial_reason": finish_reason if partial else "",
        "finish_reason": finish_reason,
        "turn_id": turn_id,
        "audit_id": audit_id,
        "budget": {
            "rounds": budget.rounds,
            "seconds": budget.seconds,
            "calls": budget.calls,
        },
        "stages": stages,
        "timings_ms": {s["stage"]: s.get("ms", 0) for s in stages if s.get("stage")},
    }
