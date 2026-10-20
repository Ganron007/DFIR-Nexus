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
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any
from uuid import uuid4

from nexus.audit import AuditWriter
from nexus.langgraph import backbone as backbone_module
from nexus.langgraph.backbone import bind_case_args, tool_contracts_block
from nexus.langgraph.model_json import json_error_note, loads_model_json
from nexus.llm.egress import egress_bound

log = logging.getLogger(__name__)

_MAX_PREVIEW_ROWS = 25
_MAX_PREVIEW_CHARS = 900
_CALL_CHARS_DEFAULT = 120_000

DEFAULT_SYSTEM = """\
You are a DFIR evidence-analysis agent inside an examiner-led investigation.
You answer only from evidence retrieved through tools in this turn. You never
invent hosts, users, files, timestamps or events.
"""


def context_loop_enabled() -> bool:
    """WP 10.53 kill-switch shared by steer, proposals, directions and report."""
    raw = os.environ.get("NEXUS_CONTEXT_LOOP", "1").strip().lower()
    return raw not in ("0", "false", "no", "off", "disabled")

_TOOL_ARGS: dict[str, set[str]] = {
    "es_mappings": set(),
    "es_search": {"query", "size", "sort", "search_after"},
    "es_aggregate": {"aggs", "query"},
    "sample_rows": {"family", "field", "value", "n"},
    "rag_search": {"query", "top_k", "source", "source_ids", "technique", "platform"},
    "run_record": set(),
    # WO-K2: the examiner toolkit, validated in the same table as every other
    # loop tool. Read-only checks against the triage baselines.
    "check_file": {"path", "hash"},
    "check_scheduled_task": {"task_path"},
    "check_process_tree": {"process_name", "parent_name", "path", "user"},
    "check_service": {"service_name", "binary_path"},
    "check_hash": {"hash_value"},
    "check_autorun": {"key_path", "value_name"},
    "check_registry": {"key_path", "value_name", "hive"},
    "analyze_filename_triage": {"filename"},
    "check_lolbin": {"filename"},
    "check_hijackable_dll": {"dll_name"},
    "deobfuscate_command": {"command"},
    "check_driver": {"driver_name", "hash_value", "hash"},
    "check_lots_domain": {"domain"},
    "check_loobin": {"binary_name"},
}

#: The tools that read the case's indexed evidence. A turn that called one of
#: these "attempted evidence": it is a different state from a turn that read no
#: evidence and from a turn that never called a tool at all. See the
#: ``evidence_attempted`` / ``evidence_read`` pair in ``run_context_loop``.
_EVIDENCE_TOOLS: frozenset[str] = frozenset({
    "es_mappings", "es_search", "es_aggregate", "sample_rows", "run_record",
})


@dataclass(frozen=True)
class LoopBudget:
    """Bounded loop limits. Environment-overridable, never silently ignored.

    Defaults are 8 tool rounds / 16 calls / 360 s, adjusted from the original
    6/12/300 proposal after live acceptance: the cross-family RDP trace needed
    eight rounds and a reserved answer-only pass, and ran in ~286 s. The outer
    turn budget (NEXUS_MODE1_TURN_TIMEOUT=900, legacy alias
    NEXUS_MODE2_TURN_TIMEOUT accepted) remains the hard ceiling.
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


def load_loop_budget(rounds: int = 0) -> LoopBudget:
    """Read the live-acceptance defaults (8 rounds / 16 calls / 360 s).

    ``rounds`` overrides the round count for one turn when the examiner set a
    depth control. It is clamped to the same range the env var uses, so the
    control can never exceed the ceiling.
    """
    budget = LoopBudget(
        rounds=_env_int("NEXUS_CONTEXT_LOOP_ROUNDS", 8, low=1, high=30),
        seconds=_env_float("NEXUS_CONTEXT_LOOP_SECONDS", 360.0, low=5.0, high=3600.0),
        calls=_env_int("NEXUS_CONTEXT_LOOP_CALLS", 16, low=1, high=100),
        call_chars=_env_int(
            "NEXUS_CONTEXT_LOOP_CALL_CHARS", _CALL_CHARS_DEFAULT,
            low=2_000, high=1_000_000,
        ),
    )
    if rounds and int(rounds) > 0:
        budget = replace(budget, rounds=max(1, min(int(rounds), 30)))
    return budget


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
            parsed = loads_model_json(candidate)
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
        args = item.get("args")
        if isinstance(args, str):
            # Models sometimes send args as a JSON string; parse it instead of
            # silently running the tool with no arguments.
            try:
                args = loads_model_json(args) if args.strip() else {}
            except (json.JSONDecodeError, TypeError):
                args = {"__invalid_json__": args[:200]}
        if not isinstance(args, dict):
            args = {"__invalid_type__": str(type(args).__name__)}
        out.append({
            "tool": name,
            "args": args,
            "why": str(item.get("why") or item.get("reason") or "")[:200],
        })
    return out


_REQUIRED_ARGS: dict[str, tuple[str, ...]] = {
    "es_search": ("query",),
    "es_aggregate": ("aggs",),
    "rag_search": ("query",),
    "ti_lookup": ("value",),
    "ti_fanout": ("value",),
    "web_search": ("query",),
    "web_fetch": ("url",),
    # WO-K2: the check's own subject is mandatory; an optional filter is not.
    "check_file": ("path",),
    "check_scheduled_task": ("task_path",),
    "check_process_tree": ("process_name", "parent_name"),
    "check_service": ("service_name",),
    "check_hash": ("hash_value",),
    "check_autorun": ("key_path",),
    "check_registry": ("key_path",),
    "analyze_filename_triage": ("filename",),
    "check_lolbin": ("filename",),
    "check_hijackable_dll": ("dll_name",),
    "deobfuscate_command": ("command",),
    "check_lots_domain": ("domain",),
    "check_loobin": ("binary_name",),
}

_STRING_FIELDS_BY_TOOL: dict[str, tuple[str, ...]] = {
    "rag_search": ("query", "source", "technique", "platform"),
    "ti_lookup": ("value", "ioc_type"),
    "ti_fanout": ("value", "ioc_type"),
    "web_search": ("query",),
    "web_fetch": ("url",),
    "sample_rows": ("family", "field", "value"),
    # WO-K2: every examiner-check argument is a string.
    "check_file": ("path", "hash"),
    "check_scheduled_task": ("task_path",),
    "check_process_tree": ("process_name", "parent_name", "path", "user"),
    "check_service": ("service_name", "binary_path"),
    "check_hash": ("hash_value",),
    "check_autorun": ("key_path", "value_name"),
    "check_registry": ("key_path", "value_name", "hive"),
    "analyze_filename_triage": ("filename",),
    "check_lolbin": ("filename",),
    "check_hijackable_dll": ("dll_name",),
    "deobfuscate_command": ("command",),
    "check_driver": ("driver_name", "hash_value", "hash"),
    "check_lots_domain": ("domain",),
    "check_loobin": ("binary_name",),
}


#: Keys a model writes to explain a call. They belong on the call (``why``), not in its arguments.
_ANNOTATION_ARGS = ("why", "reason", "rationale", "purpose")


def _validate_args(tool: str, args: dict[str, Any]) -> tuple[dict[str, Any], str]:
    """Reject unknown/ill-typed or missing required arguments with a clear error."""
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
    missing = [key for key in _REQUIRED_ARGS.get(tool, ()) if not clean.get(key)]
    if missing:
        return {}, f"{tool}: missing required argument(s): {', '.join(missing)}"
    for key in _STRING_FIELDS_BY_TOOL.get(tool, ()):
        if key in clean and not isinstance(clean[key], str):
            return {}, f"{tool}: {key} must be a string"
    if "source_ids" in clean:
        source_ids = clean["source_ids"]
        if isinstance(source_ids, str):
            clean["source_ids"] = [source_ids]
        elif not isinstance(source_ids, list):
            return {}, f"{tool}: source_ids must be a list of strings"
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
        summary = {
            "total": result.get("total", result.get("matched")),
            "returned": result.get("returned", result.get("sampled")),
            "has_more": result.get("has_more"),
            "next_search_after": result.get("next_search_after"),
            "window_truncated": result.get("window_truncated"),
            "hits": _preview_rows(rows),
        }
        # What the surface says about the query reaches the seat (IC-9). Only the six keys above did: the rewrite
        # notes, the zero-hit diagnosis and the unpopulated-field note were computed and dropped here, so a seat saw
        # `total: 0` and nothing else for 178 of the fresh Mode 3 run's 815 searches.
        for key in ("normalized", "field_population_note", "failed_terms_optional", "zero_hit", "flood"):
            if result.get(key):
                summary[key] = result[key]
        return summary
    if name == "es_aggregate":
        def summarize_aggregation(spec: Any, budget: list[int], depth: int = 0) -> dict[str, Any]:
            """Keep each named aggregation's bounded result, including nested metrics."""
            if not isinstance(spec, dict):
                return {}
            if depth > 4:
                return {"truncated": True}
            summary: dict[str, Any] = {}
            buckets = spec.get("buckets")
            if isinstance(buckets, list):
                summary["bucket_count"] = len(buckets)
                summary["buckets"] = []
                for bucket in buckets[:40]:
                    if budget[0] <= 0:
                        break
                    if not isinstance(bucket, dict):
                        continue
                    budget[0] -= 1
                    item = {
                        "key": bucket.get("key"),
                        "count": bucket.get("doc_count"),
                    }
                    if "key_as_string" in bucket:
                        item["key_as_string"] = bucket["key_as_string"]
                    for key, value in bucket.items():
                        if key not in {"key", "key_as_string", "doc_count"} and isinstance(value, dict):
                            item[key] = summarize_aggregation(value, budget, depth + 1)
                    summary["buckets"].append(item)
                if len(summary["buckets"]) < len(buckets):
                    summary["buckets_truncated"] = True
            for key in ("value", "value_as_string", "after_key", "sum_other_doc_count",
                        "doc_count_error_upper_bound"):
                if key in spec:
                    summary[key] = spec[key]
            for key, value in spec.items():
                if key not in {"buckets", "value", "value_as_string", "after_key",
                               "sum_other_doc_count", "doc_count_error_upper_bound"} and isinstance(value, dict):
                    summary[key] = summarize_aggregation(value, budget, depth + 1)
            return summary

        aggregations = result.get("aggregations") or {}
        raw_named = aggregations if isinstance(aggregations, dict) else {}
        per_aggregation_budget = max(1, min(40, 400 // max(1, len(raw_named))))
        named = {
            str(name): summarize_aggregation(spec, [per_aggregation_budget])
            for name, spec in raw_named.items()
            if isinstance(spec, dict)
        }
        first = next(iter(named.values()), {})
        summary = {
            **first,
            "bucket_count": first.get("bucket_count", 0),
            "buckets": first.get("buckets", []),
            "next_after_key": result.get("next_after_key"),
        }
        # Preserve the historic single-aggregation shape. For multiple named
        # aggregations, expose every result under its own name; selecting only
        # the first made later buckets silently invisible to the model.
        if len(named) > 1:
            summary["aggregations"] = named
        return summary
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


def _call_read_evidence(name: str, result: dict[str, Any]) -> bool:
    """True when this tool call returned evidence rows.

    A call is evidence only when it succeeded AND carried rows. A refusal
    ("case_id ... is not the active case"), an ES failure and a genuine
    zero-hit search are all indistinguishable to a seat that only sees a
    returned dict, and all three were being treated as "I checked, nothing
    there" — which is how a blind run dispositioned 11 crit/high leads
    (36c Mode 3, reviewer probe check 6).
    """
    if not isinstance(result, dict):
        return False
    if result.get("error"):
        return False
    if result.get("degraded"):
        return False
    if name == "es_search":
        return bool(result.get("hits"))
    if name == "es_aggregate":
        return bool(result.get("aggregations"))
    if name == "es_mappings":
        # The catalog is schema, not evidence rows.
        return False
    if name == "sample_rows":
        return bool(result.get("hits") or result.get("rows"))
    if name == "run_record":
        return False
    return False


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
        # Whether this call actually returned evidence rows. A call that was
        # refused, failed or returned 0 rows is not evidence, and a seat or
        # work order whose every call is in that state must not disposition
        # anything (WO-R2F item 2).
        "read_evidence": _call_read_evidence(name, result),
    }
    tool_calls.append(record)
    if name == "es_search":
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
        raw_aggs = result.get("aggregations") or {}
        named = summary.get("aggregations")
        if not isinstance(named, dict) and isinstance(raw_aggs, dict) and raw_aggs:
            first_name = next(iter(raw_aggs))
            named = {str(first_name): summary}
        for agg_name, agg_summary in (named or {}).items():
            if not isinstance(agg_summary, dict):
                continue
            buckets = agg_summary.get("buckets") or []
            item = {
                "field": str(agg_name),
                "distinct": agg_summary.get("bucket_count", len(buckets)),
                "top": [
                    {"value": b.get("key"), "count": b.get("count")}
                    for b in buckets[:15] if isinstance(b, dict)
                ],
                "audit_id": audit_id,
            }
            if "value" in agg_summary:
                item["value"] = agg_summary["value"]
            aggregations.append(item)
    return record


def _event_summary(summary: Any) -> dict[str, Any]:
    """Compact summary for streaming/transcript events (never the full catalog)."""
    if not isinstance(summary, dict):
        return {}
    out = dict(summary)
    for key in ("parsed_columns", "core_fields", "entries"):
        value = out.get(key)
        if isinstance(value, list):
            out[key] = f"{len(value)} value(s)"
    hits = out.get("hits")
    if isinstance(hits, list):
        out["hits"] = hits[:3]
        out["hits_total"] = len(hits)
    return out


def _clip(text: str, limit: int) -> str:
    """Keep an agent answer up to the call budget. Zero means no clip."""
    body = text or ""
    if limit <= 0 or len(body) <= limit:
        return body
    return body[:limit]


#: A result shorter than this is always shown whole: compacting it would save little.
_COMPACT_ABOVE = 2_000


def _observation_head(o: dict[str, Any]) -> str:
    # The call's own audit id, so the model can cite what it ran. It was never shown: Mode 2's
    # workers saw only the ledger's and the leads' ids and cited those instead of their own
    # twenty queries (2026-10-14, Mode 2 run 2).
    return (f"- {o['tool']}" + (f" [audit_id {o['audit_id']}]" if o.get("audit_id") else "") + ": "
            # What the loop changed in the call is said beside its result (never silently).
            + (f"[{o['normalized']}] " if o.get("normalized") else ""))


def _compact_observation(o: dict[str, Any]) -> str:
    """An earlier result as one line: its facts, the locations of its rows, and how to see it again.

    Nothing is cut inside a row: the rows are named by location, and repeating the call shows the
    whole result again (it is replayed, not run again), with the same audit id to cite.
    """
    summary = o.get("summary") if isinstance(o.get("summary"), dict) else {}
    facts: dict[str, Any] = {k: v for k, v in summary.items()
                             if isinstance(v, (str, int, float, bool)) or v is None}
    hits = summary.get("hits")
    if isinstance(hits, list):
        facts["rows"] = [f"{h.get('file')}:{h.get('line')}" for h in hits if isinstance(h, dict)]
    return (_observation_head(o) + json.dumps(facts, default=str)
            + f" (shown whole in round {o.get('round')}; repeat the call to see it whole again)")


def _observations_block(
    observations: list[dict[str, Any]],
    per_obs_cap: int = 60_000,
    fresh_round: int | None = None,
) -> str:
    """Render observations for the next round.

    The per-observation cap is deliberately generous: the full ``es_mappings``
    catalog can exceed 10k chars, and hiding columns behind a small cap is what
    made the live model repeat the same tool call. The project-wide context
    budget still bounds the final packed prompt.

    With ``fresh_round`` (D206, operator decision 2026-10-15), a result is shown whole in the
    round after it arrived and as a compact line afterwards. Every round used to re-send every
    result whole: Mode 3 run 1 sent 130.7 M characters in 506 calls (one call 839 K) and used up
    the provider's credit.
    """
    if not observations:
        return "(no tool calls yet)"
    lines: list[str] = []
    for o in observations:
        whole = json.dumps(o.get("summary") or {}, default=str)[:per_obs_cap]
        if (fresh_round is not None and o.get("round") is not None
                and o.get("round") != fresh_round and len(whole) > _COMPACT_ABOVE):
            lines.append(_compact_observation(o))
        else:
            lines.append(_observation_head(o) + whole)
    return "\n".join(lines)


def _force_answer(
    *,
    model: Any,
    base_system: str,
    question: str,
    observations: list[dict[str, Any]],
    call_chars: int,
    terminal_keys: tuple[str, ...] = (),
) -> str:
    """One final answer-only model call when the tool rounds are exhausted.

    Tool use is disabled for this call: the model must synthesize from the
    observations already collected. This is what turns "more retrieval until
    timeout" into an actual answer with an honest statement of what remains.

    When the caller declared ``terminal_keys``, the terminal OBJECT is what is
    asked for and returned — not a prose answer. Honouring the schema only on
    the no-tool-call branch left every seat whose rounds exhausted returning
    ``{"answer": …}``: `_parse_claims` then found no claims, the board carried
    none, no disputes could form, and the run settled with 0 candidates while
    reporting `completed` (SC1 Mode 3, 2026-10-07).
    """
    obs = _observations_block(observations)
    if call_chars > 0:
        obs = obs[:call_chars]
    if terminal_keys:
        keys = ", ".join(f'"{k}"' for k in terminal_keys)
        user = (
            f"Question: {question}\n\n"
            "OBSERVATIONS ALREADY COLLECTED THIS TURN:\n"
            f"{obs}\n\n"
            f"Return ONLY a JSON object containing {keys}. No prose, no fence, "
            "no commentary outside the JSON. Build it from the observations "
            "above; if they are insufficient, return the object with empty/"
            "explicit entries rather than inventing evidence."
        )
    else:
        user = (
            f"Question: {question}\n\n"
            "OBSERVATIONS ALREADY COLLECTED THIS TURN:\n"
            f"{obs}\n\n"
            'Return ONLY JSON: {"answer":"..."}. Do NOT call tools. '
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
        if terminal_keys and any(key in parsed for key in terminal_keys):
            return _clip(json.dumps(parsed, default=str, sort_keys=True), call_chars)
        answer = parsed.get("answer") or parsed.get("reply")
        if isinstance(answer, str) and answer.strip():
            return _clip(answer.strip(), call_chars)
        return ""
    raw = (raw or "").strip()
    # Never accept an empty JSON container or literal as the case answer.
    if not raw or raw.lower() in {"{}", "[]", "null", "true", "false"}:
        return ""
    if raw[0] in "{[":
        return ""
    if '"tool_calls"' not in raw and '"tool"' not in raw[:80]:
        return _clip(raw, call_chars)
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


@egress_bound
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
    terminal_keys: tuple[str, ...] = (),
    allowed_tools: tuple[str, ...] | None = None,
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
    # The result of each successful call, so a repeated call replays it whole (D206).
    seen_results: dict[str, dict[str, Any]] = {}
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

    allow_line = ""
    if allowed_tools:
        allow_line = (
            "\nROLE TOOL ALLOWLIST: "
            + ", ".join(allowed_tools)
            + ". Any other tool is rejected by the runtime.\n"
        )
    from nexus.langgraph.lane_gate import pending_family_notice

    pending_line = pending_family_notice(case_dir)
    base_system = (
        f"ACTIVE CASE: {case_id}\n"
        + pending_line
        + "The runtime injects case_id into every evidence tool; you do NOT need "
        "to supply it and you must never ask the examiner for it.\n"
        + allow_line
        + "\n" + (system_prompt.strip() or DEFAULT_SYSTEM)
        + "\n\n" + tool_contracts_block(include_external=False)
    )
    # One answer contract per call (D231). A caller that declares terminal keys defines its own
    # final object in the task; the protocol used to ask for {"answer": ...} anyway, so a Mode 3 seat
    # held three return formats (this one, Mode 2's role schema and its own claims object), and a
    # third of its replies came back as prose or an answer envelope that dropped its dispositions.
    if terminal_keys:
        final_shape = (
            "the JSON object the task defines (with its "
            + " / ".join(f'"{k}"' for k in terminal_keys)
            + " key), returned as is, not inside an {\"answer\":...} envelope"
        )
        answer_line = f"To answer: return {final_shape}.\n"
    else:
        final_shape = "{\"answer\":\"...\"}"
        answer_line = (
            "To answer: {\"answer\":\"...\",\"citations\":[{\"family\":\"...\","
            "\"file\":\"...\",\"line\":\"...\"}]}\n"
        )
    protocol = (
        "\n\nTOOL PROTOCOL:\n"
        "Return ONLY one JSON object per reply.\n"
        "To call tools: {\"tool_calls\":[{\"tool\":\"es_search\","
        "\"args\":{...},\"why\":\"one clause\"}]}\n"
        + answer_line +
        "Rules: do not pre-fetch unrelated evidence; use tools to inspect the "
        "schema, the run record and the rows you actually need; a zero-hit "
        "search is not negative evidence until run_record shows the relevant "
        "parser ran; cite only rows returned by tools in this turn.\n"
        "EFFICIENCY: a result is shown whole in the round after it arrives; "
        "later rounds show it as a compact line (its audit id, totals and row "
        "locations). To see it whole again, repeat the same call: it is "
        "replayed from the earlier result, not run again. Call es_mappings once, then "
        "move to es_search / es_aggregate / sample_rows. For an unknown parsed "
        "column use a multi_match over fields.* rather than re-reading the "
        "whole catalog. If you have enough evidence, answer."
    )

    def _round_nudge(round_no: int) -> str:
        """Keep the loop from spending every round on more retrieval."""
        remaining = budget.rounds - round_no
        if remaining <= 0:
            return (
                f"\n\nFINAL ROUND: do NOT call another tool. Return {final_shape} now from the "
                "observations already collected; state explicitly what remains unchecked."
            )
        if remaining <= 1:
            return (
                "\n\nYou already have enough evidence for a useful answer. "
                f"Prefer returning {final_shape} now; call another tool only if it is "
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

        # What does not change between rounds comes first and once: the system message holds the
        # role, the allowlist and the tool contracts; the user message opens with the protocol and
        # the task (work order, procedures, field sheet), then the observations that grow each
        # round, then the round's nudge. The system text used to be repeated at the top of every
        # user message (4.5 KB per call, 2026-10-14 trace), and the task sat behind the growing
        # observations, so no two rounds shared more than the system message as a prefix.
        # Everything not yet tagged arrived in the previous round (D206).
        for obs in observations:
            obs.setdefault("round", round_no - 1)
        sections = [
            (0, "protocol", protocol.strip()),
            (1, "question", question),
            (2, "observations", _observations_block(observations, fresh_round=round_no - 1)),
            (3, "prior_conversation", history_block),
            (4, "round", _round_nudge(round_no).strip()),
        ]
        window = case_window(case_dir)
        packed, report = pack_sections(sections, window=window)
        # The record holds both messages the model received (D174: it held the user message only).
        persist_context(
            case_dir, f"context-loop-{task}-round-{round_no}",
            "## SYSTEM MESSAGE\n\n" + base_system + "\n\n## USER MESSAGE\n\n" + packed, report,
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
                            "JSON object (no trailing commas, no fence; close every { and [ you open)."
                            + (f" Where it broke: {note}" if (note := json_error_note(raw)) else "")
                        ),
                    },
                })
                continue
            if raw.strip():
                reply = _clip(raw.strip(), budget.call_chars)
                finish_reason = "answer_text"
                partial = False
            else:
                finish_reason = "empty_model"
            _emit({"event": "loop_done", "reply": reply, "partial": partial})
            break

        calls = _normalize_tool_calls(parsed)
        if (
            not calls
            and terminal_keys
            and any(key in parsed for key in terminal_keys)
        ):
            # Structured task final (directions/proposals/report): the model
            # returned the domain object directly instead of the answer
            # envelope. Treat it as the terminal reply.
            reply = _clip(json.dumps(parsed, default=str, sort_keys=True), budget.call_chars)
            finish_reason = "answer_terminal"
            partial = False
            _emit({"event": "loop_done", "reply": reply, "partial": False})
            break
        if not calls:
            answer = str(parsed.get("answer") or parsed.get("reply") or "").strip()
            if answer:
                reply = _clip(answer, budget.call_chars)
                finish_reason = "answer"
                partial = False
                _emit({"event": "loop_done", "reply": reply, "partial": False})
                break
            # JSON without tools and without an answer: ask again next round.
            observations.append({
                "tool": "system",
                "why": "",
                "audit_id": "",
                "summary": {"error": f"reply contained neither tool_calls nor {final_shape}"},
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
            args = call.get("args") or {}
            # A reason written inside the arguments belongs on the call: it is moved there and the
            # move is recorded, not refused. Mode 2 lost rounds to "es_aggregate: unsupported
            # argument(s) why" (2026-10-14). Any other unknown argument is still refused.
            moved: list[str] = []
            if isinstance(args, dict):
                args = dict(args)
                for key in _ANNOTATION_ARGS:
                    if key in args:
                        text = str(args.pop(key) or "").strip()
                        moved.append(key)
                        if text and not why:
                            why = text
            clean_args, problem = _validate_args(name, args)
            if problem:
                observations.append({
                    "tool": name or "unknown", "why": why, "audit_id": "",
                    "summary": {"error": problem},
                })
                _emit({"event": "tool_result", "tool": name or "unknown",
                       "error": problem})
                continue
            if allowed_tools and name not in allowed_tools:
                message = (
                    f"tool {name!r} is outside this role's allowlist "
                    f"({', '.join(allowed_tools)})"
                )
                observations.append({
                    "tool": name, "why": why, "audit_id": "",
                    "summary": {"error": message},
                })
                _emit({"event": "tool_result", "tool": name, "error": message})
                continue
            # WO-R2F item 1 (D41): every case-bound tool is bound to THIS run's case. The
            # list is backbone.CASE_BOUND_TOOLS, so no tool is missed here.
            payload = bind_case_args(name, clean_args, case_id=case_id, case_dir=case_dir)
            call_key = json.dumps(
                {"tool": name, "args": clean_args}, sort_keys=True, default=str)
            if call_key in seen_call_keys:
                duplicate_calls += 1
                earlier = seen_results.get(call_key)
                if earlier is not None:
                    # Replayed whole, with the audit id to cite, and not run again (D206): an
                    # earlier result is a compact line by now, and this is how it is read again.
                    replay = {k: v for k, v in earlier.items() if k != "round"}
                    replay["normalized"] = "replayed from the earlier identical call; not run again"
                    observations.append(replay)
                    _emit({"event": "tool_result", "round": round_no, "tool": name,
                           "audit_id": earlier.get("audit_id"), "replayed": True})
                    continue
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
            if isinstance(result, dict) and result.get("error"):
                # A transient failure must be retryable with the same args;
                # only successful calls are suppressed as duplicates.
                seen_call_keys.discard(call_key)
            elapsed = (time.monotonic() - t1) * 1000
            # A rejected/invalid call is still an attempted action; it must
            # not terminate the loop — the next round can recover.
            obs = _append_tool_observation(
                tool_calls=tool_calls, all_hits=all_hits,
                aggregations=aggregations, name=name, args=clean_args,
                why=why, result=result, elapsed_ms=elapsed,
            )
            if moved:
                obs["normalized"] = f"moved {', '.join(moved)} from the arguments to the call's why"
            # The model must see successful tool results in the next round;
            # previously only errors/duplicates were in ``observations``.
            observations.append(obs)
            if call_key in seen_call_keys:
                seen_results[call_key] = obs
            _emit({
                "event": "tool_result", "round": round_no, "tool": name,
                "why": why, "audit_id": obs.get("audit_id"),
                "summary": _event_summary(obs.get("summary")),
                "ms": round(elapsed, 1),
                **({"normalized": obs["normalized"]} if moved else {}),
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
            terminal_keys=terminal_keys,
        )
        if forced:
            reply = forced
            partial = False
            finish_reason = "answer_forced"
            _emit({"event": "loop_done", "reply": reply, "partial": False,
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

    if not partial and reply and not tool_calls:
        reply += (
            "\n\n_No evidence tool was called in this turn — treat this "
            "answer as unverified._"
        )

    elapsed_ms = round((time.monotonic() - started) * 1000, 1)
    # WO-R2F item 2: did this turn read any evidence at all? Counted from the
    # calls themselves, so a turn whose every call was refused or zero-hit says
    # so instead of letting the seat infer "checked, nothing there".
    #
    # ``evidence_attempted`` is the separate fact that any evidence tool was
    # CALLED. A refused call and a call the model never made are different
    # states: the first is a blind seat that must not disposition anything
    # (36c Mode 3, reviewer probe check 6), the second is a seat that worked
    # from its own knowledge and still has to record what it found. Collapsing
    # them made every seat that answered without calling a tool "blocked",
    # which dropped all 11 crit/high lead dispositions from the run record.
    evidence_calls = [
        c for c in tool_calls
        if str(c.get("tool") or "") in _EVIDENCE_TOOLS
    ]
    evidence_attempted = bool(evidence_calls)
    evidence_read = bool(all_hits) or any(
        bool(c.get("read_evidence")) for c in evidence_calls
    )
    audit_id = audit.log(
        tool="context_loop",
        params={"case_id": case_id, "task": task, "question": question[:200],
                "turn_id": turn_id},
        result_summary={
            "rounds": len([s for s in stages if s.get("stage")]),
            "tool_calls": len(tool_calls),
            "duplicate_calls": duplicate_calls,
            "hits": len(all_hits),
            "evidence_attempted": evidence_attempted,
            "evidence_read": evidence_read,
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
        "evidence_attempted": evidence_attempted,
        "evidence_read": evidence_read,
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
