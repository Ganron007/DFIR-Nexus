"""Mode 2 steering agent — WP 4j.13 (the conversational evidence agent).

The examiner types a natural-language question; the agent:
  1. Reads the case's evidence landscape (index_mappings)
  2. Formulates field-scoped N4 DSL queries
  3. Executes them through the case-gated backbone
  4. Reads the results (parsed columns, not raw CSV)
  5. Iterates if the first round is insufficient (bounded)
  6. Formulates a natural-language answer grounded in the evidence rows

This is NOT a needle-proposal loop — it's a question-answering agent that
queries the evidence directly and answers the examiner. The examiner sees
the answer, the queries that produced it, and the evidence rows cited.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from nexus.audit import AuditWriter

log = logging.getLogger(__name__)

_MAX_AGENT_TURNS = 4  # bounded — the agent runs at most 4 tool calls
_MAX_HITS_IN_CONTEXT = 12  # rows fed back to the LLM per query result
_MAX_ROW_CHARS = 400


def _format_hits_for_llm(hits: list[dict[str, Any]], cap: int = _MAX_HITS_IN_CONTEXT) -> str:
    """Compact hit table for the LLM to read — parsed columns, not raw CSV."""
    lines: list[str] = []
    for h in hits[:cap]:
        fam = str(h.get("family") or "")
        text = str(h.get("text") or "")[:_MAX_ROW_CHARS]
        fields = h.get("fields") or {}
        salient = " | ".join(f"{k}={str(v)[:80]}" for k, v in list(fields.items())[:6])
        lines.append(f"[{fam}] {text[:_MAX_ROW_CHARS]}" +
                     (f" | fields: {salient}" if salient else ""))
    return "\n".join(lines) or "(no results)"


def run_steer_agent(
    case_dir: Path,
    question: str,
    model: Any = None,
    history: list[dict[str, str]] | None = None,
    max_turns: int = _MAX_AGENT_TURNS,
) -> dict[str, Any]:
    """Conversational Mode 2 agent: NL question → backbone queries → answer.

    Returns {reply, queries_executed, total_hits, aggregations, turns}.
    """
    from nexus.langgraph.backbone import backbone_call

    case_dir = Path(case_dir)
    case_id = case_dir.name
    audit = AuditWriter("nexus")

    # ── Step 1: evidence landscape (index_mappings) ──
    mappings = backbone_call("index_mappings", audit=audit, case_id=case_id)
    if mappings.get("error"):
        return {"reply": f"Cannot access evidence: {mappings['error']}",
                "queries_executed": [], "total_hits": 0, "turns": 0}

    families = mappings.get("families") or []
    family_fields = mappings.get("family_fields") or {}
    es_note = mappings.get("note") or ""

    # ── Step 2: the LLM plans and executes queries ──

    # Conversation: the agent iterates — LLM decides which tools to call
    history_block = ""
    if history:
        history_lines = "\n".join(
            f"  {h.get('role', '')}: {h.get('text', '')[:200]}"
            for h in (history or [])[-6:]
        )
        history_block = f"Prior conversation:\n{history_lines}"

    messages: list[dict[str, str]] = [
        {"role": "system", "content": (
            "You are a JSON-only tool-calling assistant. When you need to search "
            "evidence, respond with ONLY: {\"tool\": \"n4_query\", \"args\": "
            "{\"dsl\": \"...\", \"limit\": 50}} or {\"tool\": \"n4_aggregate\", "
            "\"args\": {\"dsl\": \"...\", \"field\": \"...\"}} or "
            "{\"tool\": \"family_fields\", \"args\": {\"family\": \"...\"}} or "
            "{\"tool\": \"index_mappings\", \"args\": {}}. "
            "When you have enough evidence to answer, respond with ONLY: "
            "{\"answer\": \"your natural-language answer citing specific evidence rows\", "
            "\"queries_used\": [\"...\"], \"confidence\": \"high|medium|low\"}. "
            "Never mix tool calls and answers in one response."
        )},
        {"role": "user", "content": (
            f"Examiner question: {question}\n\n"
            f"Evidence families: {', '.join(families)}\n"
            f"Family fields: {json.dumps(family_fields)[:2000]}\n"
            f"Backend: {es_note}\n"
            f"{history_block}"
        )},
    ]

    queries_executed: list[dict[str, Any]] = []
    aggregations: list[dict[str, Any]] = []
    reply = ""
    confidence = "medium"
    total_hits = 0

    for turn in range(max_turns):
        try:
            from nexus.langgraph.llm_pipeline import get_model
            model = get_model()
            if model is None:
                break
            response = model.invoke(messages)
            text = getattr(response, "content", str(response))
            start, end = text.find("{"), text.rfind("}")
            if start == -1 or end == -1:
                break
            action = json.loads(text[start:end + 1])

            if "answer" in action:
                # The LLM is done — it formulated an answer
                reply = str(action.get("answer") or "")[:3000]
                confidence = str(action.get("confidence") or "medium")
                break

            tool_name = str(action.get("tool") or "")
            tool_args = action.get("args") or {}
            tool_args["case_id"] = case_id  # enforce the case gate

            log.info("Steer agent turn %d: %s %s", turn, tool_name,
                     {k: str(v)[:60] for k, v in tool_args.items()})
            result = backbone_call(tool_name, audit=audit, **tool_args)

            # Feed the result back for the next turn
            if tool_name in ("n4_query", "n4_aggregate"):
                queries_executed.append({
                    "tool": tool_name,
                    "dsl": str(tool_args.get("dsl") or tool_args.get("field") or ""),
                    "hits": result.get("count") or result.get("rows_scanned") or 0,
                    "audit_id": (result.get("provenance") or {}).get("audit_id"),
                })
                total_hits = result.get("count") or result.get("rows_scanned") or 0
                hits_summary = _format_hits_for_llm(result.get("hits") or [])
                messages.append({"role": "assistant",
                                 "content": json.dumps(action)})
                messages.append({"role": "human",
                                 "content": f"Tool result ({total_hits} rows):\n{hits_summary}"})
            elif tool_name == "index_mappings":
                messages.append({"role": "assistant",
                                 "content": json.dumps(action)})
                messages.append({"role": "human",
                                 "content": f"Index info: {json.dumps(result.get('families', []))}, "
                                            f"fields: {json.dumps(result.get('family_fields', {}))[:1500]}"})
            elif tool_name == "family_fields":
                messages.append({"role": "assistant",
                                 "content": json.dumps(action)})
                messages.append({"role": "human",
                                 "content": f"Fields: {json.dumps(result.get('fields', []))}"})
            else:
                messages.append({"role": "assistant",
                                 "content": json.dumps(action)})
                messages.append({"role": "human",
                                 "content": f"Result: {json.dumps(result, default=str)[:2000]}"})
        except Exception as exc:
            log.warning("Steer agent turn %d failed: %s", turn, exc)
            break

    if not reply:
        # Agent ran out of turns without an answer — summarize what it found
        reply = (
            f"I searched the evidence ({len(queries_executed)} queries, "
            f"{total_hits} rows) but couldn't form a complete answer. "
            "Try a more specific question or check the evidence in Explore."
        )

    return {
        "reply": reply,
        "queries_executed": queries_executed,
        "total_hits": total_hits,
        "aggregations": aggregations,
        "turns": len(messages) - 1,
        "confidence": confidence,
    }
