"""Mode 2 steering agent — WP 4j.13 (conversational evidence agent, v2).

A reliable 3-step pipeline (NOT a fragile ReAct JSON loop):
  1. PLAN: LLM reads the NL question + evidence landscape → generates N4 DSL queries
  2. EXECUTE: the code runs them deterministically through the case-gated backbone
  3. ANSWER: LLM reads the actual result rows → formulates a natural-language answer

If step 1 fails (no LLM or bad response), fall back to keyword extraction.
If step 3 fails, return the raw evidence rows as the reply.
The examiner gets: the answer, the queries that produced it, and cited rows.
"""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

from nexus.audit import AuditWriter

log = logging.getLogger(__name__)

_MAX_QUERIES = 4
_MAX_HITS_IN_CONTEXT = 15
_MAX_ROW_CHARS = 400
_MAX_HITS_TOTAL = 500


def _format_hits_for_llm(hits: list[dict[str, Any]], cap: int = _MAX_HITS_IN_CONTEXT) -> str:
    """Compact hit table for the LLM to read — parsed columns, not raw CSV."""
    lines: list[str] = []
    for h in hits[:cap]:
        fam = str(h.get("family") or "")
        text = str(h.get("text") or "")[:_MAX_ROW_CHARS]
        fields = h.get("fields") or {}
        salient = " | ".join(f"{k}={str(v)[:80]}" for k, v in list(fields.items())[:6] if v)
        lines.append(f"[{fam}] {text}" + (f"\n         fields: {salient}" if salient else ""))
    return "\n".join(lines) or "(no results)"


def _plan_queries(question: str, model: Any, families: list[str],
                  family_fields: dict[str, list[str]]) -> list[str]:
    """Step 1: LLM translates the NL question into N4 DSL queries."""
    from nexus.knowledge.loader import dsl_prompt_block

    grammar = dsl_prompt_block(cap=8)
    fields_block = "\n".join(
        f"  {fam}: {', '.join((fields or [])[:8])}"
        for fam, fields in family_fields.items() if fields
    )

    system = (
        "You translate the examiner's natural-language question into N4 DSL "
        "search queries for forensic evidence.\n"
        f"\nN4 grammar:\n{grammar}\n\n"
        f"Available families and their fields:\n{fields_block}\n\n"
        "RULES:\n"
        "- Return ONLY JSON: {\"queries\": [\"<dsl query 1>\", \"<query 2>\", ...]}\n"
        "- Each query is ONE complete DSL expression (e.g. 'family:hayabusa AND sdelete').\n"
        "- Use family: filters to target artifact types.\n"
        "- For counting questions, include an aggregation query via n4_aggregate:\n"
        "  prefix with 'AGGREGATE:' e.g. 'AGG:family:hayabusa|field:host'.\n"
        "- Generate 1-4 queries that together answer the question.\n"
        "- If the question asks about 'users', use user: or aggregate on user fields.\n"
        "- If the question asks about 'executions' or '.exe', search process/execution "
        "fields (Image, CommandLine, SourceFileName).\n"
        "- Do NOT return methodology or explanations — ONLY the JSON."
    )
    try:
        response = model.invoke([
            {"role": "system", "content": system},
            {"role": "user", "content": f"Question: {question}"},
        ])
        text = getattr(response, "content", str(response))
        start, end = text.find("{"), text.rfind("}")
        if start == -1 or end == -1:
            return []
        parsed = json.loads(text[start:end + 1])
        queries = [str(q).strip() for q in (parsed.get("queries") or []) if str(q).strip()]
        return queries[:_MAX_QUERIES]
    except Exception as exc:
        log.warning("Query planning failed: %s", exc)
        return []


def _execute_queries(queries: list[str], case_id: str, audit: AuditWriter) -> tuple[
    list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]],
]:
    """Step 2: execute the planned queries through the case-gated backbone."""
    from nexus.langgraph.backbone import backbone_call

    all_hits: list[dict[str, Any]] = []
    queries_executed: list[dict[str, Any]] = []
    aggregations: list[dict[str, Any]] = []
    seen_rows: set[str] = set()

    for q in queries:
        if q.startswith("AGG:"):
            # Aggregation query: AGG:family:hayabusa|field:host
            parts = q[4:].split("|")
            agg_dsl = parts[0].strip() if parts else ""
            agg_field = parts[1].replace("field:", "").strip() if len(parts) > 1 else "host"
            result = backbone_call("n4_aggregate", audit=audit,
                                   case_id=case_id, dsl=agg_dsl, field=agg_field, top=15)
            if not result.get("error"):
                aggregations.append({
                    "dsl": agg_dsl,
                    "field": agg_field,
                    "distinct": result.get("distinct", 0),
                    "top": (result.get("top") or [])[:10],
                    "audit_id": (result.get("provenance") or {}).get("audit_id"),
                })
                queries_executed.append({
                    "tool": "n4_aggregate", "dsl": f"{agg_dsl} field={agg_field}",
                    "hits": result.get("rows_scanned", 0),
                    "audit_id": (result.get("provenance") or {}).get("audit_id"),
                })
        else:
            result = backbone_call("n4_query", audit=audit,
                                   case_id=case_id, dsl=q, limit=100)
            if result.get("error"):
                log.warning("Query failed: %s → %s", q, result["error"])
                continue
            hits = result.get("hits") or []
            for h in hits:
                loc = f"{h.get('family', '')}:{h.get('file', '')}:{h.get('line', '')}"
                if loc not in seen_rows:
                    seen_rows.add(loc)
                    all_hits.append(h)
            queries_executed.append({
                "tool": "n4_query",
                "dsl": q,
                "hits": result.get("count", 0),
                "audit_id": (result.get("provenance") or {}).get("audit_id"),
            })
            if len(all_hits) >= _MAX_HITS_TOTAL:
                break
    return all_hits, queries_executed, aggregations


def _formulate_answer(question: str, model: Any, hits: list[dict[str, Any]],
                      aggregations: list[dict[str, Any]],
                      queries_executed: list[dict[str, Any]]) -> str:
    """Step 3: LLM reads the actual evidence rows and answers the question."""
    hits_block = _format_hits_for_llm(hits, cap=_MAX_HITS_IN_CONTEXT)
    agg_block = ""
    if aggregations:
        agg_block = "\nAggregations:\n" + "\n".join(
            f"  {a['field']}: {a['distinct']} distinct — top: "
            + ", ".join(f"{t['value']}({t['count']})" for t in (a.get("top") or [])[:5])
            for a in aggregations
        )

    system = (
        "You are a DFIR analyst answering the examiner's question based on "
        "ACTUAL evidence rows you just searched.\n"
        "The evidence is below. Read it. Then answer the examiner's question "
        "in clear natural language.\n"
        "RULES:\n"
        "- Cite specific evidence (family, timestamp, hostname, key fields).\n"
        "- If there are NO results, say so honestly.\n"
        "- Do NOT invent facts. Do NOT return methodology.\n"
        "- Be concise. The examiner wants an ANSWER, not a process description.\n"
    )
    try:
        response = model.invoke([
            {"role": "system", "content": system},
            {"role": "user", "content": (
                f"Question: {question}\n\n"
                f"Evidence rows found ({len(hits)} total):\n{hits_block}\n"
                f"{agg_block}\n"
                "Answer the question based on these evidence rows."
            )},
        ])
        return str(getattr(response, "content", str(response)))[:3000]
    except Exception as exc:
        log.warning("Answer formulation failed: %s", exc)
        return ""


def run_steer_agent(
    case_dir: Path,
    question: str,
    model: Any = None,
    history: list[dict[str, str]] | None = None,
    max_turns: int = 0,  # unused — the 3-step pipeline is bounded by design
) -> dict[str, Any]:
    """Conversational Mode 2 agent: NL → plan → execute → answer.

    Returns {reply, queries_executed, total_hits, aggregations, hits}.
    """
    from nexus.langgraph.backbone import backbone_call

    case_dir = Path(case_dir)
    case_id = case_dir.name
    audit = AuditWriter("nexus")

    # ── Evidence landscape (deterministic — no LLM needed) ──
    mappings = backbone_call("index_mappings", audit=audit, case_id=case_id)
    if mappings.get("error"):
        return {"reply": f"Cannot access evidence: {mappings['error']}",
                "queries_executed": [], "total_hits": 0, "turns": 0,
                "confidence": "low"}

    families = mappings.get("families") or []
    family_fields = mappings.get("family_fields") or {}

    # ── Resolve the LLM ──
    from nexus.langgraph.llm_pipeline import get_model

    llm = get_model()

    # ── Step 1: plan queries ──
    queries = []
    if llm is not None:
        queries = _plan_queries(question, llm, families, family_fields)
    if not queries:
        # Deterministic fallback: search all families for keywords in the question
        keywords = re.findall(r"[a-zA-Z0-9_.]{3,}", question.lower())
        stop = {"list", "all", "the", "from", "logs", "what", "show", "find",
                "how", "many", "which", "who", "where", "when", "tell", "give",
                "involved", "user", "users", "machine", "machines", "exe"}
        terms = [t for t in keywords if t not in stop and len(t) >= 3][:6]
        queries = [" ".join(terms)] if terms else ["match_all"]

    # ── Step 2: execute ──
    all_hits, queries_executed, aggregations = _execute_queries(
        queries, case_id, audit)

    # ── Step 3: answer ──
    if not all_hits and not aggregations:
        reply = (
            f"No evidence found for '{question[:100]}'. "
            f"Families searched: {', '.join(families)}. "
            "Try different terms or check the evidence inventory."
        )
        return {
            "reply": reply, "queries_executed": queries_executed,
            "total_hits": 0, "aggregations": [], "turns": 2,
            "confidence": "low",
        }

    reply = ""
    confidence = "medium"
    if llm is not None:
        reply = _formulate_answer(question, llm, all_hits, aggregations,
                                  queries_executed)
    if not reply:
        # Deterministic fallback — format the evidence rows directly
        reply = (
            f"Found {len(all_hits)} evidence row(s) from {len(queries_executed)} query/queries.\n\n"
            + _format_hits_for_llm(all_hits, cap=10)
        )
        if aggregations:
            reply += "\n\n" + "\n".join(
                f"Aggregation [{a['field']}]: {a['distinct']} distinct — "
                + ", ".join(f"{t['value']}({t['count']})" for t in (a.get("top") or [])[:5])
                for a in aggregations
            )

    total_hits = len(all_hits)
    return {
        "reply": reply,
        "queries_executed": queries_executed,
        "total_hits": total_hits,
        "aggregations": aggregations,
        "turns": 2,
        "confidence": confidence,
    }
