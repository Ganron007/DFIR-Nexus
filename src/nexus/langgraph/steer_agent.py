"""Mode 2 steering agent — WP 4j.13 (conversational evidence agent, v3).

A reliable 3-step pipeline (NOT a fragile ReAct JSON loop):
  1. PLAN: LLM reads the NL question + the case's REAL evidence landscape
     (indexed families + row counts + their fields) → generates N4 DSL queries
  2. EXECUTE: the code runs them deterministically through the case-gated
     backbone (n4_query / n4_aggregate)
  3. ANSWER: LLM reads the ACTUAL result rows (+ deterministic extractions
     like distinct .exe names) → formulates a natural-language answer

If step 1 fails (no LLM or bad JSON), fall back to keyword extraction.
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
_MAX_HITS_IN_CONTEXT = 40
_MAX_ROW_CHARS = 280
_MAX_HITS_TOTAL = 500

_EXE_RE = re.compile(r"[A-Za-z0-9_\-.]+\.exe\b", re.IGNORECASE)
_USER_RE = re.compile(r"(?:user|account)[=:\s]+([A-Za-z0-9_.\\$-]{2,64})", re.IGNORECASE)

_STOP_WORDS = {
    "list", "all", "the", "from", "log", "logs", "what", "which", "who", "show",
    "find", "tell", "give", "me", "in", "of", "this", "case", "how", "many",
    "was", "were", "is", "are", "did", "does", "do", "and", "or", "to", "for",
    "with", "involved", "seen", "any", "there", "that", "those", "these",
    "have", "has", "been", "please", "can", "you", "about", "into", "during",
}

_FIELD_HINTS = {
    "user": "user", "users": "user", "account": "user", "accounts": "user",
    "username": "user", "usernames": "user",
    "machine": "host", "machines": "host", "host": "host", "hosts": "host",
    "computer": "host", "computers": "host", "endpoint": "host",
    "endpoints": "host", "system": "host", "systems": "host",
}


def _format_hits_for_llm(hits: list[dict[str, Any]], cap: int = _MAX_HITS_IN_CONTEXT) -> str:
    """Compact hit table for the LLM to read — parsed columns, not raw CSV."""
    lines: list[str] = []
    for h in hits[:cap]:
        fam = str(h.get("family") or "")
        text = str(h.get("text") or "")[:_MAX_ROW_CHARS]
        fields = h.get("fields") or {}
        salient = " | ".join(f"{k}={str(v)[:80]}" for k, v in list(fields.items())[:6] if v)
        lines.append(f"[{fam}] {text}" + (f"\n         fields: {salient}" if salient else ""))
    if len(hits) > cap:
        lines.append(f"... and {len(hits) - cap} more matched row(s)")
    return "\n".join(lines) or "(no results)"


def _extract_tokens(hits: list[dict[str, Any]], pattern: re.Pattern[str], cap: int = 40) -> list[tuple[str, int]]:
    """Deterministic token census across ALL matched rows (not just the LLM's window).

    For "list all X" questions this gives the model a complete, verifiable list
    even when the row window is capped.
    """
    counts: dict[str, int] = {}
    for h in hits:
        blob = str(h.get("text") or "")
        fields = h.get("fields") or {}
        if isinstance(fields, dict):
            blob += " " + " ".join(str(v) for v in fields.values() if v)
        for m in pattern.findall(blob):
            key = m.lower() if isinstance(m, str) else str(m)
            if key:
                counts[key] = counts.get(key, 0) + 1
    ranked = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    return ranked[:cap]


def _plan_queries(question: str, model: Any, families: list[str],
                  family_rows: dict[str, int],
                  family_fields: dict[str, list[str]]) -> list[str]:
    """Step 1: LLM translates the NL question into N4 DSL queries."""
    from nexus.knowledge.loader import dsl_prompt_block

    grammar = dsl_prompt_block(cap=8)
    usable = [f for f in families if int(family_rows.get(f, 0) or 0) > 0]
    empty = [f for f in families if f not in usable]

    fam_lines = []
    for fam in usable:
        fields = ", ".join((family_fields.get(fam) or [])[:10])
        fam_lines.append(
            f"  family:{fam} — {family_rows.get(fam, 0)} indexed rows; "
            f"fields: {fields or '(schema-on-read: free-text search)'}"
        )
    fam_block = "\n".join(fam_lines) or "  (no indexed rows yet)"
    empty_line = (
        f"\nFamilies with NO indexed rows — NEVER query these: {', '.join(empty)}\n"
        if empty else ""
    )

    system = (
        "You translate the examiner's natural-language question into N4 DSL "
        "search queries for forensic evidence.\n"
        "\nINDEXED FAMILIES IN THIS CASE — these are the ONLY family names "
        f"that exist. NEVER invent family names (no 'evtx', 'sysmon', "
        f"'prefetch', 'security' — only the list below):\n{fam_block}\n"
        f"{empty_line}"
        f"\nN4 grammar:\n{grammar}\n\n"
        "RULES:\n"
        "- Return ONLY JSON: {\"queries\": [\"<dsl 1>\", \"<dsl 2>\"]}\n"
        "- Each query is ONE complete DSL expression, e.g. family:hayabusa AND sdelete\n"
        "- A bare term (e.g. `exe`, `powershell`, `rundll32`) searches ALL families — "
        "prefer this when unsure which family holds the data.\n"
        "- For 'list all X' questions use the tool n4_aggregate via the AGG "
        "prefix: AGG:match_all|field:host (or field:user) to enumerate distinct "
        "hosts/users across every indexed row.\n"
        "- For executables/processes, search terms like `exe`, process names, or "
        "`family:<fam> AND <term>`; do NOT use a field: filter unless the field "
        "is listed above.\n"
        "- Generate 1-4 queries that together answer the question.\n"
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


def _looks_like_match_all(dsl: str) -> bool:
    return dsl.strip().lower() in ("", "match_all", "*", "all", "everything")


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
        q = q.strip()
        if q.upper().startswith("AGG:"):
            body = q[4:].strip()
            hit_field = re.search(r"field\s*[:=]\s*([A-Za-z0-9_]+)", body, re.IGNORECASE)
            agg_field = hit_field.group(1) if hit_field else "host"
            dsl_part = re.split(r"\|?\s*field\s*[:=]", body, flags=re.IGNORECASE)[0].strip()
            dsl_part = dsl_part.rstrip("|").strip()
            match_all = _looks_like_match_all(dsl_part)
            result = backbone_call("n4_aggregate", audit=audit,
                                   case_id=case_id, dsl="" if match_all else dsl_part,
                                   field=agg_field, top=15, match_all=match_all)
            if result.get("error"):
                log.warning("Aggregation failed: %s → %s", q, result["error"])
                continue
            aggregations.append({
                "dsl": dsl_part or "match_all",
                "field": agg_field,
                "distinct": result.get("distinct", 0),
                "rows_scanned": result.get("rows_scanned", 0),
                "top": (result.get("top") or [])[:10],
                "audit_id": (result.get("provenance") or {}).get("audit_id"),
            })
            queries_executed.append({
                "tool": "n4_aggregate",
                "dsl": f"{dsl_part or 'match_all'} field={agg_field}",
                "hits": result.get("rows_scanned", 0),
                "audit_id": (result.get("provenance") or {}).get("audit_id"),
            })
        else:
            match_all = _looks_like_match_all(q)
            result = backbone_call("n4_query", audit=audit, case_id=case_id,
                                   dsl="" if match_all else q, limit=100,
                                   match_all=match_all)
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


def _gather_helper_context(question: str, audit: AuditWriter,
                           case_dir: Path | None = None) -> tuple[str, str, str]:
    """RAG methodology + custom-KB + TI context for the answer step.

    Helpers only — evidence comes from the ES index (n4_query/n4_aggregate).
    RAG gives methodology, the KB gives examiner-curated notes, TI gives
    provider verdicts for IOCs mentioned in the question or already swept
    into the case's analysis/ti_context.md. Never case evidence (FD-001).
    """
    rag_block = ""
    kb_block = ""
    ti_block = ""
    try:
        from nexus.tools.rag import _get_index

        idx = _get_index()
        if not idx.is_loaded:
            idx.load()
        res = idx.search(query=question[:300], top_k=2)
        lines = []
        for d in (res.get("results") or [])[:2]:
            text = re.sub(r"\s+", " ", str(d.get("text") or ""))[:350]
            src = str(d.get("source") or "unknown")
            lines.append(f"[RAG {src}] {text}")
        rag_block = "\n".join(lines)
    except Exception as exc:  # noqa: BLE001 — helper is optional by design
        log.debug("RAG helper unavailable: %s", exc)
    try:
        from nexus.langgraph.backbone import backbone_call

        kb = backbone_call("kb_search", audit=audit, query=question[:200], limit=3)
        lines = []
        for h in (kb.get("hits") or [])[:3]:
            title = h.get("title") or h.get("path") or h.get("id") or "kb"
            snippet = re.sub(r"\s+", " ", str(h.get("snippet") or h.get("text") or ""))[:280]
            lines.append(f"[KB {title}] {snippet}")
        kb_block = "\n".join(lines)
    except Exception as exc:  # noqa: BLE001 — KB is optional (NEXUS_KB_DIR)
        log.debug("KB helper unavailable: %s", exc)
    try:
        from nexus.langgraph.backbone import backbone_call
        from nexus.langgraph.ti_context import extract_iocs

        lines = []
        iocs = extract_iocs([question], cap=3)
        values = [
            v for kind in ("sha256", "sha1", "md5", "ipv4", "domain", "url")
            for v in (iocs.get(kind) or [])
        ][:3]
        for value in values:
            res = backbone_call("ti_lookup", audit=audit, value=value)
            if isinstance(res, dict) and not res.get("error"):
                lines.append(
                    f"[TI {value}] status={res.get('status', 'n/a')} "
                    f"malicious_count={res.get('malicious_count', 0)}"
                )
        if not lines and case_dir is not None:
            ti_path = Path(case_dir) / "analysis" / "ti_context.md"
            if ti_path.is_file():
                lines.append(ti_path.read_text(encoding="utf-8", errors="replace")[:900])
        ti_block = "\n".join(lines)
    except Exception as exc:  # noqa: BLE001 — TI is optional context
        log.debug("TI helper unavailable: %s", exc)
    return rag_block, kb_block, ti_block


def _formulate_answer(question: str, model: Any, hits: list[dict[str, Any]],
                      aggregations: list[dict[str, Any]],
                      queries_executed: list[dict[str, Any]],
                      rag_block: str = "", kb_block: str = "",
                      ti_block: str = "") -> str:
    """Step 3: LLM reads the actual evidence rows and answers the question."""
    hits_block = _format_hits_for_llm(hits, cap=_MAX_HITS_IN_CONTEXT)
    agg_block = ""
    if aggregations:
        agg_block = "\nAggregations (exact counts over ALL matched rows):\n" + "\n".join(
            f"  {a['field']}: {a['distinct']} distinct — top: "
            + ", ".join(f"{t['value']}({t['count']})" for t in (a.get("top") or [])[:10])
            for a in aggregations
        )
    exe_list = _extract_tokens(hits, _EXE_RE)
    exe_block = ""
    if exe_list:
        exe_block = (
            "\nDistinct executables observed across ALL matched rows "
            "(deterministic extraction — use this as the authoritative list):\n  "
            + ", ".join(f"{name} ({count})" for name, count in exe_list)
        )
    user_list = _extract_tokens(hits, _USER_RE)
    user_block = ""
    if user_list:
        user_block = (
            "\nUsers/accounts observed in the matched rows (deterministic "
            "extraction; excludes placeholders like 'n/a'):\n  "
            + ", ".join(f"{name} ({count})" for name, count in user_list
                        if name not in ("n/a", "na", "system"))
        )

    system = (
        "You are a DFIR analyst answering the examiner's question based on "
        "ACTUAL evidence rows that were just searched in this case.\n"
        "RULES:\n"
        "- Read the evidence below, then answer the examiner's question in "
        "clear natural language.\n"
        "- When an authoritative extraction or aggregation is provided, USE it "
        "and enumerate its values (e.g. list every executable).\n"
        "- Cite specifics: family, timestamp, hostname, key fields.\n"
        "- Methodology context (RAG) and examiner notes (KB) are provided as "
        "HELPERS — use them for interpretation and caveats, never as evidence. "
        "If you lean on them, name the source (e.g. 'per RAG: <source>').\n"
        "- If there are NO results, say so honestly.\n"
        "- Do NOT invent facts. Do NOT describe your methodology or the JSON "
        "you produced. Do NOT echo raw data structures.\n"
        "- Be concise and structured (short intro + list/table when listing)."
    )
    helper_block = ""
    if rag_block:
        helper_block += f"\nMethodology context (RAG — helper, not evidence):\n{rag_block}\n"
    if kb_block:
        helper_block += f"\nExaminer-curated KB notes (helper, not evidence):\n{kb_block}\n"
    if ti_block:
        helper_block += f"\nThreat-intel context (helper, not evidence):\n{ti_block}\n"
    try:
        response = model.invoke([
            {"role": "system", "content": system},
            {"role": "user", "content": (
                f"Question: {question}\n\n"
                f"Evidence rows found ({len(hits)} total):\n{hits_block}\n"
                f"{agg_block}{exe_block}{user_block}{helper_block}\n"
                "Answer the question based on this evidence."
            )},
        ])
        return str(getattr(response, "content", str(response)))[:3000]
    except Exception as exc:
        log.warning("Answer formulation failed: %s", exc)
        return ""


def _fallback_queries(question: str, families: list[str]) -> list[str]:
    """Deterministic planner used when the LLM is unavailable or fails."""
    words = re.findall(r"[a-zA-Z0-9_.]{3,}", question.lower())
    terms = [w for w in words if w not in _STOP_WORDS]
    queries: list[str] = []
    hinted: set[str] = set()
    for w in words:
        field = _FIELD_HINTS.get(w)
        if field and field not in hinted:
            hinted.add(field)
            queries.append(f"AGG:match_all|field:{field}")
    if terms:
        queries.append(" ".join(terms[:6]))
    if not queries:
        queries = ["match_all"]
    return queries[:_MAX_QUERIES]


def run_steer_agent(
    case_dir: Path,
    question: str,
    model: Any = None,
    history: list[dict[str, str]] | None = None,
    max_turns: int = 0,  # unused — the 3-step pipeline is bounded by design
) -> dict[str, Any]:
    """Conversational Mode 2 agent: NL → plan → execute → answer.

    Returns {reply, queries_executed, total_hits, aggregations, hits} on success.
    Returns {error, reply} when the active case has no accessible index.
    """
    from nexus.langgraph.backbone import backbone_call

    case_dir = Path(case_dir)
    case_id = case_dir.name
    audit = AuditWriter("nexus")

    # ── Evidence landscape (deterministic — no LLM needed) ──
    mappings = backbone_call("index_mappings", audit=audit, case_id=case_id)
    if mappings.get("error"):
        return {"error": mappings["error"],
                "reply": f"Cannot access evidence: {mappings['error']}",
                "queries_executed": [], "total_hits": 0, "turns": 0,
                "confidence": "low"}

    families = mappings.get("families") or []
    family_rows = {str(k): int(v or 0) for k, v in (mappings.get("family_rows") or {}).items()}
    family_fields = {
        str(k): [str(f) for f in (v or [])]
        for k, v in (mappings.get("family_fields") or {}).items()
    }

    # ── Resolve the LLM ──
    from nexus.langgraph.llm_pipeline import get_model

    llm = get_model()

    # ── Step 1: plan queries ──
    queries: list[str] = []
    if llm is not None:
        queries = _plan_queries(question, llm, families, family_rows, family_fields)
    if not queries:
        queries = _fallback_queries(question, families)
    # Guarantee at least one evidence-row query: aggregations alone give the
    # answer step no rows to cite or extract from (e.g. the .exe census).
    if queries and all(q.upper().startswith("AGG:") for q in queries):
        extra = [q for q in _fallback_queries(question, families)
                 if not q.upper().startswith("AGG:")]
        queries = list(queries) + extra

    # ── Step 2: execute ──
    all_hits, queries_executed, aggregations = _execute_queries(
        queries, case_id, audit)

    # ── Step 3: answer ──
    if not all_hits and not aggregations:
        searched = ", ".join(f for f in families if family_rows.get(f, 0) > 0) or "none"
        reply = (
            f"No evidence found for '{question[:100]}'. "
            f"Indexed families searched: {searched} "
            f"({sum(family_rows.values())} rows total; queries run: "
            f"{len(queries_executed)}). Try different search terms."
        )
        return {
            "reply": reply, "queries_executed": queries_executed,
            "total_hits": 0, "aggregations": [], "turns": 2,
            "confidence": "low",
        }

    reply = ""
    rag_block = ""
    kb_block = ""
    ti_block = ""
    if llm is not None:
        rag_block, kb_block, ti_block = _gather_helper_context(question, audit, case_dir)
        reply = _formulate_answer(question, llm, all_hits, aggregations,
                                  queries_executed, rag_block, kb_block, ti_block)
    if not reply:
        # Deterministic fallback — format the evidence rows directly
        reply = (
            f"Found {len(all_hits)} evidence row(s) from "
            f"{len(queries_executed)} query/queries.\n\n"
            + _format_hits_for_llm(all_hits, cap=10)
        )
        if aggregations:
            reply += "\n\n" + "\n".join(
                f"Aggregation [{a['field']}]: {a['distinct']} distinct — "
                + ", ".join(f"{t['value']}({t['count']})" for t in (a.get("top") or [])[:5])
                for a in aggregations
            )

    agg_rows = max((int(a.get("rows_scanned") or 0) for a in aggregations), default=0)
    return {
        "reply": reply,
        "queries_executed": queries_executed,
        "total_hits": len(all_hits) or agg_rows,
        "aggregations": aggregations,
        "hits": all_hits[:20],
        "turns": 2,
        "confidence": "medium",
    }
