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
# Row WINDOW sent to the answer LLM: no small artificial cap — the
# prompt_budget allocator (window × fill) decides how much fits. Row chars
# remain a per-row rendering choice so one giant CSV line cannot dominate.
_MAX_HITS_IN_CONTEXT = 400
_MAX_ROW_CHARS = 400
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


def _history_block(history: list[dict[str, str]] | None) -> str:
    """Prior turns as context. Size is the allocator's business (no small cap)."""
    if not isinstance(history, list):
        return ""
    lines: list[str] = []
    for entry in history[-20:]:
        if not isinstance(entry, dict):
            continue
        role = str(entry.get("role") or "").strip().lower()
        if role not in ("examiner", "llm"):
            continue
        text = re.sub(r"\s+", " ", str(entry.get("text") or "")).strip()[:2000]
        if not text:
            continue
        lines.append(f"{role}: {text}")
    if not lines:
        return ""
    return "Prior conversation context (context only; current question controls):\n" + "\n".join(lines)


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


def _case_entity_vocabulary(case_dir: Path) -> dict[str, list[str]]:
    """Known host/user/executable values for planner grounding.

    Reads the deterministic artifacts already on disk (digest → inventory) —
    cheap, and it stops the planner from inventing entity values that exist
    nowhere in the evidence.
    """
    vocab: dict[str, list[str]] = {"hosts": [], "users": [], "executables": []}
    case_dir = Path(case_dir)
    digest_path = case_dir / "analysis" / "case_digest.json"
    if digest_path.is_file():
        try:
            digest = json.loads(digest_path.read_text(encoding="utf-8"))
            spans = digest.get("entity_spans") or {}
            vocab["hosts"] = [
                str(i.get("value")) for i in (spans.get("host") or []) if i.get("value")
            ][:8]
            vocab["users"] = [
                str(i.get("value")) for i in (spans.get("user") or []) if i.get("value")
            ][:8]
            procs = (digest.get("entities") or {}).get("processes") or []
            vocab["executables"] = [
                str(p.get("value")) for p in procs if p.get("value")
            ][:8]
            if not vocab["hosts"]:
                vocab["hosts"] = [str(h) for h in (digest.get("hosts") or [])][:8]
        except (OSError, ValueError, TypeError):
            pass
    if not any(vocab.values()):
        inv_path = case_dir / "analysis" / "entity_inventory.json"
        if inv_path.is_file():
            try:
                inv = json.loads(inv_path.read_text(encoding="utf-8"))
                vocab["hosts"] = [
                    str(h.get("value")) for h in (inv.get("hosts") or []) if h.get("value")
                ][:8]
                vocab["users"] = [
                    str(u.get("value")) for u in (inv.get("users") or []) if u.get("value")
                ][:8]
                vocab["executables"] = [
                    str(p.get("value")) for p in (inv.get("processes") or []) if p.get("value")
                ][:8]
            except (OSError, ValueError, TypeError):
                pass
    return vocab


def _plan_queries(question: str, model: Any, families: list[str],
                  family_rows: dict[str, int],
                  family_fields: dict[str, list[str]],
                  history_block: str = "",
                  vocabulary: dict[str, list[str]] | None = None) -> list[dict[str, str]]:
    """Step 1: LLM translates the NL question into N4 DSL queries.

    Returns ``[{"dsl", "why"}]`` — the why powers the UI's "what was queried
    and why" transparency line. Tolerates bare-string query lists.
    """
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
    vocab = vocabulary or {}
    vocab_lines = [
        f"  {label}: {', '.join(values)}"
        for label, values in (
            ("hosts", vocab.get("hosts") or []),
            ("users", vocab.get("users") or []),
            ("executables", vocab.get("executables") or []),
        )
        if values
    ]
    vocab_block = ""
    if vocab_lines:
        vocab_block = (
            "\nKNOWN ENTITY VALUES IN THIS CASE (exact, from the processed "
            "evidence — use these values in field filters, NEVER invent "
            "entity values):\n" + "\n".join(vocab_lines) + "\n"
        )

    system = (
        "You translate the examiner's natural-language question into N4 DSL "
        "search queries for forensic evidence.\n"
        "\nINDEXED FAMILIES IN THIS CASE — these are the ONLY family names "
        f"that exist. NEVER invent family names (no 'evtx', 'sysmon', "
        f"'prefetch', 'security' — only the list below):\n{fam_block}\n"
        f"{empty_line}"
        f"{vocab_block}"
        f"\nN4 grammar:\n{grammar}\n\n"
        "RULES:\n"
        '- Return ONLY JSON: {"queries": [{"dsl": "<dsl 1>", "why": "<one '
        'clause: what this verifies>"}, ...]}\n'
        "- Each query is ONE complete DSL expression, e.g. family:hayabusa AND sdelete\n"
        "- A bare term (e.g. `exe`, `powershell`, `rundll32`) searches ALL families — "
        "prefer this when unsure which family holds the data.\n"
        "- When the question names a host/user/process, use the EXACT value from "
        "the known-values list with field syntax (`host:WS01 AND mimikatz`) — "
        "this is what makes a lookup hit the right rows.\n"
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
        user = f"Question: {question}"
        if history_block:
            user = f"{history_block}\n\n{user}"
        response = model.invoke([
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ])
        text = getattr(response, "content", str(response))
        start, end = text.find("{"), text.rfind("}")
        if start == -1 or end == -1:
            return []
        parsed = json.loads(text[start:end + 1])
        return _norm_query_items(parsed.get("queries"))
    except Exception as exc:
        log.warning("Query planning failed: %s", exc)
        return []


def _norm_query_items(items: Any, default_why: str = "") -> list[dict[str, str]]:
    """Normalize a mixed string/dict query list into ``[{dsl, why}]``."""
    out: list[dict[str, str]] = []
    if not isinstance(items, list):
        return out
    for item in items:
        if isinstance(item, str) and item.strip():
            out.append({"dsl": item.strip(), "why": default_why})
        elif isinstance(item, dict):
            dsl = str(item.get("dsl") or item.get("query") or "").strip()
            if dsl:
                out.append({
                    "dsl": dsl,
                    "why": str(item.get("why") or default_why)[:200],
                })
    return out[:_MAX_QUERIES]


def _looks_like_match_all(dsl: str) -> bool:
    return dsl.strip().lower() in ("", "match_all", "*", "all", "everything")


def _execute_queries(queries: list[dict[str, str]], case_id: str, audit: AuditWriter) -> tuple[
    list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]],
]:
    """Step 2: execute the planned queries through the case-gated backbone.

    ``queries`` items are ``{"dsl", "why"}``; the why is carried into
    ``queries_executed`` so the UI can show what was queried *and why*.
    """
    from nexus.langgraph.backbone import backbone_call

    all_hits: list[dict[str, Any]] = []
    queries_executed: list[dict[str, Any]] = []
    aggregations: list[dict[str, Any]] = []
    seen_rows: set[str] = set()

    for item in queries:
        q = str(item.get("dsl") or "").strip()
        why = str(item.get("why") or "")
        if not q:
            continue
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
                "distinct_approximate": result.get("distinct_approximate", False),
                "rows_scanned": result.get("rows_scanned", 0),
                "top": (result.get("top") or [])[:10],
                "audit_id": (result.get("provenance") or {}).get("audit_id"),
            })
            queries_executed.append({
                "tool": "n4_aggregate",
                "dsl": f"{dsl_part or 'match_all'} field={agg_field}",
                "why": why,
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
                "why": why,
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
        res = idx.search(query=question[:300], top_k=4)
        lines = []
        for d in (res.get("results") or [])[:4]:
            text = re.sub(r"\s+", " ", str(d.get("text") or ""))[:800]
            src = str(d.get("source") or "unknown")
            lines.append(f"[RAG {src}] {text}")
        rag_block = "\n".join(lines)
    except Exception as exc:  # noqa: BLE001 — helper is optional by design
        log.debug("RAG helper unavailable: %s", exc)
    try:
        from nexus.langgraph.backbone import backbone_call

        kb = backbone_call("kb_search", audit=audit, query=question[:200], limit=5)
        lines = []
        for h in (kb.get("hits") or [])[:5]:
            title = h.get("title") or h.get("path") or h.get("id") or "kb"
            snippet = re.sub(r"\s+", " ", str(h.get("snippet") or h.get("text") or ""))[:500]
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
                      ti_block: str = "", history_block: str = "",
                      case_dir: Path | None = None) -> str:
    """Step 3: LLM reads the actual evidence rows and answers the question.

    Context is packed by the project-wide budget (window × fill, default
    1M × 0.7) — evidence rows outrank helper context, and every pack is
    persisted to analysis/llm_context/ for audit.
    """
    hits_block = _format_hits_for_llm(hits, cap=_MAX_HITS_IN_CONTEXT)
    agg_block = ""
    if aggregations:
        agg_block = "\nAggregations (grounded over ALL matched rows):\n" + "\n".join(
            f"  {a['field']}: {a['distinct']} distinct"
            f"{' (approximate)' if a.get('distinct_approximate') else ''} — top: "
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
        "- FORMAT (important): compact markdown, never a wall of text. For any "
        "list of 3+ rows use a **markdown table** with columns taken from the "
        "row fields (e.g. | Time | Host | Family | Key fields | Detail |). "
        "Use short bold bullets for conclusions and a one-line intro. Only use "
        "plain prose for a short single-fact answer.\n"
        "- When an authoritative extraction or aggregation is provided, USE it "
        "and enumerate its values (e.g. list every executable).\n"
        "- Cite specifics: family, timestamp, hostname, key fields.\n"
        "- Methodology context (RAG) and examiner notes (KB) are provided as "
        "HELPERS — use them for interpretation and caveats, never as evidence. "
        "If you lean on them, name the source (e.g. 'per RAG: <source>').\n"
        "- End with a one-line `Sources:` note naming the families/files the "
        "answer is based on.\n"
        "- If there are NO results, say so honestly.\n"
        "- Do NOT invent facts. Do NOT describe your methodology or the JSON "
        "you produced. Do NOT echo raw data structures."
    )
    helper_block = ""
    if rag_block:
        helper_block += f"\nMethodology context (RAG — helper, not evidence):\n{rag_block}\n"
    if kb_block:
        helper_block += f"\nExaminer-curated KB notes (helper, not evidence):\n{kb_block}\n"
    if ti_block:
        helper_block += f"\nThreat-intel context (helper, not evidence):\n{ti_block}\n"

    # Budget pack: evidence first, then deterministic extractions, then
    # helpers/history. No small caps — the window decides.
    try:
        from nexus.langgraph.prompt_budget import log_usage, pack_sections, persist_context

        sections = [
            (0, "evidence_rows", hits_block),
            (1, "deterministic_extractions",
             f"{agg_block}{exe_block}{user_block}".strip()),
            (2, "threat_intel", ti_block),
            (3, "methodology_rag", rag_block),
            (4, "examiner_kb", kb_block),
            (5, "conversation_history", history_block),
        ]
        packed, report = pack_sections(sections)
        if case_dir is not None:
            persist_context(
                Path(case_dir), "mode2-steer-answer", packed, report,
                meta={"question": question[:160]},
            )
        log_usage("mode2-steer-answer", report)
        evidence_block = packed
    except Exception as exc:  # noqa: BLE001 — packing must never break a turn
        log.warning("steer context pack failed (%s) — unbudgeted content", exc)
        evidence_block = (
            f"Evidence rows found ({len(hits)} total):\n{hits_block}\n"
            f"{agg_block}{exe_block}{user_block}{helper_block}"
        )

    try:
        response = model.invoke([
            {"role": "system", "content": system},
            {"role": "user", "content": (
                f"Question: {question}\n\n"
                f"Evidence rows found ({len(hits)} total):\n{evidence_block}\n\n"
                "Answer the question based on this evidence."
            )},
        ])
        return str(getattr(response, "content", str(response)))[:8000]
    except Exception as exc:
        log.warning("Answer formulation failed: %s", exc)
        return ""


def _fast_plan(question: str) -> list[str] | None:
    """Deterministic planner for clear intents (WP 4j.34).

    Skips the LLM plan call (~30-90 s on reasoning models) only when the
    question is a generic list/count ask or contains exact IOCs. ANY specific
    entity (a named executable, a named user, a quoted phrase) means the
    question needs the LLM planner — the fast path must never silently drop
    the examiner's pivot filter.
    """
    q = (question or "").lower().strip()
    if not q:
        return None
    from nexus.langgraph.ti_context import extract_iocs

    iocs = extract_iocs([question], cap=3)
    ioc_values = [
        v for kind in ("sha256", "sha1", "md5", "ipv4", "domain", "url")
        for v in (iocs.get(kind) or [])
    ][:3]

    # Specific entity markers → LLM planner (filters must be expressible).
    if re.search(
        r"\b[a-z0-9_.-]+\.(exe|dll|sys|ps1|bat|cmd|vbs|js|docx?|xlsx?|pdf|zip|rar|7z)\b", q
    ):
        return None
    if re.search(
        r"\busers?\s+(?!(?:and|or|the|involved|on|from|with|in|who|that)\b)"
        r"[a-z0-9_.\\$-]{2,}",
        q,
    ) or '"' in q:
        return None

    if ioc_values:
        return ioc_values[:_MAX_QUERIES]

    if not re.search(
        r"\b(list|all|which|who|what|how many|count|name|show|involved|fired|seen)\b", q
    ):
        return None

    queries: list[str] = []
    if re.search(r"\b(user|users|account|accounts|username|usernames)\b", q):
        queries.append("AGG:match_all|field:user")
    if re.search(r"\b(machine|machines|host|hosts|computer|computers|endpoint|endpoints)\b", q):
        queries.append("AGG:match_all|field:host")
    if re.search(r"\b(exe|executable|executables|process|processes)\b", q):
        queries.append("exe")
    if re.search(r"\b(alert|alerts|detection|detections|rule|rules|signature)\b", q):
        queries.append("alert")
    if not queries:
        return None
    # A plain row query must accompany aggregations (answer step cites rows).
    if all(x.upper().startswith("AGG:") for x in queries):
        queries.append("match_all")
    return queries[:_MAX_QUERIES]


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


def _suggest_followups(question: str, families: list[str],
                       all_hits: list[dict[str, Any]],
                       aggregations: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Deterministic drill-down chips for the next steer turn (4j-H.8).

    Built from what the turn actually surfaced (top host/user/executables),
    never from guesswork — clicking a chip simply asks that question.
    """
    q_low = (question or "").lower().strip()
    chips: list[dict[str, str]] = []

    def add(label: str, text: str) -> None:
        if len(chips) >= 4 or not text.strip():
            return
        if text.lower().strip() == q_low:
            return
        if any(c["label"] == label for c in chips):
            return
        chips.append({"label": label, "question": text})

    hosts: dict[str, int] = {}
    users: dict[str, int] = {}
    for h in all_hits:
        host = str(h.get("host") or "").strip()
        if host:
            hosts[host] = hosts.get(host, 0) + 1
    for a in aggregations:
        target = hosts if a.get("field") == "host" else users if a.get("field") == "user" else None
        if target is None:
            continue
        for t in a.get("top") or []:
            value = str(t.get("value") or "").strip()
            if value:
                target[value] = target.get(value, 0) + int(t.get("count") or 0)

    if hosts:
        top_host = max(hosts, key=lambda k: hosts[k])
        if top_host.lower() not in q_low:
            add(f"Drill into {top_host}", f"What else happened on host {top_host}?")
    exes = _extract_tokens(all_hits, _EXE_RE, cap=5)
    if exes:
        name = exes[0][0]
        if name.lower() not in q_low:
            add(f"Trace {name}", f"What else did {name} do across the case?")
    if users:
        top_user = max(users, key=lambda k: users[k])
        if top_user.lower() not in q_low:
            add(f"Trace user {top_user}", f"What did user {top_user} do in this case?")
    if "list all users" not in q_low:
        add("List all users", "List all users seen in this case")
    if "list all hosts" not in q_low:
        add("List all hosts", "List all machines and hosts in this case")
    return chips[:4]


def run_steer_agent(
    case_dir: Path,
    question: str,
    model: Any = None,
    history: list[dict[str, str]] | None = None,
    max_turns: int = 0,  # unused — the 3-step pipeline is bounded by design
) -> dict[str, Any]:
    """Conversational Mode 2 agent: NL → plan → execute → answer.

    Returns {reply, queries_executed, total_hits, aggregations, hits,
    timings_ms, stages} on success. The timings/stages fields feed the UI's
    progress line (4j.33) so an examiner sees where the turn spends time.
    """
    import time as _time

    from nexus.langgraph.backbone import backbone_call

    case_dir = Path(case_dir)
    case_id = case_dir.name
    audit = AuditWriter("nexus")
    stages: list[dict[str, Any]] = []

    def _stage(name: str, started: float, detail: str = "") -> None:
        stages.append({
            "stage": name,
            "ms": round((_time.monotonic() - started) * 1000),
            "detail": detail[:200],
        })

    # ── Evidence landscape (deterministic — no LLM needed) ──
    t0 = _time.monotonic()
    mappings = backbone_call("index_mappings", audit=audit, case_id=case_id)
    _stage("index_mappings", t0, str(mappings.get("error") or ""))
    if mappings.get("error"):
        return {"error": mappings["error"],
                "reply": f"Cannot access evidence: {mappings['error']}",
                "queries_executed": [], "total_hits": 0, "turns": 0,
                "confidence": "low", "stages": stages,
                "timings_ms": {"index_mappings": stages[-1]["ms"]}}

    families = mappings.get("families") or []
    family_rows = {str(k): int(v or 0) for k, v in (mappings.get("family_rows") or {}).items()}
    family_fields = {
        str(k): [str(f) for f in (v or [])]
        for k, v in (mappings.get("family_fields") or {}).items()
    }

    # ── Resolve the LLM (absent/broken config must not kill the turn) ──
    from nexus.langgraph.llm_pipeline import get_model

    if model is not None:
        llm = model
    else:
        try:
            llm = get_model()
        except Exception as exc:  # noqa: BLE001 — no LLM is a supported mode
            log.warning("steering: LLM unavailable (%s) — deterministic path", exc)
            llm = None
    history_context = _history_block(history)

    # ── Step 1: plan queries ──
    t0 = _time.monotonic()
    queries: list[dict[str, str]] = []
    planned_by = "llm"
    fast = _fast_plan(question)
    if fast:
        queries = _norm_query_items(fast, "deterministic fast-path intent")
        planned_by = "deterministic"
    elif llm is not None:
        queries = _plan_queries(
            question, llm, families, family_rows, family_fields, history_context,
            vocabulary=_case_entity_vocabulary(case_dir),
        )
        if not queries:
            planned_by = "fallback"
    if not queries:
        planned_by = "fallback"
        queries = _norm_query_items(
            _fallback_queries(question, families), "deterministic keyword fallback"
        )
    if queries and all(q["dsl"].upper().startswith("AGG:") for q in queries):
        extra = [
            {"dsl": q, "why": "row evidence to accompany the aggregation"}
            for q in _fallback_queries(question, families)
            if not q.upper().startswith("AGG:")
        ]
        queries = queries + extra
    _stage("plan", t0, f"{planned_by}: " + "; ".join(q["dsl"] for q in queries[:4]))

    # ── Step 2: execute ──
    t0 = _time.monotonic()
    all_hits, queries_executed, aggregations = _execute_queries(
        queries, case_id, audit)
    _stage("execute", t0,
           f"{len(queries_executed)} quer(ies), {len(all_hits)} hits")

    # ── Step 3: answer ──
    followups = _suggest_followups(question, families, all_hits, aggregations)
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
            "confidence": "low", "stages": stages, "followups": followups,
            "timings_ms": {s["stage"]: s["ms"] for s in stages},
        }

    reply = ""
    rag_block = ""
    kb_block = ""
    ti_block = ""
    if llm is not None:
        t0 = _time.monotonic()
        rag_block, kb_block, ti_block = _gather_helper_context(question, audit, case_dir)
        _stage("helpers", t0,
               f"rag={len(rag_block)} kb={len(kb_block)} ti={len(ti_block)} chars")
        t0 = _time.monotonic()
        reply = _formulate_answer(
            question, llm, all_hits, aggregations, queries_executed,
            rag_block, kb_block, ti_block, history_context, case_dir,
        )
        _stage("answer", t0, f"{len(reply)} chars")
    if not reply:
        # Deterministic fallback — format the evidence rows directly
        reply = (
            f"Found {len(all_hits)} evidence row(s) from "
            f"{len(queries_executed)} query/queries.\n\n"
            + _format_hits_for_llm(all_hits, cap=40)
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
        # Distinct rows returned (deduped); aggregation scans are reported
        # separately so the two units are never conflated.
        "total_hits": len(all_hits),
        "rows_scanned": agg_rows,
        "aggregations": aggregations,
        "hits": all_hits[:20],
        "turns": 2,
        "confidence": "medium",
        "stages": stages,
        "followups": followups,
        "timings_ms": {s["stage"]: s["ms"] for s in stages},
    }
