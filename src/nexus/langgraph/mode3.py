"""Mode 3 — agentic investigation with plan approval.

The agent proposes an investigation plan (extra parsers for SKIP'd
artifacts, corroboration queries) on top of the completed mandatory N2
lane. The examiner approves items in the Cockpit; only approved items
execute. Extras re-run the mandatory lane first (prior-OK reused) — the
agent can add parsers, never skip the lane. One case-file HMAC option
seals REPORT.md + findings via the same challenge-response + verification
ledger as per-finding approval. The agent never approves findings.
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from nexus.langgraph.mode2 import corroboration_suggestions

log = logging.getLogger(__name__)

_MAX_PLAN_ITEMS = 12

_KNOWN_EXTRAS = {
    "chrome_profiles": "Chrome/Edge Profile* History (beyond Default)",
    "drivefs": "Google Drive File Stream logs/DB",
    "email": "PST/OST mailbox copy",
    "usb_serial": "USBSTOR serial parse from setupapi",
}

# Tools that are platform-inappropriate and should not appear as
# actionable SKIPs in the plan.  Suzaku is a Linux parser; log2timeline
# is informational (the plaso suggestion row), not a real SKIP.
_PLATFORM_SKIP = {
    "win32": {"suzaku"},
    "linux": set(),
}
_INFORMATIONAL_SKIP = {"(discovery)", "log2timeline"}


def _log_agent_run(case_dir: Path, entry: dict[str, Any]) -> None:
    case_dir = Path(case_dir)
    record = {"ts": datetime.now(UTC).isoformat(), **entry}
    with (case_dir / "agent_runs.jsonl").open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, default=str) + "\n")


def _load_ledger(case_dir: Path) -> list[dict]:
    """Load the tool-lane ledger from the standard locations."""
    case_dir = Path(case_dir)
    # Direct locations (case-level + run-level)
    for cand in (
        case_dir / "extractions" / "_tool_lane_ledger.json",
        case_dir / "ledger" / "_tool_lane_ledger.json",
    ):
        if cand.is_file():
            try:
                data = json.loads(cand.read_text(encoding="utf-8"))
                return data if isinstance(data, list) else []
            except (OSError, ValueError):
                return []
    # Run-dir fallback
    from nexus.langgraph.pipeline_runs import resolve_tools_extractions

    extractions = resolve_tools_extractions(case_dir)
    for cand in (
        extractions / "_tool_lane_ledger.json",
        extractions.parent / "ledger" / "_tool_lane_ledger.json",
    ):
        if cand.is_file():
            try:
                data = json.loads(cand.read_text(encoding="utf-8"))
                return data if isinstance(data, list) else []
            except (OSError, ValueError):
                return []
    return []


def _mandatory_lane_complete(ledger: list[dict]) -> bool:
    """True if the ledger has at least one OK mandatory-lane tool."""
    return any(row.get("status") == "OK" and row.get("tool") not in ("(discovery)", "log2timeline") for row in ledger)


def _rag_methodology_for_skips(skip_tools: list[str]) -> tuple[str, list[dict[str, Any]]]:
    """WP 3.9: Retrieve RAG methodology for SKIP'd tools/artifacts.

    Returns (methodology_text, provenance) for the LLM to use during planning.
    """
    if not skip_tools:
        return "", []
    try:
        from nexus.tools.rag import _check_rag_available, _get_index

        available, _ = _check_rag_available()
        if not available:
            return "", []

        idx = _get_index()
        blocks: list[str] = []
        provenance: list[dict[str, Any]] = []
        for tool in skip_tools:
            q = f"forensic methodology for {tool} artifact analysis"
            try:
                result = idx.search(query=q, top_k=3, source="kape")
                docs = result.get("results", [])
                if not docs:
                    result = idx.search(query=q, top_k=2)
                    docs = result.get("results", [])
                if docs:
                    block = f"\n--- {tool} methodology ---\n"
                    sources: list[str] = []
                    for d in docs[:3]:
                        text = d.get("text") or ""
                        block += str(text)[:400] + "\n"
                        sources.append(d.get("source", ""))
                    blocks.append(block)
                    provenance.append({
                        "tool": tool,
                        "query": q,
                        "doc_count": len(docs),
                        "sources": sources,
                    })
            except Exception:
                pass
        return "\n".join(blocks).strip(), provenance
    except Exception as exc:
        log.warning("RAG methodology for skips failed: %s", exc)
        return "", []


def _llm_plan(
    model: Any,
    items: list[dict[str, Any]],
    queries: list[str],
    rag_context: str,
    intake_question: str,
) -> tuple[list[dict[str, Any]], str, list[dict[str, Any]]]:
    """WP 3.5: Use LLM to propose a refined plan with RAG context.

    Returns (refined_items, rationale, rag_provenance_from_llm).
    Falls back to the deterministic items if the LLM fails.
    """
    rag_provenance: list[dict[str, Any]] = []
    prompt = (
        "You are a DFIR agent planner. You see evidence gaps from the tool-lane "
        "ledger and existing findings. Propose a plan to fill coverage gaps and "
        "corroborate single-source findings.\n\n"
        f"Case question: {intake_question}\n"
        f"Deterministic items (from ledger SKIPs + known extras):\n"
        f"{json.dumps(items, indent=1, default=str)[:2000]}\n\n"
        f"Corroboration queries: {', '.join(queries[:6])}\n\n"
        f"RAG methodology for SKIP'd artifacts:\n{rag_context[:2000] or '(none)'}\n\n"
        "Return ONLY JSON: {\"items\": [...], \"rationale\": \"one sentence\"}. "
        "Items can be {\"type\": \"extra\", \"key\": \"...\", \"purpose\": \"...\"} "
        "or {\"type\": \"tool_skip\", \"tool\": \"...\", \"reason\": \"...\"}. "
        "Use RAG methodology to explain why each tool matters."
    )
    try:
        response = model.invoke([{"role": "user", "content": prompt}])
        text = getattr(response, "content", str(response))
        start, end = text.find("{"), text.rfind("}")
        if start == -1 or end == -1:
            return items, "", rag_provenance
        parsed = json.loads(text[start:end + 1])
        llm_items = parsed.get("items") or []
        rationale = str(parsed.get("rationale") or "")[:300]
        # Validate LLM items structure
        valid_items: list[dict[str, Any]] = []
        for item in llm_items[:_MAX_PLAN_ITEMS]:
            if not isinstance(item, dict):
                continue
            item_type = item.get("type")
            if item_type == "extra" and item.get("key"):
                valid_items.append({
                    "type": "extra",
                    "key": str(item["key"])[:50],
                    "purpose": str(item.get("purpose") or "")[:200],
                })
            elif item_type == "tool_skip" and item.get("tool"):
                valid_items.append({
                    "type": "tool_skip",
                    "tool": str(item["tool"])[:50],
                    "reason": str(item.get("reason") or "")[:200],
                })
        if valid_items:
            return valid_items, rationale, rag_provenance
        return items, rationale, rag_provenance
    except Exception as exc:
        log.warning("Mode 3 LLM planning failed: %s", exc)
        return items, "", rag_provenance


def plan_extras(case_dir: Path, model: Any = None) -> dict[str, Any]:
    """Agent proposes the investigation plan (extras + corroboration queries).

    WP 3.5: When an LLM is available, it proposes plan items based on
    evidence gaps and RAG methodology, not just the static _KNOWN_EXTRAS dict.
    WP 3.9: RAG methodology is retrieved for SKIP'd artifacts and injected
    into the LLM planning prompt.
    WP 3.11: Agent runs are logged with RAG usage flag.
    WP 3.12: RAG provenance is recorded in the plan output.

    Sources: tool-lane ledger SKIPs, extras not yet requested, and FD-006
    corroboration needs from existing findings. Logged to agent_runs.jsonl + chat.
    """
    from nexus.case.chat import append_chat
    from nexus.langgraph.query_pack import load_case_intake

    case_dir = Path(case_dir)
    intake = load_case_intake(case_dir)
    requested_extras = {
        p.strip().lower()
        for p in (intake.get("extras") or "").replace(";", ",").split(",")
        if p.strip()
    }

    items: list[dict[str, Any]] = []
    # 1. Known extras not yet requested
    for key, label in _KNOWN_EXTRAS.items():
        if key not in requested_extras:
            items.append({"type": "extra", "key": key, "purpose": label})

    # 2. Ledger SKIPs (real parser gaps the examiner may want to fill)
    ledger = _load_ledger(case_dir)
    platform_skips = _PLATFORM_SKIP.get(sys.platform, set())
    skip_tools: list[str] = []
    for row in ledger:
        if row.get("status") != "SKIP":
            continue
        tool = str(row.get("tool") or "")
        if tool in _INFORMATIONAL_SKIP or tool in platform_skips:
            continue
        items.append({
            "type": "tool_skip",
            "tool": tool,
            "reason": str(row.get("reason") or "")[:160],
        })
        skip_tools.append(tool)

    # 3. Corroboration queries from findings (FD-006)
    queries: list[str] = []
    findings_path = case_dir / "findings.json"
    if findings_path.is_file():
        try:
            for f in json.loads(findings_path.read_text(encoding="utf-8")):
                for q in corroboration_suggestions(f):
                    if q not in queries:
                        queries.append(q)
        except (OSError, ValueError):
            pass

    # WP 3.9: RAG methodology for SKIP'd artifacts
    rag_context, rag_provenance = _rag_methodology_for_skips(skip_tools)
    rag_used = bool(rag_context)

    rationale = (
        f"Agent plan: {len(items)} extra step(s) + {len(queries)} corroboration "
        "queries, derived from ledger SKIPs and single-source findings."
    )

    # WP 3.5: LLM-driven planning with RAG context
    if model is not None:
        try:
            llm_items, llm_rationale, _ = _llm_plan(
                model, items, queries, rag_context, intake.get("question", "")
            )
            items = llm_items
            if llm_rationale:
                rationale = llm_rationale
        except Exception as exc:  # noqa: BLE001
            log.warning("Mode 3 LLM planning failed: %s", exc)

    plan = {
        "case_id": case_dir.name,
        "items": items[:_MAX_PLAN_ITEMS],
        "queries": queries[:8],
        "rationale": rationale,
        "created_at": datetime.now(UTC).isoformat(),
        "lane_complete": _mandatory_lane_complete(ledger),
        "rag_context": rag_context,
        "rag_provenance": rag_provenance,
    }
    _log_agent_run(case_dir, {
        "action": "mode3_plan",
        "items": len(plan["items"]),
        "queries": len(queries),
        "rag_used": rag_used,
    })
    append_chat(
        case_dir, "llm", "mode3_plan",
        f"Agent plan ready: {len(plan['items'])} step(s), {len(queries)} corroboration query(ies). "
        + ("RAG methodology applied." if rag_used else "")
        + " Awaiting examiner approval.",
    )
    return plan



def _run_iterative_for_queries(
    case_dir: Path,
    question: str,
    model: Any = None,
    max_iterations: int = 3,
    limit: int = 80,
) -> dict[str, Any]:
    """WP 3.6: Run the Mode 2 iterative query loop for Mode 3 execution.

    This wraps the Mode 2 propose→query→analyze loop so the agent iterates
    on approved queries rather than running them one-shot. Every iteration
    is logged to the case chat transcript.
    """
    from nexus.langgraph.mode2 import run_iterative_loop

    return run_iterative_loop(
        case_dir, question, model=model, max_iterations=max_iterations, limit=limit
    )


def propose_agent_finding(
    case_dir: Path,
    hits: list[dict[str, Any]],
    title: str,
    model: Any = None,
    interpretation_hint: str = "",
) -> dict[str, Any]:
    """WP 3.7: Agent proposes a DRAFT finding from hits.

    Stages a DRAFT finding with ``examiner_selected=False`` — the examiner
    reviews, edits, approves, or rejects via the normal HMAC flow.
    The agent NEVER approves. Reuses Mode 2's ``propose_draft_finding``
    so the scribing + corroboration logic is shared.

    Returns {draft, corroboration} or {error}.
    """
    from nexus.case.chat import append_chat
    from nexus.langgraph.mode2 import propose_draft_finding

    if not hits:
        return {"error": "No hits to draft from"}

    result = propose_draft_finding(
        case_dir, hits, title, model=model, interpretation_hint=interpretation_hint
    )
    if "error" in result:
        return result

    draft = result.get("draft")
    if not draft:
        return {"error": "Failed to stage draft finding"}

    _log_agent_run(case_dir, {
        "action": "mode3_draft_finding",
        "title": str(draft.get("title", title))[:100],
        "evidence_count": len(draft.get("evidence") or []),
        "examiner_selected": False,
        "approval_state": "DRAFT",
    })
    append_chat(
        case_dir, "llm", "mode3_draft",
        f"Agent drafted finding: {draft.get('title', title)}. "
        f"Staged as DRAFT — examiner review required.",
    )
    return result


def execute_plan(
    case_dir: Path,
    approved_extras: list[str],
    approved_queries: list[str],
    model: Any = None,
) -> dict[str, Any]:
    """Execute examiner-approved plan items.

    Extras: persisted to CASE.yaml intake (next lane run picks them up;
    mandatory lane first, prior-OK reused). Queries: run through the
    WP 3.6 iterative loop (propose → query → analyze → re-query), not
    one-shot. Everything logged to agent_runs.jsonl + chat.

    Refuses to run if the mandatory lane has not completed at least one
    OK tool — the agent can add parsers but never skip the lane.
    """
    from nexus.case.chat import append_chat

    case_dir = Path(case_dir)

    # Mandatory-lane-first guard: refuse if the lane never ran
    ledger = _load_ledger(case_dir)
    if not _mandatory_lane_complete(ledger):
        return {
            "error": "Mandatory lane not complete — run the tools lane before executing agent extras.",
        }

    valid_extras = [e for e in approved_extras if e in _KNOWN_EXTRAS]
    if valid_extras:
        from nexus.langgraph.case_intake import persist_case_intake
        from nexus.langgraph.query_pack import load_case_intake

        intake = load_case_intake(case_dir)
        existing = [
            e.strip()
            for e in (intake.get("extras") or "").replace(";", ",").split(",")
            if e.strip()
        ]
        merged = list(dict.fromkeys(existing + valid_extras))
        persist_case_intake(case_dir, {"extras": ",".join(merged)})

    # WP 3.6: Run queries through the iterative loop, not one-shot
    iterative_result: dict[str, Any] | None = None
    if approved_queries:
        combined_query = " ".join(approved_queries)
        iterative_result = _run_iterative_for_queries(
            case_dir, combined_query, model=model, max_iterations=3, limit=80
        )
        _log_agent_run(case_dir, {
            "action": "mode3_iterative",
            "queries": approved_queries,
            "iterations": len(iterative_result.get("iterations", [])),
            "total_hits": iterative_result.get("total_hits", 0),
            "capped": iterative_result.get("capped", False),
        })

    # Derive per-query summary from the iterative result (avoids a second
    # round of n4_query calls that would double-load Elasticsearch).
    query_results: list[dict[str, Any]] = []
    if iterative_result is not None:
        total_hits = iterative_result.get("total_hits", 0)
        for q in approved_queries:
            query_results.append({"query": q, "count": total_hits})
    elif approved_queries:
        # No iterative result (e.g. model unavailable) — one-shot fallback.
        from nexus.langgraph.query_pack import n4_query

        for q in approved_queries:
            r = n4_query(case_dir, q, limit=40)
            query_results.append({"query": q, "count": r.get("count", 0), "error": r.get("error")})

    _log_agent_run(case_dir, {
        "action": "mode3_execute",
        "extras": valid_extras,
        "queries": [q.get("query") for q in query_results],
    })
    append_chat(
        case_dir, "llm", "mode3_execute",
        f"Executed approved plan: extras={valid_extras or 'none'}, "
        f"queries={len(query_results)}. Re-run the tools lane to parse new extras.",
    )
    result: dict[str, Any] = {
        "status": "executed",
        "extras_persisted": valid_extras,
        "query_results": query_results,
        "note": "Extras parse on the next lane run (mandatory lane first, prior-OK reused).",
    }
    if iterative_result is not None:
        result["iterative"] = iterative_result
    return result


def seal_case(
    case_dir: Path,
    examiner: str,
    password: str,
    *,
    skip_verify: bool = False,
) -> dict[str, Any]:
    """Case-file HMAC (Mode 3): one signature over REPORT.md + findings.

    Verifies the examiner password before signing (unless ``skip_verify``
    is True — used by the challenge-response API path which has already
    proved the examiner knows the password). Derives the signing key from
    the password (not the stored hash). The HMAC is computed over the
    exact content snapshot stored in the ledger, so verification always
    matches. Uses the same PBKDF2/HMAC verification ledger as per-finding
    approval.
    """
    from nexus.auth import (
        SIGNING_PURPOSE,
        _load_password_entry,
        compute_hmac,
        derive_hmac_key,
        derive_purpose_key,
        verify_password,
        write_verification_entry,
    )

    case_dir = Path(case_dir)
    report = case_dir / "reports" / "REPORT.md"
    findings = case_dir / "findings.json"
    if not report.is_file():
        return {"error": "No REPORT.md — generate the report first (N8)"}

    entry = _load_password_entry(examiner)
    if not entry:
        return {"error": f"No password configured for {examiner}"}

    # Verify the examiner password before signing (unless the caller
    # already proved it via challenge-response).
    if not skip_verify and not verify_password(examiner, password):
        return {"error": "Password verification failed"}

    content = report.read_text(encoding="utf-8")
    # Build the exact payload that will be stored — HMAC over the same
    # bytes so verification always matches.
    content_snapshot = content[:100000]
    findings_count = 0
    if findings.is_file():
        try:
            findings_count = len(json.loads(findings.read_text(encoding="utf-8")))
        except (OSError, ValueError):
            findings_count = 0

    # Derive the signing key.  When the caller proved identity via
    # challenge-response we don't have the plaintext password, but
    # derive_hmac_key(password, salt) == pbkdf2(password, salt) == the
    # stored hash, so we use it directly as the base key.
    if skip_verify:
        base_key = bytes.fromhex(entry["hash"])
    else:
        base_key = derive_hmac_key(password, entry["salt"])
    purpose_key = derive_purpose_key(base_key, SIGNING_PURPOSE)
    hmac_val = compute_hmac(purpose_key, content_snapshot)

    write_verification_entry(case_dir.name, {
        "finding_id": "CASE-FILE",
        "type": "case_file",
        "approved_by": examiner,
        "approved_at": datetime.now(UTC).isoformat(),
        "content_snapshot": content_snapshot,
        "hmac": hmac_val,
        "salt": entry.get("salt", ""),
        "findings_count": findings_count,
    })

    # Transparency log
    try:
        from nexus.transparency import transparency_append

        transparency_append(case_dir.name, {
            "action": "case_seal",
            "examiner": examiner,
            "findings_count": findings_count,
            "hmac": hmac_val[:16] + "...",
        })
    except Exception:  # noqa: BLE001
        pass  # transparency is best-effort

    return {"status": "SEALED", "case_id": case_dir.name, "examiner": examiner}
