"""Mode 2 — LLM-guided iterative analysis.

The LLM proposes the next query and correlations; the examiner validates
and steers. Every proposal is logged to the case chat transcript with its
rationale; the examiner accepts or rejects each one. Hard caps bound the
loop (iterations, queries per run). The LLM never approves and never
writes findings without examiner review — DRAFTs it proposes still pass
through the normal FD validation + HMAC gate.

Heuristic fallback: when no model is configured, proposals come from hit
terms and entity extraction (deterministic, no LLM).
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

_MAX_ITERATIONS = 3
_MAX_NEEDLES_PER_PROPOSAL = 6
_MAX_HITS_SUMMARY = 12
_MAX_HIT_TEXT = 160

_PROPOSE_SYSTEM = (
    "You are a DFIR investigative partner. You are given N4 hit rows from "
    "parsed forensic evidence. Propose the NEXT search needles that would "
    "corroborate or expand the investigation. Respond with ONLY a JSON "
    'object: {"needles": ["term1", "term2"], "rationale": "one sentence"}. '
    "Rules: needles are concrete (artifact names, event IDs, file names, "
    "registry keys, hostnames); never invent facts; 2-6 needles; do not "
    "repeat needles already searched."
)


def _hit_summary(hits: list[dict[str, Any]]) -> str:
    rows = []
    for h in hits[:_MAX_HITS_SUMMARY]:
        rows.append(
            f"[{h.get('family', '')}] {h.get('file', '')}:{h.get('line', '')} "
            f":: {str(h.get('text', ''))[:_MAX_HIT_TEXT]}"
        )
    return "\n".join(rows) if rows else "(no hits)"


def propose_next_needles(
    case_dir: Path,
    question: str,
    hits: list[dict[str, Any]],
    already_run: list[str],
    model: Any = None,
) -> dict[str, Any]:
    """LLM proposes the next needles from current hits. Heuristic fallback.

    Returns {"needles": [...], "rationale": str, "source": "llm"|"heuristic"}.
    """
    if model is not None:
        try:
            return _propose_with_model(case_dir, hits, already_run, model)
        except Exception as exc:  # noqa: BLE001
            log.warning("Mode 2 LLM proposal failed (%s), using heuristic", exc)
    return _propose_heuristic(hits, already_run)


def _propose_with_model(case_dir: Path, hits: list[dict], already_run: list[str], model: Any) -> dict:
    from nexus.langgraph.query_pack import load_case_intake

    intake = load_case_intake(case_dir)
    families = sorted({h.get("family", "?") for h in hits})
    hit_summary = "\n".join(
        f"- {h.get('family')}: {str(h.get('text', ''))[:_MAX_HIT_TEXT]}" for h in hits[:_MAX_HITS_SUMMARY]
    )
    user = (
        f"Case question: {intake.get('question', '(none)')}\n"
        f"Artifact families with hits: {', '.join(families) or '(none)'}\n"
        f"Already searched: {', '.join(already_run) or '(none)'}\n\n"
        f"Hit rows:\n{hit_summary}\n\n"
        "Propose 2-6 NEW search needles to corroborate or expand this picture. "
        'Return ONLY JSON: {"needles": [...], "rationale": "..."}'
    )
    response = model.invoke([
        {"role": "system", "content": _PROPOSE_SYSTEM},
        {"role": "user", "content": user},
    ])
    text = getattr(response, "content", str(response))
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end == -1:
        raise ValueError("model returned no JSON")
    parsed = json.loads(text[start:end + 1])
    needles = [str(n).strip() for n in (parsed.get("needles") or []) if str(n).strip()][
        :_MAX_NEEDLES_PER_PROPOSAL
    ]
    return {
        "needles": needles,
        "rationale": str(parsed.get("rationale") or "")[:300],
        "source": "llm",
    }


def _propose_heuristic(hits: list[dict], already_run: list[str]) -> dict:
    """Deterministic fallback: mine hit terms + entities for new needles."""
    from nexus.analysis.entities import extract_entities

    candidates: list[str] = []
    seen = {t.lower() for t in already_run}
    for h in hits[:_MAX_HITS_SUMMARY]:
        for t in str(h.get("terms") or "").split(","):
            t = t.strip().lower()
            if t and t not in seen and not t.isdigit():
                candidates.append(t)
                seen.add(t)
    entities = extract_entities([str(h.get("text", "")) for h in hits[:_MAX_HITS_SUMMARY]])
    for exe in list(entities.get("processes", {}))[:3]:
        if exe.lower() not in seen:
            candidates.append(exe)
            seen.add(exe.lower())
    for ip in list(entities.get("ips", {}))[:2]:
        candidates.append(ip)
        seen.add(ip.lower())
    return {
        "needles": candidates[:_MAX_NEEDLES_PER_PROPOSAL],
        "rationale": "Derived from hit terms and extracted entities (deterministic fallback).",
        "source": "heuristic",
    }


def run_iterative_loop(
    case_dir: Path,
    question: str,
    model: Any = None,
    max_iterations: int = 2,
    limit: int = 80,
) -> dict[str, Any]:
    """Mode 2 loop: query -> analyze -> propose -> re-query.

    Every step is logged to the case chat transcript. Hard caps:
    max_iterations re-queries; each proposal is capped. The loop NEVER
    writes findings — it returns the iteration log for examiner review.
    """
    from nexus.case.chat import append_chat
    from nexus.langgraph.mode1 import nl_to_needles
    from nexus.langgraph.query_pack import load_case_intake, n4_query

    case_dir = Path(case_dir)
    iterations: list[dict[str, Any]] = []
    all_needles_run: list[str] = []

    intake = load_case_intake(case_dir)
    _ = intake  # window comes from n4_query's internal intake handling

    # Iteration 0: initial query from the question
    parsed0 = nl_to_needles(question, model=model)
    needles0 = parsed0.get("needles", [])
    if not needles0:
        return {"error": "No needles extracted from the question", "iterations": []}
    r0 = n4_query(case_dir, " ".join(needles0), limit=limit)
    if r0.get("error"):
        return {"error": r0["error"], "iterations": []}
    all_needles_run.extend(needles0)
    hits = r0.get("hits", [])
    iterations.append({
        "iteration": 0,
        "action": "initial_query",
        "needles": needles0,
        "hits": r0.get("count", 0),
        "backend": r0.get("backend", ""),
    })
    append_chat(case_dir, "llm", "mode2_iter0", f"Initial query: {', '.join(needles0)} -> {r0.get('count', 0)} hits")

    # Iterative proposals
    for it in range(1, max_iterations + 1):
        if not hits:
            break
        proposal = propose_next_needles(case_dir, question, hits, all_needles_run, model)
        new_needles = [
            n for n in proposal.get("needles", [])
            if n.lower() not in {x.lower() for x in all_needles_run}
        ][:_MAX_NEEDLES_PER_PROPOSAL]
        if not new_needles:
            iterations.append({"iteration": it, "action": "no_new_proposals", "rationale": proposal.get("rationale", "")})
            append_chat(case_dir, "llm", "mode2_stop", "No new needles to propose.", {"iteration": it})
            break
        all_needles_run.extend(new_needles)
        rq = n4_query(case_dir, " ".join(new_needles), limit=limit)
        new_hits = rq.get("hits", [])
        iterations.append({
            "iteration": it,
            "action": "proposed_and_ran",
            "needles": new_needles,
            "rationale": proposal.get("rationale", ""),
            "source": proposal.get("source", ""),
            "hits": rq.get("count", 0),
            "new_families": sorted({h.get("family") for h in new_hits} - {h.get("family") for h in hits}),
        })
        append_chat(
            case_dir, "llm", "mode2_proposal",
            f"Iteration {it}: proposed {', '.join(new_needles)} -> {rq.get('count', 0)} hits",
            {"rationale": proposal.get("rationale", ""), "needles": ",".join(new_needles)},
        )
        hits = hits + new_hits

    return {
        "question": question,
        "iterations": iterations,
        "total_hits": len(hits),
        "needles_run": all_needles_run,
        "capped": len(iterations) >= max_iterations,
    }


def corroboration_check(finding: dict[str, Any]) -> dict[str, Any]:
    """FD-006/007: distinct evidence families + confidence rule check.

    Single-family findings must stay LOW; returns suggested corroboration
    queries when corroboration is missing.
    """
    evidence = finding.get("evidence") or []
    families = sorted({str(e.get("source", "")).split("/")[0] for e in evidence if isinstance(e, dict)})
    n_families = len([f for f in families if f])
    confidence = str(finding.get("confidence") or "LOW").upper()
    audit_ids = finding.get("audit_ids") or []

    problems: list[str] = []
    if n_families <= 1 and confidence in ("MEDIUM", "HIGH", "SPECULATIVE"):
        problems.append(
            f"FD-006/007: single evidence family ({families or ['none']}) with confidence {confidence} — "
            "corroborate across artifact families or lower to LOW."
        )
    if len(audit_ids) < 2 and confidence in ("MEDIUM", "HIGH"):
        problems.append(
            f"FD-007: confidence {confidence} with {len(audit_ids)} audit_id(s) — corroborate before escalating."
        )

    suggestions: list[str] = []
    if n_families <= 1:
        fam = families[0] if families else ""
        suggestions.extend(_corroborate_for(fam))

    return {
        "families": families,
        "distinct_families": n_families,
        "confidence": confidence,
        "ok": n_families >= 2 or confidence == "LOW",
        "problems": problems,
        "suggested_queries": suggestions,
    }


def _corroborate_for(family: str) -> list[str]:
    """Corroboration needles per artifact family (what would independently confirm)."""
    mapping = {
        "prefetch": ["amcache", "shimcache"],
        "amcache": ["prefetch", "shimcache"],
        "evtx": ["hayabusa", "sysmon"],
        "hayabusa": ["evtxecmd", "sysmon"],
        "usnjrnl": ["mft"],
        "lnk": ["jump_lists", "shellbags"],
        "srum": ["netstat"],
    }
    return mapping.get(family, [])


def corroboration_suggestions(finding: dict[str, Any]) -> list[str]:
    """Suggested next queries to corroborate a single-source finding."""
    evidence = finding.get("evidence") or []
    families = sorted({str(e.get("source", "")).split("/")[0] for e in evidence if isinstance(e, dict)})
    needles: list[str] = []
    for fam in families:
        needles.extend(_corroborate_for(fam))
    return needles
