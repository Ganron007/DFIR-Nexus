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

import contextlib
import json
import logging
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

_MAX_ITERATIONS = 5
_MAX_NEEDLES_PER_PROPOSAL = 6
_MAX_HITS_SUMMARY = 12
_MAX_HIT_TEXT = 160
# WP 2.6: enriched context uses a larger text cap for top hits per family
_MAX_HIT_TEXT_ENRICHED = 500
_MAX_TOP_HITS_PER_FAMILY = 3
_MAX_RAG_DOCS_PER_FAMILY = 3
_MAX_RAG_TEXT_PER_DOC = 400
_MAX_PLAYBOOK_CONTEXT_CHARS = 1200

_PROPOSE_SYSTEM = (
    "You are a DFIR investigative partner. You are given N4 hit rows from "
    "parsed forensic evidence, RAG methodology context, and playbook guidance. "
    "Propose the NEXT search needles that would corroborate or expand the "
    "investigation. Respond with ONLY a JSON object: "
    '{"needles": ["term1", "term2"], "rationale": "one sentence"}. '
    "Rules: needles are concrete (artifact names, event IDs, file names, "
    "registry keys, hostnames); never invent facts; 2-6 needles; do not "
    "repeat needles already searched; use RAG methodology and playbook "
    "caveats to guide your proposals."
)


def _hit_summary(hits: list[dict[str, Any]]) -> str:
    rows = []
    for h in hits[:_MAX_HITS_SUMMARY]:
        rows.append(
            f"[{h.get('family', '')}] {h.get('file', '')}:{h.get('line', '')} "
            f":: {str(h.get('text', ''))[:_MAX_HIT_TEXT]}"
        )
    return "\n".join(rows) if rows else "(no hits)"


def _aggregation_summary(hits: list[dict[str, Any]]) -> str:
    """WP 2.6: hit counts per family and per host for LLM context."""
    family_counts: dict[str, int] = {}
    host_counts: dict[str, int] = {}
    for h in hits:
        fam = h.get("family", "?")
        host = h.get("host", "?")
        family_counts[fam] = family_counts.get(fam, 0) + 1
        host_counts[host] = host_counts.get(host, 0) + 1
    lines = ["Hit counts per family:"]
    for fam, count in sorted(family_counts.items(), key=lambda x: -x[1]):
        lines.append(f"  {fam}: {count}")
    lines.append("Hit counts per host:")
    for host, count in sorted(host_counts.items(), key=lambda x: -x[1]):
        lines.append(f"  {host}: {count}")
    return "\n".join(lines)


def _top_hits_per_family(hits: list[dict[str, Any]]) -> str:
    """WP 2.6: top N hits per family with enriched text (500 chars)."""
    by_family: dict[str, list[dict[str, Any]]] = {}
    for h in hits:
        fam = h.get("family", "?")
        by_family.setdefault(fam, []).append(h)
    lines = []
    for fam in sorted(by_family):
        lines.append(f"\n--- {fam} (top {_MAX_TOP_HITS_PER_FAMILY}) ---")
        for h in by_family[fam][:_MAX_TOP_HITS_PER_FAMILY]:
            lines.append(
                f"  {h.get('file', '')}:{h.get('line', '')} "
                f":: {str(h.get('text', ''))[:_MAX_HIT_TEXT_ENRICHED]}"
            )
    return "\n".join(lines) if lines else "(no hits)"


def _rag_methodology_for_proposal(families: set[str]) -> tuple[str, list[dict[str, Any]]]:
    """WP 2.10: Retrieve RAG methodology for artifact families in hits.

    Returns (methodology_text, provenance) where provenance is a list of
    dicts with query, doc_count, sources, and scores for audit trail.
    """
    if not families:
        return "", []
    try:
        from nexus.tools.rag import _check_rag_available, _get_index

        available, _ = _check_rag_available()
        if not available:
            return "", []

        idx = _get_index()
        blocks: list[str] = []
        provenance: list[dict[str, Any]] = []
        seen: set[str] = set()
        for fam in sorted(families):
            if not fam or fam in seen:
                continue
            seen.add(fam)
            q = f"how to interpret forensic {fam} evidence methodology"
            try:
                result = idx.search(query=q, top_k=_MAX_RAG_DOCS_PER_FAMILY, source="kape")
                docs = result.get("results", [])
                if not docs:
                    result = idx.search(query=q, top_k=2)
                    docs = result.get("results", [])
                if docs:
                    block = f"\n--- {fam} methodology ---\n"
                    sources: list[str] = []
                    scores: list[float] = []
                    for d in docs[:_MAX_RAG_DOCS_PER_FAMILY]:
                        text = d.get("text") or d.get("document") or ""
                        block += str(text)[:_MAX_RAG_TEXT_PER_DOC] + "\n"
                        sources.append(d.get("source", ""))
                        scores.append(d.get("score", 0))
                    blocks.append(block)
                    provenance.append({
                        "family": fam,
                        "query": q,
                        "doc_count": len(docs),
                        "sources": sources,
                        "scores": scores,
                    })
            except Exception:
                pass
        return "\n".join(blocks).strip(), provenance
    except Exception as exc:
        log.warning("RAG methodology lookup for proposal failed: %s", exc)
        return "", []


def _playbook_context_for_families(families: set[str]) -> str:
    """WP 2.11: Load playbook caveats and Identify steps for artifact families.

    Maps artifact families to relevant playbooks and extracts caveats +
    Identify phase steps as context for the LLM proposal.
    """
    if not families:
        return ""
    try:
        from nexus.knowledge.loader import get_playbook, list_playbook_slugs

        # Build a family → playbook mapping by scanning playbook query_terms
        # and matching against our hit families
        slugs = list_playbook_slugs()
        family_lower = {f.lower() for f in families}
        blocks: list[str] = []
        seen_slugs: set[str] = set()

        for slug in slugs:
            pb = get_playbook(slug)
            if not isinstance(pb, dict):
                continue
            # Check if any query_term matches a hit family
            terms = pb.get("query_terms") or []
            if not isinstance(terms, list):
                continue
            term_lower = {str(t).lower() for t in terms}
            # Also check the playbook name/description for family mentions
            pb_text = (
                str(pb.get("name", "")) + " " + str(pb.get("description", ""))
            ).lower()
            matches = False
            for fam in family_lower:
                if fam in term_lower or fam in pb_text:
                    matches = True
                    break
            if not matches:
                continue
            if slug in seen_slugs:
                continue
            seen_slugs.add(slug)

            block = f"\n--- Playbook: {pb.get('name', slug)} ---\n"
            # Caveats — corroboration constraints
            caveats = pb.get("caveats") or []
            if isinstance(caveats, list) and caveats:
                block += "Caveats:\n"
                for c in caveats[:5]:
                    block += f"  - {str(c)[:200]}\n"
            # First phase steps — what to look for (identification/locating).
            # Playbooks use different names for the first phase: "Identify",
            # "Locate Artifacts", "Collect", "Detection", "Acquire", etc.
            # We extract the FIRST phase's steps as the methodology context.
            phases = pb.get("phases") or []
            if isinstance(phases, list) and phases:
                first_phase = phases[0]
                if isinstance(first_phase, dict):
                    steps = first_phase.get("steps") or []
                    if isinstance(steps, list) and steps:
                        phase_name = first_phase.get("phase", "first phase")
                        block += f"{phase_name} steps:\n"
                        for s in steps[:5]:
                            block += f"  - {str(s)[:200]}\n"
                    # Also check for an "Identify" phase if it's not the first
                    for phase in phases[1:]:
                        if isinstance(phase, dict) and phase.get("phase") == "Identify":
                            id_steps = phase.get("steps") or []
                            if isinstance(id_steps, list) and id_steps:
                                block += "Identify steps:\n"
                                for s in id_steps[:5]:
                                    block += f"  - {str(s)[:200]}\n"
                            break
            # Triggers — what indicators to look for
            triggers = pb.get("triggers") or []
            if isinstance(triggers, list) and triggers:
                block += "Triggers:\n"
                for t in triggers[:3]:
                    block += f"  - {str(t)[:200]}\n"

            block_text = block[:_MAX_PLAYBOOK_CONTEXT_CHARS]
            blocks.append(block_text)

        return "\n".join(blocks).strip()
    except Exception as exc:
        log.warning("Playbook context lookup failed: %s", exc)
        return ""


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

    # WP 2.10: RAG methodology for hit families
    rag_context, rag_provenance = _rag_methodology_for_proposal(set(families))

    # WP 2.11: Playbook caveats + Identify steps for hit families
    playbook_context = _playbook_context_for_families(set(families))

    # WP 2.6: Enriched context — aggregation + top hits per family
    agg_summary = _aggregation_summary(hits)
    top_hits = _top_hits_per_family(hits)

    user = (
        f"Case question: {intake.get('question', '(none)')}\n"
        f"Artifact families with hits: {', '.join(families) or '(none)'}\n"
        f"Already searched: {', '.join(already_run) or '(none)'}\n\n"
        f"Aggregation summary:\n{agg_summary}\n\n"
        f"Top hits per family:\n{top_hits}\n\n"
        f"RAG methodology:\n{rag_context[:2000] or '(none)'}\n\n"
        f"Playbook guidance:\n{playbook_context[:1500] or '(none)'}\n\n"
        "Propose 2-6 NEW search needles to corroborate or expand this picture. "
        "Use the RAG methodology and playbook caveats to guide your proposals. "
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
        "rag_context": rag_context,
        "rag_provenance": rag_provenance,
        "playbook_context": playbook_context,
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


def _emit(on_event: Any, payload: dict[str, Any]) -> None:
    """Best-effort streaming callback (WP 4d.3) — never breaks the loop."""
    if not on_event:
        return
    with contextlib.suppress(Exception):
        on_event(payload)


def run_iterative_loop(
    case_dir: Path,
    question: str,
    model: Any = None,
    max_iterations: int = 2,
    limit: int = 80,
    on_event: Any = None,
) -> dict[str, Any]:
    """Mode 2 loop: query -> analyze -> propose -> re-query.

    Every step is logged to the case chat transcript. Hard caps:
    max_iterations re-queries; each proposal is capped. The loop NEVER
    writes findings — it returns the iteration log for examiner review.

    ``on_event(iteration_dict)`` is called after each iteration step so
    the portal can stream live progress (WP 4d.3).
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
    _emit(on_event, iterations[-1])
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
        _emit(on_event, iterations[-1])
        hits = hits + new_hits

    return {
        "question": question,
        "iterations": iterations,
        "total_hits": len(hits),
        "needles_run": all_needles_run,
        "capped": len(iterations) >= max_iterations,
        "hits": hits,
    }


def propose_draft_finding(
    case_dir: Path,
    hits: list[dict[str, Any]],
    title: str,
    model: Any = None,
    interpretation_hint: str = "",
) -> dict[str, Any]:
    """Mode 2: LLM drafts a finding from hits. Staged as DRAFT with
    ``examiner_selected=False`` — the examiner reviews, edits, approves,
    or rejects via the normal HMAC flow. The LLM never approves.

    Returns {draft, corroboration} or {error}.
    """
    from nexus.langgraph.mode1 import promote_hits_to_draft, scribe_finding

    if not hits:
        return {"error": "No hits to draft from"}
    draft = promote_hits_to_draft(
        case_dir,
        hits=hits,
        title=title,
        examiner="mode2-llm",
        interpretation_hint=interpretation_hint,
        examiner_selected=False,
    )
    draft = scribe_finding(draft, hits=hits, model=model)
    return {"draft": draft, "corroboration": corroboration_check(draft)}


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
    """Corroboration needles per artifact family (what would independently confirm).

    WP 2.9: Now data-driven from playbook caveats. Falls back to the
    hard-coded mapping when no playbook caveats are available.
    """
    # Try playbook caveats first
    try:
        from nexus.knowledge.loader import get_playbook, list_playbook_slugs

        slugs = list_playbook_slugs()
        family_lower = family.lower()
        for slug in slugs:
            pb = get_playbook(slug)
            if not isinstance(pb, dict):
                continue
            terms = pb.get("query_terms") or []
            term_lower = {str(t).lower() for t in terms}
            pb_text = (
                str(pb.get("name", "")) + " " + str(pb.get("description", ""))
            ).lower()
            if family_lower not in term_lower and family_lower not in pb_text:
                continue
            # Extract corroboration terms from caveats
            caveats = pb.get("caveats") or []
            needles: list[str] = []
            for caveat in caveats:
                caveat_text = str(caveat).lower()
                # Look for artifact family names mentioned in caveats
                for term in term_lower:
                    if term in caveat_text and term not in needles:
                        needles.append(term)
            if needles:
                return needles[:8]
    except Exception:
        pass

    # Fallback: hard-coded mapping
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
