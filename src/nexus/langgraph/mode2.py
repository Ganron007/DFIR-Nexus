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

_DSL_FALLBACK_NOTE = "query failed N4 parse — bare terms used"
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
    briefing: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """LLM proposes the next needles from current hits. Heuristic fallback.

    WP 4i.9: when ``briefing`` is provided (computed once by the caller), the
    LLM sees the case's signal map — which playbook/ATT&CK/Sigma needles
    already hit, the alert surface, and top entities — so proposals are
    grounded in what the evidence actually contains, not generic vocabulary.

    Returns {"needles": [...], "rationale": str, "source": "llm"|"heuristic"}.
    """
    if model is not None:
        try:
            return _propose_with_model(case_dir, hits, already_run, model, briefing=briefing)
        except Exception as exc:  # noqa: BLE001
            log.warning("Mode 2 LLM proposal failed (%s), using heuristic", exc)
    return _propose_heuristic(hits, already_run)


def _briefing_context(briefing: dict[str, Any] | None) -> str:
    """WP 4i.9: compact signal-map block for the proposal prompt."""
    if not briefing:
        return ""
    parts: list[str] = []
    scan = briefing.get("needle_scan") or []
    if scan:
        top = ", ".join(f"{s['needle']}({s['hits']})" for s in scan[:20])
        parts.append(f"Signal map (needle→hits): {top}")
    alerts = briefing.get("alerts") or []
    if alerts:
        parts.append("Alerts: " + "; ".join(
            f"[{a['level']}] {a['title']} @{a['host']}" for a in alerts[:8]
        ))
    ents = briefing.get("entities") or {}
    if ents:
        bits = []
        for etype in ("process_name", "ipv4", "domain", "domain_user"):
            vals = [e["value"] for e in (ents.get(etype) or [])[:6]]
            if vals:
                bits.append(f"{etype}={', '.join(vals)}")
        if bits:
            parts.append("Top entities: " + " | ".join(bits))
    return "\n".join(parts)


def _propose_with_model(
    case_dir: Path, hits: list[dict], already_run: list[str], model: Any,
    briefing: dict[str, Any] | None = None,
) -> dict:
    from nexus.langgraph.query_pack import load_case_intake

    intake = load_case_intake(case_dir)
    families = sorted({h.get("family", "?") for h in hits})

    # WP 2.10: RAG methodology for hit families
    rag_context, rag_provenance = _rag_methodology_for_proposal(set(families))

    # WP 2.11: Playbook caveats + Identify steps for hit families
    playbook_context = _playbook_context_for_families(set(families))

    # Framework lenses (registry-grounded): ATT&CK detections for the hit
    # families, the Insider Threat Matrix lens, and the AI/malware registries.
    extras: list[str] = []
    try:
        from nexus.knowledge.attack_needles import (
            attack_context_for,
            attack_packs_for,
        )
        from nexus.langgraph.query_pack import playbook_techniques_for_families

        techs = (
            set(playbook_techniques_for_families(set(families))) if families else set()
        )
        attack_block = attack_context_for(
            attack_packs_for(set(families), techs, limit=3), cap=3
        )
        if attack_block:
            extras.append("ATT&CK detection guidance:\n" + attack_block[:1200])
    except Exception:  # noqa: BLE001
        pass
    question_text = str(intake.get("question") or "")
    try:
        from nexus.langgraph.itm import itm_prompt_block

        itm_block = itm_prompt_block(
            question=question_text, families=families, limit=4, full_taxonomy=False
        )
        if itm_block:
            extras.append("Insider Threat Matrix lens:\n" + itm_block[:1200])
    except Exception:  # noqa: BLE001
        pass
    try:
        from nexus.knowledge.registry_context import (
            atlas_context_for,
            mbc_context_for,
        )

        atlas_block = atlas_context_for(question_text)
        mbc_block = mbc_context_for(question_text)
        if atlas_block or mbc_block:
            extras.append(
                "Framework registry matches:\n"
                + "\n".join(x for x in (atlas_block, mbc_block) if x)[:900]
            )
    except Exception:  # noqa: BLE001
        pass
    extras_text = "\n\n".join(extras)

    # WP 2.6: Enriched context — aggregation + top hits per family
    agg_summary = _aggregation_summary(hits)
    top_hits = _top_hits_per_family(hits)

    # WP 4i.9: case briefing signal map — which needles already hit
    briefing_ctx = _briefing_context(briefing)

    # 4k.5.5: the LLM proposes Elasticsearch queries (Mode 2/3 query ES
    # directly); the field catalog grounds it in columns the case holds.
    from nexus.langgraph.backbone import tool_contracts_block
    from nexus.langgraph.field_catalog import field_catalog_block

    grammar = field_catalog_block(case_dir)

    user = (
        f"Case question: {intake.get('question', '(none)')}\n"
        f"Artifact families with hits: {', '.join(families) or '(none)'}\n"
        f"Already searched: {', '.join(already_run) or '(none)'}\n\n"
        f"Case signal map (needles that already hit in processed evidence):\n"
        f"{briefing_ctx or '(no briefing)'}\n\n"
        f"Aggregation summary:\n{agg_summary}\n\n"
        f"Top hits per family:\n{top_hits}\n\n"
        f"RAG methodology:\n{rag_context[:1800] or '(none)'}\n\n"
        f"Playbook guidance:\n{playbook_context[:1200] or '(none)'}\n\n"
        f"{extras_text}\n\n"
        "Evidence index fields:\n"
        f"{grammar or '(no parsed columns yet — use family/text terms)'}\n\n"
        f"{tool_contracts_block()}\n\n"
        "Propose 2-6 NEW Elasticsearch queries to corroborate or expand this "
        "picture. Each query is ES query JSON, e.g. "
        '{"bool": {"must": [{"term": {"family": "hayabusa"}}, '
        '{"match_phrase": {"text": "sdelete"}}]}} — time filters are '
        '{"range": {"ts": {"gte": "...", "lte": "..."}}}; parsed columns are '
        "fields.<Name> / fields.<Name>.kw. Prefer needles shown in the signal "
        "map that have hits but haven't been searched yet; use the RAG "
        "methodology and playbook caveats. When the question is a counting "
        "question (how many distinct hosts? which IPs?), propose an "
        "AGGREGATION instead: "
        '{"aggregations": [{"aggs": {"v": {"terms": {"field": "host", '
        '"size": 100}}}, "query": {}, "why": "..."}]} — aggregations answer '
        '"how many/of what" with real counts. Return ONLY JSON: '
        '{"queries": [{"es": {"query": {...}}, "why": "..."}], '
        '"aggregations": [...], "rationale": "..."} (aggregations optional)."'
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
    # WP 4j.10: proposals are DSL queries. New schema {"queries":[{"dsl","why"}]}
    # with backward compat for {"needles":[...]}. The validation wall: every
    # query must parse; a parse failure degrades that query to its bare terms
    # (deterministic fallback — never a silent wrong query).
    raw: list[str] = []
    for q in (parsed.get("queries") or []):
        if isinstance(q, dict) and str(q.get("dsl") or "").strip():
            raw.append(str(q["dsl"]).strip())
        elif isinstance(q, str) and q.strip():
            raw.append(q.strip())
    for n in (parsed.get("needles") or []):
        if str(n).strip():
            raw.append(str(n).strip())
    validated = [_validate_dsl(q) for q in raw][:_MAX_NEEDLES_PER_PROPOSAL]
    needles = [v["query"] for v in validated]
    # 4k.5.5: ES-native proposals (preferred); invalid JSON degrades to a
    # text match on the first literal so the loop never runs a wrong query.
    es_queries: list[dict[str, Any]] = []
    for q in (parsed.get("queries") or [])[:_MAX_NEEDLES_PER_PROPOSAL]:
        if not isinstance(q, dict):
            continue
        es = q.get("es")
        if not isinstance(es, dict) or not es:
            continue
        query = es.get("query") if isinstance(es.get("query"), dict) else es
        fallback = False
        try:
            from nexus.langgraph.es_native import validate_query

            validate_query(query)
        except Exception:  # noqa: BLE001 — degrade, never run a broken query
            query = {"match_phrase": {"text": _first_literal(es) or "error"}}
            fallback = True
        es_queries.append({
            "query": query,
            "fallback": fallback,
            "why": str(q.get("why") or "")[:200],
        })
    # WP 4j.12: the LLM may request aggregations as tool calls alongside
    # queries — validated here, executed through the audited backbone by the
    # loop (context, never evidence).
    aggregations: list[dict[str, Any]] = []
    for a in (parsed.get("aggregations") or [])[:3]:
        if not isinstance(a, dict):
            continue
        a_dsl = str(a.get("dsl") or "").strip()
        a_field = str(a.get("field") or "").strip()
        if not a_dsl or not a_field:
            continue
        wall = _validate_dsl(a_dsl)
        if wall.get("fallback"):
            # WP 4j.12: a degraded aggregation would mis-count — drop it
            # (the query-level fallback still runs; counts must be exact).
            continue
        aggregations.append({
            "dsl": wall["query"],
            "field": a_field[:80],
            "fallback": False,
            "why": str(a.get("why") or "")[:200],
        })
    es_aggregations: list[dict[str, Any]] = []
    for a in (parsed.get("aggregations") or [])[:3]:
        if not isinstance(a, dict) or not isinstance(a.get("aggs"), dict) or not a["aggs"]:
            continue
        try:
            from nexus.langgraph.es_native import validate_aggs

            validate_aggs(a["aggs"])
        except Exception:  # noqa: BLE001 — an invalid agg is dropped (counts)
            continue
        es_aggregations.append({
            "aggs": a["aggs"],
            "query": a.get("query") if isinstance(a.get("query"), dict) else None,
            "why": str(a.get("why") or "")[:200],
        })
    return {
        "needles": needles,
        "dsl_queries": validated,
        "es_queries": es_queries,
        "es_aggregations": es_aggregations,
        "aggregations": aggregations,
        "rationale": str(parsed.get("rationale") or "")[:300],
        "source": "llm",
        "rag_context": rag_context,
        "rag_provenance": rag_provenance,
        "playbook_context": playbook_context,
    }


def _es_query_from_expr(expr: str) -> dict[str, Any]:
    """Deterministic DSL→ES for the loop's seed/legacy strings (no agent)."""
    from nexus.langgraph.case_index import ast_to_es
    from nexus.langgraph.query_dsl import QuerySyntaxError, parse_query

    text = str(expr or "").strip()
    if not text:
        return {"match_all": {}}
    try:
        parsed = parse_query(text)
        return ast_to_es(parsed) if not parsed.is_empty() else {"match_all": {}}
    except QuerySyntaxError:
        return {"match_phrase": {"text": text[:200]}}


def _agg_label(agg: dict[str, Any]) -> str:
    """One-line label for legacy (top) and ES (aggregations) agg shapes."""
    if agg.get("aggregations") and not agg.get("top"):
        buckets = []
        for spec in (agg.get("aggregations") or {}).values():
            if isinstance(spec, dict):
                buckets = spec.get("buckets") or []
                break
        names = ",".join(sorted((agg.get("aggs") or {}).keys())) or "es"
        return f"{names}({len(buckets)} buckets)"
    return f"{agg.get('field') or 'agg'}({agg.get('distinct', 0)} distinct)"


def _first_literal(payload: Any) -> str:
    """First non-empty string in a JSON blob (degrade target for bad queries)."""
    if isinstance(payload, str):
        return payload.strip()[:80]
    if isinstance(payload, dict):
        for value in payload.values():
            got = _first_literal(value)
            if got:
                return got
    if isinstance(payload, list):
        for item in payload:
            got = _first_literal(item)
            if got:
                return got
    return ""


def _validate_dsl(query: str) -> dict[str, Any]:
    """WP 4j.10 validation wall — shared implementation (WP 4j.11 moved it to
    ``query_dsl.validate_or_degrade`` so both entry points enforce it)."""
    from nexus.langgraph.query_dsl import validate_or_degrade

    return validate_or_degrade(query)


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
    from nexus.langgraph.query_pack import load_case_intake

    case_dir = Path(case_dir)
    # One cap, enforced here regardless of the caller (API/CLI/agent).
    max_iterations = max(1, min(int(max_iterations or 2), 4))
    limit = max(1, min(int(limit or 80), 400))
    iterations: list[dict[str, Any]] = []
    all_needles_run: list[str] = []

    intake = load_case_intake(case_dir)
    _ = intake  # window comes from the tool's internal intake handling

    from nexus.audit import AuditWriter
    from nexus.langgraph.backbone import backbone_call

    # WP 4j.10c (cross-case guard): the loop's evidence access is bound to the
    # case it was invoked for — never the pointer's case by accident.
    case_id = case_dir.name
    loop_audit = AuditWriter("nexus")

    # Iteration 0: initial query from the question — through the audited
    # backbone so the initial hit set carries an audit_id like every other
    # iteration (it is citation material).
    parsed0 = nl_to_needles(question, model=model)
    needles0 = parsed0.get("needles", [])
    if not needles0 and not parsed0.get("dsl_query"):
        return {"error": "No needles extracted from the question", "iterations": []}
    # WP 4j.11: the entry point may emit a structured query — prefer it
    # verbatim; degrade to bare terms when the wall rejected it.
    dsl0 = str(parsed0.get("dsl_query") or "").strip()
    q0 = dsl0 or " ".join(needles0)
    r0 = backbone_call(
        "es_search", audit=loop_audit, case_id=case_id,
        query=_es_query_from_expr(q0), size=limit,
    )
    if r0.get("error"):
        return {"error": r0["error"], "iterations": []}
    if needles0:
        all_needles_run.extend(needles0)
    else:
        all_needles_run.append(q0)
    hits = r0.get("hits", [])
    iterations.append({
        "iteration": 0,
        "action": "initial_query",
        "needles": needles0,
        "query": q0,
        "dsl": bool(parsed0.get("dsl_query")),
        "fallback": (parsed0.get("dsl") or {}).get("fallback", False),
        "hits": r0.get("total", 0),
        "backend": r0.get("backend", ""),
        "audit_id": (r0.get("provenance") or {}).get("audit_id"),
    })
    _emit(on_event, iterations[-1])
    append_chat(case_dir, "llm", "mode2_iter0", f"Initial query: {', '.join(needles0)} -> {r0.get('total', r0.get('count', 0))} hits")

    # WP 4i.9: compute the case briefing once — proposals ground in the
    # signal map (which needles already hit) rather than generic vocabulary.
    briefing: dict[str, Any] | None = None
    try:
        from nexus.langgraph.briefing import case_briefing

        briefing = case_briefing(case_dir)
    except Exception as exc:  # noqa: BLE001
        log.debug("Mode 2 briefing unavailable: %s", exc)

    # Iterative proposals — WP 4j.10: each proposal is ONE complete DSL query,
    # executed separately through the backbone (audited, allowlist-enforced),
    # never space-joined into term soup.
    for it in range(1, max_iterations + 1):
        if not hits:
            break
        proposal = propose_next_needles(case_dir, question, hits, all_needles_run, model, briefing=briefing)
        dsl_queries = [
            q for q in (proposal.get("dsl_queries")
                        or [{"query": n, "dsl": False, "fallback": False}
                            for n in proposal.get("needles", [])])
            if q.get("query") and q["query"].lower() not in {x.lower() for x in all_needles_run}
        ][:_MAX_NEEDLES_PER_PROPOSAL]
        es_specs = proposal.get("es_queries") or []
        if not dsl_queries and not es_specs:
            iterations.append({"iteration": it, "action": "no_new_proposals", "rationale": proposal.get("rationale", "")})
            append_chat(case_dir, "llm", "mode2_stop", "No new needles to propose.", {"iteration": it})
            break
        iteration_queries: list[dict[str, Any]] = []
        prior_families = {str(h.get("family")) for h in hits}
        new_families: set[Any] = set()
        for spec in es_specs:
            query = spec.get("query") or {"match_all": {}}
            label = "es_search " + json.dumps(query, sort_keys=True, default=str)[:200]
            all_needles_run.append(label)
            ran = backbone_call("es_search", audit=loop_audit, case_id=case_id,
                                query=query, size=min(max(int(limit or 100), 1), 200))
            if ran.get("error"):
                iterations.append({"iteration": it, "action": "query_error",
                                   "query": label, "error": ran["error"]})
                append_chat(case_dir, "llm", "mode2_error", ran["error"], {"iteration": it})
                break
            new_hits = ran.get("hits") or []
            new_families |= {str(h.get("family")) for h in new_hits}
            iteration_queries.append({
                "query": label,
                "dsl": False,
                "es": True,
                "fallback": spec.get("fallback", False),
                "fallback_reason": "invalid ES query — degraded to text" if spec.get("fallback") else "",
                "hits": ran.get("total", 0),
                "audit_id": (ran.get("provenance") or {}).get("audit_id"),
            })
            hits = hits + new_hits
        for qspec in dsl_queries:
            q = qspec["query"]
            all_needles_run.append(q)
            ran = backbone_call("es_search", audit=loop_audit, case_id=case_id,
                                query=_es_query_from_expr(q), size=limit)
            if ran.get("error"):
                # gated/no-case — the loop cannot run; surface honestly
                iterations.append({"iteration": it, "action": "query_error",
                                   "query": q, "error": ran["error"]})
                append_chat(case_dir, "llm", "mode2_error", ran["error"], {"iteration": it})
                break
            new_hits = ran.get("hits", [])
            new_families |= {str(h.get("family")) for h in new_hits}
            iteration_queries.append({
                "query": q,
                "dsl": qspec.get("dsl", False),
                "fallback": qspec.get("fallback", False),
                "fallback_reason": qspec.get("reason", ""),
                "hits": ran.get("total", 0),
                "audit_id": (ran.get("provenance") or {}).get("audit_id"),
            })
            hits = hits + new_hits
        iterations.append({
            "iteration": it,
            "action": "proposed_and_ran",
            "queries": iteration_queries,
            "needles": [q["query"] for q in iteration_queries],
            "rationale": proposal.get("rationale", ""),
            "source": proposal.get("source", ""),
            "hits": sum(q["hits"] for q in iteration_queries),
            "new_families": sorted(new_families - prior_families),
        })
        # WP 4j.12: run the proposed aggregations through the backbone —
        # grounded counts (context, never evidence) appended to the iteration.
        aggregations: list[dict[str, Any]] = []
        for espec in (proposal.get("es_aggregations") or [])[:2]:
            agg = backbone_call("es_aggregate", audit=loop_audit, case_id=case_id,
                                aggs=espec.get("aggs") or {}, query=espec.get("query"))
            if agg.get("error"):
                continue
            aggregations.append({
                "aggs": espec.get("aggs") or {},
                "query": espec.get("query") or {},
                "why": espec.get("why", ""),
                "aggregations": agg.get("aggregations") or {},
                "next_after_key": agg.get("next_after_key"),
                "audit_id": (agg.get("provenance") or {}).get("audit_id"),
            })
        for aspec in (proposal.get("aggregations") or [])[:2]:
            agg = backbone_call(
                "es_aggregate", audit=loop_audit, case_id=case_id,
                aggs={"v": {"terms": {
                    "field": aspec.get("field", "host"), "size": 15,
                }}},
                query=(_es_query_from_expr(aspec.get("dsl", ""))
                       if aspec.get("dsl") else None),
            )
            if agg.get("error"):
                continue
            buckets = []
            for spec in (agg.get("aggregations") or {}).values():
                if isinstance(spec, dict):
                    buckets = spec.get("buckets") or []
                    break
            aggregations.append({
                "dsl": aspec.get("dsl", ""),
                "field": aspec.get("field", "host"),
                "why": aspec.get("why", ""),
                "distinct": len(buckets),
                "distinct_approximate": False,
                "rows_scanned": 0,
                "top": [
                    {"value": b.get("key"), "count": b.get("doc_count", 0)}
                    for b in buckets[:10]
                ],
                "audit_id": (agg.get("provenance") or {}).get("audit_id"),
            })
        if aggregations:
            iterations[-1]["aggregations"] = aggregations
            append_chat(
                case_dir, "llm", "mode2_aggregation",
                "Aggregations: " + "; ".join(_agg_label(a) for a in aggregations),
                {"aggregations": json.dumps(aggregations)[:2000]},
            )
        append_chat(
            case_dir, "llm", "mode2_proposal",
            f"Iteration {it}: ran {len(iteration_queries)} query/queries -> "
            f"{sum(q['hits'] for q in iteration_queries)} hits",
            {"rationale": proposal.get("rationale", ""),
             "needles": ",".join(q["query"] for q in iteration_queries)},
        )
        _emit(on_event, iterations[-1])

    ran_proposals = sum(
        1 for i in iterations if i.get("action") == "proposed_and_ran"
    )
    return {
        "question": question,
        "iterations": iterations,
        "total_hits": len(hits),
        "needles_run": all_needles_run,
        # Only true when the loop actually exhausted its proposal budget —
        # iteration 0 is not a proposal and early stops are not "capped".
        "capped": ran_proposals >= max_iterations,
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
    if n_families <= 1 and confidence in ("MEDIUM", "HIGH"):
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
        "ok": n_families >= 2 or confidence in ("LOW", "SPECULATIVE"),
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
