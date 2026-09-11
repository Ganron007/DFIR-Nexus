"""Mode 3 multi-agent orchestrator — real agentic implementation (WP 3.21).

Dispatches specialist agents that run real queries, extract entities,
correlate across families, detect attack patterns, and build narratives.
The orchestrator coordinates via a task queue with dependencies:
  TriageAgent → EvidenceAgents → CorrelationAgent → PatternAgent → SynthesisAgent

The orchestrator does NOT approve findings — the examiner does. The
orchestrator proposes; the examiner disposes.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from nexus.langgraph.correlation_agent import CorrelationAgent
from nexus.langgraph.entities import extract_entities
from nexus.langgraph.pattern_agent import PatternAgent
from nexus.langgraph.synthesis_agent import SynthesisAgent

log = logging.getLogger(__name__)

# Agent family mapping — which evidence families each agent handles
_AGENT_FAMILY_MAP: dict[str, list[str]] = {
    "timeline": ["hayabusa", "suzaku", "chainsaw", "evtxecmd", "evtx"],
    "endpoint": ["prefetch", "amcache", "shimcache", "lnk", "jump_lists", "shellbags"],
    "network": ["netstat", "srum", "dns", "zeek", "pcap"],
    "alert": ["sigma", "sysmon", "windows_defender", "mde"],
    "cloud": ["azure", "aws", "gcp", "office365", "entra"],
}

_MAX_RAG_DOCS_PER_FAMILY = 3
_MAX_RAG_TEXT_PER_DOC = 400


def _rag_for_family(family: str) -> tuple[str, list[dict[str, Any]]]:
    """Retrieve RAG methodology for a single evidence family."""
    try:
        from nexus.tools.rag import _check_rag_available, _get_index

        available, _ = _check_rag_available()
        if not available:
            return "", []

        idx = _get_index()
        q = f"how to interpret forensic {family} evidence methodology"
        result = idx.search(query=q, top_k=_MAX_RAG_DOCS_PER_FAMILY, source="kape")
        docs = result.get("results", [])
        if not docs:
            result = idx.search(query=q, top_k=2)
            docs = result.get("results", [])

        if not docs:
            return "", []

        block = f"--- {family} methodology ---\n"
        provenance: list[dict[str, Any]] = []
        for d in docs[:_MAX_RAG_DOCS_PER_FAMILY]:
            text = d.get("text") or ""
            block += str(text)[:_MAX_RAG_TEXT_PER_DOC] + "\n"
            provenance.append({
                "query": q,
                "source": d.get("source", ""),
                "score": d.get("score", 0),
                "title": d.get("title", ""),
            })
        return block, provenance
    except Exception as exc:
        log.warning("RAG for family %s failed: %s", family, exc)
        return "", []


def _playbook_for_family(family: str) -> str:
    """Load playbook caveats + first-phase steps for an agent's family."""
    if not family:
        return ""
    try:
        from nexus.knowledge.loader import get_playbook, list_playbook_slugs

        slugs = list_playbook_slugs()
        family_lower = family.lower()
        blocks: list[str] = []

        for slug in slugs:
            pb = get_playbook(slug)
            if not isinstance(pb, dict):
                continue
            terms = pb.get("query_terms") or []
            if not isinstance(terms, list):
                continue
            term_lower = {str(t).lower() for t in terms}
            pb_text = (
                str(pb.get("name", "")) + " " + str(pb.get("description", ""))
            ).lower()
            if family_lower not in term_lower and family_lower not in pb_text:
                continue

            block = f"\n--- Playbook: {pb.get('name', slug)} ---\n"
            caveats = pb.get("caveats") or []
            if isinstance(caveats, list) and caveats:
                block += "Caveats:\n"
                for c in caveats[:5]:
                    block += f"  - {str(c)[:200]}\n"
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
            blocks.append(block[:1200])

        return "\n".join(blocks).strip()
    except Exception as exc:
        log.warning("Playbook for family %s failed: %s", family, exc)
        return ""


def _attack_for_family(families: list[str]) -> str:
    """Load ATT&CK technique context for the given evidence families."""
    try:
        from nexus.knowledge.loader import get_attack_needles

        packs = get_attack_needles()
        blocks: list[str] = []
        for pack in packs:
            if not isinstance(pack, dict):
                continue
            pack_families = pack.get("families") or []
            if not pack_families:
                continue
            if any(f.lower() in [pf.lower() for pf in pack_families] for f in families):
                block = f"--- {pack.get('technique_id', 'T')} {pack.get('name', '')} ---\n"
                needles = pack.get("needles") or []
                if needles:
                    block += "Needles: " + ", ".join(str(n) for n in needles[:8]) + "\n"
                caveats = pack.get("caveats") or []
                if caveats:
                    block += "Caveats:\n"
                    for c in caveats[:3]:
                        block += f"  - {str(c)[:150]}\n"
                blocks.append(block[:800])
        return "\n".join(blocks[:3]).strip()
    except Exception as exc:
        log.warning("ATT&CK for families %s failed: %s", families, exc)
        return ""


def _sigma_for_family(families: list[str]) -> str:
    """Load Sigma rule context for the given evidence families."""
    try:
        from nexus.knowledge.loader import get_sigma_needles

        packs = get_sigma_needles()
        blocks: list[str] = []
        for pack in packs:
            if not isinstance(pack, dict):
                continue
            pack_families = pack.get("families") or []
            if not pack_families:
                continue
            if any(f.lower() in [pf.lower() for pf in pack_families] for f in families):
                block = f"--- {pack.get('name', 'Sigma')} ---\n"
                needles = pack.get("needles") or []
                if needles:
                    block += "Detection fields: " + ", ".join(str(n) for n in needles[:8]) + "\n"
                blocks.append(block[:600])
        return "\n".join(blocks[:3]).strip()
    except Exception as exc:
        log.warning("Sigma for families %s failed: %s", families, exc)
        return ""


def _run_agent(
    agent_name: str,
    families: list[str],
    case_dir: Path,
    model: Any = None,
    max_iterations: int = 3,
    skills: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Run a single EvidenceAgent on its assigned evidence families.

    WP 4i.8: when ``skills`` are provided (matched by the orchestrator against
    the case's families + intake keywords + techniques), the agent executes
    skill steps as its query plan — each step runs n4_query, records
    per-step hits, and contributes pivot entities that feed the next round.
    Steps that find nothing are recorded as negative evidence.

    Falls back to playbook fan-out when no skills match.
    """
    from nexus.langgraph.query_pack import attach_hit_fields, load_case_intake, n4_query

    case_dir = Path(case_dir)
    intake = load_case_intake(case_dir)
    question = intake.get("question", "")

    # Gather RAG methodology for each family
    rag_blocks: list[str] = []
    rag_provenance: list[dict[str, Any]] = []
    for fam in families:
        text, prov = _rag_for_family(fam)
        if text:
            rag_blocks.append(text)
            rag_provenance.extend(prov)
    rag_context = "\n".join(rag_blocks)

    # Gather playbook caveats for each family
    playbook_blocks: list[str] = []
    for fam in families:
        pb_text = _playbook_for_family(fam)
        if pb_text:
            playbook_blocks.append(pb_text)
    playbook_context = "\n".join(playbook_blocks)

    # Gather ATT&CK technique context for each family
    attack_context = _attack_for_family(families)

    # Gather Sigma rule context for each family
    sigma_context = _sigma_for_family(families)

    all_hits: list[dict[str, Any]] = []
    queries_run: list[str] = []
    skill_results: list[dict[str, Any]] = []
    pivot_values: set[str] = set()

    # ── Phase A: skill-step execution (procedure-driven, WP 4i.8) ────────
    for skill in skills or []:
        skill_id = str(skill.get("skill") or "")
        for step in skill.get("steps") or []:
            if not isinstance(step, dict):
                continue
            q = str(step.get("query") or "").strip()
            if not q:
                continue
            queries_run.append(q)
            step_hits: list[dict[str, Any]] = []
            try:
                result = n4_query(case_dir, q, limit=80)
                step_hits = list(result.get("hits") or [])
            except Exception as exc:
                log.warning("Agent %s skill %s step query failed: %s", agent_name, skill_id, exc)
            all_hits.extend(step_hits)
            rec: dict[str, Any] = {
                "skill": skill_id,
                "step": str(step.get("name") or q[:40]),
                "query": q,
                "hits_found": len(step_hits),
                "look_for": str(step.get("look_for") or "")[:300],
                "corroborate": str(step.get("corroborate") or "")[:200],
            }
            if step_hits:
                # pivot: extract the named field's values for the next round
                pivot_field = str(step.get("pivot") or "")
                if pivot_field:
                    try:
                        for h in attach_hit_fields(case_dir, step_hits):
                            v = str((h.get("fields") or {}).get(pivot_field) or "").strip()
                            if v and len(v) <= 120:
                                pivot_values.add(v)
                    except Exception:  # noqa: BLE001
                        pass
            elif skill.get("negative"):
                # WP 4i.8: a step that ran clean is itself a finding —
                # record the skill's negative-evidence interpretation.
                rec["negative_evidence"] = str(skill.get("negative") or "")[:300]
            skill_results.append(rec)

    # ── Phase B: entity pivots — chase values surfaced by skill steps ────
    for v in sorted(pivot_values)[:6]:
        queries_run.append(f"pivot:{v}")
        try:
            result = n4_query(case_dir, v, limit=40)
            all_hits.extend(result.get("hits") or [])
        except Exception as exc:
            log.debug("Agent %s pivot query failed: %s", agent_name, exc)

    # ── Phase C: playbook fan-out (existing behaviour / fallback) ────────
    queries: list[str] = []
    for fam in families:
        pb = _playbook_for_family(fam)
        if pb:
            for line in pb.split("\n"):
                line = line.strip()
                if line.startswith("- "):
                    queries.append(line[2:].strip())

    if not queries:
        queries = families[:5]

    iteration = 0
    while iteration < max_iterations and queries:
        iteration += 1
        for q in queries[:5]:
            queries_run.append(q)
            try:
                result = n4_query(case_dir, q, limit=80)
                all_hits.extend(result.get("hits") or [])
            except Exception as exc:
                log.warning("Agent %s query '%s' failed: %s", agent_name, q, exc)

        round_entities = extract_entities(all_hits)
        entity_values: set[str] = set()
        for entity_list in round_entities.values():
            for ent in entity_list:
                entity_values.add(ent["value"].lower())

        if model is not None and iteration < max_iterations:
            try:
                prompt = (
                    f"You are a {agent_name} DFIR specialist agent analyzing "
                    f"evidence from families: {', '.join(families)}.\n\n"
                    f"Case question: {question}\n\n"
                    f"Entities found so far: {', '.join(sorted(entity_values)[:15])}\n\n"
                    f"Skill steps run: {len(skill_results)} "
                    f"(negative: {sum(1 for r in skill_results if 'negative_evidence' in r)})\n\n"
                    f"RAG methodology:\n{rag_context[:1200] or '(none)'}\n\n"
                    f"Playbook guidance:\n{playbook_context[:800] or '(none)'}\n\n"
                    f"ATT&CK context:\n{attack_context[:600] or '(none)'}\n\n"
                    f"Sigma rules:\n{sigma_context[:600] or '(none)'}\n\n"
                    f"Propose 2-3 NEW search queries to corroborate or expand "
                    f"on the entities found. Return ONLY JSON: {{\"queries\": [...]}}"
                )
                response = model.invoke([{"role": "user", "content": prompt}])
                text = getattr(response, "content", str(response))
                start, end = text.find("{"), text.rfind("}")
                if start != -1 and end != -1:
                    parsed = json.loads(text[start:end + 1])
                    new_queries = [str(q)[:100] for q in (parsed.get("queries") or [])[:3]]
                    queries = new_queries
            except Exception as exc:
                log.warning("Agent %s LLM query refinement failed: %s", agent_name, exc)
                break

    # Final entity extraction on all hits
    entities = extract_entities(all_hits)

    # Build proposals from entities with evidence citations
    proposals: list[dict[str, Any]] = []
    for entity_type, entity_list in entities.items():
        for ent in entity_list:
            if len(ent.get("families", [])) >= 2:
                proposals.append({
                    "type": "corroborated_entity",
                    "entity_type": entity_type,
                    "value": ent["value"],
                    "families": ent["families"],
                    "evidence_refs": ent.get("hits", []),
                    "confidence": 0.5 + (len(ent["families"]) - 1) * 0.15,
                })

    return {
        "agent": agent_name,
        "status": "done",
        "evidence_families": families,
        "entities": entities,
        "queries_run": queries_run,
        "hits_reviewed": len(all_hits),
        "proposals": proposals,
        "skills_used": [s.get("skill") for s in (skills or [])],
        "skill_results": skill_results,
        "negative_evidence": [r for r in skill_results if "negative_evidence" in r],
        "rag_context": rag_context,
        "rag_provenance": rag_provenance,
        "playbook_context": playbook_context,
        "attack_context": attack_context,
        "sigma_context": sigma_context,
    }


def _log_agent_run(case_dir: Path, entry: dict[str, Any]) -> None:
    """Log each agent run to agent_runs.jsonl with full context."""
    case_dir = Path(case_dir)
    record = {
        "ts": datetime.now(UTC).isoformat(),
        **entry,
    }
    with (case_dir / "agent_runs.jsonl").open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, default=str) + "\n")


def run_orchestrator(
    case_dir: Path,
    hits: list[dict[str, Any]] | None = None,
    model: Any = None,
) -> dict[str, Any]:
    """Run the real multi-agent orchestrator.

    Backward-compatible signature: old code called
    ``run_orchestrator(case_dir, hits, model=None)`` where hits was the
    second positional arg. New code should call
    ``run_orchestrator(case_dir, model=model)`` and let agents query.

    Pipeline:
      1. TriageAgent: identify evidence families, propose analysis tasks
      2. EvidenceAgents: run queries on assigned families, extract entities
      3. CorrelationAgent: cross-family entity correlation
      4. PatternAgent: attack pattern detection
      5. SynthesisAgent: build narrative + DRAFT findings

    Args:
        case_dir: case directory
        hits: optional pre-fetched hits (for backward compatibility)
        model: LLM model (optional — deterministic fallback without it)

    Returns:
        agent_runs: list of EvidenceAgent results
        correlation: CorrelationAgent result
        patterns: PatternAgent result
        synthesis: SynthesisAgent result
        narrative: attack narrative
        findings: DRAFT findings with evidence citations
    """
    # Backward compat: if hits is not a list, it's the model (old signature
    # had model as second arg). If hits is a list, it's the hits arg.
    if hits is not None and not isinstance(hits, list):
        model = hits
        hits = None
    from nexus.case.chat import append_chat
    from nexus.langgraph.query_pack import load_case_intake

    case_dir = Path(case_dir)
    intake = load_case_intake(case_dir)
    question = intake.get("question", "")

    # If hits provided (backward compat), use them; otherwise let agents query
    if hits is None:
        # TriageAgent: identify evidence families from the case — uses the
        # same filename-hint family derivation as the N4 query engine so
        # flat extraction dirs (no per-family subdirs) still resolve.
        from nexus.langgraph.query_pack import iter_extraction_files

        families_present: set[str] = {
            fam for _path, _root, fam in iter_extraction_files(case_dir, max_bytes=None)
        }

        # WP 4i.8/4i.9: select skills for this case — matched on families
        # present + intake keywords + ATT&CK techniques. Skills are the
        # procedures agents EXECUTE, not documents they read.
        from nexus.knowledge.attack_needles import extract_techniques
        from nexus.knowledge.skills import skills_for

        intake_text = " ".join(
            str(intake.get(k) or "")
            for k in ("question", "subjects", "hypothesis", "notes")
        )
        keywords = {
            w.strip(".,;:!?()[]\"'").lower()
            for w in intake_text.split()
            if len(w.strip(".,;:!?()[]\"'")) >= 3
        }
        techniques = set(extract_techniques(intake_text))
        selected_skills = skills_for(
            families=families_present, keywords=keywords, techniques=techniques, limit=8,
        )

        # Assign families to agents
        agent_to_families: dict[str, list[str]] = {}
        for fam in families_present:
            agent = _agent_for_family(fam)
            agent_to_families.setdefault(agent, []).append(fam)

        skills_by_agent = _assign_skills(selected_skills, families_present, agent_to_families)

        # Run EvidenceAgents
        agent_runs: list[dict[str, Any]] = []
        for agent_name, families in agent_to_families.items():
            run_result = _run_agent(
                agent_name, families, case_dir, model,
                skills=skills_by_agent.get(agent_name),
            )
            agent_runs.append(run_result)
            _log_agent_run(case_dir, {
                "action": "orchestrator_agent_run",
                "agent": run_result.get("agent"),
                "status": run_result.get("status"),
                "evidence_families": run_result.get("evidence_families"),
                "hits_reviewed": run_result.get("hits_reviewed", 0),
                "queries_run": len(run_result.get("queries_run", [])),
                "entity_count": sum(len(v) for v in run_result.get("entities", {}).values()),
                "proposal_count": len(run_result.get("proposals", [])),
                "rag_used": bool(run_result.get("rag_context")),
                "rag_provenance_count": len(run_result.get("rag_provenance") or []),
                "playbook_used": bool(run_result.get("playbook_context")),
                "attack_context_used": bool(run_result.get("attack_context")),
                "sigma_context_used": bool(run_result.get("sigma_context")),
            })
    else:
        # Backward compat: hits provided, run agents on them
        family_to_agent: dict[str, str] = {}
        agent_to_families: dict[str, list[str]] = {}
        for hit in hits:
            family = hit.get("family", "?")
            if family not in family_to_agent:
                agent = _agent_for_family(family)
                family_to_agent[family] = agent
                agent_to_families.setdefault(agent, []).append(family)

        # WP 4i.8: skills for the hit families + intake context
        from nexus.knowledge.attack_needles import extract_techniques
        from nexus.knowledge.skills import skills_for

        intake_text = " ".join(
            str(intake.get(k) or "")
            for k in ("question", "subjects", "hypothesis", "notes")
        )
        keywords = {
            w.strip(".,;:!?()[]\"'").lower()
            for w in intake_text.split()
            if len(w.strip(".,;:!?()[]\"'")) >= 3
        }
        techniques = set(extract_techniques(intake_text))
        hit_families = set(family_to_agent)
        selected_skills = skills_for(
            families=hit_families, keywords=keywords, techniques=techniques, limit=8,
        )
        skills_by_agent = _assign_skills(selected_skills, hit_families, agent_to_families)

        agent_runs = []
        for agent_name, families in agent_to_families.items():
            run_result = _run_agent(
                agent_name, families, case_dir, model,
                skills=skills_by_agent.get(agent_name),
            )
            agent_runs.append(run_result)
            _log_agent_run(case_dir, {
                "action": "orchestrator_agent_run",
                "agent": run_result.get("agent"),
                "status": run_result.get("status"),
                "evidence_families": run_result.get("evidence_families"),
                "hits_reviewed": run_result.get("hits_reviewed", 0),
                "queries_run": len(run_result.get("queries_run", [])),
                "entity_count": sum(len(v) for v in run_result.get("entities", {}).values()),
                "proposal_count": len(run_result.get("proposals", [])),
                "rag_used": bool(run_result.get("rag_context")),
                "rag_provenance_count": len(run_result.get("rag_provenance") or []),
                "playbook_used": bool(run_result.get("playbook_context")),
                "attack_context_used": bool(run_result.get("attack_context")),
                "sigma_context_used": bool(run_result.get("sigma_context")),
            })

    # CorrelationAgent: cross-family entity correlation
    correlation_agent = CorrelationAgent()
    for run in agent_runs:
        entities = run.get("entities") or {}
        if entities:
            correlation_agent.feed_entities(entities)
    correlation_result = correlation_agent.run()

    _log_agent_run(case_dir, {
        "action": "correlation_agent_run",
        "corroborated_entities": len(correlation_result.get("corroborated_entities", [])),
        "chains": len(correlation_result.get("chains", [])),
        "fed_families": correlation_result.get("fed_families", []),
    })

    # PatternAgent: attack pattern detection
    pattern_agent = PatternAgent()
    all_entities: dict[str, list[dict[str, Any]]] = {}
    for run in agent_runs:
        entities = run.get("entities") or {}
        for etype, elist in entities.items():
            all_entities.setdefault(etype, []).extend(elist)
    pattern_result = pattern_agent.detect_patterns(
        all_entities, correlation_result.get("chains", [])
    )

    _log_agent_run(case_dir, {
        "action": "pattern_agent_run",
        "patterns_checked": pattern_result.get("total_patterns_checked", 0),
        "patterns_matched": pattern_result.get("total_matches", 0),
    })

    # SynthesisAgent: build narrative + DRAFT findings
    synthesis_agent = SynthesisAgent()
    synthesis_result = synthesis_agent.synthesize(
        agent_runs, correlation_result, pattern_result, question
    )

    _log_agent_run(case_dir, {
        "action": "synthesis_agent_run",
        "findings": len(synthesis_result.get("findings", [])),
        "confidence": synthesis_result.get("confidence", 0),
    })

    append_chat(
        case_dir, "llm", "orchestrator_complete",
        f"Orchestrator: {len(agent_runs)} agent(s) ran, "
        f"{correlation_result.get('corroborated_entities', []).__len__()} corroborated entities, "
        f"{pattern_result.get('total_matches', 0)} patterns matched, "
        f"{len(synthesis_result.get('findings', []))} DRAFT findings proposed. "
        "Awaiting examiner review.",
    )

    return {
        "agent_runs": agent_runs,
        "correlation": correlation_result,
        "patterns": pattern_result,
        "synthesis": synthesis_result,
        "narrative": synthesis_result.get("narrative", ""),
        "findings": synthesis_result.get("findings", []),
        "total_evidence_refs": sum(
            len(r.get("entities", {}).get(k, []))
            for r in agent_runs
            for k in r.get("entities", {})
        ),
    }


def _agent_for_family(family: str) -> str:
    """Determine which agent handles a given evidence family."""
    family_lower = family.lower()
    for agent, families in _AGENT_FAMILY_MAP.items():
        if family_lower in families:
            return agent
    # Default to endpoint for unknown families
    return "endpoint"


def _families_to_agents(families: set[str] | list[str]) -> dict[str, list[str]]:
    """Group a set of families by their owning agent (WP 4i.8)."""
    out: dict[str, list[str]] = {}
    for fam in families:
        agent = _agent_for_family(str(fam))
        out.setdefault(agent, []).append(str(fam))
    return out


def _assign_skills(
    selected: list[dict[str, Any]],
    families_present: set[str],
    agent_to_families: dict[str, list[str]],
) -> dict[str, list[dict[str, Any]]]:
    """Route each selected skill to the agent(s) that should execute it.

    A skill goes to every agent owning one of its trigger families that is
    present in the case. When the skill matched on intake keywords/techniques
    but none of its trigger families are present, it still gets executed —
    assigned to the agent that would own the skill's primary trigger family
    (its steps may still hit other families' evidence). Without that, a
    keyword-driven skill silently never runs.
    """
    skills_by_agent: dict[str, list[dict[str, Any]]] = {}
    present_lower = {f.lower() for f in families_present}
    for s in selected:
        trig_fams = [
            str(f).lower() for f in (((s.get("trigger") or {}).get("families")) or [])
        ]
        targets = {
            _agent_for_family(f) for f in trig_fams if f in present_lower
        }
        targets &= set(agent_to_families)
        if not targets:
            # keyword/technique-only match → primary trigger family's owner,
            # else the first agent that has any families
            primary_owner = _agent_for_family(trig_fams[0]) if trig_fams else ""
            if primary_owner in agent_to_families:
                targets = {primary_owner}
            elif agent_to_families:
                targets = {sorted(agent_to_families)[0]}
        for agent_name in targets:
            skills_by_agent.setdefault(agent_name, []).append(s)
    return skills_by_agent
