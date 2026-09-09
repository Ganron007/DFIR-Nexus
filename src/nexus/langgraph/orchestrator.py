"""Mode 3 multi-agent orchestrator (WP 3.10, 3.11, 3.12).

Dispatches specialist agents per evidence family, injects RAG methodology
and playbook context, collects agent findings into a synthesis node, and
routes to examiner approval. Every agent run is logged to agent_runs.jsonl
with full provenance (WP 3.11). RAG methodology used by agents is recorded
with query/doc provenance distinct from evidence (WP 3.12).

The orchestrator does NOT approve findings — the examiner does. The
orchestrator proposes; the examiner disposes.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

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


def _agent_for_family(family: str) -> str:
    """Determine which agent handles a given evidence family."""
    family_lower = family.lower()
    for agent, families in _AGENT_FAMILY_MAP.items():
        if family_lower in families:
            return agent
    # Default to endpoint for unknown families
    return "endpoint"


def _playbook_for_family(family: str) -> str:
    """WP 3.10: Load playbook caveats + first-phase steps for an agent's family.

    Reuses the same logic as mode2._playbook_context_for_families but for
    a single family (the agent's assigned family).
    """
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


def _run_agent(
    agent_name: str,
    families: list[str],
    hits: list[dict[str, Any]],
    case_dir: Path,
    model: Any = None,
) -> dict[str, Any]:
    """Run a single specialist agent on its assigned evidence families.

    Returns an agent run dict with:
        agent: str — agent name
        status: str — "done" or "error"
        evidence_families: list[str] — families this agent covered
        evidence_refs: list[dict] — hit references (file, line, family)
        proposals: list[dict] — proposed needles/findings
        rag_context: str — RAG methodology text used
        rag_provenance: list[dict] — RAG query/doc provenance
        playbook_context: str — playbook caveats + steps used
    """
    # Gather RAG methodology for each family
    rag_blocks: list[str] = []
    rag_provenance: list[dict[str, Any]] = []
    for fam in families:
        text, prov = _rag_for_family(fam)
        if text:
            rag_blocks.append(text)
            rag_provenance.extend(prov)

    rag_context = "\n".join(rag_blocks)

    # WP 3.10: Gather playbook caveats + first-phase steps for each family
    playbook_blocks: list[str] = []
    for fam in families:
        pb_text = _playbook_for_family(fam)
        if pb_text:
            playbook_blocks.append(pb_text)
    playbook_context = "\n".join(playbook_blocks)

    # Collect evidence references from hits
    evidence_refs = [
        {
            "family": h.get("family", ""),
            "file": h.get("file", ""),
            "line": h.get("line", ""),
        }
        for h in hits
        if h.get("family", "").lower() in [f.lower() for f in families]
    ]

    # Propose needles based on hit terms + RAG methodology
    proposals: list[dict[str, Any]] = []
    seen_terms: set[str] = set()
    for h in hits:
        if h.get("family", "").lower() not in [f.lower() for f in families]:
            continue
        for term in str(h.get("terms") or "").split(","):
            term = term.strip().lower()
            if term and term not in seen_terms and not term.isdigit():
                proposals.append({"needle": term, "source": "hit_terms"})
                seen_terms.add(term)

    # If LLM is available, use RAG + playbook context to propose additional needles
    if model is not None and (rag_context or playbook_context):
        try:
            prompt = (
                f"You are a {agent_name} DFIR specialist agent. "
                f"You are analyzing evidence from families: {', '.join(families)}.\n\n"
                f"Evidence hits:\n"
                f"{chr(10).join(f'- [{h.get('family')}] {str(h.get('text', ''))[:200]}' for h in hits[:10] if h.get('family', '').lower() in [f.lower() for f in families])}\n\n"
                f"RAG methodology:\n{rag_context[:1500] or '(none)'}\n\n"
                f"Playbook guidance:\n{playbook_context[:1000] or '(none)'}\n\n"
                "Propose 2-5 NEW search needles to corroborate or expand. "
                "Use the RAG methodology and playbook caveats to guide your proposals. "
                'Return ONLY JSON: {"needles": [...], "rationale": "..."}'
            )
            response = model.invoke([{"role": "user", "content": prompt}])
            text = getattr(response, "content", str(response))
            start, end = text.find("{"), text.rfind("}")
            if start != -1 and end != -1:
                parsed = json.loads(text[start:end + 1])
                for needle in (parsed.get("needles") or [])[:5]:
                    if str(needle).strip() and str(needle).strip().lower() not in seen_terms:
                        proposals.append({"needle": str(needle).strip(), "source": "llm_rag"})
                        seen_terms.add(str(needle).strip().lower())
        except Exception as exc:
            log.warning("Agent %s LLM proposal failed: %s", agent_name, exc)

    return {
        "agent": agent_name,
        "status": "done",
        "evidence_families": families,
        "evidence_refs": evidence_refs,
        "proposals": proposals,
        "rag_context": rag_context,
        "rag_provenance": rag_provenance,
        "playbook_context": playbook_context,
    }


def _synthesis(agent_runs: list[dict[str, Any]]) -> dict[str, Any]:
    """Synthesis node: cross-corroborate findings across agent families.

    Identifies:
    - Families covered by multiple agents (cross-corroboration possible)
    - Needles proposed by multiple agents (high-priority)
    - Single-family findings (need corroboration per FD-006)
    """
    all_families: set[str] = set()
    all_needles: dict[str, int] = {}
    single_family_agents: list[str] = []

    for run in agent_runs:
        families = run.get("evidence_families") or []
        all_families.update(families)
        if len(families) <= 1:
            single_family_agents.append(run.get("agent", "?"))
        for prop in run.get("proposals") or []:
            needle = prop.get("needle", "")
            if needle:
                all_needles[needle] = all_needles.get(needle, 0) + 1

    # Needles proposed by multiple agents are high-priority corroboration
    corroborated_needles = [
        n for n, count in all_needles.items() if count > 1
    ]

    return {
        "families_covered": sorted(all_families),
        "agent_count": len(agent_runs),
        "corroborated_needles": corroborated_needles,
        "single_family_agents": single_family_agents,
        "corroborated": len(corroborated_needles) > 0,
        "total_proposals": sum(len(r.get("proposals") or []) for r in agent_runs),
    }


def run_orchestrator(
    case_dir: Path,
    hits: list[dict[str, Any]],
    model: Any = None,
) -> dict[str, Any]:
    """WP 3.10: Run the multi-agent orchestrator.

    Dispatches specialist agents per evidence family, injects RAG methodology,
    collects findings into synthesis, and logs everything to agent_runs.jsonl.

    The orchestrator does NOT approve findings — it proposes. The examiner
    retains final approval authority.

    Returns:
        agent_runs: list[dict] — per-agent run results
        synthesis: dict — cross-corroboration synthesis
        total_evidence_refs: int
    """
    from nexus.case.chat import append_chat

    case_dir = Path(case_dir)

    if not hits:
        append_chat(case_dir, "llm", "orchestrator_empty", "No hits to analyze — orchestrator skipped.")
        return {"agent_runs": [], "synthesis": {}, "total_evidence_refs": 0}

    # Group hits by family → assign to agents
    family_to_agent: dict[str, str] = {}
    agent_to_families: dict[str, list[str]] = {}
    for hit in hits:
        family = hit.get("family", "?")
        if family not in family_to_agent:
            agent = _agent_for_family(family)
            family_to_agent[family] = agent
            agent_to_families.setdefault(agent, []).append(family)

    # Run each agent on its assigned families
    agent_runs: list[dict[str, Any]] = []
    for agent_name, families in agent_to_families.items():
        run_result = _run_agent(agent_name, families, hits, case_dir, model)
        agent_runs.append(run_result)

        # WP 3.11: Log each agent run
        _log_orchestrator_run(case_dir, run_result)

    # Synthesis
    synth = _synthesis(agent_runs)

    append_chat(
        case_dir, "llm", "orchestrator_complete",
        f"Orchestrator: {len(agent_runs)} agent(s) ran, "
        f"{synth['total_proposals']} proposals, "
        f"{len(synth.get('corroborated_needles', []))} corroborated. "
        "Awaiting examiner review.",
    )

    return {
        "agent_runs": agent_runs,
        "synthesis": synth,
        "total_evidence_refs": sum(len(r.get("evidence_refs") or []) for r in agent_runs),
    }


def _log_orchestrator_run(case_dir: Path, run: dict[str, Any]) -> None:
    """WP 3.11: Log each agent run to agent_runs.jsonl with full context."""
    case_dir = Path(case_dir)
    record = {
        "ts": datetime.now(UTC).isoformat(),
        "action": "orchestrator_agent_run",
        "agent": run.get("agent"),
        "status": run.get("status"),
        "evidence_families": run.get("evidence_families"),
        "evidence_ref_count": len(run.get("evidence_refs") or []),
        "proposal_count": len(run.get("proposals") or []),
        "rag_used": bool(run.get("rag_context")),
        "rag_provenance_count": len(run.get("rag_provenance") or []),
        "playbook_used": bool(run.get("playbook_context")),
    }
    with (case_dir / "agent_runs.jsonl").open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, default=str) + "\n")
