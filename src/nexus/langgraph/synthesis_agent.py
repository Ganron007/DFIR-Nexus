"""SynthesisAgent — WP 3.20.

Corroborates across all agent outputs, builds attack narrative (temporal
chain of events), assigns overall confidence, proposes DRAFT findings with
evidence citations (audit_id per citation). Feeds to examiner gate.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

log = logging.getLogger(__name__)


class SynthesisAgent:
    """Synthesis node: corroborates across all agent outputs.

    Takes the outputs from EvidenceAgents, CorrelationAgent, and PatternAgent
    and produces:
    - A coherent attack narrative (temporal chain of events)
    - DRAFT findings with evidence citations (each citation has audit_id)
    - Overall confidence assessment
    - Summary statistics
    """

    name = "synthesis"

    def synthesize(
        self,
        agent_runs: list[dict[str, Any]],
        correlation_result: dict[str, Any],
        pattern_result: dict[str, Any],
        intake_question: str = "",
    ) -> dict[str, Any]:
        """Synthesize all agent outputs into findings and narrative.

        Args:
            agent_runs: list of EvidenceAgent run results
            correlation_result: CorrelationAgent.run() output
            pattern_result: PatternAgent.detect_patterns() output
            intake_question: the examiner's original question

        Returns:
            narrative: human-readable attack narrative
            findings: list of DRAFT findings with evidence citations
            summary: overall statistics
            confidence: overall confidence score
        """
        findings: list[dict[str, Any]] = []
        narrative_parts: list[str] = []

        # 1. Corroborated entities → findings
        corroborated = correlation_result.get("corroborated_entities") or []
        for ent in corroborated:
            if len(ent.get("families", [])) >= 2:
                finding = self._finding_from_entity(ent, intake_question)
                if finding:
                    findings.append(finding)
                    narrative_parts.append(
                        f"{ent['type']} '{ent['value']}' appears in "
                        f"{len(ent['families'])} families: {', '.join(ent['families'])}"
                    )

        # 2. Temporal chains → findings
        chains = correlation_result.get("chains") or []
        for chain in chains:
            if len(chain.get("events", [])) >= 2:
                finding = self._finding_from_chain(chain, intake_question)
                if finding:
                    findings.append(finding)
                    events_desc = " → ".join(
                        f"{e['family']}({e['ts']})" for e in chain["events"]
                    )
                    narrative_parts.append(
                        f"Temporal chain: {events_desc} "
                        f"(entity: {chain['entity']}, confidence: {chain.get('confidence', 0)})"
                    )

        # 3. Pattern matches → findings
        patterns = pattern_result.get("patterns") or []
        for pattern in patterns:
            finding = self._finding_from_pattern(pattern, intake_question)
            if finding:
                findings.append(finding)
                narrative_parts.append(
                    f"Pattern: {pattern['name']} — {pattern['description']} "
                    f"(MITRE: {', '.join(pattern.get('mitre', []))}, "
                    f"confidence: {pattern.get('confidence', 0)})"
                )

        # Build overall narrative
        narrative = self._build_narrative(narrative_parts, intake_question)

        # Calculate overall confidence
        confidences = [f.get("confidence", 0.5) for f in findings]
        overall_confidence = (
            round(sum(confidences) / len(confidences), 2) if confidences else 0.0
        )

        # Backward-compatible keys for the old simulation API
        all_families: set[str] = set()
        for run in agent_runs:
            all_families.update(run.get("evidence_families") or [])
        all_families.update(correlation_result.get("fed_families") or [])

        # Collect RAG provenance from all agent runs for methodology citation
        all_rag_provenance: list[dict[str, Any]] = []
        all_rag_used: list[str] = []
        all_playbook_used: list[str] = []
        all_attack_used: list[str] = []
        all_sigma_used: list[str] = []
        for run in agent_runs:
            prov = run.get("rag_provenance") or []
            all_rag_provenance.extend(prov)
            if run.get("rag_context"):
                all_rag_used.append(run.get("agent", "unknown"))
            if run.get("playbook_context"):
                all_playbook_used.append(run.get("agent", "unknown"))
            if run.get("attack_context"):
                all_attack_used.append(run.get("agent", "unknown"))
            if run.get("sigma_context"):
                all_sigma_used.append(run.get("agent", "unknown"))

        return {
            "narrative": narrative,
            "findings": findings,
            "confidence": overall_confidence,
            "summary": {
                "total_findings": len(findings),
                "corroborated_entities": len(corroborated),
                "temporal_chains": len(chains),
                "patterns_matched": len(patterns),
                "agent_runs": len(agent_runs),
            },
            "provenance": {
                "agent_runs": len(agent_runs),
                "synthesized_at": datetime.now(UTC).isoformat(),
            },
            "methodology_provenance": {
                "rag_used_by_agents": sorted(set(all_rag_used)),
                "playbook_used_by_agents": sorted(set(all_playbook_used)),
                "attack_context_used_by_agents": sorted(set(all_attack_used)),
                "sigma_context_used_by_agents": sorted(set(all_sigma_used)),
                "rag_documents": all_rag_provenance,
            },
            # Backward-compatible keys (old simulation API)
            "corroborated": len(corroborated) > 0 or len(chains) > 0,
            "families_covered": sorted(all_families),
            "corroborated_needles": [
                e["value"] for e in corroborated
            ],
        }

    def _finding_from_entity(
        self, ent: dict[str, Any], question: str
    ) -> dict[str, Any] | None:
        """Build a DRAFT finding from a corroborated entity."""
        if len(ent.get("families", [])) < 2:
            return None
        return {
            "title": f"Corroborated {ent['type']}: {ent['value']}",
            "body": (
                f"Entity '{ent['value']}' ({ent['type']}) appears in "
                f"{len(ent['families'])} evidence families: "
                f"{', '.join(ent['families'])}. "
                f"This cross-family presence indicates the entity is active "
                f"across multiple evidence sources."
            ),
            "evidence_refs": ent.get("hits", []),
            "confidence": ent.get("confidence", 0.5),
            "mitre": [],
            "agent_id": "correlation",
            "examiner_selected": False,
            "status": "DRAFT",
        }

    def _finding_from_chain(
        self, chain: dict[str, Any], question: str
    ) -> dict[str, Any] | None:
        """Build a DRAFT finding from a temporal chain."""
        events = chain.get("events", [])
        if len(events) < 2:
            return None
        return {
            "title": f"Temporal chain: {chain['entity']}",
            "body": (
                f"Entity '{chain['entity']}' appears in a temporal chain "
                f"across {len(chain['families'])} families: "
                f"{', '.join(chain['families'])}. "
                f"Chain duration: {chain.get('duration_seconds', 0):.0f}s. "
                f"Events: {', '.join(e['family'] + '@' + e['ts'] for e in events)}."
            ),
            "evidence_refs": events,
            "confidence": chain.get("confidence", 0.5),
            "mitre": [],
            "agent_id": "correlation",
            "examiner_selected": False,
            "status": "DRAFT",
        }

    def _finding_from_pattern(
        self, pattern: dict[str, Any], question: str
    ) -> dict[str, Any] | None:
        """Build a DRAFT finding from a pattern match."""
        return {
            "title": f"Pattern: {pattern.get('name', 'unknown')}",
            "body": (
                f"{pattern.get('description', 'Attack pattern detected.')}\n\n"
                f"MITRE: {', '.join(pattern.get('mitre', []))}\n"
                f"Matched entities: {', '.join(pattern.get('matched_entities', []))}\n"
                f"Families covered: {', '.join(pattern.get('families_covered', []))}"
            ),
            "evidence_refs": pattern.get("matched_entities", []),
            "confidence": pattern.get("confidence", 0.5),
            "mitre": pattern.get("mitre", []),
            "agent_id": "pattern",
            "examiner_selected": False,
            "status": "DRAFT",
        }

    def _build_narrative(
        self, parts: list[str], question: str
    ) -> str:
        """Build a coherent attack narrative from the parts."""
        if not parts:
            return "No significant findings synthesized from the agent outputs."

        header = (
            f"Investigation narrative for: {question}\n\n"
            if question
            else "Investigation narrative:\n\n"
        )
        return header + "\n".join(f"- {p}" for p in parts)


def synthesize_findings(
    agent_runs: list[dict[str, Any]],
    correlation_result: dict[str, Any],
    pattern_result: dict[str, Any],
    intake_question: str = "",
) -> dict[str, Any]:
    """Convenience function: run the SynthesisAgent."""
    agent = SynthesisAgent()
    return agent.synthesize(agent_runs, correlation_result, pattern_result, intake_question)
