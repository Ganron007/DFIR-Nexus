"""CorrelationAgent — WP 3.18.

Runs continuously as EvidenceAgents produce entities. Correlates entities
across families: same IP in EVTX + netstat, same process hash in 4688 +
prefetch, same user in multiple artifacts. Reports cross-family matches
with confidence. Feeds clusters to PatternAgent.
"""

from __future__ import annotations

import logging
from typing import Any

from nexus.langgraph.correlation import EntityGraph, correlate_entities

log = logging.getLogger(__name__)


class CorrelationAgent:
    """Continuous cross-family entity correlation.

    Maintains a shared EntityGraph. Each EvidenceAgent feeds its extracted
    entities into the graph. The agent reports:
    - corroborated_entities: entities appearing in 2+ families
    - chains: temporal chains of correlated events
    - confidence: per-entity confidence based on family diversity
    """

    name = "correlation"

    def __init__(self) -> None:
        self.graph = EntityGraph()
        self._fed_families: set[str] = set()

    def feed_entities(self, entities: dict[str, list[dict[str, Any]]]) -> None:
        """Feed extracted entities from an EvidenceAgent into the graph."""
        self.graph.add_from_hits(entities)
        for _entity_type, entity_list in entities.items():
            for ent in entity_list:
                for hit_ref in ent.get("hits", []):
                    self._fed_families.add(hit_ref.get("family", ""))

    def run(self) -> dict[str, Any]:
        """Run correlation across all fed entities.

        Returns:
            corroborated_entities: entities in 2+ families
            chains: temporal chains of correlated events
            confidence: per-entity confidence scores
            summary: graph statistics
        """
        result = correlate_entities(self.graph)

        # Add confidence scores: more families = higher confidence
        for ent in result["corroborated_entities"]:
            family_count = len(ent.get("families", []))
            # Base confidence scales with family diversity
            base = min(0.5 + (family_count - 1) * 0.15, 0.95)
            ent["confidence"] = round(base, 2)

        # Add chain confidence
        for chain in result["chains"]:
            family_count = len(chain.get("families", []))
            event_count = len(chain.get("events", []))
            base = min(0.4 + (family_count - 1) * 0.1 + event_count * 0.05, 0.9)
            chain["confidence"] = round(base, 2)

        result["fed_families"] = sorted(self._fed_families)
        return result


def correlate_agent_runs(agent_runs: list[dict[str, Any]]) -> dict[str, Any]:
    """Convenience function: build a CorrelationAgent from agent run results.

    Args:
        agent_runs: list of agent run dicts, each with an "entities" key
            containing extract_entities() output.

    Returns:
        CorrelationAgent.run() result.
    """
    agent = CorrelationAgent()
    for run in agent_runs:
        entities = run.get("entities") or {}
        if entities:
            agent.feed_entities(entities)
    return agent.run()
