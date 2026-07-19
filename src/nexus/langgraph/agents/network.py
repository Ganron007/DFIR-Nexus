"""Network agent — Zeek/Suricata/Arkime analysis + TI enrichment."""

from __future__ import annotations

import logging
import os

from nexus.constants import ENV_TI_MOCK
from nexus.langgraph.agents.base import BaseAgent
from nexus.langgraph.types import AgentName, AgentResult, AgentStatus, PipelineState
from nexus.ti.enrich import enrich_artifacts
from nexus.ti.router import TIRouter

log = logging.getLogger(__name__)


class NetworkAgent(BaseAgent):
    """Analyzes network telemetry."""

    name = AgentName.NETWORK

    def run(self, state: PipelineState) -> AgentResult:
        log.info("NetworkAgent running for case %s", state.case_id)
        result = AgentResult(agent=self.name, status=AgentStatus.DONE)
        network_artifacts = [
            a for a in state.artifacts
            if a.source.value in ("suricata", "zeek", "arkime")
            or a.artifact_type.value == "network"
        ]
        result.notes.append(f"Network scope: {len(network_artifacts)} artifacts")
        if network_artifacts:
            result.findings.append({
                "title": "Suspicious network activity",
                "description": "Network telemetry shows potential C2 or lateral movement",
                "severity": "high",
                "technique_ids": ["T1071.001", "T1021.002"],
            })
            router = TIRouter(force_mock=True) if os.environ.get(ENV_TI_MOCK) == "1" else None
            enriched = enrich_artifacts(network_artifacts, max_iocs=5, router=router)
            result.notes.append(
                f"TI enrichment: {enriched['summary']}"
            )
            for lookup in enriched.get("lookups", []):
                for hit in lookup.get("hits", []):
                    result.notes.append(f"IOC: {lookup.get('ioc')} - {hit.get('provider')} - {hit.get('threat_type')}")
        return result
