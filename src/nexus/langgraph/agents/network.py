"""Network agent — Zeek/Suricata/Arkime analysis + TI enrichment."""

from __future__ import annotations

import logging
import os

from nexus.constants import ENV_TI_MOCK
from nexus.langgraph.agents.base import BaseAgent
from nexus.langgraph.agents.evidence import finding, top_values
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
            dst = top_values(network_artifacts, "dest_ip", 5)
            src = top_values(network_artifacts, "source_ip", 5)
            sources = sorted({a.source.value for a in network_artifacts})
            top_dst = ", ".join(f"{ip} ({n})" for ip, n in dst) or "n/a"
            top_src = ", ".join(f"{ip} ({n})" for ip, n in src) or "n/a"
            lead = (
                f"Network-related telemetry ({len(network_artifacts)} events from "
                f"{sources}) shows traffic among src=[{top_src}] and dst=[{top_dst}]. "
                "Review for C2, lateral movement, and abnormal destinations."
            )
            result.findings.append(finding(
                f"Network activity to {dst[0][0] if dst else 'multiple hosts'}",
                network_artifacts,
                severity="high",
                technique_ids_=["T1071.001", "T1021.002"],
                lead=lead,
            ))
            router = TIRouter(force_mock=True) if os.environ.get(ENV_TI_MOCK) == "1" else None
            enriched = enrich_artifacts(network_artifacts, max_iocs=5, router=router)
            result.notes.append(f"TI enrichment: {enriched['summary']}")
            for lookup in enriched.get("lookups", []):
                for hit in lookup.get("hits", []):
                    result.notes.append(
                        f"IOC: {lookup.get('ioc')} - {hit.get('provider')} - {hit.get('threat_type')}"
                    )
        return result
