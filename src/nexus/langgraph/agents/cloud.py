"""Cloud agent — Entra/Azure/M365 log analysis."""

from __future__ import annotations

import logging

from nexus.langgraph.agents.base import BaseAgent
from nexus.langgraph.types import AgentName, AgentResult, AgentStatus, PipelineState

log = logging.getLogger(__name__)


class CloudAgent(BaseAgent):
    """Analyzes Entra/Azure/cloud logs."""

    name = AgentName.CLOUD

    def run(self, state: PipelineState) -> AgentResult:
        log.info("CloudAgent running for case %s", state.case_id)
        result = AgentResult(agent=self.name, status=AgentStatus.DONE)
        cloud_artifacts = [
            a for a in state.artifacts
            if a.source.value in ("cloudtrail", "azure", "m365")
        ]
        result.notes.append(f"Cloud scope: {len(cloud_artifacts)} artifacts")
        if cloud_artifacts:
            result.findings.append({
                "title": "Cloud identity or access anomaly",
                "description": "Cloud logs indicate suspicious activity",
                "severity": "high",
                "technique_ids": ["T1078.004", "T1098"],
            })
        return result
