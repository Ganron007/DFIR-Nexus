"""Alert agent — EDR/alert clustering."""

from __future__ import annotations

import logging

from nexus.langgraph.agents.base import BaseAgent
from nexus.langgraph.types import AgentName, AgentResult, AgentStatus, PipelineState

log = logging.getLogger(__name__)


class AlertAgent(BaseAgent):
    """Clusters EDR/alert style artifacts."""

    name = AgentName.ALERT

    def run(self, state: PipelineState) -> AgentResult:
        log.info("AlertAgent running for case %s", state.case_id)
        result = AgentResult(agent=self.name, status=AgentStatus.DONE)
        alerts = [a for a in state.artifacts if a.severity.value in ("critical", "high")]
        result.notes.append(f"High/critical severity artifacts: {len(alerts)}")
        if alerts:
            result.findings.append({
                "title": "High-severity alert cluster",
                "description": f"{len(alerts)} high/critical artifacts require attention",
                "severity": "critical",
                "technique_ids": sorted({t for a in alerts for t in a.technique_ids}),
            })
        return result
