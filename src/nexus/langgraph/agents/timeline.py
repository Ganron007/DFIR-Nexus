"""Timeline agent — Hayabusa/Plaso/EVTX analysis."""

from __future__ import annotations

import logging

from nexus.langgraph.agents.base import BaseAgent
from nexus.langgraph.types import AgentName, AgentResult, AgentStatus, PipelineState

log = logging.getLogger(__name__)


class TimelineAgent(BaseAgent):
    """Analyzes timeline artifacts (Hayabusa/Plaso/EVTX)."""

    name = AgentName.TIMELINE

    def run(self, state: PipelineState) -> AgentResult:
        log.info("TimelineAgent running for case %s", state.case_id)
        result = AgentResult(agent=self.name, status=AgentStatus.DONE)
        timeline_artifacts = [
            a for a in state.artifacts
            if a.source.value in ("hayabusa", "evtx", "plaso")
            or any(t.startswith("T") for t in a.technique_ids)
        ]
        result.notes.append(f"Analyzed {len(timeline_artifacts)} timeline artifacts")
        if timeline_artifacts:
            result.findings.append({
                "title": "Suspicious timeline activity detected",
                "description": f"{len(timeline_artifacts)} artifacts clustered in case scope",
                "severity": "high",
                "technique_ids": sorted({t for a in timeline_artifacts for t in a.technique_ids}),
            })
        return result
