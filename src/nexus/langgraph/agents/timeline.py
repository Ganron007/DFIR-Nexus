"""Timeline agent — Hayabusa/Plaso/EVTX analysis."""

from __future__ import annotations

import logging

from nexus.langgraph.agents.base import BaseAgent
from nexus.langgraph.agents.evidence import finding, top_values
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
            hosts = ", ".join(h for h, _ in top_values(timeline_artifacts, "host", 3)) or "unknown host"
            titles = top_values(timeline_artifacts, "description", 3)
            lead = (
                f"Timeline clustering on {hosts}: {len(timeline_artifacts)} "
                f"Hayabusa/EVTX/technique-tagged events in case scope."
            )
            if titles:
                lead += " Top event descriptions: " + "; ".join(t for t, _ in titles) + "."
            result.findings.append(finding(
                f"Timeline activity on {hosts}",
                timeline_artifacts,
                severity="high",
                lead=lead,
            ))
        return result
