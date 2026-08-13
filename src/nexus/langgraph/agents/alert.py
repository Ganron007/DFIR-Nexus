"""Alert agent — EDR/alert clustering."""

from __future__ import annotations

import logging

from nexus.langgraph.agents.base import BaseAgent
from nexus.langgraph.agents.evidence import finding, top_values
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
            from collections import Counter
            src_counts = Counter(a.source.value for a in alerts)
            src_s = ", ".join(f"{s} ({n})" for s, n in src_counts.most_common(5))
            hosts = top_values(alerts, "host", 3)
            host_s = ", ".join(h for h, _ in hosts) or "multiple hosts"
            lead = (
                f"{len(alerts)} high/critical artifacts across sources [{src_s}] "
                f"on {host_s}. Prioritize for examiner review."
            )
            result.findings.append(finding(
                f"High-severity cluster ({len(alerts)}) on {host_s}",
                alerts,
                severity="critical",
                lead=lead,
            ))
        return result
