"""Synthesis agent — records DRAFT findings for human approval."""

from __future__ import annotations

import logging

from nexus.case import ApprovalState
from nexus.langgraph.agents.base import BaseAgent
from nexus.langgraph.types import AgentName, AgentResult, AgentStatus, PipelineState

log = logging.getLogger(__name__)


class SynthesisAgent(BaseAgent):
    """Records all agent findings as DRAFT findings in the case."""

    name = AgentName.SYNTHESIS

    def run(self, state: PipelineState) -> AgentResult:
        log.info("SynthesisAgent running for case %s", state.case_id)
        result = AgentResult(agent=self.name, status=AgentStatus.NEEDS_APPROVAL)
        if self.case_manager is None or state.case_id is None:
            result.error = "No case manager or case_id available"
            result.status = AgentStatus.ERROR
            return result

        for agent_name, agent_result in state.results.items():
            for finding in agent_result.findings:
                f = self.case_manager.add_finding(
                    case_id=state.case_id,
                    title=finding["title"],
                    description=finding["description"],
                    severity=finding.get("severity", "medium"),
                    technique_ids=finding.get("technique_ids", []),
                    created_by=f"agent:{agent_name}",
                    initial_state=ApprovalState.DRAFT,
                )
                if f is not None:
                    state.draft_finding_ids.append(f.id)
                    result.evidence_ids.append(f.id)

        result.notes.append(f"Recorded {len(result.evidence_ids)} DRAFT findings")
        return result
