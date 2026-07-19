"""LangGraph multi-agent pipeline for DFIR-Nexus (B.0 "Pathfinder").

Provides a stateful agent graph with 6 specialized agents in ``langgraph/agents/``.
The graph uses langgraph.types.interrupt() for human-in-the-loop approval
before any finding is committed.
"""

from __future__ import annotations

import logging
from typing import Any, cast

from langgraph.graph import END, START, StateGraph
from langgraph.types import interrupt

from nexus.case import CaseManager
from nexus.ingest import Artifact
from nexus.langgraph.agents import (
    AlertAgent,
    BaseAgent,
    CloudAgent,
    EndpointAgent,
    NetworkAgent,
    SynthesisAgent,
    TimelineAgent,
)
from nexus.langgraph.types import (
    AgentName,
    AgentResult,
    AgentStatus,
    PipelineState,
    PipelineStateDict,
)

log = logging.getLogger(__name__)

# Re-export for backward compatibility
__all__ = [
    "AgentName",
    "AgentResult",
    "AgentStatus",
    "AlertAgent",
    "BaseAgent",
    "CloudAgent",
    "DFIRAgentGraph",
    "EndpointAgent",
    "NetworkAgent",
    "PipelineState",
    "SynthesisAgent",
    "TimelineAgent",
    "run_analysis_without_interrupt",
]


class DFIRAgentGraph:
    """LangGraph-based multi-agent DFIR pipeline.

    Usage:
        graph = DFIRAgentGraph(case_manager=CaseManager(...))
        state = graph.run(case_id="CASE-xxx", artifacts=[...])
        # Human approves findings via case_approve MCP tool
    """

    def __init__(
        self,
        case_manager: CaseManager | None = None,
        agents: list[BaseAgent] | None = None,
        include_synthesis: bool = True,
    ) -> None:
        self.case_manager = case_manager
        self.include_synthesis = include_synthesis
        self.agents: list[BaseAgent] = agents or [
            TimelineAgent(case_manager),
            EndpointAgent(case_manager),
            NetworkAgent(case_manager),
            AlertAgent(case_manager),
            CloudAgent(case_manager),
        ]
        self._compiled = self._build_graph()

    def _make_agent_node(self, agent: BaseAgent) -> Any:
        def _node(state: PipelineStateDict) -> PipelineStateDict:
            ps = PipelineState.from_dict(state)
            result = agent.run(ps)
            update: PipelineStateDict = {
                "results": {agent.name.value: result.to_dict()},
                "step_log": [{
                    "step": agent.name.value,
                    "status": result.status.value,
                    "finding_count": len(result.findings),
                }],
            }
            if agent.name == AgentName.SYNTHESIS:
                update["draft_finding_ids"] = list(result.evidence_ids)
                update["pending_human_approval"] = result.status == AgentStatus.NEEDS_APPROVAL
            return update
        return _node

    def _synthesis_router(self, state: PipelineStateDict) -> str:
        ps = PipelineState.from_dict(state)
        if ps.error:
            return END
        if ps.draft_finding_ids:
            return "human_gate"
        return END

    def _human_gate_node(self, state: PipelineStateDict) -> PipelineStateDict:
        """Interrupt and ask for human approval of DRAFT findings."""
        ps = PipelineState.from_dict(state)
        value = interrupt({
            "case_id": ps.case_id,
            "draft_finding_ids": ps.draft_finding_ids,
            "message": "Please review and approve/reject DRAFT findings",
        })
        if isinstance(value, dict):
            return {
                "approved_finding_ids": list(value.get("approved", [])),
                "rejected_finding_ids": list(value.get("rejected", [])),
                "pending_human_approval": False,
                "step_log": [{"step": "human_gate", "input": value}],
            }
        return {
            "pending_human_approval": False,
            "step_log": [{"step": "human_gate", "input": value}],
        }

    def _build_graph(self) -> Any:
        from langgraph.checkpoint.memory import MemorySaver
        graph = StateGraph(PipelineStateDict)

        for agent in self.agents:
            if agent.name == AgentName.SYNTHESIS:
                continue
            graph.add_node(agent.name.value, self._make_agent_node(agent))

        if self.include_synthesis:
            graph.add_node("synthesis", self._make_agent_node(SynthesisAgent(self.case_manager)))
            graph.add_node("human_gate", self._human_gate_node)

        for agent in self.agents:
            if agent.name == AgentName.SYNTHESIS:
                continue
            graph.add_edge(START, agent.name.value)

        non_synthesis = [a for a in self.agents if a.name != AgentName.SYNTHESIS]
        if self.include_synthesis:
            for agent in non_synthesis:
                graph.add_edge(agent.name.value, "synthesis")
            graph.add_conditional_edges("synthesis", self._synthesis_router)
            graph.add_edge("human_gate", END)
        else:
            for agent in non_synthesis:
                graph.add_edge(agent.name.value, END)

        return graph.compile(checkpointer=MemorySaver())

    def run(
        self,
        case_id: str,
        artifacts: list[Artifact],
        case_name: str = "",
    ) -> PipelineState:
        """Run the full agent graph.

        Note: If the graph hits the human_gate interrupt, this method will
        raise a GraphInterrupt. Use ``ainvoke`` with a thread and resume after
        human approval.
        """
        initial = PipelineState(
            case_id=case_id,
            case_name=case_name,
            artifacts=list(artifacts),
        )
        config = {"configurable": {"thread_id": case_id or "default"}}
        result = self._compiled.invoke(initial.to_dict(), config=config)
        if isinstance(result, dict) and "__interrupt__" in result:
            state = PipelineState.from_dict(cast(PipelineStateDict, result))
            state.interrupt_payload = result["__interrupt__"]
            state.pending_human_approval = True
            return state
        return PipelineState.from_dict(cast(PipelineStateDict, result))

    async def arun(
        self,
        case_id: str,
        artifacts: list[Artifact],
        case_name: str = "",
    ) -> PipelineState:
        initial = PipelineState(
            case_id=case_id,
            case_name=case_name,
            artifacts=list(artifacts),
        )
        config = {"configurable": {"thread_id": case_id or "default"}}
        result = await self._compiled.ainvoke(initial.to_dict(), config=config)
        if isinstance(result, dict) and "__interrupt__" in result:
            state = PipelineState.from_dict(cast(PipelineStateDict, result))
            state.interrupt_payload = result["__interrupt__"]
            state.pending_human_approval = True
            return state
        return PipelineState.from_dict(cast(PipelineStateDict, result))


def run_analysis_without_interrupt(
    case_id: str,
    artifacts: list[Artifact],
    case_manager: CaseManager,
    case_name: str = "",
    agents: list[BaseAgent] | None = None,
) -> PipelineState:
    """Convenience runner that skips the human_gate interrupt.

    Useful for smoke tests and headless automation.
    """
    analysis_agents = agents or [
        TimelineAgent(case_manager),
        EndpointAgent(case_manager),
        NetworkAgent(case_manager),
        AlertAgent(case_manager),
        CloudAgent(case_manager),
    ]
    graph = DFIRAgentGraph(
        case_manager=case_manager,
        agents=analysis_agents,
        include_synthesis=False,
    )
    return graph.run(case_id=case_id, artifacts=artifacts, case_name=case_name)
