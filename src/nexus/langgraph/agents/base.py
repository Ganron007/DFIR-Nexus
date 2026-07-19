"""Base agent class for LangGraph DFIR agents."""

from __future__ import annotations

from nexus.case import CaseManager
from nexus.langgraph.types import AgentName, AgentResult, PipelineState


class BaseAgent:
    """Base class for all 6 DFIR agents."""

    name: AgentName

    def __init__(self, case_manager: CaseManager | None = None) -> None:
        self.case_manager = case_manager

    def run(self, state: PipelineState) -> AgentResult:
        """Execute the agent against the current pipeline state."""
        raise NotImplementedError
