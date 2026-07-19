"""Shared types for the LangGraph DFIR pipeline."""

from __future__ import annotations

import operator
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Annotated, Any, TypedDict

from nexus.ingest import Artifact


class AgentName(StrEnum):
    """Names of the specialized DFIR agents."""

    TIMELINE = "timeline"
    ENDPOINT = "endpoint"
    NETWORK = "network"
    ALERT = "alert"
    CLOUD = "cloud"
    SYNTHESIS = "synthesis"


class AgentStatus(StrEnum):
    """Status of an agent's work."""

    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    ERROR = "error"
    NEEDS_APPROVAL = "needs_approval"


class AgentResultDict(TypedDict):
    """TypedDict mirror of AgentResult for LangGraph state."""

    agent: str
    status: str
    findings: list[dict[str, Any]]
    evidence_ids: list[str]
    notes: list[str]
    error: str | None


def _merge_results(
    left: dict[str, AgentResultDict],
    right: dict[str, AgentResultDict],
) -> dict[str, AgentResultDict]:
    """Reducer that merges agent result dictionaries."""
    merged = dict(left)
    merged.update(right)
    return merged


class PipelineStateDict(TypedDict, total=False):
    """LangGraph state schema with reducers for parallel updates."""

    case_id: str | None
    case_name: str
    artifacts: list[dict[str, Any]]
    evidence_audit_ids: Annotated[list[str], operator.add]
    scope_summary: str
    results: Annotated[dict[str, AgentResultDict], _merge_results]
    draft_finding_ids: Annotated[list[str], operator.add]
    approved_finding_ids: Annotated[list[str], operator.add]
    rejected_finding_ids: Annotated[list[str], operator.add]
    pending_human_approval: bool
    report_path: str | None
    step_log: Annotated[list[dict[str, Any]], operator.add]
    error: str | None
    interrupt_payload: Any


@dataclass
class AgentResult:
    """Output from one agent."""

    agent: AgentName
    status: AgentStatus
    findings: list[dict[str, Any]] = field(default_factory=list)
    evidence_ids: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    error: str | None = None

    def to_dict(self) -> AgentResultDict:
        return {
            "agent": self.agent.value,
            "status": self.status.value,
            "findings": self.findings,
            "evidence_ids": self.evidence_ids,
            "notes": self.notes,
            "error": self.error,
        }


@dataclass
class PipelineState:
    """Mutable state shared across the LangGraph pipeline."""

    case_id: str | None = None
    case_name: str = ""
    artifacts: list[Artifact] = field(default_factory=list)
    evidence_audit_ids: list[str] = field(default_factory=list)
    scope_summary: str = ""
    results: dict[str, AgentResult] = field(default_factory=dict)
    draft_finding_ids: list[str] = field(default_factory=list)
    approved_finding_ids: list[str] = field(default_factory=list)
    rejected_finding_ids: list[str] = field(default_factory=list)
    pending_human_approval: bool = False
    report_path: str | None = None
    step_log: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None
    interrupt_payload: Any = None

    def to_dict(self) -> PipelineStateDict:
        return {
            "case_id": self.case_id,
            "case_name": self.case_name,
            "artifacts": [a.to_dict() for a in self.artifacts],
            "evidence_audit_ids": self.evidence_audit_ids,
            "scope_summary": self.scope_summary,
            "results": {k: v.to_dict() for k, v in self.results.items()},
            "draft_finding_ids": self.draft_finding_ids,
            "approved_finding_ids": self.approved_finding_ids,
            "rejected_finding_ids": self.rejected_finding_ids,
            "pending_human_approval": self.pending_human_approval,
            "report_path": self.report_path,
            "step_log": self.step_log,
            "error": self.error,
            "interrupt_payload": self.interrupt_payload,
        }

    @classmethod
    def from_dict(cls, data: PipelineStateDict) -> PipelineState:
        from nexus.ingest.schemas import Artifact as _Artifact

        raw_results = data.get("results") or {}
        results: dict[str, AgentResult] = {}
        for k, v in raw_results.items():
            if isinstance(v, dict):
                results[k] = AgentResult(
                    agent=AgentName(v.get("agent", "alert")),
                    status=AgentStatus(v.get("status", "done")),
                    findings=list(v.get("findings", [])),
                    evidence_ids=list(v.get("evidence_ids", [])),
                    notes=list(v.get("notes", [])),
                    error=v.get("error"),
                )

        return cls(
            case_id=data.get("case_id"),
            case_name=data.get("case_name", ""),
            artifacts=[_Artifact.from_dict(a) for a in data.get("artifacts", [])],
            evidence_audit_ids=list(data.get("evidence_audit_ids", [])),
            scope_summary=data.get("scope_summary", ""),
            results=results,
            draft_finding_ids=list(data.get("draft_finding_ids", [])),
            approved_finding_ids=list(data.get("approved_finding_ids", [])),
            rejected_finding_ids=list(data.get("rejected_finding_ids", [])),
            pending_human_approval=bool(data.get("pending_human_approval", False)),
            report_path=data.get("report_path"),
            step_log=list(data.get("step_log", [])),
            error=data.get("error"),
            interrupt_payload=data.get("interrupt_payload"),
        )
