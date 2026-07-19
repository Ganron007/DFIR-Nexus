"""Endpoint agent — Velociraptor VQL hunts."""

from __future__ import annotations

import logging
import os

from nexus.constants import ENV_VR_USE_MOCK
from nexus.langgraph.agents.base import BaseAgent
from nexus.langgraph.types import AgentName, AgentResult, AgentStatus, PipelineState
from nexus.vr import create_vr_service, suggest_hunt_ids

log = logging.getLogger(__name__)


class EndpointAgent(BaseAgent):
    """Runs Velociraptor VQL hunts."""

    name = AgentName.ENDPOINT

    def run(self, state: PipelineState) -> AgentResult:
        log.info("EndpointAgent running for case %s", state.case_id)
        result = AgentResult(agent=self.name, status=AgentStatus.DONE)
        endpoint_artifacts = [
            a for a in state.artifacts
            if a.source.value == "velociraptor" or a.artifact_type.value == "process"
        ]
        result.notes.append(f"Endpoint scope: {len(endpoint_artifacts)} artifacts")
        if endpoint_artifacts:
            result.findings.append({
                "title": "Endpoint persistence or execution detected",
                "description": "Velociraptor/process artifacts indicate endpoint activity",
                "severity": "critical",
                "technique_ids": ["T1547.001", "T1059.001"],
            })
            force_mock = os.environ.get(ENV_VR_USE_MOCK) == "1"
            service = create_vr_service(force_mock=force_mock)
            technique_ids = []
            for a in endpoint_artifacts:
                technique_ids.extend(a.technique_ids)
            technique_ids = list(dict.fromkeys(technique_ids))
            hunt_ids = suggest_hunt_ids(technique_ids, limit=3)
            client_id = "C.mbr01"
            for hunt_id in hunt_ids:
                run_result = service.run_hunt(hunt_id, client_id)
                result.notes.append(
                    f"vr_run_hunt: {hunt_id} on {client_id} -> {run_result.row_count} rows"
                )
        return result
