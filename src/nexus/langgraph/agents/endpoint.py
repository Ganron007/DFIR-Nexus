"""Endpoint agent — Velociraptor VQL hunts + process artifacts."""

from __future__ import annotations

import logging
import os

from nexus.constants import ENV_VR_USE_MOCK
from nexus.langgraph.agents.base import BaseAgent
from nexus.langgraph.agents.evidence import finding, top_values
from nexus.langgraph.types import AgentName, AgentResult, AgentStatus, PipelineState
from nexus.vr import create_vr_service, suggest_hunt_ids

log = logging.getLogger(__name__)


class EndpointAgent(BaseAgent):
    """Runs Velociraptor VQL hunts and cites process evidence."""

    name = AgentName.ENDPOINT

    def run(self, state: PipelineState) -> AgentResult:
        log.info("EndpointAgent running for case %s", state.case_id)
        result = AgentResult(agent=self.name, status=AgentStatus.DONE)
        endpoint_artifacts = [
            a for a in state.artifacts
            if a.source.value in ("velociraptor", "volatility")
            or a.artifact_type.value == "process"
        ]
        result.notes.append(f"Endpoint scope: {len(endpoint_artifacts)} artifacts")
        if endpoint_artifacts:
            procs = top_values(endpoint_artifacts, "process_name", 8)
            hosts = top_values(endpoint_artifacts, "host", 3)
            proc_s = ", ".join(f"{p} ({n})" for p, n in procs) or "unknown processes"
            host_s = ", ".join(h for h, _ in hosts) or "unknown host"
            lead = (
                f"Endpoint/process evidence on {host_s}: observed processes "
                f"[{proc_s}]. Sources in scope support execution/persistence review."
            )
            result.findings.append(finding(
                f"Process activity on {host_s}: {procs[0][0] if procs else 'multiple'}",
                endpoint_artifacts,
                severity="critical",
                technique_ids_=["T1547.001", "T1059.001", "T1055"],
                lead=lead,
            ))
            force_mock = os.environ.get(ENV_VR_USE_MOCK) == "1"
            service = create_vr_service(force_mock=force_mock)
            technique_ids: list[str] = []
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
