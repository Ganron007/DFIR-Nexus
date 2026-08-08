"""Velociraptor service — catalog, hunt orchestration, client selection."""

from __future__ import annotations

import logging
import os
from typing import Any

from nexus.integration.vql_runner import (
    MockVelociraptorClient,
    MonitorConfig,
    VQLQuerySpec,
    VQLResult,
    VQLRunner,
    create_velociraptor_client,
)
from nexus.utils.constants import ENV_VR_MCP_URL, ENV_VR_USE_MOCK
from nexus.vr import catalog
from nexus.vr.constants import (
    VR_HOST,
    default_api_key,
    default_mcp_api_key,
    default_mcp_url,
    default_verify_ssl,
    default_vr_endpoint,
    vr_mock_enabled,
)
from nexus.vr.remote_mcp import RemoteVRMCPClient
from nexus.vr.schemas import VRClientInfo, VRHuntRunResult

log = logging.getLogger(__name__)


class EnhancedMockVelociraptorClient(MockVelociraptorClient):
    """Mock client with hunt/artifact-aware synthetic rows."""

    def query(self, spec: VQLQuerySpec) -> VQLResult:
        result = super().query(spec)
        client_id = str(spec.params.get("client_id", "C.mbr01"))
        artifact = spec.artifact_name or spec.name
        rows = [
            {
                **row,
                "client_id": client_id,
                "artifact": artifact,
                "Hostname": client_id.replace("C.", ""),
            }
            for row in result.rows
        ]
        if artifact and "Credential" in artifact:
            rows.append(
                {
                    "client_id": client_id,
                    "artifact": artifact,
                    "Process": "lsass.exe",
                    "EventID": 4661,
                }
            )
        result.rows = rows
        return result


def create_vr_client(config: MonitorConfig, *, force_mock: bool | None = None) -> Any:
    use_mock = force_mock if force_mock is not None else vr_mock_enabled()
    if use_mock:
        return EnhancedMockVelociraptorClient(config)

    mcp_url = os.environ.get(ENV_VR_MCP_URL, default_mcp_url())
    mcp_key = default_mcp_api_key()
    if mcp_url and mcp_key:
        return RemoteVRMCPClient(
            mcp_url,
            mcp_key,
            timeout_seconds=config.timeout_seconds,
            verify_ssl=default_verify_ssl(mcp_url),
        )

    override = os.environ.get(ENV_VR_USE_MOCK, "").strip().lower()
    if override in ("0", "false", "no"):
        return create_velociraptor_client(config)

    if config.api_key:
        return create_velociraptor_client(config)

    endpoint = (config.endpoint or "").lower()
    if VR_HOST in endpoint and not config.api_key:
        log.info("Local VR endpoint without API key — using enhanced mock client")
        return EnhancedMockVelociraptorClient(config)
    return create_velociraptor_client(config)


class VRService:
    """Full Velociraptor framework for DFIR-Nexus (D.0.2)."""

    def __init__(self, *, force_mock: bool | None = None) -> None:
        self._force_mock = force_mock
        endpoint = default_vr_endpoint()
        self._config = MonitorConfig(
            endpoint=endpoint,
            api_key=default_api_key(),
            verify_ssl=default_verify_ssl(endpoint),
        )
        self._client = create_vr_client(self._config, force_mock=force_mock)
        self._runner = VQLRunner(config=self._config, queries=[], client=self._client)

    @property
    def use_mock(self) -> bool:
        if self._force_mock is not None:
            return self._force_mock
        return isinstance(self._client, (MockVelociraptorClient, EnhancedMockVelociraptorClient))

    def health(self) -> dict[str, Any]:
        mcp_url = os.environ.get(ENV_VR_MCP_URL, default_mcp_url())
        detail: dict[str, Any] = {
            "endpoint": self._config.endpoint,
            "VR_HOST": VR_HOST,
            "mcp_url": mcp_url,
            "api_key_set": bool(self._config.api_key),
            "mcp_api_key_set": bool(default_mcp_api_key()),
            "verify_ssl": self._config.verify_ssl,
            "mock_mode": self.use_mock,
            "client_type": type(self._client).__name__,
        }
        if isinstance(self._client, RemoteVRMCPClient):
            detail["mcp_health"] = self._client.health()
        return detail

    def list_clients(self) -> list[VRClientInfo]:
        return [
            VRClientInfo(
                client_id=str(row["client_id"]),
                hostname=str(row["hostname"]),
                platform=str(row["platform"]),
                ip=str(row.get("ip", "")),
                online=bool(row.get("online", True)),
            )
            for row in catalog.VR_MOCK_CLIENTS
        ]

    def list_hunts(self, *, technique_id: str | None = None) -> list[dict[str, Any]]:
        return [h.to_dict() for h in catalog.list_hunts(technique_id=technique_id)]

    def list_artifacts(self) -> list[dict[str, Any]]:
        return [a.to_dict() for a in catalog.list_custom_artifacts()]

    def get_hunt(self, hunt_id: str) -> dict[str, Any] | None:
        entry = catalog.get_hunt(hunt_id)
        return entry.to_dict() if entry else None

    def run_hunt(
        self,
        hunt_id: str,
        client_id: str,
        *,
        parameters: dict[str, Any] | None = None,
    ) -> VRHuntRunResult:
        entry = catalog.get_hunt(hunt_id)
        if entry is None:
            return VRHuntRunResult(
                hunt_id=hunt_id,
                artifact_name="",
                client_id=client_id,
                row_count=0,
                error=f"Unknown hunt: {hunt_id}. See vr_list_hunts.",
            )
        return self.collect_artifact(
            entry.artifact_name,
            client_id=client_id,
            hunt_id=hunt_id,
            parameters=parameters,
        )

    def collect_artifact(
        self,
        artifact_name: str,
        *,
        client_id: str = "C.mbr01",
        hunt_id: str = "",
        parameters: dict[str, Any] | None = None,
    ) -> VRHuntRunResult:
        str_params = {k: str(v) for k, v in (parameters or {}).items()}
        vql = catalog.artifact_vql(artifact_name, str_params)
        spec = VQLQuerySpec(
            name=hunt_id or artifact_name,
            vql=vql,
            artifact_name=artifact_name,
            params={"client_id": client_id, **(parameters or {})},
        )
        result = self._client.query(spec)
        return VRHuntRunResult(
            hunt_id=hunt_id or artifact_name,
            artifact_name=artifact_name,
            client_id=client_id,
            row_count=len(result.rows),
            rows=result.rows,
            duration_ms=result.duration_ms,
            error=result.error,
            vql=vql,
        )

    def vql_query(self, vql: str, *, client_id: str | None = None, timeout_seconds: int = 60) -> dict[str, Any]:
        from nexus.vr import catalog as cat
        from nexus.vr.vql_policy import VQLPolicyError, validate_adhoc_vql

        allowed = set(cat._ALL_BY_ARTIFACT.keys())
        try:
            vql = validate_adhoc_vql(vql, live_mode=not self.use_mock, allowed_artifacts=allowed)
        except VQLPolicyError as exc:
            return {
                "rows": [],
                "row_count": 0,
                "error": str(exc),
                "vql": vql,
                "mock_mode": self.use_mock,
            }
        spec = VQLQuerySpec(
            name="ad-hoc",
            vql=vql,
            timeout_seconds=timeout_seconds,
            params={"client_id": client_id} if client_id else {},
        )
        result = self._client.query(spec)
        return {
            "result": result.to_dict(),
            "rows": result.rows,
        }

    def suggest_hunts(self, technique_ids: list[str], *, limit: int = 3) -> list[str]:
        return catalog.suggest_hunt_ids(technique_ids, limit=limit)


def create_vr_service(*, force_mock: bool | None = None) -> VRService:
    return VRService(force_mock=force_mock)
