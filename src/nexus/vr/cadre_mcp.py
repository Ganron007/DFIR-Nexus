"""CADRE Velociraptor MCP HTTP bridge (192.168.77.51:8002)."""

from __future__ import annotations

import logging
import time
from datetime import UTC, datetime
from typing import Any

import httpx

from nexus.integration.vql_runner import VQLQuerySpec, VQLResult

log = logging.getLogger(__name__)


class CADREMCPClient:
    """HTTP client for the CADRE VR MCP endpoint (Plan 7 bridge)."""

    def __init__(
        self,
        base_url: str,
        api_key: str = "",
        *,
        timeout_seconds: int = 60,
        verify_ssl: bool = True,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        headers: dict[str, str] = {}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
            headers["X-API-Key"] = api_key
        self._client = httpx.Client(
            base_url=self.base_url,
            headers=headers,
            timeout=timeout_seconds,
            verify=verify_ssl,
        )

    def health(self) -> dict[str, Any]:
        try:
            resp = self._client.get("/health")
            if resp.status_code == 404:
                resp = self._client.get("/")
            resp.raise_for_status()
            body = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
            return {"ok": True, "endpoint": self.base_url, "detail": body}
        except httpx.HTTPError as exc:
            return {"ok": False, "endpoint": self.base_url, "error": str(exc)}

    def query(self, spec: VQLQuerySpec) -> VQLResult:
        start = time.time()
        payload = {
            "vql": spec.vql,
            "client_id": spec.params.get("client_id"),
            "parameters": spec.params,
            "timeout_seconds": spec.timeout_seconds,
        }
        try:
            resp = self._client.post("/vql", json=payload)
            if resp.status_code == 404:
                resp = self._client.post("/api/vql", json=payload)
            resp.raise_for_status()
            data = resp.json()
            rows = data.get("rows") or data.get("results") or []
            if isinstance(rows, dict):
                rows = [rows]
            duration_ms = int((time.time() - start) * 1000)
            return VQLResult(
                query_name=spec.name,
                rows=list(rows),
                timestamp=datetime.now(UTC),
                duration_ms=duration_ms,
                response_id=str(data.get("response_id", "")),
            )
        except httpx.HTTPError as exc:
            duration_ms = int((time.time() - start) * 1000)
            log.warning("CADRE MCP VQL failed: %s", exc)
            return VQLResult(
                query_name=spec.name,
                rows=[],
                timestamp=datetime.now(UTC),
                duration_ms=duration_ms,
                error=str(exc),
            )

    def close(self) -> None:
        self._client.close()
