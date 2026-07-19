"""Velociraptor monitoring — long-running VQL runner.

Periodically executes VQL queries against a Velociraptor server, parses
the results, and ingests them as Artifacts into DFIR-Nexus.

Usage:
    from nexus.integration import VQLRunner, VQLQuerySpec

    runner = VQLRunner(
        endpoint="https://velociraptor:8000/",
        api_key="...",
        queries=[
            VQLQuerySpec(name="processes", vql="SELECT * FROM pslist()"),
        ],
        interval_seconds=300,
    )
    runner.start()  # Runs in background thread

    # Or one-shot:
    results = runner.run_once()
"""

from __future__ import annotations

import logging
import os
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import httpx

from nexus.utils.constants import ENV_VR_USE_MOCK

log = logging.getLogger(__name__)


@dataclass
class VQLQuerySpec:
    """A VQL query to run periodically."""

    name: str
    vql: str
    description: str = ""
    artifact_name: str = ""
    timeout_seconds: int = 60
    params: dict[str, Any] = field(default_factory=dict)


@dataclass
class VQLResult:
    """Result of a single VQL query execution."""

    query_name: str
    rows: list[dict[str, Any]]
    timestamp: datetime
    duration_ms: int
    error: str | None = None
    response_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "query_name": self.query_name,
            "rows_count": len(self.rows),
            "timestamp": self.timestamp.isoformat(),
            "duration_ms": self.duration_ms,
            "error": self.error,
            "response_id": self.response_id,
        }


@dataclass
class MonitorConfig:
    """Configuration for the monitoring loop."""

    endpoint: str
    api_key: str = ""
    verify_ssl: bool = True
    poll_interval_seconds: int = 300
    max_retries: int = 3
    backoff_seconds: int = 30
    timeout_seconds: int = 60


class MockVelociraptorClient:
    """Mock client for testing — returns synthetic VQL results."""

    def __init__(self, config: MonitorConfig) -> None:
        self.config = config

    def query(self, spec: VQLQuerySpec) -> VQLResult:
        start = time.time()
        rows = [
            {
                "Name": "powershell.exe",
                "Pid": 1234,
                "CommandLine": "powershell.exe -enc ...",
                "Timestamp": datetime.now(UTC).isoformat(),
            },
            {
                "Name": "cmd.exe",
                "Pid": 5678,
                "CommandLine": "cmd.exe /c whoami",
                "Timestamp": datetime.now(UTC).isoformat(),
            },
        ]
        duration_ms = int((time.time() - start) * 1000) + 42
        return VQLResult(
            query_name=spec.name,
            rows=rows,
            timestamp=datetime.now(UTC),
            duration_ms=duration_ms,
            response_id=f"mock-{spec.name}-{int(time.time())}",
        )


class HTTPVelociraptorClient:
    """HTTP-based Velociraptor client (placeholder)."""

    def __init__(self, config: MonitorConfig) -> None:
        self.config = config
        self._client = httpx.Client(
            base_url=config.endpoint,
            headers={
                "Authorization": f"Bearer {config.api_key}" if config.api_key else "",
            },
            verify=config.verify_ssl,
            timeout=config.timeout_seconds,
        )

    def query(self, spec: VQLQuerySpec) -> VQLResult:
        start = time.time()
        try:
            response = self._client.post(
                "/api/v1/VQLQuery",
                json={"vql": spec.vql, "params": spec.params},
            )
            response.raise_for_status()
            data = response.json()
            rows = data.get("rows", [])
            duration_ms = int((time.time() - start) * 1000)
            return VQLResult(
                query_name=spec.name,
                rows=rows,
                timestamp=datetime.now(UTC),
                duration_ms=duration_ms,
                response_id=data.get("response_id", ""),
            )
        except httpx.HTTPError as e:
            duration_ms = int((time.time() - start) * 1000)
            log.error("VQL query '%s' failed: %s", spec.name, e)
            return VQLResult(
                query_name=spec.name,
                rows=[],
                timestamp=datetime.now(UTC),
                duration_ms=duration_ms,
                error=str(e),
            )

    def close(self) -> None:
        self._client.close()


def create_velociraptor_client(config: MonitorConfig) -> MockVelociraptorClient | HTTPVelociraptorClient:
    """Select Velociraptor client based on env and configuration."""
    override = os.environ.get(ENV_VR_USE_MOCK, "").strip().lower()
    if override in ("1", "true", "yes"):
        return MockVelociraptorClient(config)
    if override in ("0", "false", "no"):
        return HTTPVelociraptorClient(config)
    if config.api_key:
        return HTTPVelociraptorClient(config)
    endpoint = (config.endpoint or "").strip().lower()
    if not endpoint or "127.0.0.1" in endpoint or "localhost" in endpoint:
        return MockVelociraptorClient(config)
    if not config.api_key:
        log.warning(
            "Velociraptor endpoint %s has no API key; using HTTP client — "
            "set VELOCIRAPTOR_API_KEY or NEXUS_VR_USE_MOCK=1 for offline dev",
            config.endpoint,
        )
    return HTTPVelociraptorClient(config)


class VQLRunner:
    """Long-running VQL query runner."""

    def __init__(
        self,
        config: MonitorConfig,
        queries: list[VQLQuerySpec] | None = None,
        client: Any = None,
        result_handler: Callable[[VQLResult], None] | None = None,
    ) -> None:
        self.config = config
        self.queries = queries or []
        self.client = client or create_velociraptor_client(config)
        self.result_handler = result_handler
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._last_results: dict[str, VQLResult] = {}

    def add_query(self, spec: VQLQuerySpec) -> None:
        self.queries.append(spec)

    def run_once(self) -> dict[str, VQLResult]:
        """Run all queries once and return results keyed by name."""
        results: dict[str, VQLResult] = {}
        for spec in self.queries:
            log.info("Running VQL query: %s", spec.name)
            result = self.client.query(spec)
            results[spec.name] = result
            self._last_results[spec.name] = result
            if self.result_handler:
                try:
                    self.result_handler(result)
                except Exception:
                    log.error("Result handler for '%s' failed", spec.name)
        return results

    def start(self) -> None:
        """Start the monitoring loop in a background thread."""
        if self._thread and self._thread.is_alive():
            log.warning("Runner already running")
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True, name="VQLRunner")
        self._thread.start()
        log.info("VQLRunner started: %d queries, interval=%ds", len(self.queries), self.config.poll_interval_seconds)

    def stop(self, timeout: float = 5.0) -> None:
        """Stop the monitoring loop."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=timeout)
            self._thread = None
        if isinstance(self.client, HTTPVelociraptorClient):
            self.client.close()
        log.info("VQLRunner stopped")

    def _loop(self) -> None:
        """Main monitoring loop."""
        while not self._stop_event.is_set():
            try:
                self.run_once()
            except Exception:
                log.exception("Monitor loop error")
            for _ in range(self.config.poll_interval_seconds):
                if self._stop_event.is_set():
                    return
                time.sleep(1)

    @property
    def last_results(self) -> dict[str, VQLResult]:
        return dict(self._last_results)

    def stats(self) -> dict[str, Any]:
        """Return runner statistics."""
        return {
            "running": self._thread is not None and self._thread.is_alive(),
            "query_count": len(self.queries),
            "last_run_per_query": {
                name: r.timestamp.isoformat()
                for name, r in self._last_results.items()
            },
            "errors": [
                r.to_dict() for r in self._last_results.values() if r.error
            ],
        }
