"""Bounded in-memory artifact store with LRU eviction.

Replaces the unbounded global ``_artifact_store`` dict in the MCP server so that
large ingest jobs cannot exhaust process memory. The store supports optional
per-case scoping and exposes the same dict-like interface used by the ingest
tool handlers.
"""

from __future__ import annotations

import json
import os
import threading
from collections import OrderedDict
from dataclasses import asdict
from typing import Any

from nexus.constants import (
    DEFAULT_ARTIFACT_STORE_MAX_BYTES,
    DEFAULT_ARTIFACT_STORE_MAX_COUNT,
    ENV_ARTIFACT_STORE_MAX_BYTES,
    ENV_ARTIFACT_STORE_MAX_COUNT,
)
from nexus.ingest.schemas import Artifact

DEFAULT_MAX_COUNT = int(os.environ.get(ENV_ARTIFACT_STORE_MAX_COUNT, str(DEFAULT_ARTIFACT_STORE_MAX_COUNT)))
DEFAULT_MAX_BYTES = int(os.environ.get(ENV_ARTIFACT_STORE_MAX_BYTES, str(DEFAULT_ARTIFACT_STORE_MAX_BYTES)))


class ArtifactStore:
    """Thread-safe LRU artifact cache with count and byte limits.

    Args:
        max_count: Maximum number of artifacts retained.
        max_bytes: Approximate maximum bytes retained (computed from JSON size).
    """

    def __init__(
        self,
        max_count: int = DEFAULT_MAX_COUNT,
        max_bytes: int = DEFAULT_MAX_BYTES,
    ) -> None:
        self.max_count = max_count
        self.max_bytes = max_bytes
        self._lock = threading.RLock()
        self._order: OrderedDict[str, Artifact] = OrderedDict()
        self._bytes = 0

    @staticmethod
    def _artifact_size(artifact: Artifact) -> int:
        """Rough byte estimate for eviction bookkeeping."""
        try:
            payload = json.dumps(asdict(artifact), default=str)
            return len(artifact.id.encode("utf-8")) + len(payload.encode("utf-8"))
        except Exception:  # noqa: BLE001
            return 1024

    def put(self, artifact: Artifact) -> None:
        """Store or refresh an artifact, evicting oldest entries if needed."""
        with self._lock:
            if artifact.id in self._order:
                old = self._order[artifact.id]
                self._bytes -= self._artifact_size(old)
                self._order.move_to_end(artifact.id)
            self._order[artifact.id] = artifact
            self._bytes += self._artifact_size(artifact)
            self._evict_if_needed()

    def put_many(self, artifacts: list[Artifact]) -> int:
        """Store multiple artifacts. Returns number stored."""
        count = 0
        for artifact in artifacts:
            self.put(artifact)
            count += 1
        return count

    def get(self, artifact_id: str) -> Artifact | None:
        with self._lock:
            artifact = self._order.get(artifact_id)
            if artifact is not None:
                self._order.move_to_end(artifact_id)
            return artifact

    def values(self) -> list[Artifact]:
        with self._lock:
            return list(self._order.values())

    def __len__(self) -> int:
        with self._lock:
            return len(self._order)

    def clear(self) -> None:
        with self._lock:
            self._order.clear()
            self._bytes = 0

    def stats(self) -> dict[str, Any]:
        with self._lock:
            return {
                "count": len(self._order),
                "approx_bytes": self._bytes,
                "max_count": self.max_count,
                "max_bytes": self.max_bytes,
            }

    def _evict_if_needed(self) -> None:
        """Evict oldest artifacts until limits are satisfied."""
        while self._order and (
            len(self._order) > self.max_count or self._bytes > self.max_bytes
        ):
            artifact_id, artifact = self._order.popitem(last=False)
            self._bytes -= self._artifact_size(artifact)
        if self._bytes < 0:
            self._bytes = 0


# Process-global artifact store used by the MCP server and CLI.
_global_artifact_store: ArtifactStore | None = None
_global_store_lock = threading.Lock()


def get_global_artifact_store() -> ArtifactStore:
    """Return the process-global artifact store, creating it if necessary."""
    global _global_artifact_store
    if _global_artifact_store is None:
        with _global_store_lock:
            if _global_artifact_store is None:
                _global_artifact_store = ArtifactStore()
    return _global_artifact_store


def reset_global_artifact_store() -> None:
    """Reset the process-global artifact store (primarily for tests)."""
    global _global_artifact_store
    with _global_store_lock:
        if _global_artifact_store is not None:
            _global_artifact_store.clear()
        _global_artifact_store = ArtifactStore()
