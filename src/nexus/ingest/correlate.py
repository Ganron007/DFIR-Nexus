"""Cross-source correlation — union-find dedup and corroboration tracking.

When the same real-world artifact is observed by multiple tools (e.g., a file
hash seen by both Volatility and Velociraptor, or an IP seen in both Suricata
and Splunk), this module merges them into a single event with corroboration
tracking.

Match criteria (in priority order):
1. Exact SHA-256 hash match
2. Exact MD5 hash match
3. Same normalized file path within ±2 second time window
4. Same (timestamp, description) — exact duplicate

Inspired by DFIR-Companion's correlate.ts (union-find algorithm).
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import Any

from nexus.ingest.schemas import Artifact, ArtifactSource

log = logging.getLogger(__name__)

DEFAULT_TIME_WINDOW = timedelta(seconds=2)


class CorrelationResult:
    """Result of correlating a set of artifacts."""

    def __init__(self) -> None:
        self.merged: list[CorrelatedEvent] = []
        self.duplicates_removed: int = 0
        self.corroborated: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "merged_events": len(self.merged),
            "duplicates_removed": self.duplicates_removed,
            "corroborated_events": self.corroborated,
            "events": [e.to_dict() for e in self.merged],
        }


class CorrelatedEvent:
    """A merged event from one or more source artifacts."""

    def __init__(self, artifacts: list[Artifact]) -> None:
        self.artifacts = artifacts
        self.sources: list[str] = sorted(set(a.source.value for a in artifacts))
        self.corroboration_count = len(self.sources)
        self.primary = artifacts[0]

    @property
    def is_corroborated(self) -> bool:
        return self.corroboration_count >= 2

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.primary.id,
            "timestamp": self.primary.timestamp.isoformat(),
            "description": self.primary.description,
            "severity": self.primary.severity.value,
            "sources": self.sources,
            "corroboration_count": self.corroboration_count,
            "is_corroborated": self.is_corroborated,
            "artifact_count": len(self.artifacts),
        }


class UnionFind:
    """Union-Find (Disjoint Set Union) for grouping related artifacts."""

    def __init__(self) -> None:
        self._parent: dict[int, int] = {}
        self._rank: dict[int, int] = {}

    def make_set(self, x: int) -> None:
        if x not in self._parent:
            self._parent[x] = x
            self._rank[x] = 0

    def find(self, x: int) -> int:
        if self._parent[x] != x:
            self._parent[x] = self.find(self._parent[x])
        return self._parent[x]

    def union(self, x: int, y: int) -> None:
        rx, ry = self.find(x), self.find(y)
        if rx == ry:
            return
        if self._rank[rx] < self._rank[ry]:
            rx, ry = ry, rx
        self._parent[ry] = rx
        if self._rank[rx] == self._rank[ry]:
            self._rank[rx] += 1

    def groups(self) -> dict[int, list[int]]:
        groups: dict[int, list[int]] = {}
        for x in self._parent:
            root = self.find(x)
            groups.setdefault(root, []).append(x)
        return groups


def _normalize_path(path: str) -> str:
    """Normalize a file path for comparison."""
    return path.replace("\\", "/").lower().rstrip("/")


def _time_close(t1: datetime, t2: datetime, window: timedelta = DEFAULT_TIME_WINDOW) -> bool:
    """Check if two timestamps are within the time window."""
    if t1.tzinfo is None:
        t1 = t1.replace(tzinfo=UTC)
    if t2.tzinfo is None:
        t2 = t2.replace(tzinfo=UTC)
    return abs(t1 - t2) <= window


def correlate(
    artifacts: list[Artifact],
    time_window: timedelta = DEFAULT_TIME_WINDOW,
) -> CorrelationResult:
    """Correlate a list of artifacts, merging duplicates and tracking corroboration.

    This is idempotent — calling it twice on the same input produces the
    same output. Re-imports never double the timeline.
    """
    result = CorrelationResult()
    if not artifacts:
        return result

    uf = UnionFind()
    for i in range(len(artifacts)):
        uf.make_set(i)

    # Build indices for fast matching
    hash_index: dict[str, list[int]] = {}
    path_index: dict[str, list[int]] = {}

    for i, a in enumerate(artifacts):
        if a.file_hash_sha256:
            hash_index.setdefault(a.file_hash_sha256.lower(), []).append(i)
        if a.file_hash_md5:
            hash_index.setdefault(a.file_hash_md5.lower(), []).append(i)
        if a.file_path:
            norm = _normalize_path(a.file_path)
            path_index.setdefault(norm, []).append(i)

    # Match by hash (highest confidence)
    for indices in hash_index.values():
        if len(indices) > 1:
            for j in range(1, len(indices)):
                uf.union(indices[0], indices[j])

    # Match by normalized path + time window
    for indices in path_index.values():
        if len(indices) > 1:
            for i_idx in range(len(indices)):
                for j_idx in range(i_idx + 1, len(indices)):
                    a_i = artifacts[indices[i_idx]]
                    a_j = artifacts[indices[j_idx]]
                    if _time_close(a_i.timestamp, a_j.timestamp, time_window):
                        uf.union(indices[i_idx], indices[j_idx])

    # Match exact (timestamp, description) duplicates
    desc_index: dict[str, list[int]] = {}
    for i, a in enumerate(artifacts):
        key = f"{a.timestamp.isoformat()}|{a.description}"
        desc_index.setdefault(key, []).append(i)

    for indices in desc_index.values():
        if len(indices) > 1:
            result.duplicates_removed += len(indices) - 1
            for j in range(1, len(indices)):
                uf.union(indices[0], indices[j])

    # Build merged events
    for root, members in uf.groups().items():
        group_artifacts = [artifacts[i] for i in members]
        merged = CorrelatedEvent(group_artifacts)
        result.merged.append(merged)
        if merged.is_corroborated:
            result.corroborated += 1

    result.merged.sort(key=lambda e: e.primary.timestamp)
    return result
