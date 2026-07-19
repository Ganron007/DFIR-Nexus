"""Correlation engine.

Finds relationships between artifacts by shared attributes:
- Same source/dest IP
- Same user
- Same host
- Same process name
- Same file hash
- Same MITRE technique
- Time proximity (within a configurable window)
"""

from __future__ import annotations

import logging
from collections import defaultdict
from collections.abc import Callable
from datetime import timedelta

from nexus.analysis.schemas import (
    AnalysisResult,
    Correlation,
    CorrelationType,
)
from nexus.ingest.schemas import Artifact

log = logging.getLogger(__name__)


class CorrelationEngine:
    """Finds relationships between a set of artifacts.

    Usage:
        engine = CorrelationEngine(time_window_seconds=300)
        correlations = engine.correlate(artifacts)
    """

    def __init__(self, time_window_seconds: int = 300) -> None:
        """Args:
        time_window_seconds: Artifacts within this window are candidates
            for time-proximity correlation.
        """
        self.time_window = timedelta(seconds=time_window_seconds)

    def correlate(self, artifacts: list[Artifact]) -> list[Correlation]:
        """Run all correlation rules against the artifacts."""
        correlations: list[Correlation] = []
        correlations.extend(self._correlate_by_ip(artifacts))
        correlations.extend(self._correlate_by_user(artifacts))
        correlations.extend(self._correlate_by_host(artifacts))
        correlations.extend(self._correlate_by_process(artifacts))
        correlations.extend(self._correlate_by_hash(artifacts))
        correlations.extend(self._correlate_by_technique(artifacts))
        correlations.extend(self._correlate_by_time(artifacts))
        return correlations

    def _group_by(
        self, artifacts: list[Artifact], field_getter: Callable[[Artifact], str | None]
    ) -> dict[str, list[Artifact]]:
        """Group artifacts by a shared field value."""
        groups: dict[str, list[Artifact]] = defaultdict(list)
        for a in artifacts:
            value = field_getter(a)
            if value:
                groups[value].append(a)
        return groups

    def _make_correlation(
        self,
        ctype: CorrelationType,
        artifacts: list[Artifact],
        value: str,
        confidence: float = 1.0,
        description: str = "",
    ) -> Correlation:
        """Build a Correlation object."""
        return Correlation(
            type=ctype,
            artifact_ids=[a.id for a in artifacts],
            shared_value=value,
            confidence=confidence,
            description=description or f"Artifacts share {ctype.value}: {value}",
        )

    def _correlate_by_ip(self, artifacts: list[Artifact]) -> list[Correlation]:
        """Find artifacts that share source or dest IPs."""
        out: list[Correlation] = []
        for ip, group in self._group_by(artifacts, lambda a: a.source_ip).items():
            if len(group) >= 2:
                out.append(self._make_correlation(
                    CorrelationType.SHARES_IP, group, ip,
                    description=f"{len(group)} artifacts share source IP {ip}",
                ))
        for ip, group in self._group_by(artifacts, lambda a: a.dest_ip).items():
            if len(group) >= 2:
                out.append(self._make_correlation(
                    CorrelationType.SHARES_IP, group, ip,
                    description=f"{len(group)} artifacts share dest IP {ip}",
                ))
        return out

    def _correlate_by_user(self, artifacts: list[Artifact]) -> list[Correlation]:
        """Find artifacts that share a user."""
        out: list[Correlation] = []
        for user, group in self._group_by(artifacts, lambda a: a.user).items():
            if len(group) >= 2:
                out.append(self._make_correlation(
                    CorrelationType.SHARES_USER, group, user,
                    description=f"{len(group)} artifacts involve user {user}",
                ))
        return out

    def _correlate_by_host(self, artifacts: list[Artifact]) -> list[Correlation]:
        """Find artifacts that share a host."""
        out: list[Correlation] = []
        for host, group in self._group_by(artifacts, lambda a: a.host).items():
            if len(group) >= 2:
                out.append(self._make_correlation(
                    CorrelationType.SHARES_HOST, group, host,
                    description=f"{len(group)} artifacts from host {host}",
                ))
        return out

    def _correlate_by_process(self, artifacts: list[Artifact]) -> list[Correlation]:
        """Find artifacts that share a process name."""
        out: list[Correlation] = []
        for proc, group in self._group_by(artifacts, lambda a: a.process_name).items():
            if len(group) >= 2:
                out.append(self._make_correlation(
                    CorrelationType.SHARES_PROCESS, group, proc,
                    description=f"{len(group)} artifacts reference process {proc}",
                ))
        return out

    def _correlate_by_hash(self, artifacts: list[Artifact]) -> list[Correlation]:
        """Find artifacts that share any file hash."""
        out: list[Correlation] = []
        for htype in ("file_hash_md5", "file_hash_sha1", "file_hash_sha256"):
            for h, group in self._group_by(artifacts, lambda a, ht=htype: getattr(a, ht)).items():  # type: ignore[misc]
                if len(group) >= 2:
                    out.append(self._make_correlation(
                        CorrelationType.SHARES_HASH, group, h,
                        description=f"{len(group)} artifacts share {htype}={h}",
                    ))
        return out

    def _correlate_by_technique(self, artifacts: list[Artifact]) -> list[Correlation]:
        """Find artifacts that share a MITRE technique."""
        out: list[Correlation] = []
        # Flatten: build {technique: [artifacts]}
        tech_to_artifacts: dict[str, list[Artifact]] = defaultdict(list)
        for a in artifacts:
            for tid in a.technique_ids:
                tech_to_artifacts[tid].append(a)
        for tid, group in tech_to_artifacts.items():
            unique = list({a.id: a for a in group}.values())  # dedupe
            if len(unique) >= 2:
                out.append(self._make_correlation(
                    CorrelationType.SHARES_TECHNIQUE, unique, tid,
                    description=f"{len(unique)} artifacts share technique {tid}",
                ))
        return out

    def _correlate_by_time(self, artifacts: list[Artifact]) -> list[Correlation]:
        """Find artifacts that are within the time window of each other.

        Pairs every pair, but only emits a correlation if at least 3
        artifacts fall in the same window.
        """
        out: list[Correlation] = []
        if not artifacts:
            return out
        # Sort by timestamp
        sorted_a = sorted(artifacts, key=lambda a: a.timestamp)
        n = len(sorted_a)
        # Sliding window: for each i, find the largest j where ts[j] - ts[i] <= window
        for i in range(n):
            window_artifacts = [sorted_a[i]]
            for j in range(i + 1, n):
                if sorted_a[j].timestamp - sorted_a[i].timestamp <= self.time_window:
                    window_artifacts.append(sorted_a[j])
                else:
                    break
            if len(window_artifacts) >= 3:
                # Use the start time as the shared value
                shared = window_artifacts[0].timestamp.isoformat()
                out.append(self._make_correlation(
                    CorrelationType.TIME_PROXIMITY,
                    window_artifacts,
                    shared,
                    confidence=min(1.0, len(window_artifacts) / 10.0),
                    description=f"{len(window_artifacts)} artifacts within {self.time_window.seconds}s of {shared}",
                ))
        return out

    def analyze(self, artifacts: list[Artifact]) -> AnalysisResult:
        """Run correlation and return a partial AnalysisResult."""
        return AnalysisResult(
            artifact_count=len(artifacts),
            correlations=self.correlate(artifacts),
        )
