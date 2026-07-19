"""Timeline builder.

Sorts artifacts chronologically, clusters them by time window and ATT&CK
tactic, and produces a narrative timeline of the incident.
"""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any

from nexus.analysis.schemas import (
    AnalysisResult,
    TimelineCluster,
    TimelineEntry,
)
from nexus.ingest.schemas import Artifact

log = logging.getLogger(__name__)


# Map of MITRE tactics (in ATT&CK order) to common labels
TACTIC_LABELS: dict[str, str] = {
    "reconnaissance": "Reconnaissance",
    "resource_development": "Resource Development",
    "initial_access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege_escalation": "Privilege Escalation",
    "defense_evasion": "Defense Evasion",
    "credential_access": "Credential Access",
    "discovery": "Discovery",
    "lateral_movement": "Lateral Movement",
    "collection": "Collection",
    "command_and_control": "Command and Control",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
}


class TimelineBuilder:
    """Builds a narrative timeline from artifacts.

    Usage:
        builder = TimelineBuilder(cluster_window_seconds=300)
        clusters = builder.build(artifacts)
    """

    def __init__(self, cluster_window_seconds: int = 300) -> None:
        """Args:
        cluster_window_seconds: Artifacts within this window are grouped
            into a single cluster.
        """
        self.cluster_window = timedelta(seconds=cluster_window_seconds)

    def build(self, artifacts: list[Artifact]) -> list[TimelineCluster]:
        """Build a narrative timeline of the artifacts."""
        if not artifacts:
            return []

        # Sort by timestamp
        sorted_a = sorted(artifacts, key=lambda a: a.timestamp)

        # Build entries
        entries = [
            TimelineEntry(
                timestamp=a.timestamp,
                artifact_id=a.id,
                artifact_type=a.artifact_type.value,
                source=a.source.value,
                host=a.host,
                user=a.user,
                description=a.description[:200],
                severity=a.severity.value,
                technique_ids=list(a.technique_ids),
            )
            for a in sorted_a
        ]

        # Cluster by time window
        clusters: list[TimelineCluster] = []
        current_cluster: TimelineCluster | None = None
        for entry in entries:
            if current_cluster is None or (entry.timestamp - current_cluster.end) > self.cluster_window:
                # New cluster
                if current_cluster is not None:
                    self._finalize_cluster(current_cluster)
                    clusters.append(current_cluster)
                current_cluster = TimelineCluster(
                    start=entry.timestamp,
                    end=entry.timestamp,
                    label="Activity",
                    entries=[entry],
                )
            else:
                current_cluster.end = entry.timestamp
                current_cluster.entries.append(entry)
        if current_cluster is not None:
            self._finalize_cluster(current_cluster)
            clusters.append(current_cluster)

        return clusters

    def _finalize_cluster(self, cluster: TimelineCluster) -> None:
        """Add derived fields to a cluster."""
        # Collect techniques
        techs: set[str] = set()
        hosts: set[str] = set()
        for e in cluster.entries:
            techs.update(e.technique_ids)
            if e.host:
                hosts.add(e.host)
        cluster.techniques = sorted(techs)
        cluster.hosts_involved = sorted(hosts)
        # Label by the most common technique
        cluster.label = self._label_cluster(cluster)

    def _label_cluster(self, cluster: TimelineCluster) -> str:
        """Pick a human-readable label for the cluster."""
        # Count tactic frequencies from technique IDs
        # (we don't have tactic IDs, so use technique prefix buckets)
        from collections import Counter
        # Use the most-frequent artifact type
        type_counts: Counter[str] = Counter(e.artifact_type for e in cluster.entries)
        most_common_type, count = type_counts.most_common(1)[0] if type_counts else ("Activity", 0)
        if cluster.entries and count > len(cluster.entries) / 2:
            return f"{most_common_type.replace('_', ' ').title()} activity"
        # If we have techniques, try to label by tactic
        if cluster.techniques:
            return f"Activity involving {', '.join(cluster.techniques[:3])}"
        return f"Activity cluster ({len(cluster.entries)} events)"

    def to_dict_list(self, clusters: list[TimelineCluster]) -> list[dict[str, Any]]:
        """Convert clusters to a list of dicts."""
        return [c.to_dict() for c in clusters]

    def analyze(self, artifacts: list[Artifact]) -> AnalysisResult:
        """Build timeline and return a partial AnalysisResult."""
        return AnalysisResult(
            artifact_count=len(artifacts),
            timeline=self.build(artifacts),
        )
