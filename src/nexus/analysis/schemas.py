"""Schemas for the Analysis Layer."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any


class CorrelationType(StrEnum):
    """The kind of relationship between correlated artifacts."""

    SHARES_IP = "shares_ip"          # Same source or dest IP
    SHARES_USER = "shares_user"      # Same user
    SHARES_HOST = "shares_host"      # Same host
    SHARES_PROCESS = "shares_process"  # Same process name
    SHARES_HASH = "shares_hash"      # Same file hash
    SHARES_TECHNIQUE = "shares_technique"  # Same MITRE technique
    TIME_PROXIMITY = "time_proximity"  # Within same time window
    SEQUENCE = "sequence"            # A -> B -> C causal chain


@dataclass
class Correlation:
    """A relationship between two or more artifacts."""

    type: CorrelationType
    artifact_ids: list[str]
    shared_value: str  # e.g., the IP, user, technique
    confidence: float  # 0.0 - 1.0
    description: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type.value,
            "artifact_ids": self.artifact_ids,
            "shared_value": self.shared_value,
            "confidence": self.confidence,
            "description": self.description,
            "metadata": self.metadata,
        }


@dataclass
class HuntTarget:
    """A Velociraptor hunt target specification."""

    technique_id: str
    technique_name: str
    description: str
    suggested_artifacts: list[str]  # VR artifact names
    rationale: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "description": self.description,
            "suggested_artifacts": self.suggested_artifacts,
            "rationale": self.rationale,
        }


@dataclass
class HuntQuery:
    """A generated Velociraptor VQL hunt query."""

    name: str
    description: str
    technique_id: str | None
    vql: str  # The VQL query string
    parameters: dict[str, str] = field(default_factory=dict)
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "technique_id": self.technique_id,
            "vql": self.vql,
            "parameters": self.parameters,
            "notes": self.notes,
        }


@dataclass
class TimelineEntry:
    """A single entry in a narrative timeline."""

    timestamp: datetime
    artifact_id: str
    artifact_type: str
    source: str
    host: str | None
    user: str | None
    description: str
    severity: str
    technique_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "artifact_id": self.artifact_id,
            "artifact_type": self.artifact_type,
            "source": self.source,
            "host": self.host,
            "user": self.user,
            "description": self.description,
            "severity": self.severity,
            "technique_ids": self.technique_ids,
        }


@dataclass
class TimelineCluster:
    """A cluster of related timeline events within a time window."""

    start: datetime
    end: datetime
    label: str  # e.g., "Initial Access", "Credential Dumping"
    entries: list[TimelineEntry] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)
    hosts_involved: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "start": self.start.isoformat(),
            "end": self.end.isoformat(),
            "label": self.label,
            "entry_count": len(self.entries),
            "entries": [e.to_dict() for e in self.entries],
            "techniques": self.techniques,
            "hosts_involved": self.hosts_involved,
        }


@dataclass
class BeaconStats:
    """Statistics for a potential C2 beacon connection."""

    source_ip: str
    dest_ip: str
    dest_port: int
    connection_count: int
    interval_mean: float  # seconds
    interval_stdev: float
    interval_jitter_pct: float  # (stdev/mean) * 100
    bytes_up: int
    bytes_down: int
    duration_total: float
    first_seen: datetime
    last_seen: datetime
    is_likely_beacon: bool
    confidence: float
    rationale: str
    is_likely_exfil: bool = False  # NEW: large upload to same dest

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_ip": self.source_ip,
            "dest_ip": self.dest_ip,
            "dest_port": self.dest_port,
            "connection_count": self.connection_count,
            "interval_mean": round(self.interval_mean, 2),
            "interval_stdev": round(self.interval_stdev, 2),
            "interval_jitter_pct": round(self.interval_jitter_pct, 2),
            "bytes_up": self.bytes_up,
            "bytes_down": self.bytes_down,
            "duration_total": round(self.duration_total, 2),
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "is_likely_beacon": self.is_likely_beacon,
            "is_likely_exfil": self.is_likely_exfil,
            "confidence": round(self.confidence, 2),
            "rationale": self.rationale,
        }


@dataclass
class BeaconPattern:
    """A detected beacon pattern with associated artifacts."""

    stats: BeaconStats
    artifact_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.stats.to_dict(),
            "artifact_ids": self.artifact_ids,
        }


@dataclass
class ExecutiveSummary:
    """LLM-generated or rule-based executive summary."""

    case_id: str
    generated_at: datetime
    overview: str
    key_findings: list[str] = field(default_factory=list)
    timeline_phases: list[str] = field(default_factory=list)
    techniques_observed: list[str] = field(default_factory=list)
    hosts_affected: list[str] = field(default_factory=list)
    users_involved: list[str] = field(default_factory=list)
    iocs_extracted: list[str] = field(default_factory=list)
    recommended_actions: list[str] = field(default_factory=list)
    confidence: str = "medium"  # low, medium, high
    artifact_count: int = 0
    llm_generated: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "generated_at": self.generated_at.isoformat(),
            "overview": self.overview,
            "key_findings": self.key_findings,
            "timeline_phases": self.timeline_phases,
            "techniques_observed": self.techniques_observed,
            "hosts_affected": self.hosts_affected,
            "users_involved": self.users_involved,
            "iocs_extracted": self.iocs_extracted,
            "recommended_actions": self.recommended_actions,
            "confidence": self.confidence,
            "artifact_count": self.artifact_count,
            "llm_generated": self.llm_generated,
        }


@dataclass
class AnalysisResult:
    """A container for all analysis outputs from a set of artifacts."""

    artifact_count: int
    correlations: list[Correlation] = field(default_factory=list)
    timeline: list[TimelineCluster] = field(default_factory=list)
    beacons: list[BeaconPattern] = field(default_factory=list)
    hunt_queries: list[HuntQuery] = field(default_factory=list)
    summary: ExecutiveSummary | None = None
    technique_coverage: dict[str, dict[str, Any]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact_count": self.artifact_count,
            "correlations": [c.to_dict() for c in self.correlations],
            "timeline": [c.to_dict() for c in self.timeline],
            "beacons": [b.to_dict() for b in self.beacons],
            "hunt_queries": [h.to_dict() for h in self.hunt_queries],
            "summary": self.summary.to_dict() if self.summary else None,
            "technique_coverage": self.technique_coverage,
        }
