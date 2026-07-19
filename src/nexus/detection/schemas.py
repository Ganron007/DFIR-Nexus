"""Detection rule schemas — unified across Sigma / Splunk / Elastic / Sublime / CQL."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class RuleFormat(StrEnum):
    """Detection rule format."""

    SIGMA = "sigma"
    SPLUNK_ESCU = "splunk"
    ELASTIC_KQL = "kql"
    SUBLIME = "sublime"
    CROWDSTRIKE_CQL = "cql"
    UNKNOWN = "unknown"


class RuleSeverity(StrEnum):
    """Detection rule severity (normalized)."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"
    UNKNOWN = "unknown"


class DetectionSource(StrEnum):
    """Source of the detection rule."""

    SIGMAHQ = "sigmahq"
    SPLUNK_ESCU = "splunk_escu"
    ELASTIC_DETECTION_RULES = "elastic_detection_rules"
    SUBLIME_SECURITY = "sublime_security"
    CROWDSTRIKE_FALCON = "crowdstrike_falcon"
    NEXUS_CUSTOM = "nexus_custom"
    UNKNOWN = "unknown"


@dataclass
class DetectionRule:
    """A normalized detection rule across all formats."""

    id: str
    title: str
    description: str = ""
    format: RuleFormat = RuleFormat.UNKNOWN
    source: DetectionSource = DetectionSource.UNKNOWN
    severity: RuleSeverity = RuleSeverity.UNKNOWN
    # MITRE ATT&CK technique IDs this rule maps to (e.g., "T1003.001")
    technique_ids: list[str] = field(default_factory=list)
    # Tactic IDs (e.g., "TA0006" for Credential Access)
    tactic_ids: list[str] = field(default_factory=list)
    # Tags / keywords
    tags: list[str] = field(default_factory=list)
    # File path / URL of the original rule
    source_path: str = ""
    # Raw rule content (Sigma YAML, Splunk SPL, KQL, etc.)
    raw_content: str = ""
    # Extra metadata
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dict for serialization."""
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "format": self.format.value,
            "source": self.source.value,
            "severity": self.severity.value,
            "technique_ids": self.technique_ids,
            "tactic_ids": self.tactic_ids,
            "tags": self.tags,
            "source_path": self.source_path,
            "metadata": self.metadata,
        }
