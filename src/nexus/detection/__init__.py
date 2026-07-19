"""Detection layer — Sigma, Splunk ESCU, Elastic KQL, Sublime, CrowdStrike CQL rules.

Phase 1 of DFIR-Nexus. Provides:
- Detection rule search (per technique, per product, per severity)
- Local index of detection rules from multiple sources
- MITRE technique → rules coverage
- Sigma → target format translation (future Phase 6)
"""

from nexus.detection.coverage import MITRECoverage
from nexus.detection.indexer import DetectionIndexer
from nexus.detection.schemas import (
    DetectionRule,
    DetectionSource,
    RuleFormat,
    RuleSeverity,
)
from nexus.detection.search import DetectionSearcher

__all__ = [
    "DetectionRule",
    "RuleFormat",
    "RuleSeverity",
    "DetectionSource",
    "DetectionSearcher",
    "DetectionIndexer",
    "MITRECoverage",
]
