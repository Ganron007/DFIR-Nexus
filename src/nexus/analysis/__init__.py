"""DFIR-Nexus Analysis Layer.

Cross-source correlation, technique->detection mapping, narrative timeline,
Velociraptor VQL hunt generation, beacon detection, and LLM-powered summaries.

This module integrates Phase 1 (Detection) + Phase 2 (Ingest) into a unified
analytical layer. Given a set of ingested artifacts, the analyzers can:
- Correlate artifacts by IP, user, host, technique, hash
- Find what detection rules cover the observed techniques
- Build a chronological narrative timeline
- Generate Velociraptor VQL hunts for further investigation
- Detect C2 beacons from network connection patterns
- Generate LLM-powered executive summaries
"""

from nexus.analysis.beacon import BeaconDetector
from nexus.analysis.correlation import CorrelationEngine
from nexus.analysis.coverage import DetectionBridge
from nexus.analysis.hunt import VQLHuntGenerator
from nexus.analysis.schemas import (
    AnalysisResult,
    BeaconPattern,
    BeaconStats,
    Correlation,
    CorrelationType,
    ExecutiveSummary,
    HuntQuery,
    HuntTarget,
    TimelineCluster,
    TimelineEntry,
)
from nexus.analysis.summary import SummaryGenerator
from nexus.analysis.timeline import TimelineBuilder

__all__ = [
    "Correlation",
    "CorrelationType",
    "HuntQuery",
    "HuntTarget",
    "TimelineCluster",
    "TimelineEntry",
    "BeaconPattern",
    "BeaconStats",
    "ExecutiveSummary",
    "AnalysisResult",
    "CorrelationEngine",
    "DetectionBridge",
    "TimelineBuilder",
    "VQLHuntGenerator",
    "BeaconDetector",
    "SummaryGenerator",
]
