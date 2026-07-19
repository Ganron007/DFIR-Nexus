"""DFIR-Nexus Ingest Layer.

Imports forensic artifacts from various sources and normalizes them to a
common Artifact schema for downstream analysis and correlation.
"""

from nexus.ingest.base import Importer, ImporterError, ImportResult
from nexus.ingest.registry import ImporterRegistry, get_registry
from nexus.ingest.schemas import (
    AlertSeverity,
    Artifact,
    ArtifactSource,
    ArtifactType,
    AuthAction,
    FileSystemAction,
    NetworkProtocol,
    ProcessAction,
    Severity,
    TimelineEntry,
)

__all__ = [
    "Artifact",
    "ArtifactType",
    "ArtifactSource",
    "Severity",
    "NetworkProtocol",
    "FileSystemAction",
    "ProcessAction",
    "AuthAction",
    "AlertSeverity",
    "TimelineEntry",
    "Importer",
    "ImportResult",
    "ImporterError",
    "ImporterRegistry",
    "get_registry",
]
