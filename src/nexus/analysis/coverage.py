"""Detection bridge.

Given a list of techniques (from ingested artifacts), look up which detection
rules cover them. Bridges Phase 1 (Detection) and Phase 2 (Ingest) layers.
"""

from __future__ import annotations

import logging
from typing import Any

from nexus.analysis.schemas import AnalysisResult
from nexus.detection import DetectionRule, DetectionSearcher
from nexus.ingest.schemas import Artifact

log = logging.getLogger(__name__)


class DetectionBridge:
    """Bridge between ingested artifacts and the detection rules index.

    Given artifacts, this module:
    1. Extracts the unique MITRE techniques from the artifacts
    2. Looks up detection rules for each technique
    3. Reports coverage gaps (techniques with no rules)
    """

    def __init__(self, searcher: DetectionSearcher) -> None:
        self.searcher = searcher

    def techniques_from_artifacts(self, artifacts: list[Artifact]) -> list[str]:
        """Return the unique MITRE techniques observed in the artifacts."""
        techs: set[str] = set()
        for a in artifacts:
            for t in a.technique_ids:
                techs.add(t.upper())
        return sorted(techs)

    def coverage_for_artifact(
        self, artifact: Artifact, limit: int = 50
    ) -> dict[str, list[DetectionRule]]:
        """Look up detection rules for all techniques in a single artifact."""
        out: dict[str, list[DetectionRule]] = {}
        for tid in artifact.technique_ids:
            rules = self.searcher.search(technique_id=tid.upper(), limit=limit)
            out[tid.upper()] = rules
        return out

    def coverage_for_techniques(
        self, technique_ids: list[str], limit: int = 50
    ) -> dict[str, dict[str, Any]]:
        """Look up detection rule coverage for a list of techniques.

        Returns a dict of technique_id -> {rule_count, by_format, by_severity, gap}.
        """
        out: dict[str, dict[str, Any]] = {}
        for tid in technique_ids:
            rules = self.searcher.search(technique_id=tid.upper(), limit=limit)
            by_format: dict[str, int] = {}
            by_severity: dict[str, int] = {}
            for r in rules:
                fmt = r.format.value
                sev = r.severity.value
                by_format[fmt] = by_format.get(fmt, 0) + 1
                by_severity[sev] = by_severity.get(sev, 0) + 1
            out[tid.upper()] = {
                "rule_count": len(rules),
                "by_format": by_format,
                "by_severity": by_severity,
                "gap": len(rules) == 0,
                "rules": [
                    {"id": r.id, "title": r.title, "format": r.format.value, "severity": r.severity.value}
                    for r in rules[:5]
                ],
            }
        return out

    def coverage_for_artifacts(
        self, artifacts: list[Artifact], limit: int = 50
    ) -> dict[str, dict[str, Any]]:
        """Look up coverage for all techniques observed in a set of artifacts."""
        techs = self.techniques_from_artifacts(artifacts)
        return self.coverage_for_techniques(techs, limit=limit)

    def coverage_gaps(
        self, artifacts: list[Artifact], limit: int = 50
    ) -> list[dict[str, Any]]:
        """Return a list of techniques that have no detection rules."""
        coverage = self.coverage_for_artifacts(artifacts, limit=limit)
        gaps = []
        for tid, info in coverage.items():
            if info["gap"]:
                # Find which artifacts used this technique
                using_artifacts = [a for a in artifacts if tid in [t.upper() for t in a.technique_ids]]
                gaps.append({
                    "technique_id": tid,
                    "artifact_count": len(using_artifacts),
                    "artifact_ids": [a.id for a in using_artifacts],
                })
        return gaps

    def suggest_sigma_for_artifact(
        self, artifact: Artifact, limit: int = 10
    ) -> list[DetectionRule]:
        """Return detection rules that could fire for this artifact.

        Useful for a forensic analyst reviewing an artifact: "Would this have
        been caught? What existing rules apply?"
        """
        rules: list[DetectionRule] = []
        # Direct technique match
        for tid in artifact.technique_ids:
            rules.extend(self.searcher.search(technique_id=tid.upper(), limit=limit))
        # If the artifact has process/file context, also search those
        if artifact.process_name and not rules:
            rules.extend(self.searcher.search(query=artifact.process_name, limit=limit))
        if artifact.file_path and not rules:
            rules.extend(self.searcher.search(query=artifact.file_path, limit=limit))
        # Dedupe by rule ID
        seen: set[str] = set()
        unique: list[DetectionRule] = []
        for r in rules:
            if r.id not in seen:
                seen.add(r.id)
                unique.append(r)
        return unique[:limit]

    def analyze(self, artifacts: list[Artifact]) -> AnalysisResult:
        """Compute technique coverage and return a partial AnalysisResult."""
        coverage = self.coverage_for_artifacts(artifacts)
        gaps = self.coverage_gaps(artifacts)
        # Annotate coverage with gap info
        for tid, info in coverage.items():
            for g in gaps:
                if g["technique_id"] == tid:
                    info["artifact_count"] = g["artifact_count"]
                    break
        return AnalysisResult(
            artifact_count=len(artifacts),
            technique_coverage=coverage,
        )
