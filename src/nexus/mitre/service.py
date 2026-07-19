"""MITRE D.0.3 service — Navigator, threat actors, RBA."""

from __future__ import annotations

from typing import Any

from nexus.detection.coverage import MITRECoverage
from nexus.detection.search import DetectionSearcher
from nexus.mitre import catalog
from nexus.mitre.navigator import (
    build_actor_layer,
    build_coverage_layer,
    build_gap_layer,
    build_observed_layer,
)
from nexus.mitre.rba import RBAScorer, create_rba_scorer
from nexus.mitre.schemas import RBAScore, ThreatActorProfile


class MITREService:
    """Unified MITRE Navigator + actors + RBA facade."""

    def __init__(
        self,
        searcher: DetectionSearcher | None = None,
        coverage: MITRECoverage | None = None,
        rba: RBAScorer | None = None,
    ) -> None:
        self._searcher = searcher
        self._coverage = coverage
        self._rba = rba or create_rba_scorer()

    def list_actors(self) -> list[ThreatActorProfile]:
        return catalog.list_actors()

    def get_actor(self, actor_id: str) -> ThreatActorProfile | None:
        return catalog.get_actor(actor_id)

    def match_actors(self, technique_ids: list[str], *, min_overlap: int = 1) -> list[dict[str, Any]]:
        return catalog.match_actors(technique_ids, min_overlap=min_overlap)

    def navigator_observed_layer(
        self,
        technique_ids: list[str],
        *,
        name: str = "DFIR-Nexus Observed",
        description: str = "Techniques observed in investigation",
    ) -> dict[str, Any]:
        return build_observed_layer(technique_ids, name=name, description=description)

    def navigator_coverage_layer(
        self,
        technique_ids: list[str],
        *,
        name: str = "DFIR-Nexus Detection Coverage",
        description: str = "Detection rule coverage heatmap",
    ) -> dict[str, Any]:
        scores: dict[str, int] = {}
        if self._coverage:
            for tid in technique_ids:
                cov = self._coverage.coverage_for_technique(tid, limit=500)
                scores[tid] = int(cov.get("total_rules", 0))
        else:
            for tid in technique_ids:
                scores[tid] = 0
        return build_coverage_layer(scores, name=name, description=description)

    def navigator_gap_layer(
        self,
        technique_ids: list[str],
        *,
        name: str = "DFIR-Nexus Gaps",
        description: str = "Weak detection coverage",
    ) -> dict[str, Any]:
        gaps: list[str] = []
        if self._coverage:
            for gap in self._coverage.gap_analysis(technique_ids):
                gaps.append(gap["technique_id"])
        else:
            gaps = list(technique_ids)
        return build_gap_layer(gaps, name=name, description=description)

    def navigator_actor_layer(self, actor_id: str) -> dict[str, Any] | None:
        actor = catalog.get_actor(actor_id)
        if actor is None:
            return None
        return build_actor_layer(actor.id, actor.name, actor.technique_ids, description=actor.description)

    def rba_score(self, **kwargs: Any) -> RBAScore:
        return self._rba.score(**kwargs)


def create_mitre_service(
    searcher: DetectionSearcher | None = None,
    coverage: MITRECoverage | None = None,
) -> MITREService:
    if coverage is None and searcher is not None:
        coverage = MITRECoverage(searcher)
    return MITREService(searcher=searcher, coverage=coverage)
