"""Risk-based alerting (RBA) scoring (D.0.3)."""

from __future__ import annotations

from typing import Any

from nexus.mitre.catalog import match_actors
from nexus.mitre.schemas import RBAScore

_TECHNIQUE_WEIGHTS: dict[str, int] = {
    "T1003": 25,
    "T1003.001": 30,
    "T1003.006": 35,
    "T1486": 40,
    "T1490": 35,
    "T1558": 20,
    "T1558.003": 25,
    "T1068": 25,
    "T1021": 15,
    "T1071": 10,
    "T1195": 20,
    "T1649": 25,
}

_SEVERITY_WEIGHTS = {
    "critical": 20,
    "high": 12,
    "medium": 6,
    "low": 2,
    "informational": 0,
    "unknown": 0,
}


def _tier(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 55:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


def _technique_weight(tid: str) -> int:
    tid = tid.upper()
    if tid in _TECHNIQUE_WEIGHTS:
        return _TECHNIQUE_WEIGHTS[tid]
    base = tid.split(".")[0]
    return _TECHNIQUE_WEIGHTS.get(base, 8)


class RBAScorer:
    """Compute investigation risk score from techniques, severities, TI, and actors."""

    def score(
        self,
        *,
        technique_ids: list[str] | None = None,
        severities: list[str] | None = None,
        malicious_ioc_count: int = 0,
        high_severity_artifact_count: int = 0,
        actor_ids: list[str] | None = None,
    ) -> RBAScore:
        techniques = sorted({t.strip().upper() for t in (technique_ids or []) if t.strip()})
        factors: list[dict[str, Any]] = []
        total = 0

        tech_points = sum(_technique_weight(t) for t in techniques)
        if tech_points:
            factors.append({"factor": "techniques", "points": tech_points, "count": len(techniques)})
            total += tech_points

        sev_points = 0
        for sev in severities or []:
            sev_points += _SEVERITY_WEIGHTS.get(sev.lower(), 0)
        if sev_points:
            factors.append({"factor": "artifact_severity", "points": sev_points})
            total += sev_points

        if high_severity_artifact_count > 0:
            pts = min(high_severity_artifact_count * 5, 25)
            factors.append({"factor": "high_severity_artifacts", "points": pts, "count": high_severity_artifact_count})
            total += pts

        if malicious_ioc_count > 0:
            pts = min(malicious_ioc_count * 8, 24)
            factors.append({"factor": "malicious_ioc_enrichment", "points": pts, "count": malicious_ioc_count})
            total += pts

        matched = match_actors(techniques, min_overlap=2)
        if actor_ids:
            allowed = set(actor_ids)
            matched = [m for m in matched if m["actor_id"] in allowed]
        if matched:
            top = matched[0]
            pts = min(int(top["overlap_count"] * 6), 20)
            factors.append(
                {
                    "factor": "actor_overlap",
                    "points": pts,
                    "actor_id": top["actor_id"],
                    "overlap": top["overlap_count"],
                }
            )
            total += pts

        total = min(total, 100)
        return RBAScore(
            score=total,
            tier=_tier(total),
            factors=factors,
            technique_ids=techniques,
            matched_actors=matched[:5],
        )

    def score_artifacts(self, artifacts: list[Any]) -> RBAScore:
        """Score from ingest Artifact objects."""
        techniques: list[str] = []
        severities: list[str] = []
        high = 0
        for a in artifacts:
            techniques.extend(getattr(a, "technique_ids", []) or [])
            sev = getattr(getattr(a, "severity", None), "value", None) or str(getattr(a, "severity", ""))
            severities.append(sev)
            if sev in ("critical", "high"):
                high += 1
        return self.score(
            technique_ids=techniques,
            severities=severities,
            high_severity_artifact_count=high,
        )


def create_rba_scorer() -> RBAScorer:
    return RBAScorer()
