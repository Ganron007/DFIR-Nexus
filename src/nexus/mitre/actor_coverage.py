"""Actor-specific detection coverage analysis.

Given a list of observed technique IDs from an investigation, computes
per-actor coverage percentages and identifies gap techniques for each
threat actor group defined in ``adversary.py``.

Pure function — no network, no external deps beyond the local actor catalog.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from nexus.mitre.adversary import _GROUP_TECHNIQUES


def _technique_matches(observed: str, catalog: str) -> bool:
    """Check if two technique IDs match, including parent/child overlap.

    T1003 matches T1003.001 (parent matches child) and vice-versa.
    """
    o = observed.upper()
    c = catalog.upper()
    if o == c:
        return True
    return o.startswith(f"{c}.") or c.startswith(f"{o}.")


@dataclass
class ActorCoverage:
    """Coverage data for a single threat actor group."""
    actor_id: str
    actor_name: str
    total_techniques: int
    covered_techniques: int
    coverage_percent: float
    covered: list[str] = field(default_factory=list)
    gaps: list[str] = field(default_factory=list)
    overlap_techniques: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "actor_id": self.actor_id,
            "actor_name": self.actor_name,
            "total_techniques": self.total_techniques,
            "covered_techniques": self.covered_techniques,
            "coverage_percent": round(self.coverage_percent, 1),
            "covered": sorted(self.covered),
            "gaps": sorted(self.gaps),
            "overlap_techniques": sorted(self.overlap_techniques),
        }


@dataclass
class ActorCoverageReport:
    """Full per-actor coverage analysis report."""
    observed_count: int
    actors: list[ActorCoverage] = field(default_factory=list)
    best_match_actor: str | None = None
    best_match_percent: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "observed_count": self.observed_count,
            "best_match_actor": self.best_match_actor,
            "best_match_percent": round(self.best_match_percent, 1),
            "actors": [a.to_dict() for a in self.actors],
        }


def compute_actor_coverage(
    observed_technique_ids: list[str],
) -> ActorCoverageReport:
    """Compute per-actor coverage for a set of observed technique IDs.

    Uses the 8 threat actor groups from ``adversary._GROUP_TECHNIQUES``
    as the STIX data source.  Each actor's technique list is compared
    against the observed techniques using parent/child-aware matching.

    Args:
        observed_technique_ids: Technique IDs seen in the investigation
            (e.g. ``["T1003.001", "T1059.001", "T1486"]``).

    Returns:
        An ``ActorCoverageReport`` with per-actor coverage %, gap
        techniques, and the best-matching actor.
    """
    observed = {t.strip().upper() for t in observed_technique_ids if t.strip()}
    report = ActorCoverageReport(observed_count=len(observed))

    for group_id, group_data in _GROUP_TECHNIQUES.items():
        actor_techniques: list[str] = group_data["techniques"]
        actor_upper = [t.upper() for t in actor_techniques]

        covered: list[str] = []
        overlap: list[str] = []
        for obs in observed:
            for at in actor_upper:
                if _technique_matches(obs, at):
                    covered.append(at)
                    overlap.append(obs)
                    break

        covered_set = set(covered)
        gap_set = set(actor_upper) - covered_set

        total = len(actor_upper)
        coverage_pct = (len(covered_set) / total * 100) if total > 0 else 0.0

        ac = ActorCoverage(
            actor_id=group_id,
            actor_name=group_data["name"],
            total_techniques=total,
            covered_techniques=len(covered_set),
            coverage_percent=coverage_pct,
            covered=list(covered_set),
            gaps=list(gap_set),
            overlap_techniques=list(set(overlap)),
        )
        report.actors.append(ac)

    report.actors.sort(key=lambda a: (-a.coverage_percent, a.actor_id))

    if report.actors:
        best = report.actors[0]
        report.best_match_actor = best.actor_id
        report.best_match_percent = best.coverage_percent

    return report


def generate_actor_coverage_summary(report: ActorCoverageReport) -> str:
    """Generate a human-readable actor coverage summary."""
    lines = [
        "=== Actor Coverage Analysis ===",
        f"Observed techniques: {report.observed_count}",
        "",
    ]

    for ac in report.actors:
        bar_len = int(ac.coverage_percent / 5)
        bar = "#" * bar_len + "-" * (20 - bar_len)
        lines.append(
            f"  [{bar}] {ac.actor_name:30s} {ac.coverage_percent:5.1f}% "
            f"({ac.covered_techniques}/{ac.total_techniques})"
        )
        if ac.gaps:
            # Show first 5 gaps
            gap_preview = ", ".join(sorted(ac.gaps)[:5])
            suffix = " ..." if len(ac.gaps) > 5 else ""
            lines.append(f"           gaps: {gap_preview}{suffix}")

    if report.best_match_actor:
        lines.append("")
        lines.append(
            f"Best match: {report.best_match_actor} "
            f"({report.best_match_percent:.1f}%)"
        )

    return "\n".join(lines)
