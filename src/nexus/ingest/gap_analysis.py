"""Log gap analysis — detect suspicious silent periods in forensic timelines.

When logs go quiet during an active investigation, it often indicates
log tampering by an attacker (clearing Event Logs, stopping SIEM agents,
disabling auditing). This module detects suspicious gaps and generates
hypotheses about what the attacker did during the silence.

Two gap types:
- COMPLETE: all sources go dark → High severity
- PARTIAL: one tool stops reporting → Medium severity

Inspired by DFIR-Companion's gapDetect.ts + gapHypothesis.ts.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from nexus.ingest.schemas import Artifact

log = logging.getLogger(__name__)

MIN_GAP_SECONDS = 300
DENSITY_FACTOR = 3.0


@dataclass
class LogGap:
    """A detected gap in log coverage."""
    gap_type: str
    start_time: datetime
    end_time: datetime
    duration_seconds: float
    severity: str
    sources_affected: list[str]
    sources_still_active: list[str]
    host: str | None
    artifact_ids_before: list[str] = field(default_factory=list)
    artifact_ids_after: list[str] = field(default_factory=list)
    hypothesis: str = ""

    @property
    def duration_display(self) -> str:
        hours = int(self.duration_seconds // 3600)
        minutes = int((self.duration_seconds % 3600) // 60)
        if hours > 0:
            return f"{hours}h {minutes}m"
        return f"{minutes}m"

    def to_dict(self) -> dict[str, Any]:
        return {
            "gap_type": self.gap_type,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat(),
            "duration_seconds": round(self.duration_seconds, 0),
            "duration_display": self.duration_display,
            "severity": self.severity,
            "sources_affected": self.sources_affected,
            "sources_still_active": self.sources_still_active,
            "host": self.host,
            "hypothesis": self.hypothesis,
        }


@dataclass
class GapAnalysisResult:
    """Result of a gap analysis run."""
    gaps: list[LogGap] = field(default_factory=list)
    total_duration_seconds: float = 0.0
    timeline_start: datetime | None = None
    timeline_end: datetime | None = None
    event_count: int = 0

    @property
    def complete_gaps(self) -> list[LogGap]:
        return [g for g in self.gaps if g.gap_type == "COMPLETE"]

    @property
    def partial_gaps(self) -> list[LogGap]:
        return [g for g in self.gaps if g.gap_type == "PARTIAL"]

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_gaps": len(self.gaps),
            "complete_gaps": len(self.complete_gaps),
            "partial_gaps": len(self.partial_gaps),
            "event_count": self.event_count,
            "total_duration_seconds": round(self.total_duration_seconds, 0),
            "gaps": [g.to_dict() for g in self.gaps],
        }


def _compute_density(artifacts: list[Artifact]) -> float:
    """Compute the median inter-event interval for density-aware thresholding."""
    if len(artifacts) < 3:
        return MIN_GAP_SECONDS

    sorted_arts = sorted(artifacts, key=lambda a: a.timestamp)
    intervals = []
    for i in range(1, len(sorted_arts)):
        delta = (sorted_arts[i].timestamp - sorted_arts[i - 1].timestamp).total_seconds()
        if delta > 0:
            intervals.append(delta)

    if not intervals:
        return MIN_GAP_SECONDS

    intervals.sort()
    return intervals[len(intervals) // 2]


def _generate_hypothesis(gap: LogGap, context_before: list[Artifact], context_after: list[Artifact]) -> str:
    """Generate a hypothesis about attacker activity during the gap."""
    hypotheses = []

    if gap.gap_type == "COMPLETE":
        hypotheses.append(
            f"Complete log silence for {gap.duration_display}. "
            "Possible log tampering (wevtutil cl, Clear-EventLog, stopping SIEM agent). "
            "Attacker may have been active during this window."
        )
    elif gap.gap_type == "PARTIAL":
        sources = ", ".join(gap.sources_affected[:3])
        hypotheses.append(
            f"Selective log gap ({sources} silent for {gap.duration_display}). "
            "Attacker may have targeted specific log sources while others continued."
        )

    if context_before:
        last_before = context_before[-1]
        if last_before.process_name:
            hypotheses.append(
                f"Last activity before gap: {last_before.process_name} on {last_before.host or 'unknown host'}."
            )

    if context_after:
        first_after = context_after[0]
        if first_after.process_name:
            hypotheses.append(
                f"First activity after gap: {first_after.process_name} on {first_after.host or 'unknown host'}."
            )

    return " ".join(hypotheses)


def analyze_gaps(
    artifacts: list[Artifact],
    min_gap_seconds: float = MIN_GAP_SECONDS,
    density_factor: float = DENSITY_FACTOR,
) -> GapAnalysisResult:
    """Detect suspicious gaps in a forensic timeline.

    Pure function — deterministic, no AI, no network.
    """
    result = GapAnalysisResult()
    if len(artifacts) < 3:
        return result

    sorted_arts = sorted(artifacts, key=lambda a: a.timestamp)
    result.event_count = len(sorted_arts)
    result.timeline_start = sorted_arts[0].timestamp
    result.timeline_end = sorted_arts[-1].timestamp
    result.total_duration_seconds = (
        result.timeline_end - result.timeline_start
    ).total_seconds()

    median_interval = _compute_density(sorted_arts)
    gap_threshold = max(min_gap_seconds, median_interval * density_factor)

    all_sources = set(a.source.value for a in sorted_arts)

    for i in range(1, len(sorted_arts)):
        prev = sorted_arts[i - 1]
        curr = sorted_arts[i]
        delta = (curr.timestamp - prev.timestamp).total_seconds()

        if delta < gap_threshold:
            continue

        prev_sources = set(a.source.value for a in sorted_arts[:i] if
                           (curr.timestamp - a.timestamp).total_seconds() < gap_threshold)
        next_sources = set(a.source.value for a in sorted_arts[i:] if
                           (a.timestamp - prev.timestamp).total_seconds() < gap_threshold)

        silent_sources = all_sources - (prev_sources | next_sources)
        active_sources = all_sources - silent_sources

        if not silent_sources:
            continue

        gap_type = "COMPLETE" if len(silent_sources) >= len(all_sources) * 0.8 else "PARTIAL"
        severity = "high" if gap_type == "COMPLETE" else "medium"

        context_before = sorted_arts[max(0, i - 5):i]
        context_after = sorted_arts[i:min(len(sorted_arts), i + 5)]

        hosts = set(a.host for a in sorted_arts if a.host)
        host = hosts.pop() if len(hosts) == 1 else None

        gap = LogGap(
            gap_type=gap_type,
            start_time=prev.timestamp,
            end_time=curr.timestamp,
            duration_seconds=delta,
            severity=severity,
            sources_affected=sorted(silent_sources),
            sources_still_active=sorted(active_sources),
            host=host,
            artifact_ids_before=[a.id for a in context_before],
            artifact_ids_after=[a.id for a in context_after],
        )
        gap.hypothesis = _generate_hypothesis(gap, context_before, context_after)
        result.gaps.append(gap)

    result.gaps.sort(key=lambda g: -g.duration_seconds)
    return result
