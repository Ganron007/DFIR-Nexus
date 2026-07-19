"""Beacon/C2 detection — statistical regularity in outbound connections.

Groups outbound connections by (source host, dest IP, dest port) and flags
tuples with regular inter-arrival intervals (low jitter = beacon candidate).

Uses median interval + Median Absolute Deviation (MAD) for robustness
against outliers. Framed as a hunting lead, not a verdict.

Pure/deterministic — no AI, no network.
Inspired by DFIR-Companion's beaconDetect.ts.
"""

from __future__ import annotations

import logging
import math
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from nexus.ingest.schemas import Artifact

log = logging.getLogger(__name__)

MIN_CONNECTIONS = 5
MAD_MULTIPLIER = 1.4826
JITTER_THRESHOLD = 0.15


@dataclass
class BeaconCandidate:
    """A potential beacon/C2 communication pattern."""
    source_host: str
    dest_ip: str
    dest_port: int
    connection_count: int
    median_interval_seconds: float
    mad_seconds: float
    jitter_ratio: float
    score: float
    artifact_ids: list[str] = field(default_factory=list)
    first_seen: str = ""
    last_seen: str = ""

    @property
    def is_beacon(self) -> bool:
        return self.jitter_ratio < JITTER_THRESHOLD and self.connection_count >= MIN_CONNECTIONS

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_host": self.source_host,
            "dest_ip": self.dest_ip,
            "dest_port": self.dest_port,
            "connection_count": self.connection_count,
            "median_interval_seconds": round(self.median_interval_seconds, 1),
            "mad_seconds": round(self.mad_seconds, 1),
            "jitter_ratio": round(self.jitter_ratio, 3),
            "score": round(self.score, 2),
            "is_beacon": self.is_beacon,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "artifact_ids": self.artifact_ids,
        }


def _median(values: list[float]) -> float:
    """Compute median of a list of floats."""
    if not values:
        return 0.0
    sorted_vals = sorted(values)
    n = len(sorted_vals)
    if n % 2 == 0:
        return (sorted_vals[n // 2 - 1] + sorted_vals[n // 2]) / 2.0
    return sorted_vals[n // 2]


def _mad(values: list[float], median_val: float) -> float:
    """Compute Median Absolute Deviation."""
    if not values:
        return 0.0
    deviations = [abs(v - median_val) for v in values]
    return _median(deviations) * MAD_MULTIPLIER


def detect_beacons(artifacts: list[Artifact], min_connections: int = MIN_CONNECTIONS) -> list[BeaconCandidate]:
    """Detect potential beacon/C2 patterns from network artifacts.

    Groups connections by (source_host, dest_ip, dest_port), computes
    inter-arrival intervals, and flags regular patterns.

    Pure function — deterministic, no side effects.
    """
    groups: dict[tuple[str, str, int], list[Artifact]] = defaultdict(list)

    for a in artifacts:
        if a.source_ip and a.dest_ip and a.timestamp:
            host = a.host or a.source_ip
            port = a.dest_port or 0
            key = (host, a.dest_ip, port)
            groups[key].append(a)

    candidates: list[BeaconCandidate] = []

    for (host, dest_ip, dest_port), arts in groups.items():
        if len(arts) < min_connections:
            continue

        sorted_arts = sorted(arts, key=lambda a: a.timestamp)
        intervals: list[float] = []
        for i in range(1, len(sorted_arts)):
            delta = (sorted_arts[i].timestamp - sorted_arts[i - 1].timestamp).total_seconds()
            if delta > 0:
                intervals.append(delta)

        if len(intervals) < min_connections - 1:
            continue

        med = _median(intervals)
        if med <= 0:
            continue

        mad_val = _mad(intervals, med)
        jitter = mad_val / med if med > 0 else 1.0

        score = (1.0 - jitter) * min(1.0, len(arts) / 20.0)

        candidate = BeaconCandidate(
            source_host=host,
            dest_ip=dest_ip,
            dest_port=dest_port,
            connection_count=len(arts),
            median_interval_seconds=med,
            mad_seconds=mad_val,
            jitter_ratio=jitter,
            score=score,
            artifact_ids=[a.id for a in sorted_arts],
            first_seen=sorted_arts[0].timestamp.isoformat(),
            last_seen=sorted_arts[-1].timestamp.isoformat(),
        )
        candidates.append(candidate)

    candidates.sort(key=lambda c: -c.score)
    return candidates
