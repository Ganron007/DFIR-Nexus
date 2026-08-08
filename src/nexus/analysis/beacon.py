"""Beacon / C2 detection.

Given a set of network artifacts (from Suricata, Zeek, Wireshark, or any
importer that yields NETWORK/HTTP/DNS artifacts), detect potential C2
beacons based on:
- Connection interval regularity (low jitter = beacon)
- Number of connections (more = higher confidence)
- Byte ratio patterns (small up / variable down = typical beacon)
- Time range (longer = more confident)

Algorithm:
1. Group artifacts by (source_ip, dest_ip, dest_port)
2. Sort by timestamp
3. Compute intervals between consecutive connections
4. If connection_count >= threshold AND interval_jitter_pct < jitter_threshold,
   flag as likely beacon
"""

from __future__ import annotations

import contextlib
import logging
from collections import defaultdict
from statistics import mean, stdev

from nexus.analysis.schemas import (
    AnalysisResult,
    BeaconPattern,
    BeaconStats,
)
from nexus.ingest.schemas import Artifact, ArtifactType

log = logging.getLogger(__name__)


class BeaconDetector:
    """Detect potential C2 beacon patterns from network artifacts.

    Usage:
        detector = BeaconDetector(min_connections=5, jitter_threshold_pct=20.0)
        beacons = detector.detect(artifacts)
    """

    def __init__(
        self,
        min_connections: int = 5,
        jitter_threshold_pct: float = 25.0,
        byte_ratio_threshold: float = 10.0,
    ) -> None:
        """Args:
        min_connections: Minimum connections to consider for beacon detection.
        jitter_threshold_pct: Max acceptable interval jitter (stdev/mean) * 100.
        byte_ratio_threshold: Max bytes_up / bytes_down ratio.
        """
        self.min_connections = min_connections
        self.jitter_threshold = jitter_threshold_pct
        self.byte_ratio_threshold = byte_ratio_threshold

    def detect(self, artifacts: list[Artifact]) -> list[BeaconPattern]:
        """Analyze network artifacts and return likely beacons."""
        # Filter to network artifacts with source_ip + dest_ip + dest_port
        network = [
            a for a in artifacts
            if a.source_ip and a.dest_ip and a.dest_port
            and a.artifact_type in (ArtifactType.NETWORK, ArtifactType.HTTP, ArtifactType.DNS, ArtifactType.TLS)
        ]
        if not network:
            return []

        # Group by (source_ip, dest_ip, dest_port)
        groups: dict[tuple[str, str, int], list[Artifact]] = defaultdict(list)
        for a in network:
            assert a.source_ip is not None
            assert a.dest_ip is not None
            assert a.dest_port is not None
            groups[(a.source_ip, a.dest_ip, a.dest_port)].append(a)

        # Analyze each group
        beacons: list[BeaconPattern] = []
        for (src, dst, port), group in groups.items():
            if len(group) < self.min_connections:
                continue
            stats = self._analyze_group(src, dst, port, group)
            # Include if either beacon OR exfil pattern detected
            if stats.is_likely_beacon or stats.is_likely_exfil:
                beacons.append(BeaconPattern(stats=stats, artifact_ids=[a.id for a in group]))

        # Sort by confidence descending
        beacons.sort(key=lambda b: b.stats.confidence, reverse=True)
        return beacons

    def _analyze_group(
        self, src: str, dst: str, port: int, group: list[Artifact]
    ) -> BeaconStats:
        """Compute beacon statistics for a single (src, dst, port) group."""
        sorted_group = sorted(group, key=lambda a: a.timestamp)
        timestamps = [a.timestamp for a in sorted_group]

        # Compute intervals
        intervals: list[float] = []
        for i in range(1, len(timestamps)):
            delta = (timestamps[i] - timestamps[i - 1]).total_seconds()
            if delta > 0:
                intervals.append(delta)

        # Statistics
        interval_mean = mean(intervals) if intervals else 0.0
        interval_stdev = stdev(intervals) if len(intervals) >= 2 else 0.0
        jitter_pct = (interval_stdev / interval_mean * 100) if interval_mean > 0 else 100.0

        # Byte counts (from raw if present, else from artifact fields)
        bytes_up = 0
        bytes_down = 0
        for a in sorted_group:
            raw = a.raw if isinstance(a.raw, dict) else {}
            for key in ("bytes_up", "src_bytes", "orig_bytes"):
                if key in raw:
                    with contextlib.suppress(ValueError, TypeError):
                        bytes_up += int(float(raw[key]))
                    break
            for key in ("bytes_down", "resp_bytes", "dst_bytes"):
                if key in raw:
                    with contextlib.suppress(ValueError, TypeError):
                        bytes_down += int(float(raw[key]))
                    break

        first_seen = timestamps[0]
        last_seen = timestamps[-1]
        duration = (last_seen - first_seen).total_seconds()

        # Heuristic: classify this connection group.
        # Two competing signals:
        # - Beacon: low jitter (regular interval) — typical C2 callback
        # - Exfil: large upload with small download — typical data theft
        # When both apply (regular large uploads), exfil wins.
        is_beacon = False
        is_exfil = False
        confidence = 0.0
        rationale = ""

        # 1. Check exfil pattern FIRST (upload > download by large factor)
        if bytes_up > 0 and bytes_down > 0:
            ratio = bytes_up / bytes_down if bytes_down > 0 else 999
            if ratio > 100:  # huge upload → exfil
                is_exfil = True
                confidence = 0.75
                rationale = (
                    f"Large upload ({bytes_up} bytes up, {bytes_down} bytes down, "
                    f"ratio {ratio:.0f}:1) — possible data exfil"
                )
        # Pure exfil (no download info, but massive upload)
        elif bytes_up > 50_000_000:
            is_exfil = True
            confidence = 0.85
            rationale = f"Very large upload ({bytes_up} bytes) — likely data exfil"
        # Large upload + small ratio hint
        elif bytes_up > 10_000_000 and bytes_down > 0:
            ratio = bytes_up / bytes_down if bytes_down > 0 else 999
            if ratio > 50:
                is_exfil = True
                confidence = 0.7
                rationale = (
                    f"Large upload ({bytes_up} bytes up, {bytes_down} bytes down) "
                    f"— possible data exfil"
                )

        # 2. THEN check beacon pattern (only if NOT exfil)
        if not is_exfil and jitter_pct < self.jitter_threshold and interval_mean > 0:
            is_beacon = True
            confidence = 1.0 - (jitter_pct / self.jitter_threshold)
            rationale = f"Low interval jitter ({jitter_pct:.1f}% < {self.jitter_threshold}%)"
            # Byte ratio as secondary (small up + small down = beacon)
            if bytes_up > 0 and bytes_down > 0:
                ratio = bytes_up / bytes_down if bytes_down > 0 else 999
                if ratio < self.byte_ratio_threshold:
                    confidence += 0.1
                    rationale += f"; small upload/download ratio ({ratio:.2f})"

        # 3. Connection count bonus
        if len(group) >= 100:
            confidence += 0.1
        elif len(group) >= 50:
            confidence += 0.05
        confidence = min(confidence, 1.0)

        return BeaconStats(
            source_ip=src,
            dest_ip=dst,
            dest_port=port,
            connection_count=len(group),
            interval_mean=interval_mean,
            interval_stdev=interval_stdev,
            interval_jitter_pct=jitter_pct,
            bytes_up=bytes_up,
            bytes_down=bytes_down,
            duration_total=duration,
            first_seen=first_seen,
            last_seen=last_seen,
            is_likely_beacon=is_beacon,
            confidence=confidence,
            rationale=rationale or "Insufficient evidence for beacon classification",
            is_likely_exfil=is_exfil,
        )

    def analyze(self, artifacts: list[Artifact]) -> AnalysisResult:
        """Run beacon detection and return a partial AnalysisResult."""
        return AnalysisResult(
            artifact_count=len(artifacts),
            beacons=self.detect(artifacts),
        )
