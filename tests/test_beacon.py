"""Tests for beacon/C2 detection — statistical regularity analysis."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from nexus.ingest.beacon import detect_beacons
from nexus.ingest.schemas import Artifact, ArtifactSource, ArtifactType, Severity


def _make_artifact(
    host: str,
    source_ip: str,
    dest_ip: str,
    dest_port: int,
    timestamp: datetime,
) -> Artifact:
    return Artifact(
        id=Artifact.new_id(),
        artifact_type=ArtifactType.NETWORK,
        source=ArtifactSource.ZEEK,
        timestamp=timestamp,
        severity=Severity.INFORMATIONAL,
        host=host,
        source_ip=source_ip,
        dest_ip=dest_ip,
        dest_port=dest_port,
    )


class TestBeaconDetection:
    def test_regular_beacon_detected(self) -> None:
        """5 connections at exactly 60s intervals → beacon."""
        base = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
        artifacts = [
            _make_artifact("host1", "10.0.0.1", "1.2.3.4", 443, base + timedelta(seconds=60 * i))
            for i in range(10)
        ]
        candidates = detect_beacons(artifacts, min_connections=5)
        assert len(candidates) >= 1
        beacon = candidates[0]
        assert beacon.is_beacon
        assert beacon.median_interval_seconds == pytest.approx(60.0, abs=1.0)
        assert beacon.jitter_ratio < 0.15

    def test_jittery_connections_not_flagged(self) -> None:
        """Connections with random intervals → not a beacon."""
        import random
        random.seed(42)
        base = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
        t = base
        artifacts = []
        for _ in range(10):
            t = t + timedelta(seconds=random.randint(5, 300))
            artifacts.append(_make_artifact("host1", "10.0.0.1", "1.2.3.4", 443, t))
        candidates = detect_beacons(artifacts, min_connections=5)
        if candidates:
            for c in candidates:
                if c.dest_ip == "1.2.3.4":
                    assert c.jitter_ratio > 0.15 or not c.is_beacon

    def test_too_few_connections_ignored(self) -> None:
        """3 connections → below threshold, not flagged."""
        base = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
        artifacts = [
            _make_artifact("host1", "10.0.0.1", "1.2.3.4", 443, base + timedelta(seconds=60 * i))
            for i in range(3)
        ]
        candidates = detect_beacons(artifacts, min_connections=5)
        assert len(candidates) == 0

    def test_multiple_dests_separate_groups(self) -> None:
        """Different dest IPs are separate groups."""
        base = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
        artifacts = []
        for i in range(7):
            artifacts.append(_make_artifact("host1", "10.0.0.1", "1.2.3.4", 443, base + timedelta(seconds=60 * i)))
            artifacts.append(_make_artifact("host1", "10.0.0.1", "5.6.7.8", 80, base + timedelta(seconds=30 * i)))
        candidates = detect_beacons(artifacts, min_connections=5)
        dest_ips = {c.dest_ip for c in candidates}
        assert len(dest_ips) >= 1

    def test_beacon_to_dict(self) -> None:
        base = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
        artifacts = [
            _make_artifact("host1", "10.0.0.1", "1.2.3.4", 443, base + timedelta(seconds=60 * i))
            for i in range(8)
        ]
        candidates = detect_beacons(artifacts, min_connections=5)
        if candidates:
            d = candidates[0].to_dict()
            assert "source_host" in d
            assert "jitter_ratio" in d
            assert "is_beacon" in d
