"""Tests for cross-source correlation — union-find dedup and corroboration."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from nexus.ingest.correlate import correlate
from nexus.ingest.schemas import Artifact, ArtifactSource, ArtifactType, Severity


def _make_artifact(
    source: ArtifactSource,
    ts: datetime | None = None,
    hash_sha256: str | None = None,
    file_path: str | None = None,
    description: str = "test",
) -> Artifact:
    return Artifact(
        id=Artifact.new_id(),
        artifact_type=ArtifactType.FILE,
        source=source,
        timestamp=ts or datetime.now(UTC),
        severity=Severity.INFORMATIONAL,
        file_hash_sha256=hash_sha256,
        file_path=file_path,
        description=description,
    )


class TestCorrelation:
    def test_same_hash_merged(self) -> None:
        """Two artifacts with same SHA-256 → merged."""
        h = "a" * 64
        a1 = _make_artifact(ArtifactSource.VOLATILITY, hash_sha256=h)
        a2 = _make_artifact(ArtifactSource.VELOCIRAPTOR, hash_sha256=h)
        result = correlate([a1, a2])
        assert result.merged[0].corroboration_count == 2
        assert result.merged[0].is_corroborated

    def test_different_hashes_separate(self) -> None:
        """Different hashes → separate events."""
        a1 = _make_artifact(ArtifactSource.VOLATILITY, hash_sha256="a" * 64, description="file A")
        a2 = _make_artifact(ArtifactSource.VELOCIRAPTOR, hash_sha256="b" * 64, description="file B")
        result = correlate([a1, a2])
        assert len(result.merged) == 2

    def test_same_path_time_merged(self) -> None:
        """Same path within time window → merged."""
        ts = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
        a1 = _make_artifact(ArtifactSource.VOLATILITY, ts=ts, file_path="C:/Windows/System32/cmd.exe")
        a2 = _make_artifact(
            ArtifactSource.VELOCIRAPTOR,
            ts=ts + timedelta(seconds=1),
            file_path="C:\\Windows\\System32\\cmd.exe",
        )
        result = correlate([a1, a2])
        assert len(result.merged) == 1
        assert result.merged[0].is_corroborated

    def test_exact_duplicate_removed(self) -> None:
        """Exact (timestamp, description) duplicates merged."""
        ts = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
        a1 = _make_artifact(ArtifactSource.SURICATA, ts=ts, description="alert")
        a2 = _make_artifact(ArtifactSource.SURICATA, ts=ts, description="alert")
        result = correlate([a1, a2])
        assert len(result.merged) == 1
        assert result.duplicates_removed >= 1

    def test_empty_input(self) -> None:
        result = correlate([])
        assert len(result.merged) == 0

    def test_sources_tracked(self) -> None:
        h = "c" * 64
        a1 = _make_artifact(ArtifactSource.VOLATILITY, hash_sha256=h)
        a2 = _make_artifact(ArtifactSource.ZEEK, hash_sha256=h)
        result = correlate([a1, a2])
        sources = result.merged[0].sources
        assert "volatility" in sources
        assert "zeek" in sources

    def test_to_dict(self) -> None:
        h = "d" * 64
        a1 = _make_artifact(ArtifactSource.VOLATILITY, hash_sha256=h)
        result = correlate([a1])
        d = result.to_dict()
        assert "merged_events" in d
        assert "duplicates_removed" in d
        assert "events" in d
