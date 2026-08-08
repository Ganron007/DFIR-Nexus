"""Tests for log gap analysis — suspicious silence detection."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from nexus.ingest.gap_analysis import LogGap, analyze_gaps
from nexus.ingest.schemas import Artifact, ArtifactSource, ArtifactType, Severity


def _make_artifact(ts: datetime, source: ArtifactSource = ArtifactSource.EVTX) -> Artifact:
    return Artifact(
        id=Artifact.new_id(),
        artifact_type=ArtifactType.PROCESS,
        source=source,
        timestamp=ts,
        severity=Severity.INFORMATIONAL,
        description="test event",
    )


class TestGapAnalysis:
    def test_no_gap_in_uniform_timeline(self) -> None:
        """Uniform 10-second intervals → no gap."""
        base = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
        artifacts = [
            _make_artifact(base + timedelta(seconds=10 * i))
            for i in range(20)
        ]
        result = analyze_gaps(artifacts, min_gap_seconds=300)
        assert len(result.gaps) == 0

    def test_complete_gap_detected(self) -> None:
        """1-hour silence → gap detected."""
        base = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
        artifacts = [_make_artifact(base + timedelta(seconds=10 * i)) for i in range(5)]
        artifacts.append(_make_artifact(base + timedelta(hours=1, seconds=50)))
        for i in range(5):
            artifacts.append(_make_artifact(base + timedelta(hours=1, seconds=60 + 10 * i)))
        result = analyze_gaps(artifacts, min_gap_seconds=300)
        assert len(result.gaps) >= 1
        assert result.gaps[0].duration_seconds >= 3600
        assert result.gaps[0].severity in ("high", "medium")

    def test_too_few_artifacts_no_gap(self) -> None:
        """Less than 3 artifacts → no analysis."""
        base = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
        artifacts = [_make_artifact(base), _make_artifact(base + timedelta(hours=2))]
        result = analyze_gaps(artifacts)
        assert len(result.gaps) == 0

    def test_gap_has_hypothesis(self) -> None:
        """Detected gaps should have a hypothesis."""
        base = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
        artifacts = [_make_artifact(base + timedelta(seconds=10 * i)) for i in range(5)]
        artifacts.append(_make_artifact(base + timedelta(hours=2)))
        for i in range(5):
            artifacts.append(_make_artifact(base + timedelta(hours=2, seconds=10 * i)))
        result = analyze_gaps(artifacts, min_gap_seconds=300)
        if result.gaps:
            assert len(result.gaps[0].hypothesis) > 0

    def test_result_to_dict(self) -> None:
        base = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
        artifacts = [_make_artifact(base + timedelta(seconds=10 * i)) for i in range(5)]
        artifacts.append(_make_artifact(base + timedelta(hours=1)))
        result = analyze_gaps(artifacts, min_gap_seconds=300)
        d = result.to_dict()
        assert "total_gaps" in d
        assert "gaps" in d
        assert isinstance(d["gaps"], list)

    def test_duration_display(self) -> None:
        base = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
        gap = LogGap(
            gap_type="COMPLETE",
            start_time=base,
            end_time=base + timedelta(hours=2, minutes=30),
            duration_seconds=9000,
            severity="high",
            sources_affected=["evtx"],
            sources_still_active=[],
            host="host1",
        )
        assert "2h" in gap.duration_display
        assert "30m" in gap.duration_display
