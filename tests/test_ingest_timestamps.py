"""EH-7 — synthesized timestamps must be flagged, never presented as event time."""


def test_artifact_round_trips_ts_synthesized():
    from datetime import UTC, datetime

    from nexus.ingest.schemas import Artifact, ArtifactSource, ArtifactType, Severity

    art = Artifact(
        id="a1", artifact_type=ArtifactType.NETWORK, source=ArtifactSource.SURICATA,
        timestamp=datetime.now(UTC), severity=Severity.INFORMATIONAL,
        ts_synthesized=True,
    )
    d = art.to_dict()
    assert d["ts_synthesized"] is True
    assert Artifact.from_dict(d).ts_synthesized is True
    # backwards compatible: old artifacts without the key default to False
    d.pop("ts_synthesized")
    assert Artifact.from_dict(d).ts_synthesized is False


def test_suricata_flags_missing_timestamp():
    from nexus.ingest.network.suricata import SuricataImporter

    imp = SuricataImporter()
    with_ts = imp._record_to_artifact({
        "event_type": "flow", "timestamp": "2024-01-01T10:00:00.000000+0000",
    })
    assert with_ts.ts_synthesized is False
    without_ts = imp._record_to_artifact({"event_type": "flow"})
    assert without_ts.ts_synthesized is True


def test_render_ingest_row_marks_synthesized_time():
    from nexus.langgraph.query_pack import render_ingest_row

    row = render_ingest_row({
        "timestamp": "2026-09-18T12:00:00+00:00", "source": "suricata",
        "artifact_type": "network", "severity": "informational",
        "description": "Suricata flow", "ts_synthesized": True,
    })
    assert "ts_synthesized=true" in row
    clean = render_ingest_row({
        "timestamp": "2024-01-01T10:00:00+00:00", "source": "suricata",
        "artifact_type": "network", "severity": "informational",
        "description": "Suricata flow",
    })
    assert "ts_synthesized" not in clean
