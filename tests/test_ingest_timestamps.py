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

def test_importer_sweep_flags_synthesized_timestamps():
    """EH-7 sweep: every importer that substitutes ingest time marks it."""
    from datetime import datetime
    from pathlib import Path

    from nexus.ingest.cloud.cloudtrail import CloudTrailImporter
    from nexus.ingest.cloud.m365 import M365Importer
    from nexus.ingest.df.hayabusa import HayabusaImporter
    from nexus.ingest.linux.auditd import AuditdImporter
    from nexus.ingest.siem.splunk import SplunkImporter

    # hayabusa
    art = HayabusaImporter()._row_to_artifact(
        {"Timestamp": "2024-11-23 04:06:23.634 +05:30", "RuleTitle": "RDP Logon",
         "Level": "info", "Computer": "WS01", "EventID": "21"}
    )
    assert art is not None and art.ts_synthesized is False
    art2 = HayabusaImporter()._row_to_artifact(
        {"RuleTitle": "RDP Logon", "Level": "info", "Computer": "WS01", "EventID": "21"}
    )
    assert art2 is not None and art2.ts_synthesized is True

    # cloudtrail
    ct = CloudTrailImporter()._record_to_artifact(
        {"eventName": "ConsoleLogin"}, Path("x.json")
    )
    assert ct.ts_synthesized is True
    ct2 = CloudTrailImporter()._record_to_artifact(
        {"eventName": "ConsoleLogin", "eventTime": "2024-01-01T10:00:00Z"},
        Path("x.json"),
    )
    assert ct2.ts_synthesized is False

    # auditd
    ad = AuditdImporter()._line_to_artifact("type=SYSCALL msg=hello")
    assert ad.ts_synthesized is True
    ad2 = AuditdImporter()._line_to_artifact(
        "type=SYSCALL msg=audit(1705320896.123:456): hello"
    )
    assert ad2.ts_synthesized is False

    # splunk
    sp = SplunkImporter()._row_to_artifact({"sourcetype": "x"})
    assert sp.ts_synthesized is True
    sp2 = SplunkImporter()._row_to_artifact({"_time": "1705320896"})
    assert sp2.ts_synthesized is False

    # NOTE: browser-history raw parsing moved to the N-lane (SQLECmd/Hindsight);
    # the ingest importer and its converter tests were removed with it.

    # m365 helper tuple
    m365 = M365Importer()
    ts, synth = m365._extract_timestamp({}, {"CreationTime": "2024-01-01T10:00:00Z"})
    assert isinstance(ts, datetime) and synth is False
    ts2, synth2 = m365._extract_timestamp({}, {})
    assert synth2 is True

    # artifacts carry the flag through serialization
    assert art2.to_dict()["ts_synthesized"] is True
