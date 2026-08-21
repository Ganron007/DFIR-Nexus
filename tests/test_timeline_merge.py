"""I3 merge + N7 chronology."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from nexus.ingest.schemas import Artifact, ArtifactSource, ArtifactType, Severity
from nexus.langgraph.timeline_merge import (
    artifacts_to_events,
    hits_to_events,
    ingest_into_case,
    merge_events,
    rebuild_case_timeline,
)


def test_merge_host_and_zeek(tmp_path: Path):
    hits = [{
        "family": "pecmd",
        "file": "prefetch_Timeline.csv",
        "line": "2",
        "terms": "sdelete",
        "text": "2020-11-14 13:42:11,sdelete.exe",
    }]
    art = Artifact(
        id=Artifact.new_id(),
        artifact_type=ArtifactType.NETWORK,
        source=ArtifactSource.ZEEK,
        timestamp=datetime(2020, 11, 14, 13, 40, tzinfo=UTC),
        severity=Severity.MEDIUM,
        dest_ip="192.168.77.10",
        description="conn 192.168.77.62 -> 192.168.77.10:445",
    )
    merged = merge_events(hits_to_events(hits), artifacts_to_events([art]))
    assert len(merged) == 2
    sources = {e["source"] for e in merged}
    assert "n4" in sources
    assert any("zeek" in s for s in sources)


def test_rebuild_writes_timeline(tmp_path: Path):
    ext = tmp_path / "extractions" / "pecmd"
    ext.mkdir(parents=True)
    (ext / "prefetch_Timeline.csv").write_text(
        "RunTime,ExecutableName\n2020-11-14 13:42:11,sdelete.exe\n",
        encoding="utf-8",
    )
    (tmp_path / "CASE.yaml").write_text(
        "intake:\n  playbooks: data_staging\n",
        encoding="utf-8",
    )
    events = rebuild_case_timeline(tmp_path)
    assert (tmp_path / "timeline.json").is_file()
    assert (tmp_path / "analysis" / "chronology.md").is_file()
    assert any("sdelete" in (e.get("description") or "").lower() for e in events)


def test_ingest_zeek_onto_case(tmp_path: Path):
    conn = tmp_path / "conn.log"
    conn.write_text(
        "#fields\tts\tid.orig_h\tid.resp_h\tid.resp_p\tproto\n"
        "1605361320.1\t192.168.77.62\t192.168.77.10\t445\ttcp\n",
        encoding="utf-8",
    )
    case = tmp_path / "case"
    case.mkdir()
    (case / "CASE.yaml").write_text("intake:\n  playbooks: data_staging\n", encoding="utf-8")
    info = ingest_into_case(conn, case)
    assert info["success"] is True
    assert info["artifacts"] >= 1
    forced = ingest_into_case(conn, case, source="zeek")
    assert forced["success"] is True
    assert forced["source"] == "zeek"
    assert (case / "ingest" / "artifacts.jsonl").is_file()
    events = rebuild_case_timeline(case)
    chrono = (case / "analysis" / "chronology.md").read_text(encoding="utf-8")
    assert any("zeek" in str(e.get("source") or "") for e in events)
    assert "i1:zeek" in chrono or "zeek" in chrono


def test_hits_to_events_are_claims_not_raw_csv():
    evs = hits_to_events([{
        "family": "hayabusa",
        "file": "evtx-timeline.csv",
        "line": "10",
        "terms": "wevtutil,1102",
        "text": (
            '2023-01-23 07:19:16,"EventID 1102 wevtutil cl Security",'
            '"rd01.shieldbase.com"'
        ),
    }])
    assert evs[0]["host"] == "rd01.shieldbase.com"
    assert evs[0]["description"].startswith("hayabusa")
    assert "wevtutil" in evs[0]["description"].lower()


def test_generic_jsonl_is_not_a_timeline_event():
    art = Artifact(
        id=Artifact.new_id(),
        artifact_type=ArtifactType.UNKNOWN,
        source=ArtifactSource.GENERIC_JSONL,
        timestamp=datetime(2026, 8, 15, 8, 21, tzinfo=UTC),
        severity=Severity.INFORMATIONAL,
        description="Generic JSONL record",
    )
    assert artifacts_to_events([art]) == []
