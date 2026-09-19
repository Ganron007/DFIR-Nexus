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


def test_rebuild_preserves_ledger_events(tmp_path: Path):
    """T-* ledger events (evidence registration, examiner notes) must
    survive an N7 rebuild — they are case activity, not host telemetry."""
    import json

    (tmp_path / "timeline.json").write_text(json.dumps([{
        "id": "T-EV-001", "status": "APPROVED", "event_type": "evidence",
        "timestamp": "2026-09-13T08:00:00", "description": "portal register",
        "source": "sample.evtx",
    }]), encoding="utf-8")
    (tmp_path / "CASE.yaml").write_text("intake: {}\n", encoding="utf-8")
    events = rebuild_case_timeline(tmp_path)
    assert any(e.get("id") == "T-EV-001" for e in events)


def test_rebuild_includes_workbench_bookmarks(tmp_path: Path):
    """Examiner-bookmarked rows appear on the timeline pre-approval as
    UNREVIEWED candidates — approval changes state, not existence."""
    import json

    (tmp_path / "CASE.yaml").write_text("intake: {}\n", encoding="utf-8")
    (tmp_path / "workbench.json").write_text(json.dumps([{
        "id": "B-001", "family": "hayabusa", "file": "evtx-timeline.csv",
        "line": "3", "time": "2019-05-21T21:02:57",
        "text": "2019-05-21 21:02:57,cmd.exe spawned rundll32 mshta",
        "note": "suspicious chain",
    }]), encoding="utf-8")
    events = rebuild_case_timeline(tmp_path)
    wb = [e for e in events if str(e.get("source") or "") == "workbench"]
    assert wb, "bookmark rows must reach the timeline"
    assert wb[0]["status"] == "UNREVIEWED"
    assert wb[0]["note"] == "suspicious chain"


def test_merge_dedupes_same_row_across_needles(tmp_path: Path):
    """The same artifact row matched by two needles is ONE event with the
    union of terms — not two rows."""
    row = {
        "family": "hayabusa", "file": "f.csv", "line": "9",
        "text": "2019-05-21 15:32:57,mshta http://x",
    }
    evs = merge_events(
        hits_to_events([{**row, "terms": "mshta"}]),
        hits_to_events([{**row, "terms": "rundll32"}]),
    )
    assert len(evs) == 1
    assert {x.strip() for x in evs[0]["terms"].split(",")} == {"mshta", "rundll32"}


def test_rebuild_includes_finding_evidence(tmp_path: Path):
    """Finding evidence rows (promoted bookmarks) join the timeline tagged
    with the finding's id + status."""
    import json

    (tmp_path / "CASE.yaml").write_text("intake: {}\n", encoding="utf-8")
    (tmp_path / "findings.json").write_text(json.dumps([{
        "id": "F-x-001", "status": "DRAFT", "title": "Signal: mshta",
        "severity": "high",
        "evidence": [{
            "time": "2019-05-21T15:32:57", "source": "hayabusa/evtx.csv",
            "detail": "RuleTitle: MSHTA exec", "loc": "hayabusa\evtx.csv:3",
        }],
    }]), encoding="utf-8")
    events = rebuild_case_timeline(tmp_path)
    fe = [e for e in events if str(e.get("source") or "").startswith("finding:")]
    assert fe and fe[0]["source"] == "finding:F-x-001"
    assert fe[0]["status"] == "DRAFT"
    assert fe[0]["severity"] == "high"

def test_merge_events_pipe_in_description_does_not_collide():
    """EH-8: dedupe keys are tuples — a '|' or ':' inside a description or
    filename must not merge two distinct events."""
    from nexus.langgraph.timeline_merge import merge_events

    events = [
        {"timestamp": "2024-01-01T00:00:00", "source": "suricata",
         "description": "alert | part one", "file": "", "line": ""},
        {"timestamp": "2024-01-01T00:00:00", "source": "suricata",
         "description": "alert | part two", "file": "", "line": ""},
    ]
    merged = merge_events(events)
    assert len(merged) == 2


def test_artifact_key_is_tuple_and_pipe_safe():
    from nexus.langgraph.timeline_merge import _artifact_key

    a = {"source": "suricata", "artifact_type": "network",
         "description": "a|b", "user": "u", "file_path": "p"}
    b = {"source": "suricata", "artifact_type": "network",
         "description": "a", "user": "b|u", "file_path": "p"}
    key_a = _artifact_key(a)
    key_b = _artifact_key(b)
    assert isinstance(key_a, tuple)
    assert key_a != key_b
    # identical rows still dedupe
    assert _artifact_key(dict(a)) == key_a

def test_merge_events_unions_structured_terms_with_commas():
    """EH-8: a needle containing a comma must union intact, not split into
    phantom terms, when the same row is matched by several queries."""
    from nexus.langgraph.timeline_merge import merge_events

    shared = {"file": "a.csv", "line": "2", "timestamp": "2024-01-01T00:00:00"}
    ev1 = {**shared, "terms": "sc.exe, net.exe", "terms_list": ["sc.exe, net.exe"]}
    ev2 = {**shared, "terms": "rundll32", "terms_list": ["rundll32"]}
    merged = merge_events([ev1], [ev2])
    assert len(merged) == 1
    assert merged[0]["terms_list"] == ["rundll32", "sc.exe, net.exe"]
    assert "sc.exe, net.exe" in merged[0]["terms"]


def test_hits_to_events_carries_terms_list():
    from nexus.langgraph.timeline_merge import hits_to_events

    events = hits_to_events([{
        "family": "hayabusa", "file": "a.csv", "line": "3",
        "text": "2024-01-01T00:00:00Z row", "terms": "sc.exe, net.exe",
        "terms_list": ["sc.exe, net.exe"],
    }])
    assert events and events[0]["terms_list"] == ["sc.exe, net.exe"]
