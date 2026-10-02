"""A10: the event model (WO-A10 / T1-4, WPs 8.5 / 10.5 / 10.6).

These tests are about the properties that make the timeline trustworthy rather
than merely present: one event per timestamp column, ids that survive a
re-index, an unknown family that produces *no* silence, and a build that never
re-parses evidence.
"""
from __future__ import annotations

import json
from pathlib import Path

from nexus.langgraph.timeline_events import (
    SUPPORTED_FAMILIES,
    TIMELINE_SCHEMA_VERSION,
    date_columns_for,
    event_id_for,
    events_index_name,
    expand_doc,
    needs_rebuild,
    read_events_state,
)


def _mf_doc(**over) -> dict:
    """One MFT row: four timestamps plus the identifiers."""
    doc = {
        "case_id": "CASE-TL00001",
        "family": "mftecmd",
        "file": "mft/mftecmd.csv",
        "line": 42,
        "text": "C:\\Users\\bob\\AppData\\Local\\Temp\\a.exe",
        "fields": {
            "Created0x10": "2026-09-29 13:04:07.123",
            "LastModified0x10": "2026-09-29 13:04:08.001",
            "LastModified0x30": "2026-09-29 13:05:00.500",
            "FileSize": 4096,
            "FileName": "a.exe",
        },
        "host": "WS01.CADRE.LOCAL",
        "user": "bob",
        "event_id": "515",
        "ts": "2026-09-29T13:04:07.123Z",
        "ts_raw": "2026-09-29 13:04:07.123",
        "ts_src": "event",
        "ts_precision": "millisecond",
        "audit_id": "nx-audit-0007",
    }
    doc.update(over)
    return doc


def test_one_event_per_timestamp_column():
    """MACB expansion: four timestamps are four events, not one row."""
    events = expand_doc(_mf_doc())
    columns = {e["ts_desc"] for e in events}
    assert {"Created0x10", "LastModified0x10", "LastModified0x30"} <= columns
    # non-time columns never become events
    assert "FileSize" not in columns
    assert "FileName" not in columns
    # the row's own event time is included, and the file size rides along
    ingest = next(e for e in events if e["ts_desc"] == "ingest")
    assert ingest["ts"].startswith("2026-09-29T13:04:07")
    assert ingest["fields"]["FileSize"] == 4096
    assert ingest["source_line"] == 42
    assert ingest["audit_id"] == "nx-audit-0007"


def test_event_ids_are_content_derived_and_stable():
    first = expand_doc(_mf_doc())
    again = expand_doc(_mf_doc())
    assert [e["event_id"] for e in first] == [e["event_id"] for e in again]

    # a different row (different line) is a different event
    other = expand_doc(_mf_doc(line=43))
    assert {e["event_id"] for e in first}.isdisjoint(
        {e["event_id"] for e in other}
    )
    # and the id is derived, not random: same inputs, same id
    assert event_id_for("f.csv", "a:1", "Created0x10") == event_id_for(
        "f.csv", "a:1", "Created0x10"
    )
    assert event_id_for("f.csv", "a:1", "Created0x10") != event_id_for(
        "f.csv", "a:1", "LastModified0x10"
    )


def test_a_synthesized_ingest_time_is_not_promoted_to_an_event():
    """A fallback timestamp must not masquerade as an event time."""
    doc = _mf_doc(ts_src="synthesized", ts_raw="2026-01-01 00:00:00")
    events = expand_doc(doc)
    assert "ingest" not in {e["ts_desc"] for e in events}
    # the real column timestamps survive
    assert {e["ts_desc"] for e in events}


def test_an_unsupported_family_produces_nothing_and_is_not_guessed():
    for family in ("prefetchnot", "", "vol-output"):
        assert expand_doc(_mf_doc(family=family)) == []


def test_events_carry_the_reserved_skew_field_unpopulated():
    """Reserved for design review §5 #6 - present, never guessed."""
    for event in expand_doc(_mf_doc()):
        assert "host_clock_skew" in event
        assert event["host_clock_skew"] is None


def test_date_columns_come_from_the_registry():
    mft = date_columns_for("mftecmd")
    assert "Created0x10" in mft
    assert "FileSize" not in mft


def test_index_name_is_case_scoped():
    name = events_index_name("CASE-TL00001")
    assert name.endswith("-events")
    assert "case-tl00001" in name
    assert name != events_index_name("CASE-TL00002")


def test_rebuild_decision_follows_the_schema_version(tmp_path):
    case = tmp_path / "CASE-TL00001"
    (case / "analysis").mkdir(parents=True)
    assert needs_rebuild(case) is True

    (case / "analysis" / "timeline_events.json").write_text(
        json.dumps({"schema_version": TIMELINE_SCHEMA_VERSION, "events": 4}),
        encoding="utf-8",
    )
    assert needs_rebuild(case) is False
    assert read_events_state(case)["events"] == 4

    (case / "analysis" / "timeline_events.json").write_text(
        json.dumps({"schema_version": TIMELINE_SCHEMA_VERSION - 1}),
        encoding="utf-8",
    )
    assert needs_rebuild(case) is True


def test_build_reports_a_down_backend_instead_of_raising(tmp_path, monkeypatch):
    """ES unreachable is a state the caller can show, not an exception."""
    import nexus.langgraph.timeline_events as te

    case = tmp_path / "CASE-TL00002"
    (case / "analysis").mkdir(parents=True)

    def _boom(_case_id: str) -> str:
        raise RuntimeError("connection refused")

    monkeypatch.setattr(te, "ensure_events_index", _boom)
    result = te.build_events(case)

    assert result["built"] is False
    assert "elasticsearch unavailable" in result["reason"]
    assert read_events_state(case)["error"]
    # and the evidence was never touched
    assert not (case / "extractions").exists()


def test_supported_families_is_an_explicit_short_list():
    """'why is prefetch missing from my timeline' must have an answer."""
    assert set(SUPPORTED_FAMILIES) == {
        "evtx",
        "evtxecmd",
        "mftecmd",
        "mftecmd-i30",
        "tasks",
        "wxtcmd",
        "plaso",
    }


def test_evtxecmd_timecreated_becomes_an_event():
    """EZ-tool output lives under family evtxecmd. The registry types TimeCreated there."""
    doc = {
        "family": "evtxecmd",
        "file": "evtxecmd/EvtxECmd_Output.csv",
        "line": 12,
        "host": "WS01",
        "user": "",
        "ts_src": "column",
        "ts": "2020-10-27T03:54:15+00:00",
        "fields": {
            "TimeCreated": "2020-10-27 03:54:15.000",
            "EventId": "4688",
            "MapDescription": "Process start",
        },
    }
    events = expand_doc(doc)
    created = [event for event in events if event["ts_desc"] == "TimeCreated"]
    assert created
    assert created[0]["family"] == "evtxecmd"
    assert created[0]["ts_src"] == "column"
    assert created[0]["fields"]["EventId"] == "4688"


def test_plaso_l2tcsv_row_is_one_event():
    """date and time are one super-timeline event. MACB stays a label."""
    doc = {
        "family": "plaso",
        "file": "plaso/plaso.csv",
        "line": 4,
        "host": "WS01",
        "ts_src": "synthesized",
        "fields": {
            "date": "2020-10-27",
            "time": "03:54:15",
            "MACB": "M...",
            "source": "FILE",
            "sourcetype": "NTFS $MFT",
        },
    }
    events = expand_doc(doc)
    assert len(events) == 1
    assert events[0]["ts_desc"] == "event"
    assert events[0]["family"] == "plaso"
    assert events[0]["fields"]["MACB"] == "M..."
    indexed = dict(doc)
    indexed["ts_src"] = "column"
    indexed["ts"] = "2020-10-27T03:54:15+00:00"
    indexed["ts_raw"] = "2020-10-27 03:54:15"
    assert len(expand_doc(indexed)) == 1


def test_delete_events_index_targets_the_events_index(monkeypatch):
    """Cleanup must remove the events index too (A10), or it orphans per case."""
    import nexus.langgraph.case_index as ci
    import nexus.langgraph.timeline_events as te

    monkeypatch.setattr(ci, "es_url", lambda: "")
    out = te.delete_events_index("CASE-X")
    assert out["index"] == te.events_index_name("CASE-X")
    assert out["index"] == "nexus-case-case-x-events"
    assert out["deleted"] is False
    assert out["reason"] == "NEXUS_ES_URL unset"


def test_task_xml_registration_time_is_registry_typed():
    """WO-A10/D6: the task family's own timestamp column is vouched for, so the
    timeline emits it as a registry-typed event rather than a heuristic one."""
    columns = date_columns_for("tasks")
    assert "registration_date" in columns
    assert "task_registration_date" in columns


def test_no_reparse_evidence(tmp_path, monkeypatch):
    """The build reads the index, never an importer."""
    import nexus.langgraph.case_index as ci
    import nexus.langgraph.timeline_events as te

    case = tmp_path / "CASE-TL00003"
    (case / "analysis").mkdir(parents=True)
    (case / "extractions" / "mft").mkdir(parents=True)
    csv_path = case / "extractions" / "mft" / "mftecmd.csv"
    csv_path.write_text(
        "FileName,Created0x10,LastModified0x10\n"
        "a.exe,2026-09-29 13:04:07.123,2026-09-29 13:04:08.001\n",
        encoding="utf-8",
    )

    seen: list[Path] = []

    def _docs(_case: Path):
        seen.append(_case)
        yield _mf_doc()
        yield _mf_doc(line=43, fields={"Created0x10": "2026-09-29 14:00:00.000"})

    monkeypatch.setattr(ci, "iter_index_docs", _docs)
    monkeypatch.setattr(te, "ensure_events_index", lambda cid: events_index_name(cid))
    monkeypatch.setattr(ci, "_client", _fake_client)
    monkeypatch.setattr(ci, "_bulk_insert", lambda client, index, docs, chunk=2000, **kw: 0)

    result = te.build_events(case, force=True)
    assert result["built"] is True
    assert result["events"] >= 2
    # the only case path touched is the one we were given; no importer ran
    assert seen == [case]
    # the source CSV is untouched - the index was the input, the evidence intact
    assert csv_path.read_text(encoding="utf-8").startswith("FileName")


class _FakeResponse:
    status_code = 200

    def raise_for_status(self) -> None:
        return None


class _FakeClient:
    def head(self, _path: str) -> _FakeResponse:
        return _FakeResponse()

    def __enter__(self) -> _FakeClient:
        return self

    def __exit__(self, *_exc) -> None:
        return None


def _fake_client():
    return _FakeClient()