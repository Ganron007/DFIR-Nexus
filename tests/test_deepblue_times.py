"""D260: a DeepBlueCLI row carries its event's time.

DeepBlueCLI's JSON gives each event's time as .NET writes a DateTime, "\\/Date(<ms>)\\/". The index read no time from it,
so all 1,922 DeepBlueCLI rows of CASE-C5B04D31 had no `ts`: PsShutdown's 7045 sorted nowhere and no time window held
it. The fixture is that case's DeepBlueCLI System.json, verbatim (UTF-8 BOM and escaped slashes included); the expected
times are the same events' EvtxECmd `TimeCreated` in the same case's index (System records 184, 856, 857, 5261).
"""
from __future__ import annotations

import shutil
from pathlib import Path

from nexus.langgraph.case_index import iter_index_docs
from nexus.langgraph.evidence_rows import row_time
from nexus.langgraph.timestamps import parse_time_value

FIXTURE = Path(__file__).parent / "fixtures" / "d260_deepblue_System.json"

# DeepBlueCLI row (line) -> the EvtxECmd TimeCreated of the same System event.
TWINS = {
    1: ("7030", "Foxit PDF Reader Update Service", "2022-11-06T23:32:10Z"),   # record 5261, 23:32:10.7638249
    2: ("7030", "PsShutdown", "2022-08-31T18:58:03Z"),                         # record 857, 18:58:03.1823039
    3: ("7045", "PsShutdown", "2022-08-31T18:58:03Z"),                         # record 856, 18:58:03.1823039
    4: ("7030", "Printer Extensions and Notifications", "2022-08-31T17:36:42Z"),  # record 184, 17:36:42.1571813
}


def _case(tmp_path: Path) -> Path:
    out = tmp_path / "extractions" / "deepbluecli"
    out.mkdir(parents=True)
    shutil.copyfile(FIXTURE, out / "System.json")
    return tmp_path


def test_each_deepblue_row_is_indexed_at_its_events_time(tmp_path):
    docs = [d for d in iter_index_docs(_case(tmp_path)) if d["family"] == "deepbluecli"]
    assert [d["line"] for d in docs] == [1, 2, 3, 4]
    for doc in docs:
        event, service, ts = TWINS[doc["line"]]
        assert doc["event_id"] == event and service in doc["fields"]["Results"]
        assert doc["ts"] == ts, doc["line"]
        assert doc["ts_src"] == "event" and doc["ts_precision"] == "ms"
        assert "ts_tz_assumed" not in doc, "the number is UTC by its definition, not by assumption"
        # A row that carries only its fields (no `ts`) gives the same time (D236).
        assert row_time({"fields": doc["fields"]}) == ts


def test_the_form_keeps_its_milliseconds_and_an_offset_does_not_move_the_instant():
    got = parse_time_value("/Date(1661972283182)/")
    assert got["dt"].isoformat() == "2022-08-31T18:58:03.182000+00:00"
    # The raw JSON escapes the slashes; a local-kind value carries an offset that marks it, the number stays UTC.
    assert parse_time_value("\\/Date(1661972283182)\\/")["dt"] == got["dt"]
    assert parse_time_value("/Date(1661972283182+0530)/")["dt"] == got["dt"]


def test_the_form_is_a_whole_value_only():
    # Inside free text it stays text, as every number does (D120).
    assert parse_time_value("see /Date(1661972283182)/ above") is None
    assert parse_time_value("/Date()/") is None
