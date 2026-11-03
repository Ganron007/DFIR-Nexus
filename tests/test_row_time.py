"""D236: an evidence row's time is the event's time in UTC, by the rule the index computes `ts` with.

A row took the first date in its raw text. Hayabusa writes its timestamp in the lane host's zone with the
offset (`2023-01-24 06:21:58.223 +05:30`); the date lost its offset and read as 06:21:58 UTC, five and a
half hours after the same detection's EvtxECmd row (`2023-01-24 00:51:58.2235274`, UTC). The report's
timeline and its assessment put the beacon and Kekeo at the wrong hours. The rows are CASE-C5B04D31's.
"""
from __future__ import annotations

import json
from pathlib import Path

from nexus.langgraph.ecs_normalize import normalize
from nexus.langgraph.es_native import _shape_hit
from nexus.langgraph.evidence_rows import evidence_rows_for_hits, row_time

ROWS = json.loads((Path(__file__).parent / "fixtures" / "defender_rows.json").read_text(encoding="utf-8"))


def _hit(key: str, ts: str = "") -> dict:
    row = ROWS[key]
    doc = {"family": row["family"], "file": f"{row['family']}/out.csv", "line": "1", "text": "",
           "fields": row["fields"], "ecs": normalize(row["family"], row["fields"])}
    if ts:
        doc["ts"] = ts
    return _shape_hit(doc)


def test_one_detection_retains_each_tools_reported_utc_precision():
    from datetime import datetime

    hayabusa = evidence_rows_for_hits([_hit("hayabusa_1116_behaviour_svchost")])[0]
    evtxecmd = evidence_rows_for_hits([_hit("evtxecmd_1116_behaviour_svchost")])[0]
    # The captured tools report different precision for the same record. Keep
    # each literal fraction instead of forcing equality by truncating both.
    assert ROWS["hayabusa_1116_behaviour_svchost"]["fields"]["RecordID"] == ROWS["evtxecmd_1116_behaviour_svchost"]["fields"]["EventRecordId"]
    assert hayabusa["time"] == "2023-01-24T00:51:58.223Z"
    assert evtxecmd["time"] == "2023-01-24T00:51:58.2235274Z"
    finer = datetime.fromisoformat(evtxecmd["time"])
    assert finer.replace(microsecond=finer.microsecond // 1000 * 1000) == datetime.fromisoformat(hayabusa["time"])


def test_the_indexed_ts_is_the_rows_time():
    row = evidence_rows_for_hits([_hit("hayabusa_1116_behaviour_svchost", ts="2023-01-24T00:51:58Z")])[0]
    assert row["time"] == "2023-01-24T00:51:58Z"


def test_a_row_stored_before_the_fix_reads_back_in_utc():
    """The five approved findings carry rows staged with the old time; their reports read them right."""
    from nexus.integration.evidence_table import normalize_evidence_rows

    stored = {"time": "2023-01-24T06:21:58", "source": "hayabusa/hayabusa/evtx-timeline.csv",
              "artifact": "hayabusa/evtx-timeline.csv", "loc": "hayabusa/evtx-timeline.csv:58385",
              "detail": "RuleTitle: Antivirus - Exploitation Framework Signature",
              "fields": {"Timestamp": ROWS["hayabusa_1116_behaviour_svchost"]["fields"]["Timestamp"]}}
    assert row_time(stored) == "2023-01-24T00:51:58.223Z"
    (table_row,) = normalize_evidence_rows({"evidence": [stored]})
    assert table_row["time"].startswith("2023-01-24")
    assert "00:51:58" in table_row["time"] and "06:21" not in table_row["time"]
