"""D257: a rule-engine lead and the digest's alert list give a detection's time in UTC.

Hayabusa writes its Timestamp in the lane host's zone with the offset. The leads (first, last, the detail line
and the rows) and the briefing's alert list took it as written, beside EvtxECmd rows in UTC, and the modes
wrote "2022-12-14T19:49:38Z" for a logon the index has at 14:19:38Z. The rows are CASE-C5B04D31's, verbatim
from its index (tests/fixtures/defender_rows.json); a Hayabusa row and the EvtxECmd row of the same event
(record 6355) must read the same time.
"""
from __future__ import annotations

import csv
import json
from pathlib import Path

from nexus.analysis.rule_leads import hayabusa_leads
from nexus.langgraph.evidence_rows import row_time

ROWS = json.loads((Path(__file__).parent / "fixtures" / "defender_rows.json").read_text(encoding="utf-8"))
HAYABUSA = [k for k, v in ROWS.items() if v["family"] == "hayabusa"]
HEADER = ["Timestamp", "RuleTitle", "Level", "Computer", "Channel", "EventID", "RecordID", "Details",
          "ExtraFieldInfo", "RuleID"]


def _write_hayabusa(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(HEADER)
        for key in HAYABUSA:
            writer.writerow([ROWS[key]["fields"].get(col, "") for col in HEADER])


def test_a_hayabusa_lead_reads_the_same_time_as_the_events_evtxecmd_row(tmp_path):
    case = tmp_path / "CASE-D257"
    _write_hayabusa(case / "runs" / "RUN-1" / "extractions" / "hayabusa" / "evtx-timeline.csv")
    lead = next(lead for lead in hayabusa_leads(case)
                if lead.subject == "Antivirus - Exploitation Framework Signature")
    same_event = ROWS["evtxecmd_1116_behaviour_svchost"]
    assert same_event["fields"]["EventRecordId"] == ROWS["hayabusa_1116_behaviour_svchost"]["fields"]["RecordID"]
    utc = row_time({"fields": same_event["fields"]})
    assert utc == "2023-01-24T00:51:58Z"
    assert lead.extra["first"] == lead.extra["last"] == utc
    assert lead.rows[0]["timestamp"] == utc
    assert utc in lead.detail and "+05:30" not in lead.detail


def test_the_alert_list_gives_utc_times_and_sorts_on_them(tmp_path):
    from nexus.langgraph.briefing import briefing_to_markdown, case_briefing

    case = tmp_path / "CASE-D257"
    # Part 12 FM-3: the alert list is the crit/high rule-engine leads, read from the run's Hayabusa timeline.
    _write_hayabusa(case / "runs" / "RUN-1" / "extractions" / "hayabusa" / "evtx-timeline.csv")
    brief = case_briefing(case)
    times = {a["title"]: a["time"] for a in brief["alerts"]}
    # PowerRunner in msedge.exe, record 6459: 2023-01-25 20:26:43.935 +05:30 as Hayabusa wrote it.
    assert times["Defender Alert (Severe)"] == "2023-01-25T14:56:43Z", times
    assert all(t.endswith("Z") for t in times.values()), times
    assert "+05:30" not in briefing_to_markdown(brief).split("## Alert surface")[-1].split("##")[0]
