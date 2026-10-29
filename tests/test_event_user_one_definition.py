"""D471: a Windows event's user has one definition, the pinned EvtxECmd map's `UserName`, for every tool that reads it.

The pinned maps (`data/schema/evtxecmd_maps.yaml`, EricZimmerman/evtx @03a7a1f) give 152 events a user. EvtxECmd rows
had it from their rendered `UserName` column; MemProcFS's event logs from memory (and Hayabusa's) had a user only for
the ~20 events a hand-written table repeated, and in another form (4624: `BASE-RD-01$` beside the map's
`shieldbase\\BASE-RD-01$`). T22 (CASE-4387EB47, one memory image) indexed 338 Security 4672 rows, its 4697 (the
F-Response service installed by `cbarton-a`) and its 5140 share accesses with no user at all, so no mode could see who
acted, and the host's own machine account (D468) was in no typed field.
"""
from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

from nexus.langgraph.case_index import _host_user_event
from nexus.langgraph.ecs_normalize import _parse_payload, load_ecs_map, normalize
from nexus.langgraph.evtx_templates import _readers, event_value, map_value

FIXTURES = Path(__file__).parent / "fixtures"
T22 = json.loads((FIXTURES / "memprocfs_t22_rows.json").read_text(encoding="utf-8"))


def _evtxecmd_rows() -> list[dict]:
    """Every verbatim EvtxECmd row the repository holds (public samples and CASE-C5B04D31's index)."""
    csv.field_size_limit(sys.maxsize)
    with (FIXTURES / "cs1b_evtx_real_rows.csv").open(encoding="utf-8", errors="replace", newline="") as fh:
        rows = list(csv.DictReader(fh))
    rows += list(json.loads((FIXTURES / "winrm_taskscheduler_rows.json").read_text(encoding="utf-8")).values())
    rows += [r["fields"] for r in json.loads((FIXTURES / "defender_rows.json").read_text(encoding="utf-8")).values()
             if r["family"] == "evtxecmd"]
    return rows


def test_the_user_read_from_the_event_data_is_the_one_evtxecmd_renders():
    """The agreement test: one definition, two readers, the same value on every real row."""
    compared = 0
    for row in _evtxecmd_rows():
        data = _parse_payload(row.get("Payload"))
        from_data = event_value(row.get("Channel"), row.get("EventId"), "UserName", data)
        if from_data is None:
            continue
        rendered = map_value(row.get("Channel"), row.get("EventId"), "UserName", row.get("UserName"))
        assert from_data == rendered, (row.get("Channel"), row.get("EventId"), row.get("UserName"))
        compared += 1
    assert compared >= 10


def test_an_evtxecmd_row_and_its_envelope_keep_the_users_they_had():
    """4624 and 4688 now take the map's `domain\\user`, the form EvtxECmd's own column always gave the envelope."""
    seen = 0
    for row in _evtxecmd_rows():
        if (row.get("Channel"), row.get("EventId")) not in {("Security", "4624"), ("Security", "4688"),
                                                            ("Microsoft-Windows-Sysmon/Operational", "1")}:
            continue
        ecs = normalize("evtxecmd", row)
        want = map_value(row["Channel"], row["EventId"], "UserName", row["UserName"])
        assert ecs["user"]["name"] == want
        assert _host_user_event(row, "evtxecmd", ecs=ecs)[1] == want
        seen += 1
    assert seen == 3


def test_memory_events_name_the_user_the_map_gives_them():
    want = {
        ("Security", "4672"): "shieldbase\\BASE-RD-01$",
        ("Security", "4697"): "shieldbase\\cbarton-a",
        ("Security", "5140"): "NT AUTHORITY\\ANONYMOUS LOGON",
        ("Microsoft-Windows-GroupPolicy/Operational", "4004"): "shieldbase\\BASE-RD-01$",
        ("Microsoft-Windows-TaskScheduler/Operational", "140"): "shieldbase\\BASE-RD-01$",
        ("Microsoft-Windows-TaskScheduler/Operational", "100"): "shieldbase\\tdungan",
        # a UserData event: MemProcFS flattens LogFileCleared's elements to their leaf names
        ("System", "104"): "WIN10-TEST\\Administrator",
    }
    seen = set()
    for row in T22["rows"]["eventlog.csv"]:
        key = (row["Channel"], row["EventID"])
        ecs = normalize("memprocfs", row, table="eventlog.csv")
        user = _host_user_event(row, "memprocfs", table="eventlog.csv", ecs=ecs)[1]
        if key in want:
            seen.add(key)
            assert ecs["user"]["name"] == want[key], key
            assert user == want[key], key
        else:  # 4634 names its account as the target; 7045's map names no user
            assert "name" not in (ecs.get("user") or {}) and user == "", key
    assert seen == set(want)


def test_the_hand_table_names_no_user_an_events_map_names():
    """Rule 16: the second copy was deleted; this keeps it from coming back."""
    readers = _readers()
    twice = [(channel, event_id) for channel, events in (load_ecs_map().get("winlog_event_data") or {}).items()
             for event_id, names in events.items()
             if "ecs.user.name" in names.values() and "UserName" in readers.get((channel.lower(), event_id), {})]
    assert twice == []
