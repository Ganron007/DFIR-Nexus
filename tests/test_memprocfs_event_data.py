"""D233: event logs recovered from memory get the same event-data ECS fields as EvtxECmd's rows.

MemProcFS's forensic eventlog.csv writes an event's data as `Name=value; Name=value` text in its
Payload column, and only EvtxECmd's JSON Payload was read: no event from memory got an event-data
field (130 Task Scheduler 129 rows of CASE-C5B04D31 had no process). The rows are verbatim from
that case's index.
"""
from __future__ import annotations

import json
from pathlib import Path

from nexus.langgraph.ecs_normalize import normalize

ROWS = json.loads((Path(__file__).parent / "fixtures" / "memprocfs_eventlog_rows.json").read_text(encoding="utf-8"))


def test_a_task_launch_from_memory_names_its_process():
    ecs = normalize("memprocfs", ROWS["task_129"])
    assert ecs["process"]["executable"] == "C:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe"
    assert ecs["winlog"]["event_data"]["TaskName"].startswith("\\GoogleUpdateTaskMachineUA")


def test_a_service_install_from_memory_keeps_a_value_with_spaces_whole():
    ecs = normalize("memprocfs", ROWS["system_7045"])
    assert ecs["service"]["name"] == "Printer Extensions and Notifications"
    assert ecs["process"]["executable"] == "%SystemRoot%\\system32\\svchost.exe -k print"


def test_a_logoff_from_memory_names_its_account():
    ecs = normalize("memprocfs", ROWS["security_4634"])
    assert ecs["user"]["target"]["name"] == "RD01$" and ecs["winlog"]["logon"]["type"] == "3"


def test_pairs_are_read_for_memprocfs_only():
    assert normalize("generic_csv", ROWS["task_129"]).get("process") is None
