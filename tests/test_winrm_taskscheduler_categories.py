"""D95: WinRM and Task Scheduler events are categorised from Windows' own provider manifests.

No pinned pipeline categorised either channel, so a WinRM session to the domain controller and the
registration of a persistence task had no subject of their own (DRAFT 045 came out "account: system").
The rows are CASE-C5B04D31's (SANS SRL lab data), verbatim from its index on 2026-10-15.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from nexus.langgraph.ecs_normalize import normalize
from nexus.langgraph.es_native import _shape_hit
from nexus.langgraph.event_categories import category_for
from nexus.langgraph.evidence_rows import evidence_rows_for_hits
from nexus.langgraph.subject import derive_subject

ROWS = json.loads((Path(__file__).parent / "fixtures" / "winrm_taskscheduler_rows.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("provider, event_id, category", [
    ("Microsoft-Windows-WinRM", 6, "network_connection"),
    ("Microsoft-Windows-WinRM", 91, "remote_session"),
    ("Microsoft-Windows-WinRM", 161, "authentication"),
    ("Microsoft-Windows-WinRM", 132, "other"),  # an operation completed: protocol plumbing
    ("Microsoft-Windows-WinRM", 772, "other"),  # a SOAP chunk, though its task is "Request handling"
    ("Microsoft-Windows-TaskScheduler", 106, "scheduled_task_change"),
    ("Microsoft-Windows-TaskScheduler", 141, "scheduled_task_change"),
    ("Microsoft-Windows-TaskScheduler", 129, "scheduled_task_run"),
    ("Microsoft-Windows-TaskScheduler", 200, "scheduled_task_run"),
    ("Microsoft-Windows-TaskScheduler", 107, "other"),  # a trigger fired: context, not the task itself
])
def test_the_manifest_gives_each_event_its_category(provider, event_id, category):
    assert category_for(provider, event_id) == category


def test_the_session_ends_reach_ecs():
    outbound = normalize("evtxecmd", ROWS["winrm_6"])
    assert outbound["destination"]["domain"] == "wac01.shieldbase.com"
    inbound = normalize("evtxecmd", ROWS["winrm_91"])
    assert inbound["user"]["name"] == "shieldbase\\rsydow-a"
    assert inbound["source"]["ip"] == "172.16.4.7"
    assert inbound["url"]["original"] == "http://schemas.microsoft.com/powershell/Microsoft.PowerShell"
    launched = normalize("evtxecmd", ROWS["task_129"])
    assert launched["process"]["executable"] == "C:\\Windows\\System32\\SRLUpdate.exe"
    assert normalize("evtxecmd", ROWS["task_106"])["user"]["name"] == "shieldbase\\tdungan"


def _subject(key: str) -> dict:
    fields = ROWS[key]
    doc = {"family": "evtxecmd", "file": "evtxecmd/out.csv", "line": "1", "text": "", "fields": fields,
           "ecs": normalize("evtxecmd", fields), "event_id": fields["EventId"]}
    return derive_subject(evidence_rows_for_hits([_shape_hit(doc)]))


def test_each_row_is_about_what_its_event_is_about():
    assert _subject("winrm_6")["entity"] == {"type": "address", "value": "wac01.shieldbase.com"}
    assert _subject("winrm_91")["entity"] == {"type": "account", "value": "rsydow-a"}
    assert _subject("task_129")["entity"] == {"type": "process", "value": "c:\\windows\\system32\\srlupdate.exe"}
    assert _subject("task_106")["entity"] == {"type": "account", "value": "tdungan"}
    assert _subject("task_106")["category"] == "scheduled_task_change"


def test_the_table_matches_its_pinned_sources():
    import subprocess
    import sys

    repo = Path(__file__).resolve().parents[1]
    cache = repo / "devtools" / "knowledge" / "pinned" / "cache"
    if not cache.is_dir():
        pytest.skip("the Elastic pipeline cache is not fetched (import_event_categories.py --fetch)")
    done = subprocess.run([sys.executable, str(repo / "devtools" / "knowledge" / "import_event_categories.py"),
                           "--check"], capture_output=True, text=True, check=False)
    assert done.returncode == 0, done.stdout + done.stderr
