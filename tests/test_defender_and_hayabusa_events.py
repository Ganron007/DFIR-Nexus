"""D232: a Defender detection is about what it detected, and a Hayabusa row is read back as its event.

Defender's events had no category, so a detection's subject fell back to an account: the beacon DRAFTs
034, 039 and 046 came out as `account: system`, `account: detection user:` and `account: tdungan`.
Hayabusa rows named their channel by Hayabusa's abbreviation and carried no provider or event data, so
no Hayabusa row had a category at all. The categories come from Windows' own Defender manifest; a
Hayabusa row is read back through Hayabusa's own tables (hayabusa-rules 04af3d2) and the channel each
pinned manifest declares. The rows are CASE-C5B04D31's, verbatim from its index.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from nexus.langgraph.ecs_normalize import normalize
from nexus.langgraph.es_native import _shape_hit
from nexus.langgraph.event_categories import category_for, channel_for, provider_for, row_category
from nexus.langgraph.evidence_rows import evidence_rows_for_hits
from nexus.langgraph.subject import derive_subject

REPO = Path(__file__).resolve().parents[1]
ROWS = json.loads((Path(__file__).parent / "fixtures" / "defender_rows.json").read_text(encoding="utf-8"))


def _row(key: str) -> dict:
    """The evidence row staging attaches for one fixture row."""
    row = ROWS[key]
    fields = row["fields"]
    doc = {"family": row["family"], "file": f"{row['family']}/out.csv", "line": "1", "text": "",
           "fields": fields, "ecs": normalize(row["family"], fields),
           "event_id": str(fields.get("EventId") or fields.get("EventID") or "")}
    return evidence_rows_for_hits([_shape_hit(doc)])[0]


@pytest.mark.parametrize("event_id, category", [
    (1116, "malware"), (1117, "malware"), (1006, "malware"), (1015, "malware"), (1119, "malware"),
    (5001, "configuration"), (5007, "configuration"), (5013, "configuration"),
    (1001, "other"), (1151, "other"), (2001, "other"),  # a scan, a health report, an update error
])
def test_defenders_manifest_gives_each_event_its_category(event_id, category):
    assert category_for("Microsoft-Windows-Windows Defender", event_id) == category


def test_the_manifests_say_which_provider_logs_a_channels_event():
    assert provider_for("Security", 4624) == "Microsoft-Windows-Security-Auditing"
    assert provider_for("Microsoft-Windows-Windows Defender/Operational", 1116) == "Microsoft-Windows-Windows Defender"
    assert provider_for("Microsoft-Windows-PowerShell/Operational", 4104) == "Microsoft-Windows-PowerShell"
    # D474 pins Sysmon 15.15's own manifest; both readers must agree on the channel it declares.
    assert provider_for("Microsoft-Windows-Sysmon/Operational", 1) == "Microsoft-Windows-Sysmon"
    assert channel_for("Microsoft-Windows-Sysmon", 1) == "Microsoft-Windows-Sysmon/Operational"


@pytest.mark.parametrize("key, entity, category", [
    ("evtxecmd_1116_srlupdate", {"type": "file", "value": "c:\\windows\\system32\\srlupdate.exe"}, "malware"),
    ("evtxecmd_1116_behaviour_svchost", {"type": "process", "value": "c:\\windows\\system32\\svchost.exe"}, "malware"),
    ("evtxecmd_1116_amsi_msedge",
     {"type": "process", "value": "c:\\program files (x86)\\microsoft\\edge\\application\\msedge.exe"}, "malware"),
    ("evtxecmd_5007", {"type": "registry", "value": "hklm\\software\\microsoft\\windows defender\\isservicerunning"},
     "configuration"),
    ("evtxecmd_5013",
     {"type": "registry", "value": "hklm\\software\\policies\\microsoft\\windows defender\\disableantispyware"},
     "configuration"),
])
def test_a_defender_event_is_about_what_it_names(key, entity, category):
    assert derive_subject([_row(key)]) == {"entity": entity, "category": category}


@pytest.mark.parametrize("hayabusa, evtxecmd", [
    ("hayabusa_1116_behaviour_svchost", "evtxecmd_1116_behaviour_svchost"),
    ("hayabusa_1116_amsi_msedge", "evtxecmd_1116_amsi_msedge"),
])
def test_a_hayabusa_detection_names_the_same_subject_as_the_event_itself(hayabusa, evtxecmd):
    rule_row, event_row = _row(hayabusa), _row(evtxecmd)
    assert rule_row["channel"] == event_row["channel"] == "Microsoft-Windows-Windows Defender/Operational"
    assert rule_row["provider"] == event_row["provider"] == "Microsoft-Windows-Windows Defender"
    assert derive_subject([rule_row]) == derive_subject([event_row])


def test_a_hayabusa_logon_reads_back_as_its_event():
    ecs = normalize("hayabusa", ROWS["hayabusa_4624_system"]["fields"])
    data = ecs["winlog"]["event_data"]
    assert ecs["winlog"]["channel"] == "Security" and ecs["event"]["provider"] == "Microsoft-Windows-Security-Auditing"
    assert data["LogonType"] == "0", "Hayabusa's `0 - SYSTEM` is given back its original value"
    assert data["ElevatedToken"] == "%%1842"
    assert ecs["user"]["target"]["name"] == "SYSTEM"
    assert row_category(_row("hayabusa_4624_system")) == "authentication"


def test_a_hayabusa_task_event_has_its_category():
    assert row_category(_row("hayabusa_taskscheduler")) == "scheduled_task_change"


@pytest.mark.parametrize("script", ["import_event_categories.py", "import_hayabusa_fields.py"])
def test_the_tables_match_their_pinned_sources(script):
    rules = REPO.parents[1] / "Tools" / "windows" / "hayabusa" / "rules" if REPO.parent.name == ".worktrees" \
        else REPO / "Tools" / "windows" / "hayabusa" / "rules"
    extra: list[str] = []
    if script == "import_hayabusa_fields.py":
        if not (rules / ".git").exists():
            pytest.skip("the hayabusa-rules checkout is not installed")
        extra = ["--rules", str(rules)]
    elif not (REPO / "devtools" / "knowledge" / "pinned" / "cache").is_dir():
        pytest.skip("the Elastic pipeline cache is not fetched (import_event_categories.py --fetch)")
    done = subprocess.run([sys.executable, str(REPO / "devtools" / "knowledge" / script), "--check", *extra],
                          capture_output=True, text=True, check=False)
    assert done.returncode == 0, done.stdout + done.stderr
