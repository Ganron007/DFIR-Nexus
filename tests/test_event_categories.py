"""The event-to-category table is generated from pinned pySigma pipelines, and the loader reads it."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import yaml

from nexus.langgraph.event_categories import OTHER, category_for, known_categories

REPO = Path(__file__).resolve().parents[1]
GENERATOR = REPO / "devtools" / "knowledge" / "import_event_categories.py"
TABLE = REPO / "src" / "nexus" / "data" / "schema" / "event_categories.yaml"


def test_committed_table_is_the_generator_output():
    proc = subprocess.run([sys.executable, str(GENERATOR), "--check"],
                          capture_output=True, text=True, check=False)
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_sources_are_pinned_to_the_reviewed_wheels():
    doc = yaml.safe_load(TABLE.read_text(encoding="utf-8"))
    pins = {(s["package"], s["version"]): s["sha256"] for s in doc["sources"]}
    assert pins == {
        ("pysigma-pipeline-windows", "2.0.1"):
            "f62d1d5be64379dcb1584ea89cf3765732a25470b249f7ffac1fb9e2e2e19d80",
        ("pysigma-pipeline-sysmon", "2.0.0"):
            "84575bbde5dd891882306ca1f6ce16bdc592da2e511ac8960012af2efb9d120b",
    }


def test_known_events_carry_their_pinned_category():
    assert category_for("Microsoft-Windows-Security-Auditing", "4688") == "process_creation"
    assert category_for("Microsoft-Windows-PowerShell", "4104") == "ps_script"
    assert category_for("PowerShell", "800") == "ps_classic_script"
    assert category_for("Microsoft-Windows-Sysmon", "3") == "network_connection"
    assert category_for("Microsoft-Windows-Sysmon", "11") == "file_event"
    # Sysmon 12 is registry_add, registry_delete and registry_event in the pipeline; the generic
    # one names the event.
    assert category_for("Microsoft-Windows-Sysmon", "12") == "registry_event"


def test_the_event_id_alone_has_no_category():
    assert category_for("", "4688") == OTHER
    assert category_for(None, "4688") == OTHER


def test_logons_have_no_pinned_category_yet():
    # The pinned pipelines define no logon category: the Windows pipeline maps only process
    # creation, registry audit and PowerShell, and the Sysmon pipeline maps Sysmon ids only.
    assert category_for("Microsoft-Windows-Security-Auditing", "4624") == OTHER
    assert category_for("Microsoft-Windows-Security-Auditing", "4672") == OTHER


def test_every_table_category_is_a_known_name():
    names = known_categories()
    assert "process_creation" in names and "network_connection" in names
    assert OTHER not in names
