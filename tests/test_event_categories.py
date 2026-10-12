"""The event-to-category table is generated from pinned sources, and the loader reads it."""
from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from nexus.langgraph.event_categories import OTHER, category_for, known_categories

REPO = Path(__file__).resolve().parents[1]
GENERATOR = REPO / "devtools" / "knowledge" / "import_event_categories.py"
TABLE = REPO / "src" / "nexus" / "data" / "schema" / "event_categories.yaml"
# The Elastic pipeline is ELv2 and is never committed: it is cached by `--fetch`, gitignored.
ELASTIC_CACHE = REPO / "devtools" / "knowledge" / "pinned" / "cache" / "security_standard-59aa0e9.yml"


def _generator():
    spec = importlib.util.spec_from_file_location("import_event_categories", GENERATOR)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_committed_table_is_the_generator_output():
    if not ELASTIC_CACHE.is_file():
        pytest.skip("the pinned Elastic pipeline is not cached: run import_event_categories.py --fetch")
    proc = subprocess.run([sys.executable, str(GENERATOR), "--check"],
                          capture_output=True, text=True, check=False)
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_sources_are_pinned_to_the_reviewed_digests():
    doc = yaml.safe_load(TABLE.read_text(encoding="utf-8"))
    pins = {(s["package"], s["version"]): s["sha256"] for s in doc["sources"]}
    assert pins == {
        ("pysigma-pipeline-windows", "2.0.1"):
            "f62d1d5be64379dcb1584ea89cf3765732a25470b249f7ffac1fb9e2e2e19d80",
        ("pysigma-pipeline-sysmon", "2.0.0"):
            "84575bbde5dd891882306ca1f6ce16bdc592da2e511ac8960012af2efb9d120b",
        ("elastic-integrations-windows-security", "59aa0e9"):
            "4c9aef7c941fde2b684e0db6442972545600d6a9e35b524d04bd7d0ff40f7831",
    }
    elastic = next(s for s in doc["sources"] if s["package"].startswith("elastic"))
    assert elastic["licence"] == "Elastic-2.0"
    assert elastic["commit"] == "59aa0e901d5683cb933859bb21bf4da590400e94"


def test_elastic_scope_is_the_authentication_category_and_4672():
    if not ELASTIC_CACHE.is_file():
        pytest.skip("the pinned Elastic pipeline is not cached: run import_event_categories.py --fetch")
    gen = _generator()
    rows = gen._elastic_rows(gen._elastic_yaml())
    assert {eid for _, eid, _ in rows} == {
        4624, 4625, 4634, 4647, 4648, 4672, 4768, 4769, 4770, 4771, 4776, 4778, 4779,
    }
    assert {cat for _, _, cat in rows} == {"authentication", "iam"}
    assert [cat for _, eid, cat in rows if eid == 4672] == ["iam"]


def test_the_table_holds_only_the_in_scope_elastic_rows():
    doc = yaml.safe_load(TABLE.read_text(encoding="utf-8"))
    elastic = {(e["provider"], e["event_id"]) for e in doc["entries"] if e["source"].startswith("elastic")}
    assert {eid for _, eid in elastic} == {
        4624, 4625, 4634, 4647, 4648, 4672, 4768, 4769, 4770, 4771, 4776, 4778, 4779,
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


def test_logons_carry_the_elastic_category():
    # The pySigma pipelines define no logon category; the Elastic pipeline does (D94).
    for eid in ("4624", "4625", "4634", "4647", "4648", "4768", "4769", "4770", "4771", "4776",
                "4778", "4779"):
        assert category_for("Microsoft-Windows-Security-Auditing", eid) == "authentication", eid
    assert category_for("Microsoft-Windows-Security-Auditing", "4672") == "iam"


def test_account_management_stays_other():
    # iam is wider than the logon scope: account management (4720, 4726 ...) is not in the table.
    assert category_for("Microsoft-Windows-Security-Auditing", "4720") == OTHER
    assert category_for("Microsoft-Windows-Security-Auditing", "4726") == OTHER


def test_every_table_category_is_a_known_name():
    names = known_categories()
    assert "process_creation" in names and "network_connection" in names
    assert OTHER not in names
