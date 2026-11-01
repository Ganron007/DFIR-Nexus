"""D518: case metadata agrees with the audit destination and I1 names its case.

Case IDs and no-op calls are control-plane fixtures. I1 inputs are byte-exact
registered T09 exports; no forensic rows are authored here.
"""
from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

import pytest

from nexus.audit import AuditWriter
from nexus.config import settings
from nexus.langgraph.timeline_merge import ingest_into_case

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture()
def scope(tmp_path, monkeypatch):
    root = tmp_path / "cases"
    for name in ("CASE-A", "CASE-B"):
        (root / name).mkdir(parents=True)
    pointer = tmp_path / "active_case"
    pointer.write_text("CASE-B", encoding="utf-8")
    monkeypatch.setattr(settings, "cases_root", root)
    monkeypatch.setattr(settings, "audit_dir", tmp_path / "process-audit")
    monkeypatch.setenv("NEXUS_ACTIVE_CASE_FILE", str(pointer))
    monkeypatch.setenv("NEXUS_EXAMINER", "tester")
    for name in ("NEXUS_ACTIVE_CASE", "NEXUS_CASE_DIR", "NEXUS_AUDIT_DIR"):
        monkeypatch.delenv(name, raising=False)
    return root


def _entries(folder):
    path = folder / "audit/nexus.jsonl"
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()] if path.exists() else []


@pytest.mark.parametrize("ambient", [None, "CASE-B"])
def test_bound_destination_supplies_metadata_without_using_a_different_ambient_case(scope, monkeypatch, ambient):
    if ambient:
        monkeypatch.setenv("NEXUS_ACTIVE_CASE", ambient)
    writer = AuditWriter("nexus", audit_dir=scope / "CASE-A/audit")
    assert writer.log("control_call", params={"value": 1})
    assert [row["case_id"] for row in _entries(scope / "CASE-A")] == ["CASE-A"]
    assert not _entries(scope / "CASE-B")


def test_active_pointer_destination_and_metadata_agree_without_an_environment_case(scope):
    writer = AuditWriter("nexus")
    assert writer.log("control_call", params={"value": 1})
    assert [row["case_id"] for row in _entries(scope / "CASE-B")] == ["CASE-B"]
    assert not _entries(scope / "CASE-A")


def test_a_named_case_cannot_be_written_into_a_different_bound_case_folder(scope):
    writer = AuditWriter("nexus", audit_dir=scope / "CASE-A/audit")
    assert writer.log("control_call", params={"case_id": "CASE-B"}) is None
    assert not _entries(scope / "CASE-A") and not _entries(scope / "CASE-B")


@pytest.mark.parametrize("filename,rows", [
    ("d518_RBCmd_Output.csv", 19),
    ("d518_USB_Detective_Timeline.xlsx", 334),
])
def test_i1_named_case_survives_a_different_ambient_case_for_both_import_paths(scope, monkeypatch, tmp_path, filename, rows):
    manifest = json.loads((FIXTURES / "d518_input_hashes.json").read_text(encoding="utf-8"))
    source = FIXTURES / filename
    assert hashlib.sha256(source.read_bytes()).hexdigest() == manifest[filename]["sha256"]
    inputs = tmp_path / "input"
    inputs.mkdir()
    local = inputs / manifest[filename]["source_name"]
    shutil.copyfile(source, local)
    monkeypatch.setenv("NEXUS_ACTIVE_CASE", "CASE-B")
    result = ingest_into_case(local, scope / "CASE-A")
    assert result["success"] and result["artifacts"] == rows
    entries = _entries(scope / "CASE-A")
    assert len(entries) == 1 and entries[0]["tool"] == "ingest_auto"
    assert entries[0]["case_id"] == entries[0]["params"]["case_id"] == "CASE-A"
    assert entries[0]["params"]["path"] == str(local)
    assert not _entries(scope / "CASE-B")
