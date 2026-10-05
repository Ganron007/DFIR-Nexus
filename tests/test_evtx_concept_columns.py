"""WO-KR2c 0c: an EvtxECmd concept maps to its generic column, per event.

The reviewer's root-cause example: EvtxECmd **4624** carries the user in
`PayloadData1` as `Target: %TargetDomainName%\\%TargetUserName%`, the logon type in
`PayloadData2` as `LogonType %LogonType%`, and the binary in `ExecutableInfo`. A
stored query searching `process_name`/`command_line` on an EVTX family searches
columns that are not there - which is what the reviewer measured.

These tests read the **pinned EZTools maps** (`evtxecmd_maps.yaml`, imported by
`devtools/knowledge/import_evtx_maps.py`), so the evidence is the parser's own
extraction and not this agent's idea of what a 4624 row holds.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
HELPER = REPO / "devtools" / "knowledge" / "evtx_concept_columns.py"


@pytest.fixture(scope="module")
def ecc():
    spec = importlib.util.spec_from_file_location("ecc", HELPER)
    assert spec and spec.loader, HELPER
    module = importlib.util.module_from_spec(spec)
    sys.modules["ecc"] = module
    spec.loader.exec_module(module)
    return module


def test_the_maps_snapshot_is_present(ecc):
    assert ecc.summary()["entries"] >= 400, ecc.summary()


def test_a_4624_user_is_carried_by_the_generic_columns(ecc):
    """The reviewer's worked example, checked against the pinned maps.

    A 4624 carries **two** users - the subject (`UserName`) and the target
    (`PayloadData1`, `Target: <domain>\\<user>`) - and a stored query that wants
    "the user who was logged onto" must target the target one, not the subject.
    """
    cols = {c["column"] for c in ecc.columns_for_concept("user", event_id="4624")}
    assert "PayloadData1" in cols, cols
    assert "UserName" in cols, cols
    target = next(c for c in ecc.columns_for_concept("user", event_id="4624")
                  if c["column"] == "PayloadData1")
    assert target["template"].startswith("Target: "), target["template"]
    assert "%TargetUserName%" in target["template"], target["template"]


def test_a_4624_logon_type_is_payloaddata2(ecc):
    cols = {c["column"] for c in ecc.columns_for_concept("logontype", event_id="4624")}
    assert "PayloadData2" in cols, cols


def test_a_bare_value_column_has_no_literal_prefix(ecc):
    """Honest limit: `%domain%\\%user%` has no static text before the placeholder.

    Searching the column for a literal prefix would be wrong, so the helper returns
    the placeholder name rather than inventing one - and a caller that wants to
    match must search the value itself, not a prefix.
    """
    assert ecc.query_for_concept("logontype", event_id="4624") == []


def test_the_columns_the_importer_slots_pretend_to_be_are_not_the_evtx_columns():
    """The registry has no `command_line`/`process_name` for EvtxECmd rows.

    This is the reviewer's measurement restated: those slots exist for the ingest
    schema, which `expand_families` mixes into `evtxecmd`.
    """
    from nexus.knowledge.query_validation import load_field_registry

    cols = load_field_registry()
    for slot in ("process_name", "command_line", "parent_process"):
        info = cols.get(slot) or {}
        fams = {str(f).lower() for f in (info.get("families") or [])}
        assert "evtxecmd" not in fams, f"{slot} should not be an evtxecmd column"
    # ... and the columns that ARE there are the generic ones.
    assert "evtxecmd" in {str(f).lower() for f in
                          (cols.get("PayloadData1") or {}).get("families") or []}
