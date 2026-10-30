"""D502: file-name tokens cannot displace the tool/family identity within the existing linkage budget.

The producer input is an unchanged native ledger row with 1,179 output paths; it is read in place, not fabricated
or redistributed. The matching audit JSONL entry is copied verbatim into the isolated scratch case.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from nexus.langgraph.audit_linkage import _MAX_TOKENS_PER_ID, is_linked, linkage_map, tool_tokens

SOURCE = Path(__file__).resolve().parents[1] / "cases/CASE-218CD55A"
LEDGER = SOURCE / "runs/RUN-20261030T053019140016Z-tools-c1e652f7/ledger/_tool_lane_ledger.json"
AUDIT_ID = "nexus-claudebot-20261030-005"


@pytest.mark.skipif(not LEDGER.is_file(), reason="the private native T02 ledger is not present on this host")
def test_many_native_output_paths_keep_their_producing_tool_linked(tmp_path):
    row = next(r for r in json.loads(LEDGER.read_text(encoding="utf-8")) if r.get("audit_id") == AUDIT_ID)
    assert len(row["output_files"]) == 1179
    case = tmp_path / "CASE-LINKAGE"
    ledger = case / "extractions/_tool_lane_ledger.json"
    ledger.parent.mkdir(parents=True)
    ledger.write_text(json.dumps([row]), encoding="utf-8")
    audit_line = None
    for audit in (SOURCE / "audit").glob("*.jsonl"):
        with audit.open(encoding="utf-8") as stream:
            audit_line = next((line for line in stream if json.loads(line).get("audit_id") == AUDIT_ID), None)
        if audit_line:
            break
    assert audit_line, "the native call has its actual case audit record"
    audit_dir = case / "audit"
    audit_dir.mkdir()
    (audit_dir / "nexus.jsonl").write_text(audit_line, encoding="utf-8")
    tokens = linkage_map(case)[AUDIT_ID]
    assert tool_tokens(row["tool"]) <= tokens
    assert tool_tokens(json.loads(audit_line)["tool"]) <= tokens
    assert len(tokens) <= _MAX_TOKENS_PER_ID == 64
    assert is_linked(case, AUDIT_ID, families=["thumbcache_viewer"])
    assert not is_linked(case, AUDIT_ID, families=["vol"])
