"""A case's evidence paths are the examiner's evidence, never the lane's own tool output (D57; 2026-10-11).

A --from-case run inherits its case's registered paths. Those included tool stdout captures (kind
tool_extraction, and plain file entries under the case's runs or extractions folders), so the register
step registered hayabusa_stdout.txt as evidence on the re-run of CASE-C5B04D31.
"""

from __future__ import annotations

import json

from nexus.config import settings
from nexus.langgraph import llm_pipeline


def test_the_case_evidence_paths_are_the_examiners_items_only(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "cases_root", tmp_path)
    case = tmp_path / "CASE-EVIDENCE"
    examiner_item = tmp_path / "source" / "disk.E01"
    examiner_item.parent.mkdir(parents=True)
    examiner_item.write_text("evidence", encoding="utf-8")
    capture = case / "runs" / "RUN-1" / "extractions" / "hayabusa" / "x_stdout.txt"
    capture.parent.mkdir(parents=True)
    capture.write_text("tool output", encoding="utf-8")
    flat_capture = case / "extractions" / "sbecmd" / "y_stdout.txt"
    flat_capture.parent.mkdir(parents=True)
    flat_capture.write_text("tool output", encoding="utf-8")
    (case / "evidence.json").write_text(json.dumps([
        {"path": str(examiner_item), "kind": "file"},
        {"path": str(capture), "kind": "tool_extraction"},
        {"path": str(flat_capture), "kind": "file"},
    ]), encoding="utf-8")

    assert llm_pipeline._case_evidence_paths("CASE-EVIDENCE") == [str(examiner_item)]
