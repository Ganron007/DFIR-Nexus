"""A tool's own stdout is not evidence (D57; found on CASE-C5B04D31, 2026-10-11).

persist_tool_output appended every lane output to evidence.json as a tool_extraction item: 232 such
items sat in the registry, beside the examiner's two evidence items. The default is now off, and the two
MCP callers pass it off. Registration stays available for a file the examiner supplies.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from nexus.case.outputs import persist_tool_output

REPO = Path(__file__).resolve().parents[1]


def test_a_tool_output_is_recorded_in_the_case_but_not_registered_as_evidence(tmp_path):
    case = tmp_path / "CASE-OUTPUT"
    case.mkdir()
    (case / "evidence.json").write_text("[]", encoding="utf-8")

    result = persist_tool_output(tool_key="sbecmd", stdout="a,b\n1,2\n", case_dir=case)

    assert result["output_files"], "the output is written into the case folder"
    assert json.loads((case / "evidence.json").read_text(encoding="utf-8")) == []


def test_registration_still_happens_when_it_is_asked_for(tmp_path):
    case = tmp_path / "CASE-REGISTER"
    case.mkdir()
    (case / "evidence.json").write_text("[]", encoding="utf-8")

    persist_tool_output(tool_key="sbecmd", stdout="a,b\n1,2\n", case_dir=case, register_evidence=True)

    entries = json.loads((case / "evidence.json").read_text(encoding="utf-8"))
    assert len(entries) == 1 and entries[0]["kind"] == "tool_extraction"


def test_both_mcp_callers_persist_tool_output_as_not_evidence():
    for rel in ("src/nexus/tools/windows.py", "src/nexus/tools/sift.py"):
        text = (REPO / rel).read_text(encoding="utf-8")
        calls = re.findall(r"persist_tool_output\((.*?)\n\s*\)", text, flags=re.DOTALL)
        assert calls, rel
        for call in calls:
            assert "register_evidence=False" in call, f"{rel} registers a tool output as evidence"
            assert "register_evidence=True" not in call, rel
