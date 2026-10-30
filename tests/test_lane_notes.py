"""D493: the rows the lane writes about the evidence, and the importer pass's rows, each have one definition.

The tool lane writes rows that name no tool: `(discovery)`, `(empty)` (T06's file of zeros) and `(network)`. The plan
sliver kept its own list of them, the coverage matrix another, and they disagreed: the plan offered T06's `(empty)`
row to the examiner as a parser gap, and the R1 matrix read it as a tool missing from the universe. The importer
pass's rows are named `import:<source>`, or `import` for a file no importer recognised (T18's empty `spooler` and
`tallylog`), which the matrix read as a tool called `import`.
"""
from __future__ import annotations

import ast
from pathlib import Path

from nexus.langgraph import tool_lane
from nexus.langgraph.lane_gate import IMPORT_TOOL, import_row, import_source

LANE_MODULES = [Path(tool_lane.__file__), Path(tool_lane.__file__).with_name("network_lane.py")]


def test_every_row_the_lane_writes_names_a_tool_or_one_of_its_notes():
    notes, literals = set(), set()
    for path in LANE_MODULES:
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if not (isinstance(node, ast.keyword) and node.arg == "tool"):
                continue
            if isinstance(node.value, ast.Name) and node.value.id.startswith("NOTE_"):
                notes.add(getattr(tool_lane, node.value.id))
            elif isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                literals.add(node.value.value)
    assert notes == tool_lane.LANE_NOTES, "every note is written by its name, and every name is written"
    assert not [name for name in literals if name.startswith("(") or tool_lane.is_lane_note(name)]


def test_a_file_of_zeros_is_a_note_not_a_tool(tmp_path):
    zeros = tmp_path / "$Max"
    zeros.write_bytes(b"\x00" * 4096)
    [job] = tool_lane._plan_single_artifact(zeros, tmp_path / "ex")
    assert tool_lane.is_lane_note(job.tool) and job.status == "SKIP"
    assert not tool_lane.is_lane_note("mftecmd")


def test_an_importer_row_is_told_from_a_tool_by_the_gates_own_naming(tmp_path):
    empty, log = tmp_path / "spooler", tmp_path / "bind.log"
    empty.write_bytes(b"")
    log.write_text("x\n", encoding="utf-8")
    bare = import_row(empty, {})
    named = import_row(log, {"source": "bind", "artifacts": 1})
    assert (bare["tool"], bare["reason"]) == (IMPORT_TOOL, "empty file")
    assert import_source(bare["tool"]) == "" and import_source(named["tool"]) == "bind"
    assert import_source("hayabusa") is None and import_source("importer") is None
