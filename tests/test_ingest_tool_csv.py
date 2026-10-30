"""D282, D283: a tool's CSV is read as that tool's output, and a header word alone picks no importer (2026-10-18).

Sample S09 registers folders of the examiner's own tool output. RECmd's TaskCache CSV has an Author column and went
to the task-XML importer by it, which read 0 rows; a registered EvtxECmd CSV failed on an "evtx" importer that does
not exist; the rest was read as generic rows, 626,255 under no family. The fixtures are the first records of real
files, verbatim: S09's TaskCache CSV and an EvtxECmd output from the ES-Mapping folder.
"""
from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

import pytest

from nexus.ingest.detect import detect_format
from nexus.ingest.schemas import ArtifactSource
from nexus.langgraph.lane_gate import import_row
from nexus.langgraph.timeline_merge import ingest_into_case

FIXTURES = Path(__file__).parent / "fixtures"
EVTXECMD = FIXTURES / "d283_tool_csv" / "20260822131246_EvtxECmd_Output.csv"


@pytest.fixture
def case(tmp_path):
    case_dir = tmp_path / "CASE-S09"
    (case_dir / "audit").mkdir(parents=True)
    return case_dir


def _audit(case_dir: Path) -> list[dict]:
    return [json.loads(line) for f in (case_dir / "audit").glob("*.jsonl")
            for line in f.read_text(encoding="utf-8").splitlines() if line.strip()]


def test_a_header_word_its_importer_does_not_confirm_leaves_the_csv_to_the_generic_reader(case, tmp_path):
    taskcache = tmp_path / "Registry" / "20250227112749_TaskCache_Windows_System32_config_SOFTWARE.csv"
    taskcache.parent.mkdir()
    shutil.copy(FIXTURES / "d282_taskcache.csv", taskcache)
    assert detect_format(taskcache) == ArtifactSource.GENERIC_CSV
    info = ingest_into_case(taskcache, case)
    assert (info["source"], info["artifacts"]) == ("generic_csv", 2)
    assert import_row(taskcache, info)["status"] == "OK"


def test_a_tool_csv_in_a_registered_folder_is_indexed_as_that_tool(case, tmp_path):
    folder = tmp_path / "processed"
    folder.mkdir()
    src = folder / EVTXECMD.name
    shutil.copy(EVTXECMD, src)
    info = ingest_into_case(src, case)
    placed = Path(info["placed_at"])
    assert (info["source"], info["artifacts"]) == ("evtxecmd", 3)
    assert placed == case / "ingest" / "evtxecmd" / src.name, "the family folder the index names rows by"
    assert hashlib.sha256(placed.read_bytes()).digest() == hashlib.sha256(src.read_bytes()).digest()
    assert not (case / "ingest" / "artifacts.jsonl").exists(), "not read a second time as generic rows"
    assert import_row(src, info) == {"tool": "import:evtxecmd", "purpose": f"import {src}", "family": "evtxecmd",
                                     "pass": "importer", "status": "OK", "reason": "3 row(s)"}
    entry = _audit(case)[-1]
    assert entry["tool"] == "ingest_auto" and entry["result_summary"]["placed_at"] == str(placed)
    # A second lane run places nothing new.
    assert ingest_into_case(src, case)["placed_at"] == str(placed)
    assert [p.name for p in (case / "ingest" / "evtxecmd").iterdir()] == [src.name]
